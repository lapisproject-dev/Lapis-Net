package net.lapisphilosophorum.lapisnet.networking.relay

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/** How often the renewal task wakes up to look for reservations approaching expiry. */
private val RENEWAL_TICK: Duration = Duration.ofSeconds(30)

/**
 * The client side of NAT traversal: obtains and keeps alive Circuit-Relay-v2 reservations on other
 * peers' relays, and derives the `/p2p-circuit` addresses this node can then advertise so peers
 * that could never dial it directly can still reach it.
 *
 * **Explicit, never automatic.** Nothing here runs until a caller names a relay
 * ([reserve]). There is no background "find me a relay" sweep: candidate relays come from the peer
 * directory (`net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip.relayCandidates`, which
 * lists identities advertising `PeerCapability.RELAY`) and the decision to use one is the caller's.
 * That is a deliberate contrast to `io.libp2p.protocol.circuit.RelayTransport.initialize`, which
 * schedules a relay-hunting task on a fixed timer whether or not the node ever wanted one.
 *
 * Renewal, once a reservation exists, *is* automatic: a reservation that silently lapsed would
 * leave this node advertising a `/p2p-circuit` address that no longer resolves, which is worse than
 * advertising none.
 */
class RelayReservationClient internal constructor(
    private val host: Host,
    private val hopBinding: LapisCircuitHopBinding,
    private val limits: RelayClientLimits,
    private val clock: () -> Instant = Instant::now,
) {
    private class Held(
        val relay: PeerInfo,
        @Volatile var reservation: RelayReservation,
    )

    private val held = ConcurrentHashMap<PeerId, Held>()
    private val stopped = AtomicBoolean(false)
    private val renewer: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "lapis-relay-renewal").apply { isDaemon = true }
        }

    private val renewalScheduled = AtomicBoolean(false)

    /**
     * Starts the renewal tick, once, on the first reservation this node actually takes.
     *
     * Deliberately not in an `init` block: every [net.lapisphilosophorum.lapisnet.networking.LapisNode]
     * owns one of these whether or not it ever touches a relay, and scheduling on construction meant
     * every node started a renewal thread that had nothing to renew - including nodes that were
     * never even `start()`ed, whose `stop()` is therefore never called either, leaving the thread
     * behind for the life of the process.
     */
    private fun ensureRenewalScheduled() {
        if (!renewalScheduled.compareAndSet(false, true)) return
        renewer.scheduleWithFixedDelay(
            { runCatching { renewDueReservations() }.onFailure { logger.warn(it) { "relay renewal pass failed" } } },
            RENEWAL_TICK.toSeconds(),
            RENEWAL_TICK.toSeconds(),
            TimeUnit.SECONDS,
        )
    }

    /**
     * Reserves a slot on [relay] so third parties can reach this node through it, and returns the
     * granted reservation.
     *
     * Blocking, with [RelayClientLimits.controlTimeout] as its deadline: this is a deliberate,
     * caller-initiated act, and its result (a working circuit address, or an exception saying why
     * not) is exactly what the caller needs before it can publish anything.
     *
     * @throws RelayException if the relay refuses, misbehaves, or cannot be reached, or if this
     * node already holds [RelayClientLimits.maxReservations] reservations.
     */
    fun reserve(relay: PeerInfo): RelayReservation {
        check(!stopped.get()) { "relay reservation client is stopped" }
        require(relay.peerId != host.peerId) { "cannot reserve a relay slot on ourselves" }
        require(relay.addresses.isNotEmpty()) { "relay ${relay.peerId} has no addresses to dial" }
        if (!held.containsKey(relay.peerId) && held.size >= limits.maxReservations) {
            throw RelayException("already holding ${limits.maxReservations} relay reservations")
        }
        val reservation = requestReservation(relay)
        held[relay.peerId] = Held(relay, reservation)
        ensureRenewalScheduled()
        logger.info { "reserved a relay slot on ${relay.peerId} until ${reservation.expiresAt}" }
        return reservation
    }

    /**
     * One `RESERVE` exchange with [relay], start to finish.
     *
     * The hop control stream is closed in **every** outcome - granted, refused, timed out, or
     * failed. It is a pure control exchange with nothing left to say afterwards, and the reservation
     * itself lives on the underlying *connection*, not on this stream, so closing it costs nothing.
     * Leaving it open cost a great deal: renewal runs every 30 seconds against every held relay, so
     * a relay that grants a reservation and then goes quiet would accumulate one abandoned mplex
     * substream on both ends every half minute, for as long as the node runs. Mirrors the same
     * discipline `LapisRelayTransport.dial` already applies to its own hop stream.
     */
    private fun requestReservation(relay: PeerInfo): RelayReservation {
        val addresses = relay.addresses.map { it.withP2P(relay.peerId) }
        val timeoutMillis = limits.controlTimeout.toMillis()
        val hopStream = CompletableFuture<Stream>()
        return try {
            val promise = hopBinding.dial(host, relay.peerId, *addresses.toTypedArray())
            promise.stream.whenComplete { stream, error ->
                if (error != null) hopStream.completeExceptionally(error) else hopStream.complete(stream)
            }
            val controller = promise.controller.get(timeoutMillis, TimeUnit.MILLISECONDS)
            val sender =
                controller as? HopSender ?: throw RelayException("hop protocol returned a responder controller")
            sender
                .reserve(addresses, limits, clock())
                .get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw RelayException("interrupted while reserving a relay slot on ${relay.peerId}", e)
        } catch (e: RelayException) {
            throw e
        } catch (e: Exception) {
            throw RelayException("failed to reserve a relay slot on ${relay.peerId}: ${e.message}", e)
        } finally {
            // Fires whenever the stream eventually materialises, including after this method has
            // already thrown; a stream that never materialised has nothing to close.
            hopStream.whenComplete { stream, _ -> if (stream != null) runCatching { stream.close() } }
        }
    }

    /**
     * Whether this node currently holds a live reservation with [relay] - the gate [StopReceiver]
     * uses to decide whether an offered inbound circuit is one this node could plausibly have asked
     * for. An expired reservation counts as absent, exactly as it does for [circuitAddresses].
     */
    fun holdsReservationWith(relay: PeerId): Boolean {
        val entry = held[relay] ?: return false
        return entry.reservation.expiresAt.isAfter(clock())
    }

    /** Reservations currently held, newest state per relay. */
    fun reservations(): List<RelayReservation> = held.values.map { it.reservation }

    /**
     * The `/p2p-circuit` addresses this node is currently reachable at, one per address of each
     * relay holding a live reservation. Each is `<relay addr>/p2p/<relay>/p2p-circuit`; the
     * trailing `/p2p/<self>` is appended by libp2p's own `Host.listenAddresses()`.
     *
     * Expired reservations are filtered out rather than merely renewed on a timer, so this never
     * hands back an address that is already known not to work.
     */
    fun circuitAddresses(): List<Multiaddr> {
        val now = clock()
        return held.values
            .filter { it.reservation.expiresAt.isAfter(now) }
            .flatMap { entry -> entry.reservation.relayAddresses.map { circuitListenAddress(it) } }
            .distinct()
    }

    /** Drops the reservation held on [relay], if any. The relay forgets it on its own once the TTL
     * runs out; this only stops this node from advertising or renewing it. */
    fun release(relay: PeerId) {
        held.remove(relay)
    }

    internal fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        held.clear()
        renewer.shutdownNow()
    }

    private fun renewDueReservations() {
        if (stopped.get()) return
        val now = clock()
        held.values.forEach { entry ->
            if (entry.reservation.expiresAt
                    .minus(limits.renewBefore)
                    .isAfter(now)
            ) {
                return@forEach
            }
            runCatching { requestReservation(entry.relay) }
                .onSuccess { renewed ->
                    entry.reservation = renewed
                    logger.debug { "renewed relay reservation on ${entry.relay.peerId} until ${renewed.expiresAt}" }
                }.onFailure { error ->
                    // Keep the (possibly already expired) entry rather than dropping it:
                    // circuitAddresses() already filters expired entries out, and keeping it means
                    // the next tick retries instead of silently forgetting the relay forever.
                    logger.warn { "failed to renew relay reservation on ${entry.relay.peerId}: ${error.message}" }
                }
        }
    }
}
