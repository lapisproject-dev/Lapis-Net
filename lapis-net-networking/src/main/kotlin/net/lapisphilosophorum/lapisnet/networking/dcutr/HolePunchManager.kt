package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.PeerId
import java.net.InetSocketAddress
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

private const val REANNOUNCE_DELAY_NANOS = 250_000_000L
private const val ROLE_REGISTRY_FULL = "role registry full"

/** Why one hole-punch attempt did not produce a direct connection. Plain text, never contains addresses. */
class HolePunchFailure(
    val reason: String,
) : RuntimeException(reason)

/** Time source and scheduler of the state machine; tests replace it with a manual clock. */
internal interface HolePunchClock {
    fun nowMillis(): Long

    fun nanoTime(): Long

    /** Runs [task] after [delayNanos]; closing the handle cancels it. */
    fun schedule(
        delayNanos: Long,
        task: Runnable,
    ): AutoCloseable

    fun close() = Unit
}

internal class SystemHolePunchClock : HolePunchClock {
    private val executor =
        ScheduledThreadPoolExecutor(1) { r -> Thread(r, "lapis-holepunch").apply { isDaemon = true } }
            .apply { removeOnCancelPolicy = true }

    override fun nowMillis(): Long = System.currentTimeMillis()

    override fun nanoTime(): Long = System.nanoTime()

    override fun schedule(
        delayNanos: Long,
        task: Runnable,
    ): AutoCloseable {
        val future =
            try {
                executor.schedule(
                    {
                        try {
                            task.run()
                        } catch (e: RuntimeException) {
                            logger.warn { "hole punch timer task failed: ${e.javaClass.simpleName}" }
                        }
                    },
                    delayNanos.coerceAtLeast(0),
                    TimeUnit.NANOSECONDS,
                )
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                return AutoCloseable { }
            }
        return AutoCloseable { future.cancel(false) }
    }

    override fun close() {
        executor.shutdownNow()
    }
}

/** What the state machine needs from the node; the real one is [NodeHolePunchEnvironment]. */
internal interface HolePunchEnvironment {
    fun openWire(connection: Connection): CompletableFuture<DcutrWire>

    fun hasDirectConnection(peer: PeerId): Boolean

    fun isRelayed(connection: Connection): Boolean

    fun ownAddresses(): Set<InetSocketAddress>

    /** Dials [remote] from the listener port with the role the state machine decided. */
    fun punchDial(
        remote: InetSocketAddress,
        expected: PeerId,
        initiatorRole: Boolean,
    ): CompletableFuture<Connection>

    /** Registers that a connection from [remote] is expected to be [peer] with this role; `null` if the register is full. */
    fun registerRole(
        peer: PeerId,
        remote: InetSocketAddress,
        initiatorRole: Boolean,
    ): AutoCloseable?

    /**
     * Whether other peers currently hold role entries on [remote]. A punch that fails on such a contested
     * address is not necessarily the fault of [peer] (a hostile peer can name someone else's address).
     */
    fun hasForeignRoleEntries(
        peer: PeerId,
        remote: InetSocketAddress,
    ): Boolean = false

    /** The peer an incoming direct connection was registered for, by its remote address; `null` if none. */
    fun expectedPeerAt(connection: Connection): PeerId?

    /** Asks the reservation relays for the address they observe this node at. */
    fun refreshObservedAddresses(): CompletableFuture<Unit>
}

/** Snapshot of the hole-punching counters, for `/status` and the CLI. */
data class HolePunchStatus(
    val mode: HolePunchMode,
    val attemptsStarted: Long,
    val succeeded: Long,
    val failed: Long,
    val rejected: Long,
    val identityMismatches: Long,
    val lastFailure: String?,
    val activeSessions: Int,
    val trackedPeers: Int,
)

/**
 * The DCUtR state machine (libp2p hole-punching specification).
 *
 * Roles follow the specification: **B** is the peer that *received* the relayed connection (it holds
 * the reservation behind the NAT). B opens the `/libp2p/dcutr` stream, sends CONNECT with its observed
 * addresses, measures the round trip, receives A's CONNECT, sends SYNC and dials A after RTT/2. **A**
 * answers with CONNECT and dials the moment SYNC arrives. For everything above TCP, **A is the
 * client**, even if the connection reaches A through its listener (see [PunchRoleRegistry]).
 *
 * Everything is bounded: attempts per peer (with exponential backoff), concurrent sessions, tracked
 * peers, responder sessions per peer and window, message sizes, dial targets, and every wait has a timeout.
 * A failed punch never touches the relayed connection; a successful one lets it go after a grace period.
 */
class HolePunchManager internal constructor(
    private val env: HolePunchEnvironment,
    private val book: ObservedAddressBook,
    private val filter: HolePunchAddressFilter,
    private val config: HolePunchConfig,
    private val clock: HolePunchClock = SystemHolePunchClock(),
    /**
     * Called with the direct connection after the relayed one it replaced was closed. Protocols that learn
     * about peers from connection events (GossipSub) forget a peer when ANY of its connections closes, so
     * they have to be told about the surviving direct connection again.
     */
    private val onRelayReplaced: (Connection) -> Unit = {},
) : ConnectionHandler {
    private val stopped = AtomicBoolean(false)

    // Separate pools per role: a peer that merely opens relayed connections (role B) cannot starve the
    // punches other peers start towards us (role A) and vice versa.
    private val initiatorPermits = Semaphore(config.maxConcurrentUpgrades)
    private val responderPermits = Semaphore(config.maxConcurrentUpgrades)
    private val sessions = ConcurrentHashMap<PeerId, Attempt>()
    private val timers = ConcurrentLinkedQueue<AutoCloseable>()

    private class PeerState(
        var attempts: Int = 0,
        var nextAllowedAtMs: Long = 0,
    )

    private val lock = Any()
    private val states =
        object : LinkedHashMap<PeerId, PeerState>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, PeerState>?): Boolean =
                size > config.maxTrackedPeers
        }
    private val responderHistory =
        object : LinkedHashMap<PeerId, ArrayDeque<Long>>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, ArrayDeque<Long>>?): Boolean =
                size > config.maxTrackedPeers
        }

    private val started = AtomicLong()
    private val succeeded = AtomicLong()
    private val failed = AtomicLong()
    private val rejected = AtomicLong()
    private val mismatches = AtomicLong()

    @Volatile
    private var lastFailure: String? = null

    fun status(): HolePunchStatus =
        HolePunchStatus(
            config.mode,
            started.get(),
            succeeded.get(),
            failed.get(),
            rejected.get(),
            mismatches.get(),
            lastFailure,
            sessions.size,
            synchronized(lock) { states.size },
        )

    // ---------------------------------------------------------------------------------------------
    // Entry points
    // ---------------------------------------------------------------------------------------------

    /** Registered as a relayed-inbound handler: fires for a relayed connection this node ACCEPTED, i.e. the "B" role. */
    override fun handleConnection(conn: Connection) {
        if (stopped.get()) return
        val peer = runCatching { conn.secureSession().remoteId }.getOrNull() ?: return
        if (!env.isRelayed(conn)) return
        if (env.hasDirectConnection(peer)) return
        beginAttempt(peer, conn, initiatorPermits) { attempt -> runInitiator(attempt) }
    }

    /** A dcutr stream a peer opened to us over [conn]: the "A" role. Refused unless it is safe and useful. */
    internal fun onInboundStream(
        conn: Connection,
        wire: DcutrWire,
    ) {
        val peer = runCatching { conn.secureSession().remoteId }.getOrNull()
        val acceptable =
            peer != null &&
                !stopped.get() &&
                // dcutr over a direct connection is pointless and would be an amplification lever
                env.isRelayed(conn) &&
                !env.hasDirectConnection(peer) &&
                responderRateAllowed(peer)
        if (!acceptable || !beginAttempt(peer!!, conn, responderPermits) { attempt -> runResponder(attempt, wire) }) {
            rejected.incrementAndGet()
            wire.close()
        }
    }

    /** Every direct connection of the node: completes the rendezvous of a waiting session. */
    fun onDirectConnection(conn: Connection) {
        if (stopped.get() || env.isRelayed(conn)) return
        val peer = runCatching { conn.secureSession().remoteId }.getOrNull() ?: return
        val expected = env.expectedPeerAt(conn)
        // Only inbound connections are checked, and a mismatch merely keeps the connection out of the
        // rendezvous: the registered address is attacker-influenced, so closing would let a hostile peer
        // cut off unrelated connections.
        if (!conn.isInitiator && expected != null && expected != peer) {
            mismatches.incrementAndGet()
            logger.warn { "ignoring a direct connection whose peer id does not match the hole-punch target" }
            return
        }
        sessions[peer]?.offer(conn)
    }

    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        sessions.values.toList().forEach { it.abort(HolePunchFailure("node stopping")) }
        timers.forEach { runCatching { it.close() } }
        timers.clear()
        clock.close()
    }

    // ---------------------------------------------------------------------------------------------
    // Admission and bookkeeping
    // ---------------------------------------------------------------------------------------------

    private fun beginAttempt(
        peer: PeerId,
        relayConn: Connection,
        permits: Semaphore,
        body: (Attempt) -> CompletableFuture<Connection>,
    ): Boolean {
        synchronized(lock) {
            val state = states[peer]
            if (state != null && clock.nowMillis() < state.nextAllowedAtMs) return false
        }
        if (!permits.tryAcquire()) return false
        val attempt = Attempt(peer, relayConn, permits)
        if (sessions.putIfAbsent(peer, attempt) != null) {
            permits.release()
            return false
        }
        started.incrementAndGet()
        val outcome =
            try {
                body(attempt)
            } catch (e: RuntimeException) {
                CompletableFuture.failedFuture(e)
            }
        outcome.whenComplete { connection, error -> finish(attempt, connection, error) }
        return true
    }

    private fun responderRateAllowed(peer: PeerId): Boolean =
        synchronized(lock) {
            val now = clock.nowMillis()
            val window = config.responderWindow.toMillis()
            val history = responderHistory.getOrPut(peer) { ArrayDeque() }
            while (history.isNotEmpty() && now - history.first() > window) history.removeFirst()
            if (history.size >= config.maxResponderSessionsPerPeerPerWindow) return false
            history.addLast(now)
            true
        }

    private fun finish(
        attempt: Attempt,
        connection: Connection?,
        error: Throwable?,
    ) {
        if (!attempt.markFinished()) return
        // Dials still in flight are only cancelled when the attempt failed: after a success one of them can
        // be the very TCP connection the peer's accept side is using, and cancelling it would kill the winner.
        val contested = attempt.isContested()
        attempt.release(cancelDials = error != null || connection == null)
        sessions.remove(attempt.peer, attempt)
        attempt.permits.release()
        if (connection != null && error == null) {
            succeeded.incrementAndGet()
            synchronized(lock) { states.remove(attempt.peer) }
            logger.info { "hole punch succeeded with ${attempt.peer}" }
            scheduleRelayClose(attempt.relayConn, connection)
        } else {
            failed.incrementAndGet()
            val reason = reasonOf(error)
            lastFailure = reason
            // Neither a full role register nor a contested address proves the peer misbehaved: a hostile third
            // peer can fill or share the address, and must not be able to push an honest peer into backoff.
            if (reason != ROLE_REGISTRY_FULL && !contested) recordFailure(attempt.peer)
            logger.info { "hole punch with ${attempt.peer} failed: $reason" }
        }
    }

    private fun recordFailure(peer: PeerId) {
        synchronized(lock) {
            if (states.size >= config.maxTrackedPeers) {
                val now = clock.nowMillis()
                states.values.removeIf { it.nextAllowedAtMs <= now }
            }
            val state = states.getOrPut(peer) { PeerState() }
            state.attempts++
            val delay =
                if (state.attempts >= config.maxAttemptsPerPeer) {
                    // Gave up: nothing before the maximum backoff has passed, then the count starts over.
                    state.attempts = 0
                    config.backoffMax.toMillis()
                } else {
                    val factor = 1L shl (state.attempts - 1).coerceAtMost(20)
                    minOf(config.backoffBase.toMillis() * factor, config.backoffMax.toMillis())
                }
            state.nextAllowedAtMs = clock.nowMillis() + delay
        }
    }

    /** Milliseconds until [peer] may be tried again, 0 if now. For tests and diagnostics. */
    internal fun backoffRemainingMillis(peer: PeerId): Long =
        synchronized(lock) { maxOf(0, (states[peer]?.nextAllowedAtMs ?: 0) - clock.nowMillis()) }

    internal fun trackedPeerCount(): Int = synchronized(lock) { states.size }

    /**
     * Lets the relayed connection go once the direct one has replaced it, and re-announces the direct
     * connection when the relayed one is gone.
     *
     * The re-announcement is tied to the relayed connection ending, NOT to this side being the one that
     * closes it. Both peers run this on their own timer; whichever closes first ends the connection for the
     * other as well, so the second timer regularly finds it already closed. If only the side that closed it
     * re-announced, the other side would stay without a GossipSub stream towards the peer for good (a peer's
     * GossipSub stream is outbound-only): everything it publishes goes nowhere.
     */
    private fun scheduleRelayClose(
        relayConn: Connection,
        direct: Connection,
    ) {
        if (stopped.get()) return
        val reannounced = AtomicBoolean(false)
        relayConn.closeFuture().whenComplete { _, _ ->
            // A moment later, so every listener of the closed connection has run first.
            if (!stopped.get() && reannounced.compareAndSet(false, true)) {
                timers +=
                    clock.schedule(REANNOUNCE_DELAY_NANOS) {
                        if (!direct.closeFuture().isDone && !stopped.get()) {
                            runCatching { onRelayReplaced(direct) }
                                .onFailure { logger.warn { "re-announcing a direct connection failed" } }
                        }
                    }
            }
        }
        timers +=
            clock.schedule(config.relayCloseGrace.toNanos()) {
                if (!direct.closeFuture().isDone && !relayConn.closeFuture().isDone) {
                    logger.debug { "closing the relayed connection, the direct one replaces it" }
                    relayConn.close()
                }
            }
    }

    private fun reasonOf(error: Throwable?): String {
        val cause = generateSequence(error) { if (it is CompletionException) it.cause else null }.lastOrNull()
        return (cause as? HolePunchFailure)?.reason ?: cause?.javaClass?.simpleName ?: "unknown"
    }

    // ---------------------------------------------------------------------------------------------
    // The two roles
    // ---------------------------------------------------------------------------------------------

    private fun runInitiator(a: Attempt): CompletableFuture<Connection> =
        ownAddresses(a).thenCompose { own ->
            within(env.openWire(a.relayConn), "open dcutr stream").thenCompose { wire ->
                a.wire = wire
                val t0 = clock.nanoTime()
                wire
                    .send(HolePunchMessage(HolePunchType.CONNECT, own.map { it.serialize() }))
                    .thenCompose { within(wire.receive(), "no CONNECT reply") }
                    .thenCompose { reply ->
                        val rtt = clock.nanoTime() - t0
                        if (reply.type != HolePunchType.CONNECT) throw HolePunchFailure("unexpected message from peer")
                        val targets = filter.dialable(reply.observedAddresses, env.ownAddresses())
                        if (targets.isEmpty()) throw HolePunchFailure("peer offered no dialable address")
                        val registered = a.expect(targets, initiatorRole = false)
                        wire.send(HolePunchMessage(HolePunchType.SYNC)).thenCompose {
                            wire.close()
                            punch(a, registered, initiatorRole = false, delayNanos = rtt / 2)
                        }
                    }
            }
        }

    private fun runResponder(
        a: Attempt,
        wire: DcutrWire,
    ): CompletableFuture<Connection> {
        a.wire = wire
        return within(wire.receive(), "no CONNECT from peer").thenCompose { first ->
            if (first.type != HolePunchType.CONNECT) throw HolePunchFailure("unexpected message from peer")
            val targets = filter.dialable(first.observedAddresses, env.ownAddresses())
            // Answered at once from what is already known: B measures the round trip on this reply,
            // so waiting for an address lookup here would skew its dial timing.
            val own = book.confirmed(config.observedAddressThreshold)
            wire.send(HolePunchMessage(HolePunchType.CONNECT, own.map { it.serialize() })).thenCompose {
                if (targets.isEmpty()) throw HolePunchFailure("peer offered no dialable address")
                if (own.isEmpty()) throw HolePunchFailure("no observed address")
                within(wire.receive(), "no SYNC from peer").thenCompose { sync ->
                    if (sync.type != HolePunchType.SYNC) throw HolePunchFailure("unexpected message from peer")
                    wire.close()
                    // Registered only now, after SYNC: a hostile peer's claim on the address then lives as long
                    // as the punch, not as long as it can delay the exchange.
                    val registered = a.expect(targets, initiatorRole = true)
                    punch(a, registered, initiatorRole = true, delayNanos = 0)
                }
            }
        }
    }

    private fun ownAddresses(a: Attempt): CompletableFuture<List<io.libp2p.core.multiformats.Multiaddr>> {
        val known = book.confirmed(config.observedAddressThreshold)
        if (known.isNotEmpty()) return CompletableFuture.completedFuture(known)
        return within(env.refreshObservedAddresses(), "address observation")
            .handle { _, _ -> book.confirmed(config.observedAddressThreshold) }
            .thenApply { found ->
                if (found.isEmpty()) throw HolePunchFailure("no observed address")
                found
            }
    }

    /** Dials [targets] after [delayNanos] and waits for the rendezvous (our dial or the peer's, whichever arrives). */
    private fun punch(
        a: Attempt,
        targets: List<InetSocketAddress>,
        initiatorRole: Boolean,
        delayNanos: Long,
    ): CompletableFuture<Connection> {
        a.timers += clock.schedule(delayNanos) { a.launchDials(targets, initiatorRole) }
        return within(a.result, "punch timed out", config.punchTimeout)
    }

    private fun <T> within(
        future: CompletableFuture<T>,
        what: String,
        timeout: Duration = config.protocolTimeout,
    ): CompletableFuture<T> {
        val timer =
            clock.schedule(
                timeout.toNanos(),
            ) { future.completeExceptionally(HolePunchFailure("timeout: $what")) }
        future.whenComplete { _, _ -> runCatching { timer.close() } }
        return future
    }

    // ---------------------------------------------------------------------------------------------

    private inner class Attempt(
        val peer: PeerId,
        val relayConn: Connection,
        val permits: Semaphore,
    ) {
        /** The rendezvous: the verified direct connection to [peer]. */
        val result = CompletableFuture<Connection>()

        @Volatile
        var wire: DcutrWire? = null
        val timers = ConcurrentLinkedQueue<AutoCloseable>()
        private val registrations = ConcurrentLinkedQueue<AutoCloseable>()
        private val dials = ConcurrentLinkedQueue<CompletableFuture<Connection>>()
        private val finished = AtomicBoolean(false)
        private val targetsSeen = ConcurrentLinkedQueue<InetSocketAddress>()

        @Volatile
        private var contested = false
        private val released = AtomicBoolean(false)

        /** Whether another peer held role entries on an address of this attempt (now or at registration time). */
        fun isContested(): Boolean = contested || targetsSeen.any { env.hasForeignRoleEntries(peer, it) }

        fun markFinished(): Boolean = finished.compareAndSet(false, true)

        /** Registers every target it can and returns those; a refused target is skipped, none left fails the attempt. */
        fun expect(
            targets: List<InetSocketAddress>,
            initiatorRole: Boolean,
        ): List<InetSocketAddress> {
            val registered = ArrayList<InetSocketAddress>()
            for (target in targets) {
                targetsSeen += target
                val registration = env.registerRole(peer, target, initiatorRole)
                if (env.hasForeignRoleEntries(peer, target)) contested = true
                if (registration == null) continue
                registrations += registration
                registered += target
            }
            if (registered.isEmpty()) throw HolePunchFailure(ROLE_REGISTRY_FULL)
            return registered
        }

        fun launchDials(
            targets: List<InetSocketAddress>,
            initiatorRole: Boolean,
        ) {
            if (result.isDone || stopped.get()) return
            for (target in targets) {
                val dial = env.punchDial(target, peer, initiatorRole)
                dials += dial
                dial.whenComplete { connection, error ->
                    if (connection != null) {
                        offer(connection)
                    } else {
                        logger.debug { "punch dial did not connect: ${error?.javaClass?.simpleName}" }
                    }
                }
            }
        }

        /** A direct connection to [peer] showed up (our dial or the peer's). Verified here, once more, by identity. */
        fun offer(connection: Connection) {
            if (env.isRelayed(connection)) return
            val remote = runCatching { connection.secureSession().remoteId }.getOrNull()
            if (remote != peer) {
                mismatches.incrementAndGet()
                logger.warn { "discarding a connection whose authenticated peer id is not the hole-punch target" }
                connection.close()
                result.completeExceptionally(HolePunchFailure("identity mismatch"))
                return
            }
            // A second direct connection (both sides dialled successfully) is kept: closing
            // asymmetrically could let the two sides drop different connections.
            result.complete(connection)
        }

        fun abort(error: Throwable) {
            result.completeExceptionally(error)
            release(cancelDials = true)
        }

        /** Cancels everything this attempt still holds. Idempotent. */
        fun release(cancelDials: Boolean) {
            if (!released.compareAndSet(false, true)) return
            timers.forEach { runCatching { it.close() } }
            registrations.forEach { runCatching { it.close() } }
            if (cancelDials) dials.forEach { if (!it.isDone) it.cancel(true) }
            wire?.let { runCatching { it.close() } }
            if (!result.isDone) result.completeExceptionally(HolePunchFailure("attempt ended"))
        }
    }
}
