package net.lapisphilosophorum.lapisnet.networking.relay

import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import java.time.Duration
import java.time.Instant
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicInteger

/** One granted reservation, as the relay itself tracks it. */
internal class GrantedReservation(
    val requestor: PeerId,
    /** The address the reservation holder was observed connecting **from**. Handed to
     * `host.newStream(...)` when a circuit needs to reach it - in practice that call short-circuits
     * onto the already-open reservation connection (see [RelayReservationRegistry]'s doc comment),
     * so this is a fallback hint rather than something ever really dialled. */
    val observedAddress: Multiaddr,
    val expiresAt: Instant,
    /** Circuits currently terminating at this peer. **Shared across renewals _and_ across an
     * expiry/re-reservation gap** - see [RelayReservationRegistry.reserve]: a renewal replaces the
     * [GrantedReservation] object while circuits opened against the previous one are still live, and
     * those circuits release against whichever object their close callback captured. If each
     * renewal got a fresh counter, every such release would decrement an object nobody consults any
     * more while the live object's count stayed permanently inflated, so a long-lived peer would
     * slowly lose its whole [RelayServerLimits.maxCircuitsPerReservation] budget. The registry
     * therefore keeps one counter per [PeerId] alive for as long as that peer has any live circuit,
     * even across a prune, and hands the same object to every [GrantedReservation] it mints. */
    val liveCircuits: AtomicInteger = AtomicInteger(0),
)

/**
 * Identifies the *network location* a peer reserved from, for [
 * RelayServerLimits.maxReservationsPerSourceAddress]. `null` when the observed address carries no
 * recognisable host component at all, in which case the per-address cap simply does not apply -
 * refusing on an unparsable address would be a denial-of-service of its own, and the per-[PeerId]
 * cap still holds.
 *
 * Deliberately the bare host component, with no port: a port is free to vary per connection, so
 * keying on it would make the cap trivially bypassable from one machine.
 */
internal fun reservationSourceKey(observedAddress: Multiaddr): String? {
    val hostProtocols = listOf(Protocol.IP4, Protocol.IP6, Protocol.DNS4, Protocol.DNS6, Protocol.DNS, Protocol.DNSADDR)
    return hostProtocols.firstNotNullOfOrNull { protocol ->
        observedAddress.getFirstComponent(protocol)?.stringValue?.let { "${protocol.typeName}/$it" }
    }
}

/**
 * Sliding-window rate limiter over `HOP CONNECT` attempts, keyed by initiating [PeerId].
 *
 * A `CONNECT` is cheap to send and expensive to serve: the relay dials a stop stream and the
 * *target* runs a full Noise handshake. Without a ceiling, any stranger could loop `CONNECT`s at a
 * reserved peer and use this relay as a CPU amplifier pointed at it. Attempts are counted before
 * anything is dialled, so a rejected attempt costs the target nothing.
 *
 * Its own bookkeeping is bounded too: windows that have fully elapsed are dropped on every call,
 * and the table itself is hard-capped - an attacker minting a fresh [PeerId] per attempt would
 * otherwise turn the rate limiter into the unbounded structure it exists to prevent. Once the table
 * is full and nothing can be pruned, further attempts from *unknown* peers are refused (fail
 * closed), which is the same answer they would get a moment later anyway.
 */
internal class ConnectRateLimiter(
    private val limit: Int,
    private val window: Duration,
    private val maxTrackedPeers: Int = DEFAULT_MAX_TRACKED_PEERS,
) {
    private val attempts = HashMap<PeerId, ArrayDeque<Instant>>()

    @Synchronized
    fun tryAcquire(
        peer: PeerId,
        now: Instant,
    ): Boolean {
        val cutoff = now.minus(window)
        prune(cutoff)
        val existing = attempts[peer]
        if (existing == null && attempts.size >= maxTrackedPeers) return false
        val timestamps = existing ?: ArrayDeque<Instant>().also { attempts[peer] = it }
        if (timestamps.size >= limit) return false
        timestamps.addLast(now)
        return true
    }

    /** Attempts currently counted against [peer] - test/diagnostic accessor. */
    @Synchronized
    fun attemptsFor(peer: PeerId): Int = attempts[peer]?.size ?: 0

    @Synchronized
    fun trackedPeers(): Int = attempts.size

    private fun prune(cutoff: Instant) {
        val iterator = attempts.entries.iterator()
        while (iterator.hasNext()) {
            val timestamps = iterator.next().value
            while (timestamps.isNotEmpty() && !timestamps.peekFirst().isAfter(cutoff)) timestamps.removeFirst()
            if (timestamps.isEmpty()) iterator.remove()
        }
    }

    companion object {
        /** Hard ceiling on how many distinct initiators the limiter remembers at once. Generous
         * relative to any legitimate peer count this codebase targets, and finite. */
        const val DEFAULT_MAX_TRACKED_PEERS = 4096
    }
}

/** Outcome of [RelayReservationRegistry.claimCircuitFor]. */
internal sealed interface CircuitClaim {
    /** A slot was claimed against [reservation]; the caller now owes exactly one release. */
    data class Granted(
        val reservation: GrantedReservation,
    ) : CircuitClaim

    /** The named target holds no live reservation on this relay. */
    data object NoReservation : CircuitClaim

    /** A reservation exists, but its own or the relay-wide circuit budget is exhausted. */
    data object LimitExceeded : CircuitClaim
}

/**
 * The relay-server-side reservation table: who is currently reachable *through* this node, until
 * when, and how much forwarding capacity each of them is currently using.
 *
 * **Replaces `io.libp2p.protocol.circuit.CircuitHopProtocol.RelayManager.limitTo` wholesale.** That
 * helper keeps reservations in a plain `HashMap` that is never pruned (an expired reservation stays
 * valid forever, and the map only shrinks when the process exits), hands out a 4 096-byte /
 * 120-second circuit budget that is far too small to carry a real relayed connection, and applies
 * no per-reservation circuit cap at all. This class fixes all four points and is the only
 * reservation authority this module uses.
 *
 * **How a circuit actually reaches a reserved peer.** The reservation is granted over a connection
 * the reserving peer opened *to* this relay, and that connection stays open for the reservation's
 * lifetime. When a third party later asks to be connected to that peer,
 * `io.libp2p.core.Host.newStream` -> `io.libp2p.network.NetworkImpl.connect` finds that existing
 * connection by [PeerId] and short-circuits onto it rather than dialling anything - which is
 * exactly what makes this work for a peer behind NAT that could never be dialled directly. If that
 * connection has gone away, the stop-stream attempt simply fails and the circuit request is
 * refused; nothing here tries to resurrect it.
 *
 * Thread-safe: every mutating method is `synchronized` on this object, and the per-reservation
 * circuit counter is an [AtomicInteger] released from Netty close callbacks on arbitrary event-loop
 * threads.
 */
internal class RelayReservationRegistry(
    private val limits: RelayServerLimits,
) {
    private val reservations = HashMap<PeerId, GrantedReservation>()

    /**
     * One circuit counter per peer, kept alive independently of [reservations] for exactly as long
     * as that peer still has a live circuit. Without this, a reservation that expired while its
     * circuits were still up would be pruned, the peer's next `RESERVE` would mint a *fresh*
     * counter starting at zero, and the still-live circuits would eventually decrement the orphaned
     * old one - letting that peer exceed [RelayServerLimits.maxCircuitsPerReservation] for as long
     * as both generations overlap.
     */
    private val circuitCounters = HashMap<PeerId, AtomicInteger>()
    private val liveCircuits = AtomicInteger(0)
    private val connectRateLimiter =
        ConnectRateLimiter(limits.maxConnectAttemptsPerWindow, limits.connectRateLimitWindow)

    /** Grants (or renews) a reservation for [requestor], or `null` if this relay is full. Expired
     * entries are pruned on every call, so a burst of abandoned reservations frees itself up
     * without needing any background timer. */
    @Synchronized
    fun reserve(
        requestor: PeerId,
        observedAddress: Multiaddr,
        now: Instant,
    ): GrantedReservation? {
        pruneExpired(now)
        // A renewal by a peer that already holds a slot must never be counted as a new slot, or a
        // well-behaved client renewing on schedule would be refused once the relay filled up.
        val existing = reservations[requestor]
        if (existing == null && reservations.size >= limits.maxConcurrentReservations) return null
        if (existing == null && !sourceAddressHasRoom(observedAddress)) return null
        val granted =
            GrantedReservation(
                requestor = requestor,
                observedAddress = observedAddress,
                expiresAt = now.plus(limits.reservationTtl),
                // Carry the SAME counter object across a renewal, not its value - see its own doc
                // comment for the capacity leak that copying the value instead would cause.
                liveCircuits = circuitCounters.getOrPut(requestor) { AtomicInteger(0) },
            )
        reservations[requestor] = granted
        return granted
    }

    /** Whether another *distinct* peer may reserve from [observedAddress]'s host, per
     * [RelayServerLimits.maxReservationsPerSourceAddress]. Callers hold this object's lock. */
    private fun sourceAddressHasRoom(observedAddress: Multiaddr): Boolean {
        val key = reservationSourceKey(observedAddress) ?: return true
        val used = reservations.values.count { reservationSourceKey(it.observedAddress) == key }
        return used < limits.maxReservationsPerSourceAddress
    }

    /** The still-valid reservation for [target], or `null`. */
    @Synchronized
    fun find(
        target: PeerId,
        now: Instant,
    ): GrantedReservation? {
        pruneExpired(now)
        return reservations[target]
    }

    /**
     * Looks a reservation up **and** claims one circuit slot against it in one atomic step. Every
     * [CircuitClaim.Granted] must be paired with exactly one [releaseCircuit] - see
     * `HopReceiver.spliceCircuit`'s close wiring.
     *
     * Deliberately one call rather than [find] followed by [tryClaimCircuit]: between those two the
     * reservation can expire and be pruned, so the pair could claim a slot against a reservation
     * that no longer exists and whose counter nobody consults any more. The three-way result keeps
     * the caller able to answer `NO_RESERVATION` and `RESOURCE_LIMIT_EXCEEDED` distinctly without
     * looking twice.
     */
    @Synchronized
    fun claimCircuitFor(
        target: PeerId,
        now: Instant,
    ): CircuitClaim {
        val reservation = find(target, now) ?: return CircuitClaim.NoReservation
        return if (tryClaimCircuit(reservation)) CircuitClaim.Granted(reservation) else CircuitClaim.LimitExceeded
    }

    /**
     * Claims one circuit slot against [reservation] and the relay-wide budget, or returns `false`
     * if either is exhausted. Prefer [findAndClaim]; this stays separate only so the claim rule
     * itself is directly testable.
     */
    fun tryClaimCircuit(reservation: GrantedReservation): Boolean {
        if (liveCircuits.incrementAndGet() > limits.maxConcurrentCircuits) {
            liveCircuits.decrementAndGet()
            return false
        }
        if (reservation.liveCircuits.incrementAndGet() > limits.maxCircuitsPerReservation) {
            reservation.liveCircuits.decrementAndGet()
            liveCircuits.decrementAndGet()
            return false
        }
        return true
    }

    fun releaseCircuit(reservation: GrantedReservation) {
        reservation.liveCircuits.decrementAndGet()
        liveCircuits.decrementAndGet()
    }

    /**
     * Whether [initiator] may make another `HOP CONNECT` attempt right now - see
     * [ConnectRateLimiter] for why this exists at all.
     */
    fun allowConnectAttempt(
        initiator: PeerId,
        now: Instant,
    ): Boolean = connectRateLimiter.tryAcquire(initiator, now)

    @Synchronized
    fun reservationCount(): Int = reservations.size

    fun circuitCount(): Int = liveCircuits.get()

    private fun pruneExpired(now: Instant) {
        // An expired reservation whose circuits are still being torn down keeps its own counter;
        // the relay-wide counter is only ever decremented by releaseCircuit, so dropping the map
        // entry here cannot lose relay-wide capacity.
        reservations.entries.removeIf { !it.value.expiresAt.isAfter(now) }
        // A per-peer counter outlives its reservation while circuits opened against it are still
        // live (see circuitCounters), and is dropped only once both are gone - so this map is
        // bounded by reservations plus peers with live circuits, never by attempts.
        circuitCounters.entries.removeIf { !reservations.containsKey(it.key) && it.value.get() <= 0 }
    }
}
