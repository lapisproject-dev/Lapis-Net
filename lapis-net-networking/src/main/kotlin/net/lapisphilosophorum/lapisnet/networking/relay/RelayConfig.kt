package net.lapisphilosophorum.lapisnet.networking.relay

import java.time.Duration

/**
 * How a [net.lapisphilosophorum.lapisnet.networking.LapisNode] participates in Circuit-Relay-v2
 * NAT traversal.
 *
 * **Two independent roles, deliberately separated.** Being able to *use* a relay (dial a
 * `/p2p-circuit` address, hold a reservation on somebody else's relay) and being willing to *be* a
 * relay (forward third-party traffic for strangers) are entirely different risk profiles, so they
 * are two different switches rather than one "relay support" flag:
 *
 *  - **Client role** - always available, costs nothing until used. A node can always dial a
 *    `/p2p-circuit` multiaddr, and can ask a relay for a reservation via
 *    [net.lapisphilosophorum.lapisnet.networking.LapisNode.reserveRelaySlot]. Both are explicit,
 *    caller-initiated actions: nothing happens on its own.
 *  - **Server role** - **opt-in, off by default** ([serverEnabled] `= false`). A node that has not
 *    switched this on answers every inbound `HOP RESERVE` with `PERMISSION_DENIED` and every
 *    inbound `HOP CONNECT` with `NO_RESERVATION`, so it can never be conscripted into carrying
 *    somebody else's traffic. This is the single most important safety property of this whole
 *    module: a relay forwards attacker-chosen bytes to attacker-chosen third parties on the
 *    operator's bandwidth and IP address, so it must never be the accidental default.
 *
 * **No Virtus/Libertaler compensation scheme for relay operators in this wave** - a deliberate
 * scope cut, consistent with the answer already settled for storage replication: at the protocol
 * layer, running infrastructure for others earns *reputation* (Madli, `lapis-net-madli`), not
 * payment. Adding a dedicated Madli "relay service quality" metric is a possible follow-up; this
 * wave deliberately ships the raw network capability first and leaves the incentive question
 * exactly where `docs/architecture.adoc` already had it.
 */
data class RelayConfig(
    /** Whether this node is willing to act as a relay **for other peers**. Off by default - see
     * this class's doc comment for why this specific default is load-bearing. */
    val serverEnabled: Boolean = false,
    /** Resource ceilings applied when [serverEnabled] is `true`. Ignored otherwise. */
    val serverLimits: RelayServerLimits = RelayServerLimits(),
    /** Ceilings applied to circuits this node uses as a *client* - see [RelayClientLimits]. */
    val clientLimits: RelayClientLimits = RelayClientLimits(),
) {
    companion object {
        /** Client-capable, never a relay for others. The default for [
         * net.lapisphilosophorum.lapisnet.networking.LapisNode.create]. */
        val CLIENT_ONLY = RelayConfig()

        /** Convenience for an intentionally-operated public relay node. */
        fun relayServer(limits: RelayServerLimits = RelayServerLimits()): RelayConfig =
            RelayConfig(serverEnabled = true, serverLimits = limits)
    }
}

/**
 * Every ceiling a relay-serving node applies to the traffic it forwards for strangers.
 *
 * **Why every single one of these exists.** A relay is the one place in this codebase where a
 * remote, unauthenticated party makes this node spend *its own* bandwidth, sockets and file
 * descriptors on traffic that is not addressed to it and that it cannot read. Every structure an
 * attacker can grow therefore has an explicit, finite cap, exactly as
 * `net.lapisphilosophorum.lapisnet.networking.MAX_CONCURRENT_CONNECTIONS`,
 * `net.lapisphilosophorum.lapisnet.storage.BoundedRecordStore` and `lapis-net-dm`'s
 * `MAX_LIVE_SESSIONS` already do for their own attacker-fillable structures.
 *
 * **The library's own defaults are not usable and are deliberately not reused.**
 * `io.libp2p.protocol.circuit.CircuitHopProtocol.RelayManager.limitTo` hands out reservations with
 * a 4 096-byte / 120-second budget per circuit, which cannot carry even a Noise handshake plus an
 * mplex-multiplexed identify exchange, and it never expires a reservation at all (its map only
 * ever grows until the process restarts). This class replaces both.
 *
 * All magnitudes below are *provisional operator-facing defaults*, not protocol requirements -
 * the same caveat every other numeric cap in this codebase carries.
 */
data class RelayServerLimits(
    /** How many peers may simultaneously hold a reservation on this relay. Each reservation costs
     * one live TCP connection plus a map entry, and a reservation is what makes a peer *dialable
     * through* this node, so this is the primary "how much of a public service am I running"
     * dial. 64 is deliberately small: a personal node volunteering as a relay for a handful of
     * contacts, not an internet-scale relay. */
    val maxConcurrentReservations: Int = 64,
    /** How long a granted reservation stays valid before the client must renew it. Bounds how long
     * a peer that has silently gone away keeps occupying a slot. 15 minutes mirrors the order of
     * magnitude go-libp2p's relay uses, and is short enough that
     * [maxConcurrentReservations] recovers quickly from a burst of abandoned reservations. */
    val reservationTtl: Duration = Duration.ofMinutes(15),
    /** How many circuits (forwarded connections) this relay will carry at once, across all
     * reservations. Each circuit pins two streams and proxies bytes between them, so this bounds
     * the relay's total forwarding footprint independently of how many peers hold reservations. */
    val maxConcurrentCircuits: Int = 128,
    /** How many circuits may terminate at any single reserved peer at once. Without this a single
     * reserved peer (or anyone who wants to hurt it) could consume the whole
     * [maxConcurrentCircuits] budget alone and starve every other reservation holder. */
    val maxCircuitsPerReservation: Int = 8,
    /** How many reservations may be held by peers connecting from one **source IP address** at
     * once, on top of [maxConcurrentReservations].
     *
     * [maxConcurrentReservations] alone is counted per [io.libp2p.core.PeerId], and a `PeerId` costs
     * one Ed25519 keygen to mint - so a single machine can generate as many identities as it likes
     * and squat the whole reservation table on its own (a trivial Sybil flood, no botnet needed).
     * Counting per source address as well makes that flood cost as many distinct network locations
     * as it wants slots. It is deliberately crude: an attacker with a /64 of IPv6 or a botnet still
     * gets one slot per address, and a genuine NAT gateway with more than [
     * maxReservationsPerSourceAddress] clients behind it is refused. A reputation-weighted
     * admission rule (Madli) is the real answer and remains the documented follow-up - this is the
     * cheap floor under it, not a replacement for it. */
    val maxReservationsPerSourceAddress: Int = 4,
    /** How many `HOP CONNECT` attempts one initiating peer may make per
     * [connectRateLimitWindow].
     *
     * A `CONNECT` costs this relay a stop-stream dial and costs the *target* a full Noise
     * handshake, while costing the initiator almost nothing - a strong CPU asymmetry that a
     * stranger could otherwise turn into an amplification attack on any reserved peer simply by
     * looping. Exceeding this budget is answered with `PERMISSION_DENIED` **before** any stop
     * stream is opened, so a rejected attempt costs the target nothing at all. */
    val maxConnectAttemptsPerWindow: Int = 30,
    /** The window [maxConnectAttemptsPerWindow] is measured over. */
    val connectRateLimitWindow: Duration = Duration.ofMinutes(1),
    /** Total bytes this relay will forward in one direction of one circuit before tearing it
     * down. 64 MiB is generous for the traffic shapes this project actually relays (a DM session,
     * a mail fetch, a directory exchange) while still being a hard ceiling that turns "relay me an
     * unbounded stream forever" into a bounded cost.
     *
     * **This is a lifetime budget, not a memory budget.** What bounds the relay's *heap* is the
     * flow control in `CircuitProxyHandler`: forwarding stops reading from one leg as soon as the
     * other leg's transport is over its write-buffer high water mark, so a circuit occupies at most
     * a small constant amount of buffered data no matter how much of this budget it eventually
     * spends. Before that flow control existed, this number was the only ceiling, which meant a
     * slow or deliberately non-reading peer could park [circuitMaxBytes] of heap per circuit. */
    val circuitMaxBytes: Long = 64L * 1024 * 1024,
    /** Wall-clock lifetime of one circuit, regardless of how few bytes it moved. Stops an attacker
     * from parking [maxConcurrentCircuits] near-idle circuits indefinitely, which
     * [circuitMaxBytes] alone would never notice. */
    val circuitMaxDuration: Duration = Duration.ofMinutes(10),
    /** Deadline for the relay's own half of opening a circuit: reaching the destination over the
     * stop protocol and getting its answer. Without it, a destination that accepts the stop stream
     * and then goes silent would pin a claimed circuit slot indefinitely - the exact shape of
     * resource exhaustion [maxConcurrentCircuits] exists to bound. */
    val circuitSetupTimeout: Duration = Duration.ofSeconds(20),
) {
    init {
        require(!circuitSetupTimeout.isNegative && !circuitSetupTimeout.isZero) {
            "circuitSetupTimeout must be positive"
        }
        require(maxConcurrentReservations > 0) { "maxConcurrentReservations must be > 0" }
        require(maxConcurrentCircuits > 0) { "maxConcurrentCircuits must be > 0" }
        require(maxCircuitsPerReservation > 0) { "maxCircuitsPerReservation must be > 0" }
        require(maxReservationsPerSourceAddress > 0) { "maxReservationsPerSourceAddress must be > 0" }
        require(maxConnectAttemptsPerWindow > 0) { "maxConnectAttemptsPerWindow must be > 0" }
        require(!connectRateLimitWindow.isNegative && !connectRateLimitWindow.isZero) {
            "connectRateLimitWindow must be positive"
        }
        require(circuitMaxBytes > 0) { "circuitMaxBytes must be > 0" }
        require(!reservationTtl.isNegative && !reservationTtl.isZero) { "reservationTtl must be positive" }
        require(!circuitMaxDuration.isNegative && !circuitMaxDuration.isZero) {
            "circuitMaxDuration must be positive"
        }
        // The relay advertises circuitMaxDuration to clients as an int number of seconds
        // (Circuit.Limit.duration is an int32), so a value that cannot be expressed there would be
        // silently truncated on the wire.
        require(circuitMaxDuration.seconds <= Int.MAX_VALUE) { "circuitMaxDuration is too large to advertise" }
    }
}

/**
 * Ceilings a node applies to relayed connections it is the *endpoint* of - i.e. protection against
 * a **malicious relay**, as opposed to [RelayServerLimits]' protection against malicious clients.
 *
 * A relay a node holds a reservation with is an untrusted intermediary: it cannot read the relayed
 * payload (every relayed connection is Noise-encrypted end to end by
 * [io.libp2p.protocol.circuit.RelayTransport.upgradeStream], exactly like a direct TCP connection -
 * the relay only ever sees ciphertext), but it *is* the party feeding this node bytes, and it
 * chooses the numbers it announces in its own reservation response. Those announced numbers are
 * therefore never trusted as this node's own budget - these locally-configured values are.
 */
data class RelayClientLimits(
    /** Simultaneous reservations this node will hold across all relays. More than one relay is
     * useful redundancy; an unbounded number is just an unbounded number of held-open
     * connections. */
    val maxReservations: Int = 4,
    /** Total inbound bytes this node accepts on one relayed connection before closing it,
     * regardless of what limit the relay announced. Matches [RelayServerLimits.circuitMaxBytes]'s
     * default so an honest relay pair never trips it first. */
    val maxInboundBytesPerCircuit: Long = 64L * 1024 * 1024,
    /** Upper bound this node imposes on a relay-announced reservation expiry. A malicious relay
     * that answered "your reservation is valid for 100 years" would otherwise suppress renewal
     * forever, leaving this node advertising a circuit address that stopped working long ago. */
    val maxReservationTtl: Duration = Duration.ofHours(1),
    /** How long before a reservation's expiry this node tries to renew it. */
    val renewBefore: Duration = Duration.ofMinutes(2),
    /** Deadline for one relay control exchange (`RESERVE`, or the `CONNECT` handshake half of a
     * dial). Keeps a silent or slow relay from parking a dial attempt indefinitely. */
    val controlTimeout: Duration = Duration.ofSeconds(20),
    /** How many inbound relayed circuits this node will have **mid-upgrade** at once - accepted by
     * the stop protocol but not yet finished their end-to-end Noise handshake.
     *
     * `MAX_CONCURRENT_CONNECTIONS` (`ConnectionCapHandler`) only ever sees a connection *after* its
     * Noise handshake completed, so without this counter a hostile relay could push an unbounded
     * number of circuits at this node and simply never let any of them finish, holding a stream and
     * a half-built Noise session each while staying entirely invisible to that cap. The mirror
     * image of [RelayServerLimits.maxConcurrentCircuits], and deliberately much smaller: an honest
     * relay opens circuits one at a time as callers dial. */
    val maxConcurrentInboundCircuits: Int = 32,
    /** Deadline for one accepted inbound circuit to finish its Noise + muxer upgrade. A circuit
     * that misses it is closed and gives its [maxConcurrentInboundCircuits] slot back, so a relay
     * that offers circuits and then stalls them cannot permanently fill that budget. Mirrors
     * [RelayServerLimits.circuitSetupTimeout] on the other side of the same handshake. */
    val circuitAcceptTimeout: Duration = Duration.ofSeconds(20),
) {
    init {
        require(maxReservations > 0) { "maxReservations must be > 0" }
        require(maxConcurrentInboundCircuits > 0) { "maxConcurrentInboundCircuits must be > 0" }
        require(!circuitAcceptTimeout.isNegative && !circuitAcceptTimeout.isZero) {
            "circuitAcceptTimeout must be positive"
        }
        require(maxInboundBytesPerCircuit > 0) { "maxInboundBytesPerCircuit must be > 0" }
        require(!maxReservationTtl.isNegative && !maxReservationTtl.isZero) { "maxReservationTtl must be positive" }
        require(!renewBefore.isNegative) { "renewBefore must not be negative" }
        require(!controlTimeout.isNegative && !controlTimeout.isZero) { "controlTimeout must be positive" }
    }
}
