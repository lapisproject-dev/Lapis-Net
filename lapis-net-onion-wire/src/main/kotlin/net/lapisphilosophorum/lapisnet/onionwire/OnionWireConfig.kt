package net.lapisphilosophorum.lapisnet.onionwire

import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionRelayLimits
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Tunables of the onion wire integration. Defaults are *assumptions awaiting confirmation* (see
 * docs/anonymity.adoc, "Assumptions"). Every value is validated: nothing here may be zero, negative or
 * inconsistent, because each one bounds a resource an attacker could otherwise exhaust.
 */
data class OnionWireConfig(
    /** Opt-in. `false`: no protocol handler is registered, no key is created, no descriptor published. */
    val relayMode: Boolean = false,
    val relayLimits: OnionRelayLimits = OnionRelayLimits(maxCircuitsTotal = 1024, maxCircuitsPerLink = 128),
    /** Hard cap of simultaneously open links (inbound + outbound). */
    val maxLinks: Int = 64,
    val maxInboundLinksPerPeer: Int = 2,
    /**
     * Slots of [maxLinks] that inbound links can never occupy, so that outbound links (EXTEND towards the next hop) stay
     * possible while inbound links are flooded. Inbound links may hold at most `maxLinks - reservedOutboundLinks` slots.
     */
    val reservedOutboundLinks: Int = maxLinks / 4,
    /**
     * An inbound link that carries no circuit and delivered no non-PADDING cell within this is closed. PADDING does not
     * count as activity, so it cannot keep an otherwise useless link (and its slot) alive.
     */
    val inboundIdleWithoutCircuitTimeout: Duration = 30.seconds,
    /** Cells per second a single link may deliver before it is closed. */
    val cellsPerSecondPerLink: Int = 4000,
    /** Cells written but not yet flushed per link before the link is closed (about 256 KiB). */
    val maxQueuedCellsPerLink: Int = 256,
    val extendTimeout: Duration = 10.seconds,
    val linkIdleTimeout: Duration = 5.minutes,
    /** An inbound link must deliver a first complete cell, and any started cell must complete, within this. */
    val linkHandshakeTimeout: Duration = 10.seconds,
    val sweepInterval: Duration = 30.seconds,
    val onionKeyLifetime: Duration = 7.days,
    val onionKeyRotateAfter: Duration = 4.days,
    val descriptorTtl: Duration = 24.hours,
    val descriptorRepublishInterval: Duration = 6.hours,
    /** First descriptor re-announcement after start (the gossip mesh is usually not formed yet at attach time). */
    val descriptorInitialRepublishDelay: Duration = 30.seconds,
    /** Threads for blocking dial work of extends and link opening. */
    val dialThreads: Int = 8,
    val maxQueuedDials: Int = 512,
    val maxPendingDials: Int = 64,
) {
    init {
        require(maxLinks > 0 && maxInboundLinksPerPeer > 0) { "link limits must be positive" }
        require(reservedOutboundLinks in 0 until maxLinks) { "reservedOutboundLinks must be in 0 until maxLinks" }
        require(inboundIdleWithoutCircuitTimeout.isPositive()) { "inboundIdleWithoutCircuitTimeout must be positive" }
        require(cellsPerSecondPerLink > 0 && maxQueuedCellsPerLink > 0) { "cell limits must be positive" }
        require(extendTimeout.isPositive() && linkIdleTimeout.isPositive() && linkHandshakeTimeout.isPositive()) {
            "timeouts must be positive"
        }
        require(sweepInterval.isPositive()) { "sweepInterval must be positive" }
        require(onionKeyLifetime.isPositive() && onionKeyRotateAfter.isPositive()) { "key times must be positive" }
        require(onionKeyRotateAfter < onionKeyLifetime) { "onionKeyRotateAfter must be shorter than the key lifetime" }
        require(
            descriptorTtl.isPositive() && descriptorRepublishInterval.isPositive(),
        ) { "descriptor times must be positive" }
        require(descriptorTtl.inWholeSeconds <= OnionRelayDescriptor.MAX_TTL_WINDOW_SECONDS) {
            "descriptorTtl exceeds the maximum descriptor validity window"
        }
        require(descriptorRepublishInterval < descriptorTtl) { "republish must happen before the descriptor expires" }
        require(
            !descriptorInitialRepublishDelay.isNegative(),
        ) { "descriptorInitialRepublishDelay must not be negative" }
        require(dialThreads > 0 && maxQueuedDials > 0 && maxPendingDials > 0) { "dial limits must be positive" }
    }
}
