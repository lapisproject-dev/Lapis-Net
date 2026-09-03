package net.lapisphilosophorum.lapisnet.call

import java.time.Duration

/**
 * Tunable limits and timeouts for a [CallManager] instance. Every numeric default here follows this
 * codebase's established "generous headroom, provisional magnitude, not derived from pilot data"
 * convention (see `DmSessionManager.MAX_LIVE_SESSIONS`'s own doc comment for the precedent).
 */
data class CallConfig(
    /** No call-waiting/hold this wave - a second inbound `INVITE` while one call is already active
     * is answered with `REJECT(BUSY)`, the ongoing call left untouched. */
    val maxConcurrentCalls: Int = 1,
    /** How long an outgoing call rings before [CallManager] gives up with
     * [CallEndReason.RING_TIMEOUT]. */
    val ringTimeout: Duration = Duration.ofSeconds(45),
    /** How long, after an `ACCEPT` is sent/received, [CallManager] waits for the underlying
     * [CallMediaSession] to report [CallMediaObserver.onMediaConnected] before giving up with
     * [CallEndReason.CONNECT_TIMEOUT]. */
    val connectTimeout: Duration = Duration.ofSeconds(30),
    /** Passed straight through to [CallMediaSession.createOffer]/[CallMediaSession
     * .acceptOfferAndCreateAnswer] as their own `timeout` - bounds ICE gathering, not the whole call
     * setup (see [connectTimeout] for that). */
    val iceGatheringTimeout: Duration = Duration.ofSeconds(5),
    /** [CallSignal.notValidAfterEpochMillis] is set to `now + signalTtl` for every signal this node
     * originates. */
    val signalTtl: Duration = Duration.ofSeconds(60),
    /** An inbound [CallSignal] whose `createdAtEpochMillis` is more than this far in the FUTURE
     * (relative to this node's own clock) is rejected - a defense against a clock-skewed or
     * malicious peer minting signals that would otherwise stay "valid" far longer than intended. */
    val maxClockSkew: Duration = Duration.ofSeconds(30),
    /** [CallManager]'s own invite-flood rate limiter - see that class's own
     * `net.lapisphilosophorum.lapisnet.core.ratelimit.FixedWindowRateLimiter` field doc comment. */
    val maxInvitesPerWindow: Int = 10,
    val inviteRateWindow: Duration = Duration.ofSeconds(60),
    /** `true` (the default): an inbound `INVITE` from a sender `DmSessionManager` classifies as
     * quarantined is silently dropped - no `REJECT`, the caller simply rings out to
     * [CallEndReason.RING_TIMEOUT]. See `CallManager`'s own class doc comment for the metadata-
     * minimization reasoning ("no online-presence leak to a stranger") and its accepted UX cost. */
    val autoRejectQuarantined: Boolean = true,
)
