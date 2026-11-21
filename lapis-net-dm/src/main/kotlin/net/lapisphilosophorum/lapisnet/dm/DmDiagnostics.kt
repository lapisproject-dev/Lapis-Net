package net.lapisphilosophorum.lapisnet.dm

/**
 * Counters of [DmSessionManager]'s first-contact handshake handling, for diagnosing multi-node test failures and
 * one-time-prekey collisions (see `docs/architecture.adoc`, "One-time-prekey collisions and authenticated handshake
 * rejection"). Counts only: no keys, no fingerprints, no addresses, no peer identities.
 *
 * - [x3dhInitialRejectedOtkConsumed] / [x3dhInitialRejectedOtkUnknown]: inbound `X3DH_INITIAL` envelopes refused
 *   because the named one-time prekey was already consumed / is unknown to this node.
 * - [x3dhInitialRejectedSpkMismatch]: inbound `X3DH_INITIAL` envelopes naming a signed prekey id this node does not
 *   hold (stale bundle after a signed-prekey rotation).
 * - [rejectionsSent]: authenticated `X3DH_REJECTED` frames this node handed to a transport.
 * - [rejectionsSuppressedByRateLimit]: rejections this node did not send because a rate limit or the bounded
 *   rejection queue refused them.
 * - [rejectionsAccepted] / [rejectionsIgnored]: inbound rejections that matched (and acted on) / did not match a
 *   pending, unacknowledged initiation of this node.
 * - [rebootstrapsAfterRejection]: sessions this node rebuilt after an accepted rejection.
 * - [rebootstrapsUnacked]: sessions this node rebuilt by the unacknowledged-session fallback.
 * - [textRejectedNoSession]: inbound `TEXT` envelopes refused because no session with the claimed sender exists.
 */
data class DmDiagnostics(
    val x3dhInitialRejectedOtkConsumed: Long,
    val x3dhInitialRejectedOtkUnknown: Long,
    val x3dhInitialRejectedSpkMismatch: Long,
    val rejectionsSent: Long,
    val rejectionsSuppressedByRateLimit: Long,
    val rejectionsAccepted: Long,
    val rejectionsIgnored: Long,
    val rebootstrapsAfterRejection: Long,
    val rebootstrapsUnacked: Long,
    val textRejectedNoSession: Long,
    /** Dials that ran while the caller held the peer's stripe lock. A guard counter: since inbound listeners run after
     * the stripe lock (not even a listener that sends synchronously dials under it any more), it stays `0`. */
    val dialsUnderPeerLock: Long = 0,
)
