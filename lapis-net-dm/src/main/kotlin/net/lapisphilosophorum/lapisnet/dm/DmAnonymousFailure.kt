package net.lapisphilosophorum.lapisnet.dm

/**
 * V0.10.0-F1: the closed set of reasons an anonymity-mode send is refused BEFORE any session state
 * is touched. [code] is the fixed, UI-safe token; it never carries an address, peer id, circuit id
 * or key, and the exception message is exactly this token (no cause chain with details).
 *
 * Every "recipient cannot be reached anonymously" situation - unknown identity, peer in direct mode,
 * peer without the DM service, missing prekey bundle - maps to ONE code on purpose, so the
 * response is not an oracle for the recipient's mode or acceptance policy.
 */
enum class DmAnonymousFailure(
    val code: String,
) {
    RECIPIENT_NOT_REACHABLE_ANONYMOUSLY("recipient-not-reachable-anonymously"),
    ANONYMITY_NOT_READY("anonymity-not-ready"),
    RATE_LIMITED("rate-limited"),
    MESSAGE_TOO_LARGE("message-too-large-anonymous"),
}

/** Thrown by an anonymity-mode send; the message is the fixed [DmAnonymousFailure.code]. */
class DmAnonymousDeliveryException(
    val failure: DmAnonymousFailure,
) : DmSessionException(failure.code)
