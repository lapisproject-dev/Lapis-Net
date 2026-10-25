package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import net.lapisphilosophorum.lapisnet.networking.config.AnonymityPaddingMode

/** Stable, content-free error codes of anonymity mode. Never carries an address, identity or key. */
enum class AnonymityErrorCode(
    val wire: String,
) {
    NONE("none"),
    INSUFFICIENT_RELAYS("insufficient-relays"),
    BUILD_FAILED("build-failed"),
    BUILD_TIMEOUT("build-timeout"),
    RATE_LIMITED("rate-limited"),
    GUARD_STATE_RESET("guard-state-reset"),
    PUBLISH_FAILED("publish-failed"),

    /** A send found no anonymous way to the recipient (a counter and this code only, never the recipient). */
    RECIPIENT_UNREACHABLE("recipient-unreachable"),
}

/** Status of anonymity mode for the node status (CLI start line, browser panel). Enums and numbers only. */
data class AnonymityStatus(
    /** `"off"` or `"on"`. */
    val mode: String,
    /** `true` whenever the mode is on: call media and the network mesh are not anonymised. */
    val incomplete: Boolean,
    val guards: Int,
    val activeCircuits: Int,
    val lastError: AnonymityErrorCode,
    val lastErrorAgeSeconds: Long?,
    /** Sends that found no anonymous way to the recipient since start (a number, no target). */
    val recipientUnreachableCount: Long = 0,
    /** V0.10.0-H: `"standard"` or `"off"` (padding and timing protection). */
    val padding: String = "off",
    /** Warm circuits waiting for their one use (a number). */
    val warmCircuits: Int = 0,
    /** Cover cells sent since start (a number). */
    val coverCellsSent: Long = 0,
    /** Cover cells not sent because the cover budget was spent (a number). */
    val coverBudgetExhausted: Long = 0,
) {
    companion object {
        val OFF = AnonymityStatus("off", false, 0, 0, AnonymityErrorCode.NONE, null)
    }
}

/**
 * The warning of wave V0.10.0-H, in four fixed texts (calls off or exposed, padding standard or off). The browser's
 * `app.js` carries the same four character for character, and a test compares them.
 */
private const val WARNING_HEAD =
    "Anonymity mode is incomplete: direct messages, mail and call signals travel over circuits"
private const val WARNING_PADDED =
    ", padded to size classes with cover cells towards the guard; this does not hide traffic from an observer " +
        "who sees both ends"
private const val WARNING_CALLS_OFF_TAIL =
    "calls are off because call media would reveal your IP address; the network mesh, DHT lookups and fetches " +
        "still show your identity and address."
private const val WARNING_CALLS_EXPOSED_TAIL =
    "calls are allowed (--anonymity-allow-call-media=true) and call media connects directly: every call reveals " +
        "your IP address to the other party and to network observers; the network mesh, DHT lookups and fetches " +
        "still show your identity and address."

/** The sentence that `--anonymity-padding=off` adds: what an observer of the connection can then see. */
const val ANONYMITY_PADDING_OFF_SENTENCE: String =
    "padding is off (--anonymity-padding=off), so message sizes and timing are visible to an observer of your connection"

/** Logged once at start and shown in the CLI and the browser whenever anonymity mode is on (calls off, padding standard). */
const val ANONYMITY_INCOMPLETE_WARNING: String = WARNING_HEAD + WARNING_PADDED + "; " + WARNING_CALLS_OFF_TAIL

/** Used instead of [ANONYMITY_INCOMPLETE_WARNING] when `--anonymity-allow-call-media=true`. */
const val ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED: String =
    WARNING_HEAD + WARNING_PADDED + "; but " + WARNING_CALLS_EXPOSED_TAIL

/** Calls off, `--anonymity-padding=off`. */
const val ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF: String =
    WARNING_HEAD + "; " + ANONYMITY_PADDING_OFF_SENTENCE + "; " + WARNING_CALLS_OFF_TAIL

/** Calls allowed, `--anonymity-padding=off`. */
const val ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF_CALL_MEDIA_EXPOSED: String =
    WARNING_HEAD + "; " + ANONYMITY_PADDING_OFF_SENTENCE + "; but " + WARNING_CALLS_EXPOSED_TAIL

/** The warning for a combination of the two options. */
fun anonymityIncompleteWarning(
    callMediaAllowed: Boolean,
    padding: AnonymityPaddingMode,
): String =
    when (padding) {
        AnonymityPaddingMode.STANDARD ->
            if (callMediaAllowed) ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED else ANONYMITY_INCOMPLETE_WARNING
        AnonymityPaddingMode.OFF ->
            if (callMediaAllowed) {
                ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF_CALL_MEDIA_EXPOSED
            } else {
                ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF
            }
    }
