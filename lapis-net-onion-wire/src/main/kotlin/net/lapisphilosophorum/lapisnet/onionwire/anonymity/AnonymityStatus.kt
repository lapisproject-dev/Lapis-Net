package net.lapisphilosophorum.lapisnet.onionwire.anonymity

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
) {
    companion object {
        val OFF = AnonymityStatus("off", false, 0, 0, AnonymityErrorCode.NONE, null)
    }
}

/** Logged once at start and shown in the CLI and the browser whenever anonymity mode is on (calls off, the default). */
const val ANONYMITY_INCOMPLETE_WARNING: String =
    "Anonymity mode is incomplete: direct messages, mail and call signals travel over circuits; calls are off " +
        "because call media would reveal your IP address; the network mesh, DHT lookups and fetches still show " +
        "your identity and address."

/** Used instead of [ANONYMITY_INCOMPLETE_WARNING] when `--anonymity-allow-call-media=true`. */
const val ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED: String =
    "Anonymity mode is incomplete: direct messages, mail and call signals travel over circuits, but calls are " +
        "allowed (--anonymity-allow-call-media=true) and call media connects directly: every call reveals your IP " +
        "address to the other party and to network observers; the network mesh, DHT lookups and fetches still show " +
        "your identity and address."
