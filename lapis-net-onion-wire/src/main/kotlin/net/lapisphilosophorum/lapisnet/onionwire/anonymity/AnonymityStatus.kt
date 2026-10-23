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
}

/** Status of anonymity mode for the node status (CLI start line, browser panel). Enums and numbers only. */
data class AnonymityStatus(
    /** `"off"` or `"on"`. */
    val mode: String,
    /** `true` whenever the mode is on: direct messages, mail and calls are not anonymised yet. */
    val incomplete: Boolean,
    val guards: Int,
    val activeCircuits: Int,
    val lastError: AnonymityErrorCode,
    val lastErrorAgeSeconds: Long?,
) {
    companion object {
        val OFF = AnonymityStatus("off", false, 0, 0, AnonymityErrorCode.NONE, null)
    }
}

/** Logged once at start and shown in the CLI and the browser whenever anonymity mode is on. */
const val ANONYMITY_INCOMPLETE_WARNING: String =
    "Anonymity mode is incomplete: direct messages, mail and call signalling still use direct connections and " +
        "reveal your IP address; only the directory publication and path selection are active."
