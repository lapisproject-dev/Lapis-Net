package net.lapisphilosophorum.lapisnet.call

/**
 * V0.10.0-G: how call MEDIA is handled relative to anonymity mode. Call SIGNALS follow the DM route (circuits in
 * anonymity mode); the media path is a direct WebRTC connection that cannot be anonymised.
 */
enum class CallMediaPolicy(
    val wire: String,
) {
    /** Anonymity mode off: unchanged behaviour. */
    DIRECT("direct"),

    /** Anonymity mode on, `--anonymity-allow-call-media` not set: no outgoing or incoming calls at all. */
    DISABLED("disabled"),

    /** Anonymity mode on with `--anonymity-allow-call-media=true`: calls work, media reveals the IP address. */
    EXPOSED("exposed"),
    ;

    /** `true` whenever anonymity mode is on. */
    val anonymity: Boolean get() = this != DIRECT

    companion object {
        fun of(
            anonymityOn: Boolean,
            allowCallMedia: Boolean,
        ): CallMediaPolicy =
            when {
                !anonymityOn -> DIRECT
                allowCallMedia -> EXPOSED
                else -> DISABLED
            }
    }
}

/** Calls are not available in anonymity mode (media would reveal the IP address). Thrown synchronously. */
class CallMediaDisabledException :
    IllegalStateException("Calls are not available in anonymity mode because call media reveals your IP address")

/** The media-exposure confirmation was not given for this very action. Thrown synchronously, nothing sent. */
class CallMediaExposureNotConfirmedException :
    IllegalStateException("The exposure of your IP address through call media has not been confirmed")
