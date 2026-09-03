package net.lapisphilosophorum.lapisnet.call

/**
 * The media kind a [CallSignal.INVITE]/[CallSignal.ACCEPT] declares.
 *
 * **[AUDIO_VIDEO] is reserved and rejected outright this wave** - `webrtc-java` supports video in
 * principle, but this codebase has no capture-device story in a headless/CI environment and no
 * render surface anywhere a call could be driven from this wave (see `docs/architecture.adoc`'s "1:1
 * calls over WebRTC" section, "explicit, deliberate scope cuts" subsection). Reserving the wire value
 * now means a later video wave needs no [CallSignalCodec] format-version bump.
 */
enum class CallMediaKind(
    val wireValue: Byte,
) {
    AUDIO(0),

    /** Reserved for a future video wave - rejected outright this wave. */
    AUDIO_VIDEO(1),
    ;

    companion object {
        fun fromWireValue(value: Byte): CallMediaKind? = entries.firstOrNull { it.wireValue == value }
    }
}
