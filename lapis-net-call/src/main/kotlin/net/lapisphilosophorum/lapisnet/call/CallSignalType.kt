package net.lapisphilosophorum.lapisnet.call

/**
 * The wire discriminator for a [CallSignal]'s kind - see [CallSignalCodec]'s own class doc comment
 * for the exact byte layout.
 *
 * **[ICE_CANDIDATE], [RINGING], and [RENEGOTIATE] are reserved and rejected outright this wave** -
 * following this codebase's established `DmMessageType.RECEIPT`/`EncryptionMode.MLS_ARCHIVE`
 * precedent of reserving a wire value before its implementation exists, so a LATER wave (Trickle-ICE,
 * a distinct "phone is ringing" signal, or mid-call renegotiation) never needs a
 * [CallSignalCodec]-format-version bump to introduce it. This wave is Non-Trickle (full ICE gathering
 * completes before [INVITE]/[ACCEPT] is ever sent - see `CallMediaSession.createOffer`'s own doc
 * comment) and single-media-kind-for-the-call's-lifetime (no renegotiation), so none of the three are
 * reachable from [CallManager] today.
 */
enum class CallSignalType(
    val wireValue: Byte,
) {
    INVITE(0),
    ACCEPT(1),
    REJECT(2),
    HANGUP(3),

    /** Reserved for a future Trickle-ICE wave - rejected outright this wave. */
    ICE_CANDIDATE(4),

    /** Reserved for a future distinct "phone is ringing" signal - rejected outright this wave (today,
     * [CallEvent.IncomingCall] is raised directly off a received [INVITE]). */
    RINGING(5),

    /** Reserved for a future mid-call renegotiation wave (e.g. adding video) - rejected outright this
     * wave (see [CallMediaKind.AUDIO_VIDEO]'s own doc comment for the matching media-kind cut). */
    RENEGOTIATE(6),
    ;

    companion object {
        /** `null` for any byte that is not a defined type - mirrors `DmMessageType.fromWireValue`'s
         * identical contract. */
        fun fromWireValue(value: Byte): CallSignalType? = entries.firstOrNull { it.wireValue == value }
    }
}
