package net.lapisphilosophorum.lapisnet.dm

/**
 * The wire discriminator for a [DmContent]'s shape - carried INSIDE the AEAD-authenticated ratchet
 * plaintext, not in [DmEnvelope]/[DmEnvelopeCodec] (that outer frame's `messageType` stays
 * `TEXT`/`X3DH_INITIAL` unchanged - see [DmContentCodec]'s own class doc comment for why V0.8.6
 * needed no wire-format-version bump at the envelope layer).
 *
 * Values 2..255 are reserved and [DmContentCodec.decode] rejects any of them outright - it never
 * shrugs an unknown kind off as "ignore, forward-compatible", mirroring [DmMessageType]'s own
 * `RECEIPT`/`CALL_SIGNAL` reservation discipline: a wire value existing before its implementation
 * does is precedent this codebase already uses (`EncryptionMode.MLS_ARCHIVE` in `lapis-net-mail`).
 */
enum class DmContentKind(
    val wireValue: Byte,
) {
    TEXT(0),
    TEXT_WITH_ATTACHMENTS(1),
    ;

    companion object {
        /** `null` for any byte that is not a defined kind - the caller (the codec) turns that into
         * a structural rejection, mirroring [DmMessageType.fromWireValue]'s identical contract. */
        fun fromWireValue(value: Byte): DmContentKind? = entries.firstOrNull { it.wireValue == value }
    }
}
