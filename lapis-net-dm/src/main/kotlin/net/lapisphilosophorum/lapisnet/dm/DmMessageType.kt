package net.lapisphilosophorum.lapisnet.dm

/**
 * The wire discriminator for a [DmEnvelope]'s payload kind.
 *
 * **[RECEIPT] and [CALL_SIGNAL] are reserved and rejected outright this wave** - no delivery
 * receipts, no typing indicators (both explicitly deferred, not built even as stubs - the spec's
 * own "off by default for metadata reasons" reasoning from the DM concept note applies), and no
 * calling until a later wave (V0.8.7+). Their wire values are reserved now so a later wave does not
 * need a wire-format version bump to introduce them - mirrors `EncryptionMode.MLS_ARCHIVE`'s
 * precedent in `lapis-net-mail` exactly (see that enum's own doc comment: "the same mechanism this
 * codebase uses whenever a wire value needs to exist before its implementation does").
 *
 * Both reserved values are rejected at all three layers `MLS_ARCHIVE` is rejected at: (a)
 * [DmEnvelope]'s own constructor, (b) [DmEnvelopeCodec.decode] (immediately after the messageType
 * byte is parsed - the cheapest possible rejection point, before touching senderIdentity/X3DH-
 * section/ratchet-message bytes at all), (c) [DmSessionManager]'s inbound-envelope handler (defense
 * in depth, since a caller could in principle construct/decode elsewhere).
 */
enum class DmMessageType(
    val wireValue: Byte,
) {
    TEXT(0),
    X3DH_INITIAL(1),

    /** Reserved and rejected outright this wave - no delivery receipts, not even as a stub. */
    RECEIPT(2),

    /** Reserved for V0.8.7 (calling) and rejected outright this wave - same precedent as
     * [RECEIPT]. */
    CALL_SIGNAL(3),
    ;

    companion object {
        /** `null` for any byte that is not a defined type - callers decide whether that is a
         * structural error (the codec) or an unreachable state, mirroring
         * `EncryptionMode.fromWireValue`'s identical contract. */
        fun fromWireValue(value: Byte): DmMessageType? = entries.firstOrNull { it.wireValue == value }
    }
}
