package net.lapisphilosophorum.lapisnet.mail

/**
 * How a [MessageEnvelope]'s referenced [MessageBody] blob is protected.
 *
 * **Only [NONE] is functional in V0.9.1.** [HYBRID_ECIES] and [MLS_ARCHIVE] exist as wire values
 * and enum constants so the V0.9.2 encryption wave needs no wire-format or schema change - they
 * are structurally representable but rejected outright at every layer that can reject them
 * ([MessageEnvelope]'s constructor, [MessageEnvelopeCodec.decode], and [InboxGossip]'s
 * validator). This mirrors `LtrRecordCodec`'s own `proofType = 2` precedent, which was
 * `PROOF_TYPE_LIGHTNING_RESERVED` and rejected outright through V0.5 before V0.6 implemented it
 * (see that file's own comment on the constant).
 */
enum class EncryptionMode(
    val wireValue: Byte,
) {
    NONE(0),
    HYBRID_ECIES(1),
    MLS_ARCHIVE(2),
    ;

    companion object {
        /** `null` for any byte that is not a defined mode - callers decide whether that is a
         * structural error (the codec) or an unreachable state. */
        fun fromWireValue(value: Byte): EncryptionMode? = entries.firstOrNull { it.wireValue == value }
    }
}
