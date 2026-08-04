package net.lapisphilosophorum.lapisnet.mail

/**
 * How a [MessageEnvelope]'s referenced [MessageBody] blob is protected.
 *
 * **[NONE] and [HYBRID_ECIES] are both functional as of V0.9.2.** [HYBRID_ECIES] is
 * `lapis-net-mail`'s hybrid AES-256-GCM + ECIES-on-secp256k1 encryption scheme - see
 * [HybridEcies]'s class doc comment for the encryption itself and [MailAadContext]'s for the
 * associated-data binding that stops a sealed body/wrap pair from being transplanted onto a
 * different envelope.
 *
 * **[MLS_ARCHIVE] remains reserved and rejected outright** at every layer that can reject it
 * ([MessageEnvelope]'s constructor, [MessageEnvelopeCodec.decode], and [InboxGossip]'s validator) -
 * no implementation plan exists for it in this arc (V0.9.1-V0.9.4). This mirrors
 * `LtrRecordCodec`'s own `proofType = 2` precedent, which was `PROOF_TYPE_LIGHTNING_RESERVED` and
 * rejected outright through V0.5 before V0.6 implemented it (see that file's own comment on the
 * constant) - the same mechanism this codebase uses whenever a wire value needs to exist before
 * its implementation does.
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
