package net.lapisphilosophorum.lapisnet.dm

/**
 * The wire discriminator for a [DmEnvelope]'s payload kind.
 *
 * **[RECEIPT] is reserved and rejected outright** - no delivery receipts, no typing indicators (both
 * explicitly deferred, not built even as stubs - the spec's own "off by default for metadata reasons"
 * reasoning from the DM concept note applies), and this wave has no plan to build them. Its wire
 * value is reserved now so a later wave does not need a wire-format version bump to introduce it -
 * mirrors `EncryptionMode.MLS_ARCHIVE`'s precedent in `lapis-net-mail` exactly (see that enum's own
 * doc comment: "the same mechanism this codebase uses whenever a wire value needs to exist before its
 * implementation does").
 *
 * [RECEIPT] is rejected at all three layers `MLS_ARCHIVE` is rejected at: (a) [DmEnvelope]'s own
 * constructor, (b) [DmEnvelopeCodec.decode] (immediately after the messageType byte is parsed - the
 * cheapest possible rejection point, before touching senderIdentity/X3DH-section/ratchet-message
 * bytes at all), (c) [DmSessionManager]'s inbound-envelope handler (defense in depth, since a caller
 * could in principle construct/decode elsewhere).
 *
 * **[CALL_SIGNAL] - since V0.8.7 (1:1 calling): ACTIVE, no longer reserved.** Carries a
 * `net.lapisphilosophorum.lapisnet.call.CallSignalCodec`-encoded frame as the ratchet plaintext
 * (instead of the [DmContentCodec] frame every [DmMessageType.TEXT]/[DmMessageType.X3DH_INITIAL]
 * envelope carries - see [DmEnvelopeCodec]'s own class doc comment for exactly how the plaintext
 * contract is now messageType-dependent). Sent and received EXCLUSIVELY through
 * [DmSessionManager.sendCallSignal]/[DmSessionManager.addCallSignalListener] - never through
 * [DmSessionManager.send]/[DmSessionManager.addInboundListener], and never via the offline mailbox
 * (see [DmSessionManager.handleOfflineEnvelope]'s own doc comment for why a call is online-only by
 * design, not merely by omission). No wire-format-version bump was needed to activate it - this
 * value has been reserved since V0.8.4 specifically so this moment would not need one; see
 * `docs/architecture.adoc`'s "1:1 calls over WebRTC (V0.8.7)" section for the full design.
 */
enum class DmMessageType(
    val wireValue: Byte,
) {
    TEXT(0),
    X3DH_INITIAL(1),

    /** Reserved and rejected outright - no delivery receipts, not even as a stub. */
    RECEIPT(2),

    /** Active since V0.8.7 - see this enum's own class doc comment. */
    CALL_SIGNAL(3),
    ;

    companion object {
        /** `null` for any byte that is not a defined type - callers decide whether that is a
         * structural error (the codec) or an unreachable state, mirroring
         * `EncryptionMode.fromWireValue`'s identical contract. */
        fun fromWireValue(value: Byte): DmMessageType? = entries.firstOrNull { it.wireValue == value }
    }
}
