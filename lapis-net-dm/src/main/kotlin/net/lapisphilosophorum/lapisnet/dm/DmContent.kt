package net.lapisphilosophorum.lapisnet.dm

/**
 * The structured payload a [DmSessionManager.send]/[DmSessionManager.sendOffline] caller now
 * builds and hands in, instead of a raw [ByteArray] plaintext - V0.8.6. [DmContentCodec.encode]'s
 * output IS the ratchet plaintext (`DoubleRatchetSession.encrypt`'s input); [DmContentCodec.decode]
 * is what [DmSessionManager.processInboundDmEnvelope] runs on a successfully-decrypted plaintext
 * before ever handing a [DmInboundMessage] to a listener.
 *
 * [kind] is derived, never independently settable - a [DmContent] with attachments is always
 * [DmContentKind.TEXT_WITH_ATTACHMENTS] and one without is always [DmContentKind.TEXT]; there is no
 * way to construct an inconsistent pairing.
 *
 * [firstContactDeposit] carries a [DmFirstContactDeposit]/[DmDepositBinding] IN-BAND, inside the
 * AEAD - see `docs/architecture.adoc`'s "two acceptance gates" section for why this is deliberately
 * unreadable by the offline pre-check gate, and readable only by the post-AEAD authoritative gate.
 */
class DmContent(
    val body: String,
    attachments: List<DmAttachmentRef> = emptyList(),
    val firstContactDeposit: DmFirstContactDeposit? = null,
) {
    val attachments: List<DmAttachmentRef> = attachments.toList()

    val kind: DmContentKind
        get() = if (this.attachments.isEmpty()) DmContentKind.TEXT else DmContentKind.TEXT_WITH_ATTACHMENTS

    init {
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        require(bodyBytes.size <= DmContentCodec.MAX_DM_BODY_BYTES) {
            "body must be at most ${DmContentCodec.MAX_DM_BODY_BYTES} UTF-8 bytes, was ${bodyBytes.size}"
        }
        require(this.attachments.size <= DmContentCodec.MAX_DM_ATTACHMENTS) {
            "at most ${DmContentCodec.MAX_DM_ATTACHMENTS} attachments allowed, was ${this.attachments.size}"
        }
        val totalAttachmentBytes = this.attachments.sumOf { it.size }
        require(totalAttachmentBytes <= DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES) {
            "total attachment size must be at most ${DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES} bytes, " +
                "was $totalAttachmentBytes"
        }
        val distinctCids = this.attachments.map { it.cid }.toSet()
        require(distinctCids.size == this.attachments.size) {
            "duplicate attachment CIDs are not allowed within one DmContent"
        }
    }

    /** Deliberately reports only LENGTHS/COUNTS - never [body] text, attachment names, or any key
     * material. Mirrors [DmAttachmentRef.toString]'s and this codebase's whole logging-discipline
     * convention. */
    override fun toString(): String =
        "DmContent(bodyBytes=${body.toByteArray(Charsets.UTF_8).size}, attachments=${attachments.size}, " +
            "deposit=${firstContactDeposit != null})"
}
