package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify

/** Domain-separation tag for a [MessageEnvelope]'s signature - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. */
private const val MAIL_ENVELOPE_DOMAIN_TAG = "LapisNet:mail-envelope:v1"

private const val SIGNATURE_SIZE = 64

/**
 * A signed, addressed mail envelope: [sender] asserts, over their own signature, that this
 * message goes to [recipients] and that its payload is the [MessageBody] blob whose bytes hash to
 * [contentCid] - see [MessageBody]'s own doc comment for why the body carries no signature of its
 * own and is instead authenticated transitively through this binding.
 *
 * **Scope cuts (V0.9.1) - see [InboxGossip]'s class doc comment for the full list, repeated here
 * because they bear directly on this type:** there is no DHT inbox record, gossip-only delivery,
 * no catch-up path for an offline recipient; a sender who lists themself among [recipients] never
 * sees the message in their own inbox (GossipSub never delivers a node's own publishes to its own
 * subscription - see [net.lapisphilosophorum.lapisnet.networking.GossipPubSub.subscribe]'s doc
 * comment).
 *
 * **V0.9.2: [EncryptionMode.NONE] and [EncryptionMode.HYBRID_ECIES] are both functional** (see the
 * [init] block); [EncryptionMode.MLS_ARCHIVE] remains reserved and rejected outright - no
 * implementation plan exists in this arc. A [EncryptionMode.HYBRID_ECIES] envelope carries exactly
 * `recipients.size + 1` [wraps] (one per recipient plus the sender's own self-wrap) - see
 * [HybridEcies]'s class doc comment for the encryption scheme itself and [MailAadContext]'s for the
 * associated-data binding that ties [wraps] to this exact sender/recipient/content combination.
 *
 * [replyTo]/[threadRoot] are carried and signed - as of V0.9.3, [replyTo] alone is walked into a
 * thread by [ThreadBuilder] (see that object's class doc comment for why [threadRoot] remains
 * structurally unused: this wave resolves the "nothing walks them" sentence only for [replyTo]).
 */
class MessageEnvelope private constructor(
    val sender: Secp256k1PublicKey,
    recipients: List<Secp256k1PublicKey>,
    val sentAtEpochSecond: Long,
    val encryption: EncryptionMode,
    val contentCid: Cid,
    val replyTo: Cid?,
    val threadRoot: Cid?,
    wraps: List<EciesWrap>,
    signature: ByteArray,
) {
    /** Immutable snapshot - safe from later mutation of any list the caller passed in. */
    val recipients: List<Secp256k1PublicKey> = recipients.toList()

    /** Empty for [EncryptionMode.NONE]; exactly `recipients.size + 1` entries for
     * [EncryptionMode.HYBRID_ECIES] - see this class's doc comment. Immutable snapshot. */
    val wraps: List<EciesWrap> = wraps.toList()

    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [sender] over this envelope's canonical bytes. Returns
     * a fresh copy on every access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == SIGNATURE_SIZE) {
            "envelope signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
        require(this.recipients.isNotEmpty()) { "an envelope must have at least one recipient" }
        require(this.recipients.size <= MessageEnvelopeCodec.MAX_RECIPIENTS) {
            "at most ${MessageEnvelopeCodec.MAX_RECIPIENTS} recipients allowed, was ${this.recipients.size}"
        }
        require(this.recipients.toSet().size == this.recipients.size) {
            "recipients must not contain duplicates"
        }
        require(encryption != EncryptionMode.MLS_ARCHIVE) {
            "encryption mode $encryption is reserved and rejected outright - no implementation plan exists in this arc"
        }
        when (encryption) {
            EncryptionMode.NONE ->
                require(this.wraps.isEmpty()) {
                    "an unencrypted envelope must carry no recipient wraps, had ${this.wraps.size}"
                }
            EncryptionMode.HYBRID_ECIES ->
                require(this.wraps.size == this.recipients.size + 1) {
                    "a hybrid-ecies envelope must carry exactly one wrap per recipient plus the sender's " +
                        "self-wrap (${this.recipients.size + 1}), had ${this.wraps.size}"
                }
            EncryptionMode.MLS_ARCHIVE -> Unit // unreachable - rejected above
        }
        val contentCidBytes = contentCid.toBytes()
        require(contentCidBytes.size in 1..MessageEnvelopeCodec.MAX_CID_BYTES) {
            "contentCid must be 1..${MessageEnvelopeCodec.MAX_CID_BYTES} bytes, was ${contentCidBytes.size}"
        }
        replyTo?.let {
            val bytes = it.toBytes()
            require(bytes.size in 1..MessageEnvelopeCodec.MAX_CID_BYTES) {
                "replyTo must be 1..${MessageEnvelopeCodec.MAX_CID_BYTES} bytes, was ${bytes.size}"
            }
        }
        threadRoot?.let {
            val bytes = it.toBytes()
            require(bytes.size in 1..MessageEnvelopeCodec.MAX_CID_BYTES) {
                "threadRoot must be 1..${MessageEnvelopeCodec.MAX_CID_BYTES} bytes, was ${bytes.size}"
            }
        }
        // Deliberately NO range check on sentAtEpochSecond: this field is attacker-controlled
        // (a receiving node's InboxGossip validator must never trust it for an accept/reject
        // decision - see InboxGossip's class doc comment) and this constructor runs both for
        // locally-created envelopes AND for gossip-decoded ones. Mirrors
        // MadliDailyVectorCodec's identical decision about epochDay.
    }

    /** SHA-256 over this envelope's full canonical bytes (signed body + signature). */
    fun contentId(): ByteArray = MessageEnvelopeCodec.contentId(this)

    /** `true` iff [identity] is among this envelope's [recipients]. */
    fun isAddressedTo(identity: Secp256k1PublicKey): Boolean = recipients.contains(identity)

    override fun equals(other: Any?): Boolean {
        if (other !is MessageEnvelope) return false
        return sender == other.sender &&
            recipients == other.recipients &&
            sentAtEpochSecond == other.sentAtEpochSecond &&
            encryption == other.encryption &&
            contentCid == other.contentCid &&
            replyTo == other.replyTo &&
            threadRoot == other.threadRoot &&
            wraps == other.wraps &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = sender.hashCode()
        result = 31 * result + recipients.hashCode()
        result = 31 * result + sentAtEpochSecond.hashCode()
        result = 31 * result + encryption.hashCode()
        result = 31 * result + contentCid.hashCode()
        result = 31 * result + (replyTo?.hashCode() ?: 0)
        result = 31 * result + (threadRoot?.hashCode() ?: 0)
        result = 31 * result + wraps.hashCode()
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Never includes the signature, a full recipient key, or wrap bytes - only fingerprints/
     * counts, mirroring [net.lapisphilosophorum.lapisnet.trust.VeritasGrant.toString]'s
     * precedent. */
    override fun toString(): String =
        "MessageEnvelope(sender=${sender.fingerprint()}, recipients=${recipients.size}, " +
            "encryption=$encryption, contentCid=$contentCid, wraps=${wraps.size})"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(MAIL_ENVELOPE_DOMAIN_TAG, body)

        /** Creates and signs a new envelope from [sender] to [recipients], bound to [contentCid].
         * For [EncryptionMode.HYBRID_ECIES], [wraps] must already be the complete, correctly
         * AAD-bound wrap list produced by [HybridEcies.seal] - this function does not build or
         * validate the wraps' cryptographic content itself, only the count invariant (enforced by
         * the constructor's [init] block). */
        fun create(
            sender: Secp256k1KeyPair,
            recipients: List<Secp256k1PublicKey>,
            contentCid: Cid,
            sentAtEpochSecond: Long = System.currentTimeMillis() / 1000,
            encryption: EncryptionMode = EncryptionMode.NONE,
            replyTo: Cid? = null,
            threadRoot: Cid? = null,
            wraps: List<EciesWrap> = emptyList(),
        ): MessageEnvelope {
            val body =
                MessageEnvelopeCodec.encodeSignedBody(
                    sender = sender.publicKey,
                    recipients = recipients,
                    sentAtEpochSecond = sentAtEpochSecond,
                    encryption = encryption,
                    contentCid = contentCid,
                    replyTo = replyTo,
                    threadRoot = threadRoot,
                    wraps = wraps,
                )
            val signature = sender.sign(signingDigest(body))
            return MessageEnvelope(
                sender.publicKey,
                recipients,
                sentAtEpochSecond,
                encryption,
                contentCid,
                replyTo,
                threadRoot,
                wraps,
                signature,
            )
        }

        /** Self-contained cryptographic verification: checks [envelope]'s signature against the
         * sender public key embedded in the envelope itself. Never throws - see
         * [net.lapisphilosophorum.lapisnet.identity.verify]'s doc comment. */
        fun verify(envelope: MessageEnvelope): Boolean {
            val body = MessageEnvelopeCodec.encodeSignedBody(envelope)
            return envelope.sender.verify(signingDigest(body), envelope.signature)
        }

        /** As [verify], but additionally asserts [envelope] was signed by [expectedSender] rather
         * than trusting whichever sender key happens to be embedded in the envelope. */
        fun verify(
            expectedSender: Secp256k1PublicKey,
            envelope: MessageEnvelope,
        ): Boolean = envelope.sender == expectedSender && verify(envelope)

        /** Reconstructs an envelope from already-decoded, unverified fields. Used only by
         * [MessageEnvelopeCodec.decode] and by tests exercising deliberately-invalid signatures -
         * callers must call [verify] before trusting the result. */
        internal fun fromDecoded(
            sender: Secp256k1PublicKey,
            recipients: List<Secp256k1PublicKey>,
            sentAtEpochSecond: Long,
            encryption: EncryptionMode,
            contentCid: Cid,
            replyTo: Cid?,
            threadRoot: Cid?,
            signature: ByteArray,
            wraps: List<EciesWrap> = emptyList(),
        ): MessageEnvelope =
            MessageEnvelope(
                sender,
                recipients,
                sentAtEpochSecond,
                encryption,
                contentCid,
                replyTo,
                threadRoot,
                wraps,
                signature,
            )
    }
}
