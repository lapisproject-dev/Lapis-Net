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
 * because they bear directly on this type:** only [EncryptionMode.NONE] is functional this wave
 * (see the [init] block); there is no DHT inbox record, gossip-only delivery, no catch-up path for
 * an offline recipient; a sender who lists themself among [recipients] never sees the message in
 * their own inbox (GossipSub never delivers a node's own publishes to its own subscription - see
 * [net.lapisphilosophorum.lapisnet.networking.GossipPubSub.subscribe]'s doc comment).
 *
 * [replyTo]/[threadRoot] are carried and signed but nothing walks them into a thread yet - that is
 * V0.9.3 (thread assembly).
 */
class MessageEnvelope private constructor(
    val sender: Secp256k1PublicKey,
    recipients: List<Secp256k1PublicKey>,
    val sentAtEpochSecond: Long,
    val encryption: EncryptionMode,
    val contentCid: Cid,
    val replyTo: Cid?,
    val threadRoot: Cid?,
    signature: ByteArray,
) {
    /** Immutable snapshot - safe from later mutation of any list the caller passed in. */
    val recipients: List<Secp256k1PublicKey> = recipients.toList()

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
        require(encryption == EncryptionMode.NONE) {
            "encryption mode $encryption is reserved for V0.9.2 and rejected outright in V0.9.1"
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
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Never includes the signature or a full recipient key - only fingerprints/counts, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrant.toString]'s precedent. */
    override fun toString(): String =
        "MessageEnvelope(sender=${sender.fingerprint()}, recipients=${recipients.size}, " +
            "encryption=$encryption, contentCid=$contentCid)"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(MAIL_ENVELOPE_DOMAIN_TAG, body)

        /** Creates and signs a new envelope from [sender] to [recipients], bound to [contentCid]. */
        fun create(
            sender: Secp256k1KeyPair,
            recipients: List<Secp256k1PublicKey>,
            contentCid: Cid,
            sentAtEpochSecond: Long = System.currentTimeMillis() / 1000,
            encryption: EncryptionMode = EncryptionMode.NONE,
            replyTo: Cid? = null,
            threadRoot: Cid? = null,
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
        ): MessageEnvelope =
            MessageEnvelope(
                sender,
                recipients,
                sentAtEpochSecond,
                encryption,
                contentCid,
                replyTo,
                threadRoot,
                signature,
            )
    }
}
