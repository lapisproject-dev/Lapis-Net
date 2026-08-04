package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

private const val ENVELOPE_CONTEXT_MAGIC = "LNAC"
private const val ENVELOPE_CONTEXT_VERSION: Byte = 1

private const val BODY_AAD_DOMAIN_TAG = "LapisNet:mail-ecies-body-aad:v1"
private const val WRAP_AAD_DOMAIN_TAG = "LapisNet:mail-ecies-wrap-aad:v1"

/** The sealed-body blob's own magic + version + flags (see [SealedBodyCodec]'s layout) - 6
 * constant bytes. Binds the body ciphertext to the sealed-blob FORMAT VERSION, not just its
 * content, so a future format-version bump cannot be replayed against an old AAD. */
private val SEALED_BODY_HEADER_PREFIX = "LNSB".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 0)

/**
 * The content-independent envelope context that both AEADs in [HybridEcies] are bound to.
 *
 * Exists as a first-class value object, and is the ONLY way to call [HybridEcies.seal], for the
 * same reason `KeystoreEncryption` takes its AAD header as an explicit parameter (see that
 * object's doc comment in `lapis-net-identity`): it makes the AAD binding unambiguous by
 * construction. A caller cannot seal against one context and then sign an envelope describing a
 * different one, because [MailSender] builds the envelope FROM this object's fields rather than
 * alongside them.
 *
 * **This is the load-bearing security mechanism of V0.9.2 - see [HybridEcies]'s class doc comment
 * for the full "wrap transplant" attack this closes.** In short: an attacker who takes a
 * legitimately-sealed body and its wraps from one envelope and attaches them to a NEW envelope
 * with a different claimed sender (or a different recipient set) produces something that is
 * structurally valid and even correctly signed under the new, attacker-controlled key - every
 * V0.9.1 check (signature, addressing, CID binding) passes. Only the fact that [aadForWrap]/
 * [aadForBody] bind the sender, the full recipient set, and the rest of this context stops the
 * recipient's [HybridEcies.open] from succeeding: the transplanted wrap was derived against a
 * DIFFERENT context's digest, so both the HKDF-derived wrap key and the GCM AAD check fail.
 *
 * Deliberately excludes [contentCid] - see [aadForBody]'s doc comment for why that omission is not
 * a gap and where the contentCid binding actually lives instead.
 */
class MailAadContext internal constructor(
    val sender: Secp256k1PublicKey,
    recipients: List<Secp256k1PublicKey>,
    val sentAtEpochSecond: Long,
    val encryption: EncryptionMode,
    val replyTo: Cid?,
    val threadRoot: Cid?,
) {
    /** Immutable snapshot - safe from later mutation of any list the caller passed in. */
    val recipients: List<Secp256k1PublicKey> = recipients.toList()

    /** recipients.size + 1 - one wrap per recipient plus the sender's self-wrap. */
    val wrapCount: Int get() = this.recipients.size + 1

    /** §2.2's canonical serialization, computed once at construction and cached - it is hashed
     * twice per recipient by [aadForWrap]. Deliberately NOT [MessageEnvelopeCodec.encodeSignedBody]
     * minus fields: that function contains `contentCid` and (for HYBRID_ECIES) the wrap section
     * itself, both of which would make an AAD built from it circular. Both optional CIDs are
     * ALWAYS length-prefixed with an explicit 0 for absent - deliberately not
     * `encodeSignedBody`'s flags-conditional encoding - so `(replyTo=null, threadRoot=X)` and
     * `(replyTo=X, threadRoot=null)` can never serialize to the same bytes. */
    internal val contextBytes: ByteArray

    init {
        require(this.recipients.isNotEmpty()) { "an envelope must have at least one recipient" }
        require(this.recipients.size <= MessageEnvelopeCodec.MAX_RECIPIENTS) {
            "at most ${MessageEnvelopeCodec.MAX_RECIPIENTS} recipients allowed, was ${this.recipients.size}"
        }
        require(this.recipients.toSet().size == this.recipients.size) {
            "recipients must not contain duplicates"
        }
        val replyToBytes = replyTo?.toBytes()
        require(replyToBytes == null || replyToBytes.size in 1..MessageEnvelopeCodec.MAX_CID_BYTES) {
            "replyTo must be 1..${MessageEnvelopeCodec.MAX_CID_BYTES} bytes, was ${replyToBytes?.size}"
        }
        val threadRootBytes = threadRoot?.toBytes()
        require(threadRootBytes == null || threadRootBytes.size in 1..MessageEnvelopeCodec.MAX_CID_BYTES) {
            "threadRoot must be 1..${MessageEnvelopeCodec.MAX_CID_BYTES} bytes, was ${threadRootBytes?.size}"
        }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(ENVELOPE_CONTEXT_MAGIC.toByteArray(Charsets.US_ASCII))
            writeByte(ENVELOPE_CONTEXT_VERSION.toInt())
            write(sender.bytes)
            writeShort(this@MailAadContext.recipients.size)
            this@MailAadContext.recipients.forEach { write(it.bytes) }
            writeLong(sentAtEpochSecond)
            writeByte(encryption.wireValue.toInt())
            writeShort(replyToBytes?.size ?: 0)
            replyToBytes?.let { write(it) }
            writeShort(threadRootBytes?.size ?: 0)
            threadRootBytes?.let { write(it) }
        }
        contextBytes = out.toByteArray()
    }

    /**
     * 32-byte AAD for the body AEAD.
     *
     * **Deliberately omits `contentCid`.** `contentCid` is the CID of the sealed body bytes, which
     * are the *output* of the body encryption - including it here would be circular. The binding
     * is recovered in three independent ways instead:
     * 1. [aadForWrap] includes `contentCid` - the content key can only be unwrapped in a context
     *    whose `contentCid` matches, so a body swap breaks key recovery before the body AEAD is
     *    even reached.
     * 2. [HybridEcies.open] explicitly re-checks `MessageBodyCodec.cidFor(sealedBodyBytes) ==
     *    envelope.contentCid` before ever calling this function.
     * 3. `contentCid` is inside the envelope's signed body, so an unchanged sender cannot change it
     *    without breaking their own signature.
     *
     * There is no attack a `contentCid`-bearing body AAD would additionally close: if every field
     * of [contextBytes] is identical AND `contentCid` is identical, the two envelopes are identical
     * modulo signature - no transplant has occurred.
     */
    internal fun aadForBody(): ByteArray =
        domainSeparatedDigest(BODY_AAD_DOMAIN_TAG, SEALED_BODY_HEADER_PREFIX, contextBytes)

    /** 32-byte AAD for the key-wrap AEAD at [slotIndex]. Binds this wrap to: the sender and full
     * recipient set (via [contextBytes]), this specific sealed body (`contentCid`), this wrap's
     * position in the list (`slotIndex`) so a wrap permutation also fails, the identity this slot
     * is addressed to ([slotKey]), and the ephemeral key used to derive it. */
    internal fun aadForWrap(
        slotIndex: Int,
        slotKey: Secp256k1PublicKey,
        ephemeralPublicKey: Secp256k1PublicKey,
        contentCid: Cid,
    ): ByteArray {
        val slotIndexBytes = byteArrayOf((slotIndex ushr 8).toByte(), slotIndex.toByte())
        return domainSeparatedDigest(
            WRAP_AAD_DOMAIN_TAG,
            contextBytes,
            contentCid.toBytes(),
            slotIndexBytes,
            slotKey.bytes,
            ephemeralPublicKey.bytes,
        )
    }

    /** The public key whose wrap occupies [slotIndex]: `recipients[i]` for `i < recipients.size`,
     * and [sender] for the final self-wrap slot. */
    internal fun slotKey(slotIndex: Int): Secp256k1PublicKey =
        if (slotIndex < recipients.size) recipients[slotIndex] else sender

    companion object {
        /** For a message being composed, BEFORE its contentCid or wraps exist. */
        fun forNewMessage(
            sender: Secp256k1PublicKey,
            recipients: List<Secp256k1PublicKey>,
            sentAtEpochSecond: Long,
            replyTo: Cid? = null,
            threadRoot: Cid? = null,
        ): MailAadContext =
            MailAadContext(
                sender = sender,
                recipients = recipients,
                sentAtEpochSecond = sentAtEpochSecond,
                encryption = EncryptionMode.HYBRID_ECIES,
                replyTo = replyTo,
                threadRoot = threadRoot,
            )

        /** For a received envelope. The reconstruction is byte-identical to what the sender used -
         * that identity is what the whole scheme rests on, see `MailAadContextTest`. */
        fun of(envelope: MessageEnvelope): MailAadContext =
            MailAadContext(
                sender = envelope.sender,
                recipients = envelope.recipients,
                sentAtEpochSecond = envelope.sentAtEpochSecond,
                encryption = envelope.encryption,
                replyTo = envelope.replyTo,
                threadRoot = envelope.threadRoot,
            )
    }
}
