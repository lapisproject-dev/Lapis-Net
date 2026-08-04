package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [MessageEnvelope]'s canonical byte encoding fails structurally (bad
 * magic, unsupported version, truncated/overrun buffer, out-of-range field, a reserved/unknown
 * encryption mode). Never thrown for signature verification failures - [MessageEnvelopeCodec.decode]
 * does not verify signatures, see its doc comment.
 */
class MalformedMessageEnvelopeException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [MessageEnvelope]. Follows
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec`'s layout discipline verbatim (magic,
 * version, reserved-flag-bits-must-be-zero, sequential length-prefixed variable fields, every
 * length validated BEFORE the corresponding allocation) but NOT its literal field order: an
 * envelope has a variable-length recipient list immediately after the sender, which
 * `VeritasGrantCodec`'s truster/target/scalar/flag-conditional-field/variable-fields order has no
 * equivalent of. All integers are big-endian.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4) | version(1) | flags(1) | sender(33) |
 * recipientCount(2) | recipients(33*count) | sentAtEpochSecond(8) | encryption(1) |
 * contentCidLen(2) | contentCid(contentCidLen) | replyToLen(2, only if flags bit0 set) |
 * replyTo(replyToLen) | threadRootLen(2, only if flags bit1 set) | threadRoot(threadRootLen)`.
 * [encode] appends the 64-byte signature after that.
 */
object MessageEnvelopeCodec {
    private val MAGIC = "LNME".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val FLAG_HAS_REPLY_TO = 0x01
    private const val FLAG_HAS_THREAD_ROOT = 0x02
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64

    /** Hard cap on the number of recipients a single envelope may address. */
    const val MAX_RECIPIENTS = 64

    /** Cap on the encoded byte length of a CID field (contentCid/replyTo/threadRoot). */
    const val MAX_CID_BYTES = 128

    /** [net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest] treats the whole signed
     * body as a single part, capped at this size. Worst case: `4+1+1+33 + 2 + 64*33 (recipients) +
     * 8 + 1 + 2+128 (contentCid) + 2+128 (replyTo) + 2+128 (threadRoot)` ≈ 2.6 KB - comfortably
     * under this limit. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [MessageEnvelope.create]. Deliberately accepts ANY [EncryptionMode] (including the reserved
     * [EncryptionMode.HYBRID_ECIES]/[EncryptionMode.MLS_ARCHIVE]) - this is the "structurally
     * representable" half of the V0.9.2 forward-compatibility requirement (see [EncryptionMode]'s
     * doc comment): it lets a future encryption wave add real payloads without touching this
     * codec, and it lets adversarial tests build reserved-mode bytes without reflection. Every
     * OTHER path ([MessageEnvelope]'s constructor, [MessageEnvelope.create], [decode]) rejects
     * them - only this raw-field overload does not. */
    fun encodeSignedBody(
        sender: Secp256k1PublicKey,
        recipients: List<Secp256k1PublicKey>,
        sentAtEpochSecond: Long,
        encryption: EncryptionMode,
        contentCid: Cid,
        replyTo: Cid?,
        threadRoot: Cid?,
    ): ByteArray {
        require(recipients.isNotEmpty()) { "an envelope must have at least one recipient" }
        require(recipients.size <= MAX_RECIPIENTS) {
            "at most $MAX_RECIPIENTS recipients allowed, was ${recipients.size}"
        }
        val contentCidBytes = contentCid.toBytes()
        require(contentCidBytes.size in 1..MAX_CID_BYTES) {
            "contentCid must be 1..$MAX_CID_BYTES bytes, was ${contentCidBytes.size}"
        }
        val replyToBytes = replyTo?.toBytes()
        require(replyToBytes == null || replyToBytes.size in 1..MAX_CID_BYTES) {
            "replyTo must be 1..$MAX_CID_BYTES bytes, was ${replyToBytes?.size}"
        }
        val threadRootBytes = threadRoot?.toBytes()
        require(threadRootBytes == null || threadRootBytes.size in 1..MAX_CID_BYTES) {
            "threadRoot must be 1..$MAX_CID_BYTES bytes, was ${threadRootBytes?.size}"
        }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            var flags = 0
            if (replyToBytes != null) flags = flags or FLAG_HAS_REPLY_TO
            if (threadRootBytes != null) flags = flags or FLAG_HAS_THREAD_ROOT
            writeByte(flags)
            write(sender.bytes)
            writeShort(recipients.size)
            recipients.forEach { write(it.bytes) }
            writeLong(sentAtEpochSecond)
            writeByte(encryption.wireValue.toInt())
            writeShort(contentCidBytes.size)
            write(contentCidBytes)
            if (replyToBytes != null) {
                writeShort(replyToBytes.size)
                write(replyToBytes)
            }
            if (threadRootBytes != null) {
                writeShort(threadRootBytes.size)
                write(threadRootBytes)
            }
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded envelope body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [envelope]. */
    fun encodeSignedBody(envelope: MessageEnvelope): ByteArray =
        encodeSignedBody(
            sender = envelope.sender,
            recipients = envelope.recipients,
            sentAtEpochSecond = envelope.sentAtEpochSecond,
            encryption = envelope.encryption,
            contentCid = envelope.contentCid,
            replyTo = envelope.replyTo,
            threadRoot = envelope.threadRoot,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. */
    fun encode(envelope: MessageEnvelope): ByteArray = encodeSignedBody(envelope) + envelope.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - a content identifier, not itself a
     * signed value. A fresh [MessageDigest] instance per call - not thread-safe otherwise. */
    fun contentId(envelope: MessageEnvelope): ByteArray = sha256(encode(envelope))

    /**
     * Structural decode only - does **not** verify the signature, mirroring
     * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec.decode`'s contract exactly. An
     * envelope typically arrives from an untrusted peer over gossip; callers must explicitly call
     * [MessageEnvelope.verify] before trusting it.
     *
     * @throws MalformedMessageEnvelopeException if the bytes are structurally invalid, including
     * an unknown encryption wire value or a known-but-reserved one ([EncryptionMode.HYBRID_ECIES]/
     * [EncryptionMode.MLS_ARCHIVE] - rejected outright in V0.9.1, see [EncryptionMode]'s doc
     * comment).
     */
    fun decode(bytes: ByteArray): MessageEnvelope {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedMessageEnvelopeException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedMessageEnvelopeException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags and (FLAG_HAS_REPLY_TO or FLAG_HAS_THREAD_ROOT).inv() != 0) {
                throw MalformedMessageEnvelopeException("reserved flag bits must be zero: $flags")
            }

            val senderBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val recipientCount = input.readUnsignedShort()
            if (recipientCount !in 1..MAX_RECIPIENTS) {
                throw MalformedMessageEnvelopeException("too many recipients: $recipientCount")
            }
            val recipientBytes =
                (0 until recipientCount).map {
                    ByteArray(PUBLIC_KEY_SIZE).also { buf -> input.readFully(buf) }
                }

            val sentAtEpochSecond = input.readLong()
            // Deliberately no range check - see MessageEnvelope's init block doc comment.

            val encryptionByte = input.readByte()
            val encryption =
                EncryptionMode.fromWireValue(encryptionByte)
                    ?: throw MalformedMessageEnvelopeException("unknown encryption mode: $encryptionByte")
            if (encryption != EncryptionMode.NONE) {
                throw MalformedMessageEnvelopeException(
                    "encryption mode $encryption is reserved for V0.9.2 and rejected outright in V0.9.1",
                )
            }

            val contentCidLen = input.readUnsignedShort()
            if (contentCidLen !in 1..MAX_CID_BYTES) {
                throw MalformedMessageEnvelopeException("invalid contentCid length: $contentCidLen")
            }
            val contentCidBytes = ByteArray(contentCidLen).also { input.readFully(it) }
            // Field-length caps above bound the WIRE bytes for this field, not the multihash
            // length declared INSIDE those bytes - see CidBytesValidation's class doc comment for
            // why Cid.cast() must never see bytes that fail this check.
            if (!CidBytesValidation.isSafeToCast(contentCidBytes)) {
                throw MalformedMessageEnvelopeException("contentCid declares an unsafe multihash length")
            }

            val replyTo =
                if (flags and FLAG_HAS_REPLY_TO != 0) {
                    val len = input.readUnsignedShort()
                    if (len !in
                        1..MAX_CID_BYTES
                    ) {
                        throw MalformedMessageEnvelopeException("invalid replyTo length: $len")
                    }
                    val replyToBytes = ByteArray(len).also { input.readFully(it) }
                    if (!CidBytesValidation.isSafeToCast(replyToBytes)) {
                        throw MalformedMessageEnvelopeException("replyTo declares an unsafe multihash length")
                    }
                    Cid.cast(replyToBytes)
                } else {
                    null
                }

            val threadRoot =
                if (flags and FLAG_HAS_THREAD_ROOT != 0) {
                    val len = input.readUnsignedShort()
                    if (len !in 1..MAX_CID_BYTES) {
                        throw MalformedMessageEnvelopeException("invalid threadRoot length: $len")
                    }
                    val threadRootBytes = ByteArray(len).also { input.readFully(it) }
                    if (!CidBytesValidation.isSafeToCast(threadRootBytes)) {
                        throw MalformedMessageEnvelopeException("threadRoot declares an unsafe multihash length")
                    }
                    Cid.cast(threadRootBytes)
                } else {
                    null
                }

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedMessageEnvelopeException("trailing bytes after signature")

            return MessageEnvelope.fromDecoded(
                sender = Secp256k1PublicKey(senderBytes),
                recipients = recipientBytes.map { Secp256k1PublicKey(it) },
                sentAtEpochSecond = sentAtEpochSecond,
                encryption = encryption,
                contentCid = Cid.cast(contentCidBytes),
                replyTo = replyTo,
                threadRoot = threadRoot,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedMessageEnvelopeException("truncated envelope bytes", e)
        } catch (e: IOException) {
            throw MalformedMessageEnvelopeException("failed to decode envelope", e)
        } catch (e: MalformedMessageEnvelopeException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, independent of CidBytesValidation.isSafeToCast's guard above: if
            // some other unforeseen path ever attempts an oversized allocation while decoding an
            // envelope, this must still surface as a clean malformed-input rejection, never an
            // Error escaping to InboxGossip.onGossipMessage's caller. Deliberately narrow - only
            // OutOfMemoryError, not a blanket Throwable/Error catch, which would risk masking a
            // real JVM problem unrelated to this decode call.
            throw MalformedMessageEnvelopeException("envelope field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from Secp256k1PublicKey's curve check / from
            // MessageEnvelope's own init requirements, and io.ipfs.cid.Cid.CidEncodingException
            // from Cid.cast() on malformed CID bytes - decode() must never leak an arbitrary
            // third-party exception type to callers.
            throw MalformedMessageEnvelopeException("invalid envelope field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
