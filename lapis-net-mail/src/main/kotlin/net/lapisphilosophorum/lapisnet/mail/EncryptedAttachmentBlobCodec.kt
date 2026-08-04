package net.lapisphilosophorum.lapisnet.mail

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/** Thrown when decoding an [EncryptedAttachmentBlob]'s canonical byte encoding fails
 * structurally. */
class MalformedEncryptedAttachmentBlobException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [EncryptedAttachmentBlob]. Follows the same
 * length-prefixed, check-before-allocate discipline as [SealedBodyCodec]/[MessageBodyCodec], but
 * with a **32-bit**, not 16-bit, ciphertext-length field: an attachment can legitimately be far
 * larger than [MessageBodyCodec.MAX_BODY_BLOB_SIZE] allows, because - unlike [SealedBody] - this
 * blob is stored SEPARATELY under its own CID and is never embedded in a gossiped
 * [MailFrameCodec] frame.
 *
 * Layout: `magic(4) "LNEA" | version(1) = 1 | flags(1, reserved, must be zero) | nonce(12) |
 * ciphertextLen(4) | ciphertext(ciphertextLen)` (ciphertext includes the trailing 16-byte GCM
 * tag). `total = HEADER_SIZE + ciphertextLen`.
 *
 * **DoS-surface note, unlike every other `decode()` in this module**: this codec is never called
 * from [InboxGossip.onGossipMessage] - attachment blobs are not part of the gossip frame at all
 * (see [MailFrameCodec]'s class doc comment). It is only reachable from an explicit,
 * loopback-only, local-caller-triggered fetch path (`GET /api/mail/attachment/{cid}` in
 * `lapis-net-browser`), so the check-before-allocate discipline here is defense-in-depth/
 * consistency with this module's other codecs, not closing a gossip-reachable amplification
 * vector the way [MessageBodyCodec.decode]/[MessageEnvelopeCodec.decode]'s `OutOfMemoryError`
 * catches do.
 */
object EncryptedAttachmentBlobCodec {
    private val MAGIC = "LNEA".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1

    const val HEADER_SIZE = 4 + 1 + 1 + GCM_NONCE_SIZE + 4 // 22

    /** Reuses [MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES]'s already-accepted 1 GiB
     * declared-size ceiling as this codec's ciphertext ceiling, rather than inventing a new
     * arbitrary number - plaintext cap plus the 16-byte GCM tag. Comfortably fits a signed `Int`
     * (well under `Int.MAX_VALUE`). */
    const val MAX_CIPHERTEXT_BYTES: Int = (MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES + GCM_TAG_SIZE).toInt()
    const val MAX_PLAINTEXT_BYTES: Int = MAX_CIPHERTEXT_BYTES - GCM_TAG_SIZE

    fun encode(blob: EncryptedAttachmentBlob): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: all bits reserved, must be zero
            write(blob.nonce)
            val ciphertext = blob.ciphertext
            writeInt(ciphertext.size)
            write(ciphertext)
        }
        return out.toByteArray()
    }

    /** @throws MalformedEncryptedAttachmentBlobException if the bytes are structurally invalid. */
    fun decode(bytes: ByteArray): EncryptedAttachmentBlob {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedEncryptedAttachmentBlobException("bad magic")

            val version = input.readByte()
            if (version != VERSION) {
                throw MalformedEncryptedAttachmentBlobException("unsupported version $version")
            }

            val flags = input.readUnsignedByte()
            if (flags != 0) {
                throw MalformedEncryptedAttachmentBlobException("reserved flag bits must be zero: $flags")
            }

            val nonce = ByteArray(GCM_NONCE_SIZE).also { input.readFully(it) }

            val ciphertextLen = input.readInt()
            if (ciphertextLen !in (GCM_TAG_SIZE + 1)..MAX_CIPHERTEXT_BYTES) {
                throw MalformedEncryptedAttachmentBlobException("invalid ciphertext length: $ciphertextLen")
            }
            val ciphertext = ByteArray(ciphertextLen).also { input.readFully(it) }

            if (input.available() > 0) {
                throw MalformedEncryptedAttachmentBlobException("trailing bytes after ciphertext")
            }

            return EncryptedAttachmentBlob(nonce, ciphertext)
        } catch (e: EOFException) {
            throw MalformedEncryptedAttachmentBlobException("truncated encrypted-attachment bytes", e)
        } catch (e: IOException) {
            throw MalformedEncryptedAttachmentBlobException("failed to decode encrypted attachment", e)
        } catch (e: MalformedEncryptedAttachmentBlobException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, mirroring SealedBodyCodec.decode/MessageBodyCodec.decode's
            // identical narrow OutOfMemoryError catch - see this object's class doc comment for
            // why this path is not gossip-reachable but the discipline is kept anyway.
            throw MalformedEncryptedAttachmentBlobException(
                "encrypted-attachment field declared an oversized allocation",
                e,
            )
        } catch (e: RuntimeException) {
            throw MalformedEncryptedAttachmentBlobException("invalid encrypted-attachment field", e)
        }
    }
}
