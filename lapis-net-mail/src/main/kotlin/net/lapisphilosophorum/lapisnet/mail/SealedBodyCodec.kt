package net.lapisphilosophorum.lapisnet.mail

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/** Thrown when decoding a [SealedBody]'s canonical byte encoding fails structurally. */
class MalformedSealedBodyException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [SealedBody]. Follows the same length-prefixed,
 * check-before-allocate discipline as [MessageBodyCodec]/[MessageEnvelopeCodec]. All integers are
 * big-endian.
 *
 * Layout: `magic(4) "LNSB" | version(1) = 1 | flags(1, reserved, must be zero) | nonce(12) |
 * ciphertextLen(2) | ciphertext(ciphertextLen)` (ciphertext includes the trailing 16-byte GCM
 * tag). `total = HEADER_SIZE + ciphertextLen`.
 */
object SealedBodyCodec {
    private val MAGIC = "LNSB".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1

    const val HEADER_SIZE = 4 + 1 + 1 + GCM_NONCE_SIZE + 2 // 20

    /** `0xFFFF - HEADER_SIZE` - a sealed blob must still fit [MailFrameCodec]'s 16-bit body-length
     * field and [MessageBodyCodec.MAX_BODY_BLOB_SIZE], which are both `0xFFFF`. */
    const val MAX_CIPHERTEXT_BYTES = 0xFFFF - HEADER_SIZE // 65_515

    /** The largest [MessageBodyCodec.encode] output [HybridEcies.seal] will accept: the cipher
     * adds a 16-byte GCM tag, and the blob must still fit [MAX_CIPHERTEXT_BYTES].
     * [MessageBodyCodec]'s own cap is `0xFFFF`, so - in principle - a body between 65,500 and
     * 65,535 bytes would encode fine but be unsealable. In practice this range is unreachable
     * through [MessageBody]'s public constructor: its own per-field caps (subject + markdown +
     * attachments + headers, see [MessageBodyCodec]'s class doc comment for the arithmetic) sum to
     * at most ~48 KB, well under this limit. The `require` in [HybridEcies.seal] is therefore
     * defence-in-depth against a future relaxation of those per-field caps (or a second, larger
     * body-producing path) rather than a currently-reachable rejection - it is cheap to keep and
     * means such a future change would fail loudly here instead of overflowing
     * [MAX_CIPHERTEXT_BYTES]'s wire field. */
    const val MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - GCM_TAG_SIZE // 65_499

    fun encode(sealed: SealedBody): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: all bits reserved, must be zero
            write(sealed.nonce)
            val ciphertext = sealed.ciphertext
            writeShort(ciphertext.size)
            write(ciphertext)
        }
        return out.toByteArray()
    }

    /** @throws MalformedSealedBodyException if the bytes are structurally invalid. */
    fun decode(bytes: ByteArray): SealedBody {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedSealedBodyException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedSealedBodyException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedSealedBodyException("reserved flag bits must be zero: $flags")

            val nonce = ByteArray(GCM_NONCE_SIZE).also { input.readFully(it) }

            val ciphertextLen = input.readUnsignedShort()
            if (ciphertextLen !in (GCM_TAG_SIZE + 1)..MAX_CIPHERTEXT_BYTES) {
                throw MalformedSealedBodyException("invalid ciphertext length: $ciphertextLen")
            }
            val ciphertext = ByteArray(ciphertextLen).also { input.readFully(it) }

            if (input.available() > 0) throw MalformedSealedBodyException("trailing bytes after ciphertext")

            return SealedBody(nonce, ciphertext)
        } catch (e: EOFException) {
            throw MalformedSealedBodyException("truncated sealed-body bytes", e)
        } catch (e: IOException) {
            throw MalformedSealedBodyException("failed to decode sealed body", e)
        } catch (e: MalformedSealedBodyException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, mirroring MessageBodyCodec.decode/MessageEnvelopeCodec.decode's
            // identical narrow OutOfMemoryError catch - these bytes reach InboxGossip.onGossipMessage,
            // so an unforeseen oversized-allocation path here must still surface as a clean
            // malformed-input rejection, never an Error escaping the validator.
            throw MalformedSealedBodyException("sealed-body field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            throw MalformedSealedBodyException("invalid sealed-body field", e)
        }
    }
}
