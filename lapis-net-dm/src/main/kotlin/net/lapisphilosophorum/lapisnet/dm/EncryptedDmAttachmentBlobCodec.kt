package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/** Thrown when decoding an [EncryptedDmAttachmentBlob]'s canonical byte encoding fails
 * structurally. */
class MalformedEncryptedDmAttachmentBlobException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [EncryptedDmAttachmentBlob] - structurally identical
 * to `lapis-net-mail`'s `EncryptedAttachmentBlobCodec` (32-bit ciphertext-length field, same
 * check-before-allocate discipline), with its own `"LNDA"` magic (mail uses `"LNEA"`) purely so the
 * two blob families never collide by construction, even though nothing in this codebase ever tries
 * to decode one as the other.
 *
 * Layout: `magic(4) "LNDA" | version(1) = 1 | flags(1, reserved, must be zero) | nonce(12) |
 * ciphertextLen(4) | ciphertext(ciphertextLen)`. `MAX_CIPHERTEXT_BYTES` derives from
 * [DmContentCodec.MAX_DM_ATTACHMENT_BYTES] (16 MiB) plus the GCM tag - deliberately far smaller
 * than mail's 1 GiB ceiling (see [DmAttachmentCipher]'s class doc comment for why this smaller cap
 * is a deliberate V0.8.6 choice, not an oversight).
 *
 * **This codec is only ever reachable from an explicit, local-caller-triggered fetch path**
 * ([DmAttachmentFetcher.fetchAndDecrypt]'s direct Bitswap fetch - a future `lapis-net-browser`
 * attachment-download route is the intended eventual caller, not yet built this wave) - never from
 * [DmSessionManager]'s gossip/stream-protocol hot path. The check-before-allocate discipline here is
 * defense-in-depth/consistency, mirroring `EncryptedAttachmentBlobCodec`'s identical note.
 */
object EncryptedDmAttachmentBlobCodec {
    private val MAGIC = "LNDA".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1

    const val HEADER_SIZE = 4 + 1 + 1 + DM_GCM_NONCE_SIZE + 4 // 22

    const val MAX_CIPHERTEXT_BYTES: Int = (DmContentCodec.MAX_DM_ATTACHMENT_BYTES + DM_GCM_TAG_SIZE).toInt()
    const val MAX_PLAINTEXT_BYTES: Int = MAX_CIPHERTEXT_BYTES - DM_GCM_TAG_SIZE
    const val MAX_BLOB_BYTES: Int = HEADER_SIZE + MAX_CIPHERTEXT_BYTES

    fun encode(blob: EncryptedDmAttachmentBlob): ByteArray {
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

    /** @throws MalformedEncryptedDmAttachmentBlobException if the bytes are structurally invalid. */
    fun decode(bytes: ByteArray): EncryptedDmAttachmentBlob {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedEncryptedDmAttachmentBlobException("bad magic")

            val version = input.readByte()
            if (version != VERSION) {
                throw MalformedEncryptedDmAttachmentBlobException("unsupported version $version")
            }

            val flags = input.readUnsignedByte()
            if (flags != 0) {
                throw MalformedEncryptedDmAttachmentBlobException("reserved flag bits must be zero: $flags")
            }

            val nonce = ByteArray(DM_GCM_NONCE_SIZE).also { input.readFully(it) }

            val ciphertextLen = input.readInt()
            if (ciphertextLen !in (DM_GCM_TAG_SIZE + 1)..MAX_CIPHERTEXT_BYTES) {
                throw MalformedEncryptedDmAttachmentBlobException("invalid ciphertext length: $ciphertextLen")
            }
            // V0.8.6 hardening-pass finding: check the declared length against what is ACTUALLY
            // left in the buffer before allocating - `input.available()` on a
            // ByteArrayInputStream is exact (the whole blob is already fully in memory, never a
            // streamed/partial socket read), so this is a free, always-correct bound. Without it, a
            // tiny blob (e.g. 22-byte header + a few ciphertext bytes) whose header lies about
            // `ciphertextLen` (up to MAX_CIPHERTEXT_BYTES, ~16 MiB) forces a ~16 MiB transient
            // allocation on every fetch attempt before readFully ever notices the truncation - only
            // reachable from the explicit, local-caller-triggered fetch path this codec's own class
            // doc comment describes, but a cheap, load-bearing check regardless of how it is
            // reached.
            if (ciphertextLen > input.available()) {
                throw MalformedEncryptedDmAttachmentBlobException(
                    "declared ciphertext length $ciphertextLen exceeds ${input.available()} remaining bytes",
                )
            }
            val ciphertext = ByteArray(ciphertextLen).also { input.readFully(it) }

            if (input.available() > 0) {
                throw MalformedEncryptedDmAttachmentBlobException("trailing bytes after ciphertext")
            }

            return EncryptedDmAttachmentBlob(nonce, ciphertext)
        } catch (e: EOFException) {
            throw MalformedEncryptedDmAttachmentBlobException("truncated encrypted DM-attachment bytes", e)
        } catch (e: IOException) {
            throw MalformedEncryptedDmAttachmentBlobException("failed to decode encrypted DM attachment", e)
        } catch (e: MalformedEncryptedDmAttachmentBlobException) {
            throw e
        } catch (e: OutOfMemoryError) {
            throw MalformedEncryptedDmAttachmentBlobException(
                "encrypted DM-attachment field declared an oversized allocation",
                e,
            )
        } catch (e: RuntimeException) {
            throw MalformedEncryptedDmAttachmentBlobException("invalid encrypted DM-attachment field", e)
        }
    }

    /** The [Cid] `NabuStorage.put(bytes)` would return for these exact bytes - CIDv1/raw/sha2-256,
     * mirrors `MessageBodyCodec.cidFor`'s identical local, zero-I/O computation. */
    fun cidFor(blobBytes: ByteArray): Cid =
        Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, MessageDigest.getInstance("SHA-256").digest(blobBytes))
}
