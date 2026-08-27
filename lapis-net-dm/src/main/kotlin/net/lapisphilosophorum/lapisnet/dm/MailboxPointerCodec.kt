package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/** Thrown when decoding a [MailboxPointer]'s canonical byte encoding fails structurally. Never
 * thrown for a signature-verification failure - [MailboxPointerCodec.decode] does not verify it,
 * see its doc comment. */
class MalformedMailboxPointerException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [MailboxPointer]. Mirrors `PeerRecordCodec`'s
 * discipline exactly: magic, version, reserved-flag-bits-must-be-zero, sequential length-prefixed
 * variable fields, every length validated BEFORE the corresponding allocation, and
 * [CidBytesValidation.isSafeToCast] checked BEFORE `Cid.cast` runs - mirroring
 * `net.lapisphilosophorum.lapisnet.mail.MessageEnvelopeCodec`'s identical CID-handling discipline
 * (the same OOM-DoS class `CidBytesValidation`'s own class doc comment documents). All integers are
 * big-endian.
 *
 * Exact wire layout, byte by byte:
 * ```
 * off    len   field
 *   0      4   magic "LNMP"  (Lapis Net Mailbox Pointer)
 *   4      1   version = 1
 *   5      1   flags - reserved, must be zero
 *   6     33   recipientIdentity (secp256k1 compressed public key)
 *  39     33   senderIdentity    (secp256k1 compressed public key) - the routing hint
 *  72      2   blobCidLen (unsigned short, 1..MAX_CID_BYTES)
 *  74      N   blobCid bytes    (N = blobCidLen)
 * 74+N     8   notValidAfterEpochSecond (long, big-endian)
 * 82+N    64   signature (compact ECDSA by senderIdentity)
 * ```
 * [MAILBOX_POINTER_FIXED_PREFIX_SIZE] = 74 (through the `blobCidLen` field, before the CID bytes
 * themselves). [MIN_POINTER_BYTES] = 74 + 1 + 8 + 64 = 147. [MAX_POINTER_BYTES] = 74 + 128 + 8 + 64
 * = 274.
 *
 * [encodeSignedBody] = bytes 0 through `notValidAfterEpochSecond` inclusive (everything except the
 * trailing signature) - [encode] appends the signature after, mirroring `PeerRecordCodec.encode =
 * encodeSignedBody(record) + record.signature` exactly.
 *
 * Decode order (cheapest/most-selective first, mirrors `PeerRecordCodec.decode`/
 * `DmEnvelopeCodec.decode`):
 * 1. `bytes.size > MAX_POINTER_BYTES` rejected first.
 * 2. `bytes.size < MIN_POINTER_BYTES` rejected next - too-short-to-be-structurally-valid, mirroring
 *    [net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec.decode]'s own step 2 EXACTLY (this codec's
 *    own doc-comment claim to mirror that pattern used to be aspirational only - [MIN_POINTER_BYTES]
 *    was declared and documented but never actually consulted here; a too-short frame was instead
 *    rejected only indirectly, via an `EOFException` from a `readFully` running out of bytes
 *    mid-parse - fixed to be an explicit, first-line check like every sibling codec's).
 * 3. magic/version/flags.
 * 4. `recipientIdentity`/`senderIdentity` - [Secp256k1PublicKey]'s own constructor validates
 *    curve-point-ness.
 * 5. `blobCidLen` range-checked (`1..MAX_CID_BYTES`) BEFORE the `ByteArray(blobCidLen)` allocation.
 * 6. [CidBytesValidation.isSafeToCast] checked on the CID bytes BEFORE `Cid.cast` ever runs -
 *    identical discipline to `MessageEnvelopeCodec`'s `contentCid`/`replyTo`/`threadRoot` handling.
 * 7. `notValidAfterEpochSecond` - no range check (attacker-controlled, checked only at
 *    read/poll time, mirrors `PeerRecord`).
 * 8. `signature` fixed 64 bytes, trailing-bytes check.
 * 9. A blanket `catch (e: RuntimeException)` funnels `Secp256k1PublicKey`'s/`Cid.cast`'s own
 *    exceptions into [MalformedMailboxPointerException], mirroring every sibling codec - never
 *    leak a third-party exception type.
 */
object MailboxPointerCodec {
    private val MAGIC = "LNMP".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64

    /** Cap on the encoded byte length of [MailboxPointer.blobCid] - mirrors
     * `net.lapisphilosophorum.lapisnet.mail.MessageEnvelopeCodec.MAX_CID_BYTES` (a small, local
     * constant, not a cross-module reference: this module already declares no dependency on
     * `lapis-net-mail`, and the magnitude is the same for the same reason - generous headroom above
     * a realistic sha2-256 CIDv1 encoding, which is well under 40 bytes). */
    const val MAX_CID_BYTES = 128

    /** `4 (magic) + 1 (version) + 1 (flags) + 33 (recipientIdentity) + 33 (senderIdentity) +
     * 2 (blobCidLen) = 74`. */
    const val MAILBOX_POINTER_FIXED_PREFIX_SIZE = 4 + 1 + 1 + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + 2

    private const val NOT_VALID_AFTER_SIZE = 8

    /** `74 + 1 + 8 + 64 = 147`. */
    const val MIN_POINTER_BYTES = MAILBOX_POINTER_FIXED_PREFIX_SIZE + 1 + NOT_VALID_AFTER_SIZE + SIGNATURE_SIZE

    /** `74 + 128 + 8 + 64 = 274`. */
    const val MAX_POINTER_BYTES =
        MAILBOX_POINTER_FIXED_PREFIX_SIZE + MAX_CID_BYTES + NOT_VALID_AFTER_SIZE + SIGNATURE_SIZE

    fun encodeSignedBody(
        recipientIdentity: Secp256k1PublicKey,
        senderIdentity: Secp256k1PublicKey,
        blobCid: Cid,
        notValidAfterEpochSecond: Long,
    ): ByteArray {
        val blobCidBytes = blobCid.toBytes()
        require(blobCidBytes.size in 1..MAX_CID_BYTES) {
            "blobCid must be 1..$MAX_CID_BYTES bytes, was ${blobCidBytes.size}"
        }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: reserved, must be zero
            write(recipientIdentity.bytes)
            write(senderIdentity.bytes)
            writeShort(blobCidBytes.size)
            write(blobCidBytes)
            writeLong(notValidAfterEpochSecond)
        }
        return out.toByteArray()
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [pointer]. */
    fun encodeSignedBody(pointer: MailboxPointer): ByteArray =
        encodeSignedBody(
            pointer.recipientIdentity,
            pointer.senderIdentity,
            pointer.blobCid,
            pointer.notValidAfterEpochSecond,
        )

    /** The full canonical artifact: signed body followed by the pointer's own 64-byte signature. */
    fun encode(pointer: MailboxPointer): ByteArray = encodeSignedBody(pointer) + pointer.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - a content identifier/index key, not
     * itself a signed value. A fresh [MessageDigest] instance per call. */
    fun contentId(pointer: MailboxPointer): ByteArray = sha256(encode(pointer))

    /**
     * Structural decode only - does **not** verify [pointer]'s signature. Callers must explicitly
     * call [MailboxPointer.verify] before trusting the result.
     *
     * @throws MalformedMailboxPointerException if the bytes are structurally invalid.
     */
    fun decode(bytes: ByteArray): MailboxPointer {
        if (bytes.size > MAX_POINTER_BYTES) {
            throw MalformedMailboxPointerException("mailbox pointer exceeds $MAX_POINTER_BYTES bytes: ${bytes.size}")
        }
        if (bytes.size < MIN_POINTER_BYTES) {
            throw MalformedMailboxPointerException(
                "mailbox pointer too short to be structurally valid: ${bytes.size} bytes",
            )
        }
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedMailboxPointerException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedMailboxPointerException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedMailboxPointerException("reserved flag bits must be zero: $flags")

            val recipientBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val senderBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val blobCidLen = input.readUnsignedShort()
            if (blobCidLen !in 1..MAX_CID_BYTES) {
                throw MalformedMailboxPointerException("invalid blobCid length: $blobCidLen")
            }
            val blobCidBytes = ByteArray(blobCidLen).also { input.readFully(it) }
            // See CidBytesValidation's class doc comment for why Cid.cast() must never see bytes
            // that fail this check first - a declared multihash length INSIDE those bytes, not the
            // field's own byte count, is what an OOM-DoS attempt would abuse.
            if (!CidBytesValidation.isSafeToCast(blobCidBytes)) {
                throw MalformedMailboxPointerException("blobCid declares an unsafe multihash length")
            }

            val notValidAfterEpochSecond = input.readLong()
            // Deliberately no range check - see MailboxPointer's init block doc comment.

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedMailboxPointerException("trailing bytes after signature")

            return MailboxPointer.fromDecoded(
                recipientIdentity = Secp256k1PublicKey(recipientBytes),
                senderIdentity = Secp256k1PublicKey(senderBytes),
                blobCid = Cid.cast(blobCidBytes),
                notValidAfterEpochSecond = notValidAfterEpochSecond,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedMailboxPointerException("truncated mailbox pointer bytes", e)
        } catch (e: IOException) {
            throw MalformedMailboxPointerException("failed to decode mailbox pointer", e)
        } catch (e: MalformedMailboxPointerException) {
            throw e
        } catch (e: OutOfMemoryError) {
            throw MalformedMailboxPointerException("mailbox pointer field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers Secp256k1PublicKey's curve check and Cid.cast's own format checks - decode()
            // must never leak an arbitrary third-party exception type to callers.
            throw MalformedMailboxPointerException("invalid mailbox pointer field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
