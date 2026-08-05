package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/** Thrown when decoding a [PrekeyBundle]'s canonical byte encoding fails structurally. Never
 * thrown for signature/binding verification failures - [PrekeyBundleCodec.decode] does not verify
 * any of the three signatures, see its doc comment. */
class MalformedPrekeyBundleException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [PrekeyBundle]. Mirrors
 * `net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec`'s layout discipline exactly: magic,
 * version, reserved-flag-bits-must-be-zero, sequential length-prefixed variable fields, every
 * length validated BEFORE the corresponding allocation. All integers are big-endian.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4) | version(1) | flags(1, reserved, must be zero)
 * | identity(33) | x25519IdentityKey(32) | encryptionBindingSignature(64) | signedPrekeyId(4) |
 * signedPrekey(32) | signedPrekeySignature(64) | oneTimePrekeyCount(2) | ( id(4) | publicKey(32) )
 * * oneTimePrekeyCount | sequenceNumber(8) | notValidAfterEpochSecond(8)`. [encode] appends the
 * bundle's own 64-byte outer signature after that - a FOURTH, DIFFERENT 64 bytes from both
 * `encryptionBindingSignature` and `signedPrekeySignature` above - see [PrekeyBundle]'s class doc
 * comment for why three independent signatures exist.
 *
 * **No `io.ipfs.cid.Cid` field anywhere in this layout - deliberately.** No `Cid.cast`/`Cid.decode`
 * call exists anywhere in this codec or in [PrekeyStoreFileFormat], so
 * `net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation` is never invoked by this module -
 * there is nothing for it to guard, mirroring `PeerRecordCodec`'s own equivalent N/A note.
 *
 * **Worst-case size, computed and checked so a future field addition cannot silently exceed
 * [MAX_BODY_SIZE]:** `4+1+1+33+32+64+4+32+64+2 + 100*36 + 8+8 = 3,853` bytes body, `3,917` with the
 * outer signature - comfortably under [MAX_BODY_SIZE] and under
 * `net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest`'s own `0xFFFF` per-part cap.
 */
object PrekeyBundleCodec {
    private val MAGIC = "LNPB".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val X25519_KEY_SIZE = 32
    private const val SIGNATURE_SIZE = 64

    /** Hard cap on the number of one-time prekeys a single bundle may carry - generous headroom
     * (100 prekeys) above a realistic session-establishment burst, not derived from any protocol
     * requirement. */
    const val MAX_ONE_TIME_PREKEYS = 100

    /** [net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest] treats the whole signed
     * body as a single part, capped at this size - see this object's class doc comment for the
     * worst-case arithmetic that stays comfortably under it. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [PrekeyBundle.create]. */
    fun encodeSignedBody(
        identity: Secp256k1PublicKey,
        encryptionBinding: EncryptionKeyBinding,
        signedPrekeyId: Int,
        signedPrekey: X25519PublicKey,
        signedPrekeySignature: ByteArray,
        oneTimePrekeys: List<OneTimePrekey>,
        sequenceNumber: Long,
        notValidAfterEpochSecond: Long,
    ): ByteArray {
        require(oneTimePrekeys.size <= MAX_ONE_TIME_PREKEYS) {
            "at most $MAX_ONE_TIME_PREKEYS one-time prekeys allowed, was ${oneTimePrekeys.size}"
        }
        require(signedPrekeyId >= 0) { "signedPrekeyId must be >= 0, was $signedPrekeyId" }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0, was $sequenceNumber" }
        require(signedPrekeySignature.size == SIGNATURE_SIZE) {
            "signedPrekeySignature must be a compact $SIGNATURE_SIZE-byte ECDSA signature, was ${signedPrekeySignature.size}"
        }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: all bits reserved, must be zero
            write(identity.bytes)
            write(encryptionBinding.x25519PublicKey.bytes)
            write(encryptionBinding.signature)
            writeInt(signedPrekeyId)
            write(signedPrekey.bytes)
            write(signedPrekeySignature)
            writeShort(oneTimePrekeys.size)
            oneTimePrekeys.forEach { prekey ->
                writeInt(prekey.id)
                write(prekey.publicKey.bytes)
            }
            writeLong(sequenceNumber)
            writeLong(notValidAfterEpochSecond)
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded prekey bundle body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [bundle]. */
    fun encodeSignedBody(bundle: PrekeyBundle): ByteArray =
        encodeSignedBody(
            identity = bundle.identity,
            encryptionBinding = bundle.encryptionBinding,
            signedPrekeyId = bundle.signedPrekeyId,
            signedPrekey = bundle.signedPrekey,
            signedPrekeySignature = bundle.signedPrekeySignature,
            oneTimePrekeys = bundle.oneTimePrekeys,
            sequenceNumber = bundle.sequenceNumber,
            notValidAfterEpochSecond = bundle.notValidAfterEpochSecond,
        )

    /** The full canonical artifact: signed body followed by the bundle's own 64-byte outer
     * signature (NOT `encryptionBinding.signature` or `signedPrekeySignature`, both of which
     * already sit inside the signed body itself). */
    fun encode(bundle: PrekeyBundle): ByteArray = encodeSignedBody(bundle) + bundle.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - a content identifier/index key, not
     * itself a signed value. A fresh [MessageDigest] instance per call. */
    fun contentId(bundle: PrekeyBundle): ByteArray = sha256(encode(bundle))

    /**
     * Structural decode only - does **not** verify any of the three signatures, mirroring
     * `PeerRecordCodec.decode`'s contract exactly. Callers must explicitly call [PrekeyBundle.verify],
     * [verifyEncryptionBinding], AND [verifySignedPrekey] before trusting the result.
     *
     * The one-time-prekey count is validated - **`> MAX_ONE_TIME_PREKEYS` is rejected before
     * entering the per-entry loop and before any list allocation** - and every entry is a fixed 36
     * bytes, so the count check alone bounds the whole section at `100 * 36 = 3,600` bytes. A
     * low-order/non-canonical [X25519PublicKey] anywhere in the signed prekey or one-time prekey
     * slots is rejected by that class's own constructor, funnelled here via the blanket
     * `catch (e: RuntimeException)` below - i.e. rejected structurally, at decode time, before any
     * DH computation ever runs.
     *
     * @throws MalformedPrekeyBundleException if the bytes are structurally invalid.
     */
    fun decode(bytes: ByteArray): PrekeyBundle {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedPrekeyBundleException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedPrekeyBundleException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedPrekeyBundleException("reserved flag bits must be zero: $flags")

            val identityBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val x25519IdentityKeyBytes = ByteArray(X25519_KEY_SIZE).also { input.readFully(it) }
            val encryptionBindingSignature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }

            val signedPrekeyId = input.readInt()
            if (signedPrekeyId < 0) throw MalformedPrekeyBundleException("signedPrekeyId must be >= 0: $signedPrekeyId")
            val signedPrekeyBytes = ByteArray(X25519_KEY_SIZE).also { input.readFully(it) }
            val signedPrekeySignature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }

            val oneTimePrekeyCount = input.readUnsignedShort()
            if (oneTimePrekeyCount > MAX_ONE_TIME_PREKEYS) {
                throw MalformedPrekeyBundleException("too many one-time prekeys: $oneTimePrekeyCount")
            }
            val oneTimePrekeys =
                (0 until oneTimePrekeyCount).map {
                    val id = input.readInt()
                    if (id < 0) throw MalformedPrekeyBundleException("one-time prekey id must be >= 0: $id")
                    val keyBytes = ByteArray(X25519_KEY_SIZE).also { buf -> input.readFully(buf) }
                    OneTimePrekey(id, X25519PublicKey(keyBytes))
                }

            val sequenceNumber = input.readLong()
            if (sequenceNumber < 0) throw MalformedPrekeyBundleException("sequenceNumber must be >= 0: $sequenceNumber")

            val notValidAfterEpochSecond = input.readLong()
            // Deliberately no range check - see PrekeyBundle's init block doc comment.

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedPrekeyBundleException("trailing bytes after signature")

            val encryptionBinding =
                EncryptionKeyBinding(X25519PublicKey(x25519IdentityKeyBytes), encryptionBindingSignature)

            return PrekeyBundle.fromDecoded(
                identity = Secp256k1PublicKey(identityBytes),
                encryptionBinding = encryptionBinding,
                signedPrekeyId = signedPrekeyId,
                signedPrekey = X25519PublicKey(signedPrekeyBytes),
                signedPrekeySignature = signedPrekeySignature,
                oneTimePrekeys = oneTimePrekeys,
                sequenceNumber = sequenceNumber,
                notValidAfterEpochSecond = notValidAfterEpochSecond,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedPrekeyBundleException("truncated prekey bundle bytes", e)
        } catch (e: IOException) {
            throw MalformedPrekeyBundleException("failed to decode prekey bundle", e)
        } catch (e: MalformedPrekeyBundleException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, kept for structural consistency with every sibling codec - every
            // allocation in this function is already bounded by an explicit cap checked BEFORE
            // allocation (fixed-size fields, MAX_ONE_TIME_PREKEYS * 36 bytes). Never thrown by a
            // known path today.
            throw MalformedPrekeyBundleException("prekey bundle field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers Secp256k1PublicKey's curve check, X25519PublicKey's canonical-encoding/
            // low-order-point checks, EncryptionKeyBinding's signature-size check, and
            // PrekeyBundle.init's duplicate-id/duplicate-key checks - decode() must never leak an
            // arbitrary third-party/internal exception type to callers. This is also the exact
            // path that rejects a low-order X25519 public key at decode time, before any DH ever
            // runs (see this object's class doc comment).
            throw MalformedPrekeyBundleException("invalid prekey bundle field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
