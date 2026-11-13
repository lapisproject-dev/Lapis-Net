package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.util.Arrays
import java.nio.ByteBuffer

/**
 * Fixed-size frame of an authenticated `X3DH_REJECTED` (wire type 4), all integers big-endian:
 * ```
 * off  len  field
 *   0    4  magic "LNDM"
 *   4    1  version = 1
 *   5    1  flags = 0
 *   6    1  messageType = 4 (X3DH_REJECTED)
 *   7   33  rejecterIdentity              (secp256k1 compressed, the responder)
 *  40   32  rejectedEphemeralPublicKey    (the refused X3DH_INITIAL's ephemeral key)
 *  72    4  signedPrekeyId                (as named by the refused header)
 *  76    1  oneTimePrekeyIdPresent        (0 or 1)
 *  77    4  oneTimePrekeyId               (0 when absent)
 *  81    1  reason                        (DmX3dhRejectionReason wire value)
 *  82    8  issuedAtEpochSecond
 *  90   32  tag = HMAC-SHA256(K, bytes[0..90))
 * --- FRAME_SIZE = 122 ---
 * ```
 * `K = HKDF-SHA256(ikm = X25519(IK_responder, IK_initiator), salt = 0^32,
 * info = "LapisNet:dm-x3dh-reject:v1" || initiatorIdentity(33) || responderIdentity(33), L = 32)`. The static
 * identity DH gives both parties the same key (deniability: no transferable proof that the responder processed
 * anything, unlike a signature), and nobody else can compute it. A fresh [HKDFBytesGenerator]/[HMac] per call;
 * the X3DH shared secret is never involved. The size stays far below [DmEnvelopeCodec.MAX_ENVELOPE_BYTES]; circuit
 * framing pads it like any envelope.
 */
object DmX3dhRejectionCodec {
    private val MAGIC = "LNDM".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private val INFO_LABEL = "LapisNet:dm-x3dh-reject:v1".toByteArray(Charsets.US_ASCII)
    private const val IDENTITY_SIZE = 33
    private const val X25519_SIZE = 32
    const val TAG_SIZE = 32

    /** Bytes covered by the tag (everything before it). */
    const val AUTHENTICATED_SIZE = 4 + 1 + 1 + 1 + IDENTITY_SIZE + X25519_SIZE + 4 + 1 + 4 + 1 + 8

    /** Exact frame length; anything else is malformed. */
    const val FRAME_SIZE = AUTHENTICATED_SIZE + TAG_SIZE

    init {
        check(FRAME_SIZE == 122) { "X3DH_REJECTED frame layout drifted" }
    }

    /** The authenticated fields, before a tag exists. */
    class Fields(
        val rejecterIdentity: Secp256k1PublicKey,
        val rejectedEphemeralPublicKey: X25519PublicKey,
        val signedPrekeyId: Int,
        val oneTimePrekeyId: Int?,
        val reason: DmX3dhRejectionReason,
        val issuedAtEpochSecond: Long,
    ) {
        init {
            require(signedPrekeyId >= 0) { "signedPrekeyId must be >= 0" }
            require(oneTimePrekeyId == null || oneTimePrekeyId >= 0) { "oneTimePrekeyId must be null or >= 0" }
        }
    }

    private fun authenticatedBytes(fields: Fields): ByteArray {
        val buffer = ByteBuffer.allocate(AUTHENTICATED_SIZE)
        buffer.put(MAGIC)
        buffer.put(VERSION)
        buffer.put(0)
        buffer.put(DmMessageType.X3DH_REJECTED.wireValue)
        buffer.put(fields.rejecterIdentity.bytes)
        buffer.put(fields.rejectedEphemeralPublicKey.bytes)
        buffer.putInt(fields.signedPrekeyId)
        buffer.put(if (fields.oneTimePrekeyId != null) 1 else 0)
        buffer.putInt(fields.oneTimePrekeyId ?: 0)
        buffer.put(fields.reason.wireValue)
        buffer.putLong(fields.issuedAtEpochSecond)
        check(buffer.position() == AUTHENTICATED_SIZE)
        return buffer.array()
    }

    private fun fieldsOf(r: DmX3dhRejection): Fields =
        Fields(
            r.rejecterIdentity,
            r.rejectedEphemeralPublicKey,
            r.signedPrekeyId,
            r.oneTimePrekeyId,
            r.reason,
            r.issuedAtEpochSecond,
        )

    /**
     * HMAC-SHA256 tag over [fields]. [ownX25519Private]/[peerX25519Public] are this party's X25519 identity private
     * key and the other party's X25519 identity public key; [initiator]/[responder] fix the info-string order, so
     * both sides derive the same key. The caller still owns (and destroys) [ownX25519Private].
     */
    fun computeTag(
        ownX25519Private: X25519PrivateKey,
        peerX25519Public: X25519PublicKey,
        initiator: Secp256k1PublicKey,
        responder: Secp256k1PublicKey,
        fields: Fields,
    ): ByteArray {
        val shared = x25519SharedSecret(ownX25519Private, peerX25519Public)
        val key = ByteArray(32)
        try {
            val generator = HKDFBytesGenerator(SHA256Digest())
            generator.init(HKDFParameters(shared, ByteArray(32), INFO_LABEL + initiator.bytes + responder.bytes))
            generator.generateBytes(key, 0, key.size)
            val mac = HMac(SHA256Digest())
            mac.init(KeyParameter(key))
            val data = authenticatedBytes(fields)
            mac.update(data, 0, data.size)
            val tag = ByteArray(TAG_SIZE)
            mac.doFinal(tag, 0)
            return tag
        } finally {
            shared.fill(0)
            key.fill(0)
        }
    }

    /** Builds a tagged rejection (responder side). */
    fun create(
        ownX25519Private: X25519PrivateKey,
        initiatorX25519Public: X25519PublicKey,
        initiator: Secp256k1PublicKey,
        fields: Fields,
    ): DmX3dhRejection {
        val tag = computeTag(ownX25519Private, initiatorX25519Public, initiator, fields.rejecterIdentity, fields)
        return DmX3dhRejection(
            fields.rejecterIdentity,
            fields.rejectedEphemeralPublicKey,
            fields.signedPrekeyId,
            fields.oneTimePrekeyId,
            fields.reason,
            fields.issuedAtEpochSecond,
            tag,
        )
    }

    /**
     * Constant-time tag check (initiator side): recomputes the tag with this party's ([initiator]) X25519 identity
     * private key and the responder's X25519 identity public key as used for the initiation. Never throws for a
     * wrong tag or a degenerate DH; returns `false` instead.
     */
    fun verifyTag(
        ownX25519Private: X25519PrivateKey,
        responderX25519Public: X25519PublicKey,
        initiator: Secp256k1PublicKey,
        rejection: DmX3dhRejection,
    ): Boolean {
        val expected =
            try {
                computeTag(
                    ownX25519Private,
                    responderX25519Public,
                    initiator,
                    rejection.rejecterIdentity,
                    fieldsOf(rejection),
                )
            } catch (e: RuntimeException) {
                return false
            }
        return Arrays.constantTimeAreEqual(expected, rejection.tag)
    }

    fun encode(rejection: DmX3dhRejection): ByteArray {
        val out = ByteArray(FRAME_SIZE)
        authenticatedBytes(fieldsOf(rejection)).copyInto(out, 0)
        rejection.tag.copyInto(out, AUTHENTICATED_SIZE)
        return out
    }

    /** @throws MalformedDmEnvelopeException for any structural problem (exact length, header, keys, ids, reason). */
    fun decode(bytes: ByteArray): DmX3dhRejection {
        if (bytes.size != FRAME_SIZE) {
            throw MalformedDmEnvelopeException("X3DH_REJECTED frame must be $FRAME_SIZE bytes, was ${bytes.size}")
        }
        val buffer = ByteBuffer.wrap(bytes)
        val magic = ByteArray(MAGIC.size).also { buffer.get(it) }
        if (!magic.contentEquals(MAGIC)) throw MalformedDmEnvelopeException("bad magic")
        if (buffer.get() != VERSION) throw MalformedDmEnvelopeException("unsupported version")
        if (buffer.get() != 0.toByte()) throw MalformedDmEnvelopeException("non-zero flags")
        if (buffer.get() != DmMessageType.X3DH_REJECTED.wireValue) {
            throw MalformedDmEnvelopeException("not an X3DH_REJECTED frame")
        }
        try {
            val rejecter = Secp256k1PublicKey(ByteArray(IDENTITY_SIZE).also { buffer.get(it) })
            // X25519PublicKey's own constructor rejects non-canonical, all-zero and small-order points.
            val ephemeral = X25519PublicKey(ByteArray(X25519_SIZE).also { buffer.get(it) })
            val signedPrekeyId = buffer.getInt()
            if (signedPrekeyId < 0) throw MalformedDmEnvelopeException("negative signedPrekeyId")
            val otkPresent = buffer.get().toInt()
            val otkRaw = buffer.getInt()
            val otkId =
                when (otkPresent) {
                    0 -> if (otkRaw != 0) throw MalformedDmEnvelopeException("absent otk id must be 0") else null
                    1 -> if (otkRaw < 0) throw MalformedDmEnvelopeException("negative otk id") else otkRaw
                    else -> throw MalformedDmEnvelopeException("otkPresent must be 0 or 1")
                }
            val reason =
                DmX3dhRejectionReason.fromWireValue(buffer.get())
                    ?: throw MalformedDmEnvelopeException("unknown rejection reason")
            val issuedAt = buffer.getLong()
            val tag = ByteArray(TAG_SIZE).also { buffer.get(it) }
            if (buffer.hasRemaining()) throw MalformedDmEnvelopeException("trailing bytes")
            return DmX3dhRejection(rejecter, ephemeral, signedPrekeyId, otkId, reason, issuedAt, tag)
        } catch (e: MalformedDmEnvelopeException) {
            throw e
        } catch (e: RuntimeException) {
            throw MalformedDmEnvelopeException("invalid X3DH_REJECTED field", e)
        }
    }
}
