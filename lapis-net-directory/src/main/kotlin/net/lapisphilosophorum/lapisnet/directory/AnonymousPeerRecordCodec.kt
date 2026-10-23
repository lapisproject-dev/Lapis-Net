package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.nio.ByteBuffer

/** Thrown for any structurally invalid encoding of an [AnonymousPeerRecord]; the message never contains input bytes. */
class MalformedAnonymousPeerRecordException(
    message: String,
) : RuntimeException(message)

/**
 * Wire format of [AnonymousPeerRecord], exactly [ENCODED_SIZE] (248) bytes, no length fields:
 * `"LNAP"(4) | version(1)=1 | flags(1) [bit0 REVOKED, rest MUST be 0] | identity(33) | serviceKey(32) |
 * servicePossessionProof(64) | capabilities(1) [bit0 DM, bit1 MAIL, bit2 CALL_SIGNAL, rest MUST be 0] |
 * prekeyBundleDigest(32, all zero = none) | sequenceNumber(8) | notValidAfter(8) | signature(64)`.
 * The exact length is checked before anything is read.
 */
object AnonymousPeerRecordCodec {
    const val ENCODED_SIZE = 248
    private const val SIGNED_BODY_SIZE = ENCODED_SIZE - 64
    private const val VERSION: Byte = 1
    private const val FLAG_REVOKED = 1
    private val MAGIC = "LNAP".toByteArray(Charsets.US_ASCII)

    internal fun encodeSignedBody(record: AnonymousPeerRecord): ByteArray =
        encodeSignedBody(
            record.identity,
            record.serviceKey,
            record.servicePossessionProof,
            record.capabilities,
            record.prekeyBundleDigest,
            record.sequenceNumber,
            record.notValidAfterEpochSecond,
        )

    internal fun encodeSignedBody(
        identity: Secp256k1PublicKey,
        serviceKey: Ed25519PublicKey?,
        proof: ByteArray,
        capabilities: Set<AnonymousCapability>,
        digest: ByteArray?,
        sequenceNumber: Long,
        notValidAfter: Long,
    ): ByteArray {
        val b = ByteBuffer.allocate(SIGNED_BODY_SIZE)
        b.put(MAGIC)
        b.put(VERSION)
        b.put((if (serviceKey == null) FLAG_REVOKED else 0).toByte())
        b.put(identity.bytes)
        b.put(serviceKey?.bytes ?: ByteArray(32))
        b.put(proof)
        b.put(capabilities.fold(0) { acc, c -> acc or (1 shl c.bit) }.toByte())
        b.put(digest ?: ByteArray(32))
        b.putLong(sequenceNumber)
        b.putLong(notValidAfter)
        check(!b.hasRemaining()) { "anonymous peer record body size drifted" }
        return b.array()
    }

    fun encode(record: AnonymousPeerRecord): ByteArray = encodeSignedBody(record) + record.signature

    /** SHA-256 based, domain-separated content identifier (dedup key). */
    fun contentId(record: AnonymousPeerRecord): ByteArray =
        domainSeparatedDigest("LapisNet:anonymous-peer-record-id:v1", encode(record))

    /** @throws MalformedAnonymousPeerRecordException on any structural problem (and only that). */
    fun decode(bytes: ByteArray): AnonymousPeerRecord {
        if (bytes.size != ENCODED_SIZE) throw MalformedAnonymousPeerRecordException("wrong length")
        try {
            val b = ByteBuffer.wrap(bytes)

            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            if (!take(4).contentEquals(MAGIC)) throw MalformedAnonymousPeerRecordException("bad magic")
            if (b.get() != VERSION) throw MalformedAnonymousPeerRecordException("unsupported version")
            val flags = b.get().toInt() and 0xFF
            if (flags and FLAG_REVOKED.inv() != 0) throw MalformedAnonymousPeerRecordException("unknown flags")
            val revoked = flags and FLAG_REVOKED != 0
            val identity = Secp256k1PublicKey(take(33))
            val serviceKeyBytes = take(32)
            val proof = take(64)
            val capBits = b.get().toInt() and 0xFF
            if (capBits and AnonymousCapability.ALL_BITS.inv() != 0) {
                throw MalformedAnonymousPeerRecordException("unknown capabilities")
            }
            val digest = take(32)
            val seq = b.getLong()
            if (seq < 0) throw MalformedAnonymousPeerRecordException("negative sequence number")
            val nva = b.getLong()
            val signature = take(64)
            val digestOrNull = digest.takeIf { d -> d.any { it != 0.toByte() } }
            val caps = AnonymousCapability.entries.filter { capBits and (1 shl it.bit) != 0 }.toSet()
            if (revoked) {
                if (serviceKeyBytes.any { it != 0.toByte() } ||
                    proof.any { it != 0.toByte() } ||
                    caps.isNotEmpty() ||
                    digestOrNull != null
                ) {
                    throw MalformedAnonymousPeerRecordException("inconsistent revocation")
                }
                return AnonymousPeerRecord.fromDecoded(identity, null, proof, caps, null, seq, nva, signature)
            }
            return AnonymousPeerRecord.fromDecoded(
                identity,
                Ed25519PublicKey(serviceKeyBytes),
                proof,
                caps,
                digestOrNull,
                seq,
                nva,
                signature,
            )
        } catch (e: MalformedAnonymousPeerRecordException) {
            throw e
        } catch (e: RuntimeException) {
            throw MalformedAnonymousPeerRecordException("invalid field")
        }
    }
}
