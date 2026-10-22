package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Thrown for any structurally invalid descriptor bytes. The message never contains byte contents. */
class MalformedOnionRelayDescriptorException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Fixed-length wire format of an [OnionRelayDescriptor] (379 bytes, `VERSION` 1):
 *
 * `ver(1) | identity(33) | ed25519(32) | bindingSig(64) | onionKey(32) | onionNotValidAfter(8) |
 * onionBindingSig(64) | seq(8) | notValidAfter(8) | familyCount(1)=0 | possession(64) | sig(64)`
 *
 * No length field exists, so no allocation ever depends on attacker-chosen data; the exact length is
 * checked FIRST and trailing bytes are rejected. The signed body is everything but the final signature.
 */
object OnionRelayDescriptorCodec {
    const val VERSION = 1
    const val ENCODED_SIZE = 379
    const val MAX_ENCODED_BYTES = 512
    private const val SIGNED_BODY_SIZE = ENCODED_SIZE - 64

    fun encodeSignedBody(d: OnionRelayDescriptor): ByteArray =
        encodeSignedBody(
            d.identity,
            d.binding,
            d.onionKeyBinding,
            d.sequenceNumber,
            d.notValidAfterEpochSecond,
            d.possessionProof,
        )

    internal fun encodeSignedBody(
        identity: Secp256k1PublicKey,
        binding: IdentityBinding,
        onionKeyBinding: OnionKeyBinding,
        sequenceNumber: Long,
        notValidAfterEpochSecond: Long,
        possessionProof: ByteArray,
    ): ByteArray {
        val b = ByteBuffer.allocate(SIGNED_BODY_SIZE)
        b.put(VERSION.toByte())
        b.put(identity.bytes)
        b.put(binding.ed25519PublicKey.bytes)
        b.put(binding.signature)
        b.put(onionKeyBinding.onionKey.bytes)
        b.putLong(onionKeyBinding.notValidAfterEpochSecond)
        b.put(onionKeyBinding.signature)
        b.putLong(sequenceNumber)
        b.putLong(notValidAfterEpochSecond)
        b.put(0)
        b.put(possessionProof)
        return b.array()
    }

    fun encode(d: OnionRelayDescriptor): ByteArray = encodeSignedBody(d) + d.signature

    fun contentId(d: OnionRelayDescriptor): ByteArray = MessageDigest.getInstance("SHA-256").digest(encode(d))

    fun decode(bytes: ByteArray): OnionRelayDescriptor {
        if (bytes.size != ENCODED_SIZE) throw MalformedOnionRelayDescriptorException("wrong descriptor length")
        try {
            val b = ByteBuffer.wrap(bytes)

            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            if (b.get().toInt() != VERSION) throw MalformedOnionRelayDescriptorException("unsupported version")
            val identity = Secp256k1PublicKey(take(33))
            val binding = IdentityBinding(Ed25519PublicKey(take(32)), take(64))
            val onionKey = X25519PublicKey(take(32))
            val onionNotValidAfter = b.getLong()
            val onionSignature = take(64)
            val seq = b.getLong()
            if (seq < 0) throw MalformedOnionRelayDescriptorException("negative sequence number")
            val notValidAfter = b.getLong()
            if (b.get().toInt() != 0) throw MalformedOnionRelayDescriptorException("family list not supported")
            val possession = take(64)
            val signature = take(64)
            return OnionRelayDescriptor.fromDecoded(
                identity,
                binding,
                OnionKeyBinding(identity, onionKey, onionNotValidAfter, onionSignature),
                seq,
                notValidAfter,
                possession,
                signature,
            )
        } catch (e: MalformedOnionRelayDescriptorException) {
            throw e
        } catch (e: RuntimeException) {
            // off-curve key, low-order X25519 point, wrong-size signature: anything a field constructor refuses
            throw MalformedOnionRelayDescriptorException("invalid descriptor field", e)
        }
    }
}
