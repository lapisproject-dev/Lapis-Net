package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.nio.ByteBuffer

private const val SIGNATURE_SIZE = 64

/** Distinct from the X3DH [net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding]'s tag: a
 * relay's onion key is a separate, rotatable key and a signature for one purpose can never be
 * replayed as the other. */
private const val ONION_KEY_DOMAIN_TAG = "LapisNet:onion-key:v1"
private const val RELAY_ID_DOMAIN_TAG = "LapisNet:onion-relay-id:v1"
private const val ONION_FP_DOMAIN_TAG = "LapisNet:onion-key-fp:v1"

/**
 * A relay's signed claim "this X25519 onion key is mine until [notValidAfterEpochSecond]".
 *
 * The onion key is deliberately NOT the X3DH encryption key: it is a short-lived, rotatable key
 * (as in Tor) so that compromising it later does not unlock old circuits - and circuits are
 * forward-secret anyway through the ephemeral half of the ntor handshake. The signed digest covers
 * the relay identity, the onion key and the expiry, so the binding cannot be re-attributed to a
 * different identity. Time is always passed in (`nowEpochSecond`) so tests are deterministic.
 */
class OnionKeyBinding(
    val relayIdentity: Secp256k1PublicKey,
    val onionKey: X25519PublicKey,
    val notValidAfterEpochSecond: Long,
    signature: ByteArray,
) {
    private val storedSignature = signature.copyOf()
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == SIGNATURE_SIZE) { "onion key binding signature must be $SIGNATURE_SIZE bytes" }
    }

    /** SHA-256, domain-separated, over the compressed relay identity key: the relay's address in
     * CREATE/EXTEND. */
    fun relayIdDigest(): ByteArray = domainSeparatedDigest(RELAY_ID_DOMAIN_TAG, relayIdentity.bytes)

    /** Fingerprint of the onion key as carried in CREATE/EXTEND (lets a relay detect a stale key). */
    fun onionKeyFingerprint(): ByteArray = domainSeparatedDigest(ONION_FP_DOMAIN_TAG, onionKey.bytes)

    override fun equals(other: Any?): Boolean =
        other is OnionKeyBinding &&
            relayIdentity == other.relayIdentity &&
            onionKey == other.onionKey &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            storedSignature.contentEquals(other.storedSignature)

    override fun hashCode(): Int = 31 * relayIdentity.hashCode() + onionKey.hashCode()

    override fun toString(): String = "OnionKeyBinding(relay=${relayIdentity.fingerprint()})"

    companion object {
        const val DOMAIN_TAG = ONION_KEY_DOMAIN_TAG

        private fun digest(
            identity: Secp256k1PublicKey,
            onionKey: X25519PublicKey,
            notValidAfter: Long,
        ): ByteArray =
            domainSeparatedDigest(
                ONION_KEY_DOMAIN_TAG,
                identity.bytes,
                onionKey.bytes,
                ByteBuffer.allocate(8).putLong(notValidAfter).array(),
            )

        fun create(
            identity: Secp256k1KeyPair,
            onionKey: X25519PublicKey,
            notValidAfter: Long,
        ): OnionKeyBinding =
            OnionKeyBinding(
                identity.publicKey,
                onionKey,
                notValidAfter,
                identity.sign(digest(identity.publicKey, onionKey, notValidAfter)),
            )

        /** `true` iff the signature is valid and the binding has not expired. Never throws on bad input. */
        fun verify(
            binding: OnionKeyBinding,
            nowEpochSecond: Long,
        ): Boolean =
            nowEpochSecond <= binding.notValidAfterEpochSecond &&
                binding.relayIdentity.verify(
                    digest(binding.relayIdentity, binding.onionKey, binding.notValidAfterEpochSecond),
                    binding.signature,
                )
    }
}
