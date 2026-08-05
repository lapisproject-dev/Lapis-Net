package net.lapisphilosophorum.lapisnet.identity

import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

private const val ED25519_KEY_SIZE = 32
private const val ED25519_SIGNATURE_SIZE = 64

/**
 * An Ed25519 private key seed - the raw 32-byte representation jvm-libp2p expects
 * (`Ed25519PrivateKeyParameters(seed, 0)`). Used only for this identity's libp2p peer ID, never
 * as the canonical Lapis Net identity (that role belongs to the secp256k1 key).
 */
class Ed25519PrivateKey(
    seed: ByteArray,
) {
    private val storedSeed: ByteArray = seed.copyOf()

    /** Returns a fresh copy on every access - the caller cannot mutate the stored key through it. */
    val seed: ByteArray get() = storedSeed.copyOf()

    init {
        require(storedSeed.size == ED25519_KEY_SIZE) { "Ed25519 seed must be $ED25519_KEY_SIZE bytes" }
        // Not a cryptographic requirement of Ed25519 itself - an all-zero/all-ones seed is the
        // classic symptom of a broken or mocked SecureRandom, so it is rejected as a sanity guard.
        require(!storedSeed.all { it == 0.toByte() }) { "Ed25519 seed must not be all-zero (likely broken RNG)" }
        require(!storedSeed.all { it == 0xFF.toByte() }) { "Ed25519 seed must not be all-ones (likely broken RNG)" }
    }

    override fun equals(other: Any?): Boolean = other is Ed25519PrivateKey && storedSeed.contentEquals(other.storedSeed)

    override fun hashCode(): Int = storedSeed.contentHashCode()

    override fun toString(): String = "Ed25519PrivateKey(REDACTED)"
}

/** An Ed25519 public key in its raw 32-byte representation. */
class Ed25519PublicKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == ED25519_KEY_SIZE) { "Ed25519 public key must be $ED25519_KEY_SIZE bytes" }
        // Bytes of the right length are not necessarily a valid point on the curve. Without this
        // check, constructing an Ed25519PublicKey from untrusted/decoded bytes (e.g.
        // PeerRecordCodec.decode reading a gossip-supplied binding key off the wire) would
        // silently succeed, and a *later* caller - jvm-libp2p's `unmarshalEd25519PublicKey` via
        // `PeerRecord.peerId`, or BouncyCastle's own `Ed25519Signer` via `verify` below - would
        // throw an uncaught IllegalArgumentException instead of this constructor rejecting the key
        // up front. That is exactly the bug class `Secp256k1PublicKey`'s own constructor-time
        // curve-validation guard (see its doc comment) was hardened against, and the same fix
        // applies here at the same root cause: a record that passes both `PeerRecord.verify()` and
        // `verifyBinding()` (both of which are satisfied by an attacker legitimately signing their
        // OWN garbage ed25519 bytes into their own binding) must never end up indexed/persisted
        // with a `peerId`/`toString()` that throws.
        require(runCatching { Ed25519PublicKeyParameters(storedBytes, 0) }.isSuccess) {
            "Ed25519 public key bytes do not represent a valid point on the curve"
        }
    }

    /** Short hex fingerprint safe to log or display - never applies to private key material. */
    fun fingerprint(): String = storedBytes.fingerprintHex()

    override fun equals(other: Any?): Boolean =
        other is Ed25519PublicKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = storedBytes.contentHashCode()

    override fun toString(): String = "Ed25519PublicKey(${fingerprint()})"
}

class Ed25519KeyPair internal constructor(
    val privateKey: Ed25519PrivateKey,
    val publicKey: Ed25519PublicKey,
) {
    companion object {
        fun generate(random: SecureRandom = SecureRandom()): Ed25519KeyPair {
            val generator =
                Ed25519KeyPairGenerator().apply {
                    init(Ed25519KeyGenerationParameters(random))
                }
            val keyPair = generator.generateKeyPair()
            val privateKeyParams = keyPair.private as Ed25519PrivateKeyParameters
            val publicKeyParams = keyPair.public as Ed25519PublicKeyParameters
            return Ed25519KeyPair(
                Ed25519PrivateKey(privateKeyParams.encoded),
                Ed25519PublicKey(publicKeyParams.encoded),
            )
        }

        /** Derives the matching public key from a private key seed - used to cross-check a stored
         * keypair on decode, mirroring [Secp256k1KeyPair.fromPrivateKeyBytes]. */
        fun fromPrivateKeySeed(seed: ByteArray): Ed25519KeyPair {
            val privateKey = Ed25519PrivateKey(seed)
            val publicKeyParams = Ed25519PrivateKeyParameters(privateKey.seed, 0).generatePublicKey()
            return Ed25519KeyPair(privateKey, Ed25519PublicKey(publicKeyParams.encoded))
        }
    }

    /** Signs a message with a fresh [Ed25519Signer] instance - the signer is not thread-safe. */
    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey.seed, 0))
        signer.update(message, 0, message.size)
        val signature = signer.generateSignature()
        check(signature.size == ED25519_SIGNATURE_SIZE) { "Ed25519Signer produced an unexpected signature length" }
        return signature
    }
}

/** Verifies an Ed25519 signature with a fresh [Ed25519Signer] instance per call. */
fun Ed25519PublicKey.verify(
    message: ByteArray,
    signature: ByteArray,
): Boolean {
    require(signature.size == ED25519_SIGNATURE_SIZE) { "Ed25519 signature must be $ED25519_SIGNATURE_SIZE bytes" }
    val signer = Ed25519Signer()
    signer.init(false, Ed25519PublicKeyParameters(bytes, 0))
    signer.update(message, 0, message.size)
    return signer.verifySignature(signature)
}
