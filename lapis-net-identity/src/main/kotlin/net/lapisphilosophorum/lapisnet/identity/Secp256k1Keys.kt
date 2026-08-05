package net.lapisphilosophorum.lapisnet.identity

import fr.acinq.secp256k1.Secp256k1
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import java.security.SecureRandom

private const val PRIVATE_KEY_SIZE = 32
private const val COMPRESSED_PUBLIC_KEY_SIZE = 33
private const val SIGNATURE_SIZE = 64
private const val DIGEST_SIZE = 32
private const val KEY_GENERATION_ATTEMPTS = 10

/**
 * A secp256k1 private key - the raw 32-byte scalar. This is the canonical Lapis Net identity key
 * (Bitcoin-compatible). There is no recovery mechanism: losing this key means losing the
 * identity permanently, by design.
 */
class Secp256k1PrivateKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access - the caller cannot mutate the stored key through it.
     * If [destroy] has been called on this instance, [storedBytes] is genuinely all-zero at that
     * point (see [destroy]'s doc comment), so this correctly - and honestly - hands back a
     * zeroed copy rather than lying about still holding live key material. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == PRIVATE_KEY_SIZE) { "secp256k1 private key must be $PRIVATE_KEY_SIZE bytes" }
        require(Secp256k1.secKeyVerify(storedBytes)) {
            "invalid secp256k1 private key (zero, out of curve order, or otherwise degenerate)"
        }
    }

    /**
     * Zeroes the actual backing 32-byte scalar **in place** - not merely a copy of it. Unlike
     * [bytes], which by design always hands out a fresh defensive copy (so a caller filling that
     * copy with zeroes, e.g. `privateKey.bytes.fill(0)`, only ever scrubs a disposable snapshot
     * and never touches [storedBytes] itself), this method mutates [storedBytes] directly, so the
     * secret does not linger in heap memory for as long as this object happens to remain
     * reachable.
     *
     * Intended for short-lived, single-use keys with a clear end of scope and no further
     * legitimate use - the canonical caller is `HybridEcies.seal`'s per-message ephemeral
     * keypair, generated fresh for one call and destroyed before that call returns. **Never call
     * this on a long-term identity key** (e.g. an identity's own [Secp256k1KeyPair]): doing so
     * would permanently destroy the identity, since there is no recovery mechanism (see this
     * class's own doc comment). This is exactly why [ecdhSharedSecret] deliberately does NOT call
     * this method on the caller-supplied private key it is given - it only zeroes its own
     * throwaway `privateKey.bytes` copy - leaving that choice to the caller who actually owns the
     * key's lifetime.
     *
     * Idempotent: calling this more than once is safe and a no-op after the first call.
     */
    fun destroy() {
        storedBytes.fill(0)
    }

    override fun equals(other: Any?): Boolean =
        other is Secp256k1PrivateKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = storedBytes.contentHashCode()

    override fun toString(): String = "Secp256k1PrivateKey(REDACTED)"
}

/** A secp256k1 public key in its canonical compressed (33-byte) form. */
class Secp256k1PublicKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == COMPRESSED_PUBLIC_KEY_SIZE) {
            "secp256k1 public key must be compressed ($COMPRESSED_PUBLIC_KEY_SIZE bytes)"
        }
        // Bytes of the right length are not necessarily a valid point on the curve. Without this
        // check, constructing a Secp256k1PublicKey from untrusted/decoded bytes (e.g. a Veritas
        // grant read off the DFS) would silently succeed, and a *later* call to verify() would
        // throw an uncaught native Secp256k1Exception instead of returning false - turning any
        // caller that verifies a batch/stream of untrusted grants into a trivial remote DoS.
        require(runCatching { Secp256k1.pubkeyParse(storedBytes) }.isSuccess) {
            "secp256k1 public key bytes do not represent a valid point on the curve"
        }
    }

    // Cached at construction, not recomputed per call: storedBytes never changes after the init
    // block above runs (bytes returns a defensive copy; the array it copies from is fixed for the
    // object's lifetime), so contentHashCode() always produces the same result for this instance -
    // safe to compute once, same pattern as java.lang.String's cached hashCode. This matters
    // because Secp256k1PublicKey is used as a HashMap/HashSet key throughout lapis-net-trust's
    // hot BFS path (TrustPathFinder's `best`/`visited`/`candidates` maps), where hashCode() is
    // called far more often than the key is constructed.
    private val cachedHashCode: Int = storedBytes.contentHashCode()

    /** Short hex fingerprint safe to log or display - never applies to private key material. */
    fun fingerprint(): String = storedBytes.fingerprintHex()

    override fun equals(other: Any?): Boolean =
        other is Secp256k1PublicKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = cachedHashCode

    override fun toString(): String = "Secp256k1PublicKey(${fingerprint()})"
}

class Secp256k1KeyPair internal constructor(
    val privateKey: Secp256k1PrivateKey,
    val publicKey: Secp256k1PublicKey,
) {
    companion object {
        fun generate(random: SecureRandom = SecureRandom()): Secp256k1KeyPair {
            repeat(KEY_GENERATION_ATTEMPTS) {
                val candidate = ByteArray(PRIVATE_KEY_SIZE).also(random::nextBytes)
                if (Secp256k1.secKeyVerify(candidate)) {
                    return fromPrivateKeyBytes(candidate)
                }
            }
            error("failed to generate a valid secp256k1 private key after $KEY_GENERATION_ATTEMPTS attempts")
        }

        fun fromPrivateKeyBytes(privateKeyBytes: ByteArray): Secp256k1KeyPair {
            val privateKey = Secp256k1PrivateKey(privateKeyBytes)
            val uncompressedPublicKey = Secp256k1.pubkeyCreate(privateKey.bytes)
            val compressedPublicKey = Secp256k1.pubKeyCompress(uncompressedPublicKey)
            return Secp256k1KeyPair(privateKey, Secp256k1PublicKey(compressedPublicKey))
        }
    }

    /**
     * Signs a 32-byte digest with a normalized (low-S) compact ECDSA signature. Callers must pass
     * an already-hashed 32-byte digest - secp256k1 does not hash its input internally. Never log
     * the returned signature bytes at any log level.
     */
    fun sign(digest: ByteArray): ByteArray {
        require(digest.size == DIGEST_SIZE) { "digest to sign must be exactly $DIGEST_SIZE bytes" }
        val signature = Secp256k1.sign(digest, privateKey.bytes)
        check(signature.size == SIGNATURE_SIZE) { "Secp256k1.sign produced an unexpected signature length" }
        return signature
    }
}

/**
 * Verifies a compact 64-byte ECDSA signature over a 32-byte digest.
 *
 * The [require] length checks above are hard preconditions on shape and stay unforgiving - a
 * digest that isn't 32 bytes or a signature that isn't 64 bytes is a caller programming error,
 * not untrusted-input territory. What is untrusted-input territory: a signature that *is* exactly
 * 64 bytes but whose contents are not a well-formed `(r, s)` pair (e.g. `r` at or above the curve
 * order) - live-repro'd against the real `secp256k1-kmp-jvm` jar to throw an uncaught
 * `fr.acinq.secp256k1.Secp256k1Exception` out of the native call rather than returning `false`.
 * Exactly the same bug class as [Secp256k1PublicKey]'s own constructor-time curve-validation fix
 * (a native call throwing on malformed-but-right-length input instead of returning `false`) - but
 * that fix only ever hardened public-key *construction*. Every caller of *this* function
 * (including [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s GossipSub validator, which
 * calls it transitively via `VeritasGrant.verify` on every message from every peer, before any
 * other check) needs the same hardening: a verify that can't cryptographically confirm a
 * signature - for a genuine mismatch OR for malformed input - must return `false`, never throw.
 * Fixing it here, at the shared root cause, makes every current and future caller safe by
 * construction, rather than requiring each call site to remember to wrap it individually.
 */
fun Secp256k1PublicKey.verify(
    digest: ByteArray,
    signature: ByteArray,
): Boolean {
    require(digest.size == DIGEST_SIZE) { "digest to verify must be exactly $DIGEST_SIZE bytes" }
    require(signature.size == SIGNATURE_SIZE) { "signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature" }
    return runCatching { Secp256k1.verify(signature, digest, bytes) }.getOrDefault(false)
}
