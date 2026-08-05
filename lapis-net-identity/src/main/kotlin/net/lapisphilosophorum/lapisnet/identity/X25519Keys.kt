package net.lapisphilosophorum.lapisnet.identity

import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.SecureRandom

private const val X25519_KEY_SIZE = 32

/**
 * Curve25519's field prime `p = 2^255 - 19`, in X25519's own little-endian 32-byte wire order.
 * Used by [X25519PublicKey]'s canonical-encoding check (see that class's doc comment for why this
 * check is load-bearing, not paranoia).
 */
private val X25519_FIELD_PRIME_LE: ByteArray =
    hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

/**
 * The twelve published small-order / non-canonical Curve25519 u-coordinates that a conformant
 * X25519 implementation must never treat as a legitimate peer key - see [X25519PublicKey]'s doc
 * comment for the full measured evidence this list is built from (verified against the resolved
 * `bcprov-jdk18on:1.85` jar during this wave's planning pass, reproduced by
 * `X25519KeyPairTest`'s BouncyCastle-pinning regression).
 *
 * The first seven are the classically published small-order points (each of order 1, 2, or 8) -
 * BouncyCastle's own `X25519.calculateAgreement` all-zero-output check independently catches every
 * one of these, so rejecting them here is belt-and-braces for THESE seven specifically.
 *
 * The remaining five are NON-CANONICAL encodings (bit 255 set, or `u >= p`) that, after RFC 7748's
 * mandatory masking of bit 255, reduce to ordinary FULL-order points - measured to NOT produce an
 * all-zero agreement output, so BouncyCastle's own defence does not catch these five at all. Only
 * the canonical-encoding rules ([X25519PublicKey]'s `bit 255 clear` / `u < p` checks) reject them.
 * This is why both mitigations are implemented, not either/or - see [X25519PublicKey]'s doc comment.
 */
private val X25519_LOW_ORDER_POINTS: List<ByteArray> =
    listOf(
        // --- Canonical small-order points (order 1, 2, or 8) - also caught by BouncyCastle's own
        // all-zero-agreement-output check, rejected here too as defence in depth. ---
        "0000000000000000000000000000000000000000000000000000000000000000", // u = 0
        "0100000000000000000000000000000000000000000000000000000000000000", // u = 1
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1, order 2
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p (= 0)
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1 (= 1)
        // --- Non-canonical (bit 255 set / u >= p) re-encodings of small-order points - NOT caught
        // by BouncyCastle's all-zero check (measured: they reduce to full-order points after RFC
        // 7748's mandatory bit-255 masking), rejected here ONLY by the canonical-encoding rules. ---
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "d9" + "ff".repeat(31),
        "da" + "ff".repeat(31),
        "db" + "ff".repeat(31),
    ).map { hex(it) }

private fun hex(s: String): ByteArray {
    require(s.length % 2 == 0) { "hex string must have an even length" }
    return ByteArray(
        s.length / 2,
    ) { i -> ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte() }
}

/** Little-endian unsigned compare: `true` iff [u] (a 32-byte X25519 u-coordinate) is strictly less
 * than [X25519_FIELD_PRIME_LE] as an unsigned integer. No allocation. Iterates from the
 * most-significant byte (index 31, since the encoding is little-endian) down to the least. */
private fun isBelowFieldPrime(u: ByteArray): Boolean {
    for (i in 31 downTo 0) {
        val a = u[i].toInt() and 0xFF
        val b = X25519_FIELD_PRIME_LE[i].toInt() and 0xFF
        if (a != b) return a < b
    }
    return false // u == p is not strictly below p
}

/**
 * An X25519 private key - the raw 32-byte scalar. Used only as an encryption sub-key (see
 * [EncryptionKeyBinding]); the canonical Lapis Net identity remains the secp256k1 key
 * ([Secp256k1PrivateKey]), exactly as [Ed25519PrivateKey] is only ever a transport sub-key.
 *
 * **BouncyCastle stores the caller's raw bytes verbatim and clamps internally, at
 * scalar-multiplication time - measured against the resolved jar, not assumed.**
 * `X25519PrivateKeyParameters(bytes, 0).encoded` round-trips an UNCLAMPED RFC 7748 test-vector
 * scalar byte-for-byte, and deriving that scalar's public key still produces the RFC's published
 * result - clamping happens only inside `generatePublicKey()`/`generateSecret()`, not at
 * construction. This is exactly why this class does NOT require clamped input from callers.
 *
 * **An all-zero scalar is ACCEPTED by BouncyCastle** - measured: it clamps to `2^254` and yields
 * the fixed, well-known public key `2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74`.
 * The all-zero/all-ones guards below are therefore not a formality mirroring [Ed25519PrivateKey]'s
 * identical guard out of habit - they are the only thing standing between a broken or mocked
 * `SecureRandom` and a catastrophically weak long-term encryption key that BouncyCastle itself
 * would silently accept and derive a stable public key from.
 */
class X25519PrivateKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access - the caller cannot mutate the stored key through it.
     * If [destroy] has been called, this correctly hands back a zeroed copy. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == X25519_KEY_SIZE) { "X25519 private key must be $X25519_KEY_SIZE bytes" }
        // Not a cryptographic requirement of X25519 itself (BouncyCastle happily accepts and
        // clamps an all-zero scalar - see this class's doc comment) - an all-zero/all-ones scalar
        // is the classic symptom of a broken or mocked SecureRandom, rejected here as a sanity
        // guard, mirroring Ed25519PrivateKey's identical guard.
        require(!storedBytes.all { it == 0.toByte() }) { "X25519 private key must not be all-zero (likely broken RNG)" }
        require(
            !storedBytes.all { it == 0xFF.toByte() },
        ) { "X25519 private key must not be all-ones (likely broken RNG)" }
    }

    /** Zeroes the actual backing 32-byte scalar in place - see [Secp256k1PrivateKey.destroy]'s doc
     * comment for the full reasoning this mirrors (fresh-copy `bytes` vs. in-place `destroy`).
     * Idempotent. Never call this on a long-term identity/prekey private key still needed by
     * [PrekeyStore] - only on short-lived, single-use keys such as `X3dh.initiate`'s per-call
     * ephemeral keypair. */
    fun destroy() {
        storedBytes.fill(0)
    }

    override fun equals(other: Any?): Boolean =
        other is X25519PrivateKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = storedBytes.contentHashCode()

    override fun toString(): String = "X25519PrivateKey(REDACTED)"
}

/**
 * An X25519 public key in its raw 32-byte little-endian u-coordinate representation.
 *
 * **Three independent constructor-time rejections - this is the security-critical part of this
 * file, mirroring exactly why [Secp256k1PublicKey] runs `Secp256k1.pubkeyParse` and
 * [Ed25519PublicKey] runs `Ed25519PublicKeyParameters(bytes, 0)` in their own constructors:
 * untrusted wire bytes of the right length are not necessarily usable key material, and the fix
 * belongs at the root - the constructor - so every current and future decode path is safe by
 * construction rather than by each call site remembering.** `PrekeyBundleCodec.decode` is the only
 * site in this project that builds an [X25519PublicKey] from untrusted wire bytes, and its blanket
 * `catch (e: RuntimeException)` funnels these [IllegalArgumentException]s into
 * `MalformedPrekeyBundleException` - so a low-order key is rejected structurally, BEFORE any DH
 * computation runs, which is precisely what this wave's low-order-key adversarial test demands.
 *
 * 1. **Length must be exactly 32 bytes.**
 * 2. **Bit 255 (the top bit of the last little-endian byte) must be clear, and the encoded integer
 *    must be strictly less than the field prime `p = 2^255 - 19`.** These are the "canonical
 *    encoding" rules RFC 7748 §5 associates with a well-formed u-coordinate. **Why this is
 *    load-bearing and not paranoia, with the measured evidence:** five of the twelve classically
 *    published low-order/blacklist values -
 *    `cdeb7a7c…b880`, `4c9c95bc…f11d7`, `d9ff…ff`, `daff…ff`, `dbff…ff` - are NOT caught by
 *    BouncyCastle's own all-zero-agreement-output defence, because RFC 7748's MANDATORY masking of
 *    bit 255 before scalar multiplication turns those five into ordinary, FULL-order points once
 *    masked - measured directly against the resolved `bcprov-jdk18on:1.85` jar. Relying on
 *    BouncyCastle's degenerate-output check alone (the SPEC's implicit "either mitigation is fine"
 *    framing) would leave those five silently accepted. Only the canonical-encoding rule below
 *    rejects them, at construction time, before any DH ever runs.
 * 3. **The 32 bytes must not equal any of the twelve values in [X25519_LOW_ORDER_POINTS]** (seven
 *    canonical small-order points, plus the five non-canonical re-encodings above) - the
 *    "blacklist" belt to the canonical-encoding-rule's braces, and vice versa: the seven canonical
 *    small-order values ARE also caught by BouncyCastle's own all-zero check, so listing them here
 *    too is defence in depth against a future BouncyCastle version silently changing that internal
 *    behaviour (`X25519KeyPairTest`'s BouncyCastle-pinning regression exists exactly to catch that).
 *
 * **Why this can never reject a legitimate key**: any conformant X25519 implementation's
 * `scalarMultBase` output is reduced modulo `p` and therefore always has bit 255 clear and is
 * always `< p` - verified against BouncyCastle-generated keys and both RFC 7748 §6.1 published
 * public keys.
 */
class X25519PublicKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == X25519_KEY_SIZE) { "X25519 public key must be $X25519_KEY_SIZE bytes" }
        require(storedBytes[31].toInt() and 0x80 == 0) {
            "X25519 public key uses a non-canonical encoding (bit 255 set)"
        }
        require(isBelowFieldPrime(storedBytes)) {
            "X25519 public key uses a non-canonical encoding (u >= field prime)"
        }
        require(X25519_LOW_ORDER_POINTS.none { it.contentEquals(storedBytes) }) {
            "X25519 public key is a known small-order/degenerate point"
        }
    }

    private val cachedHashCode: Int = storedBytes.contentHashCode()

    /** Short hex fingerprint safe to log or display - never applies to private key material. */
    fun fingerprint(): String = storedBytes.fingerprintHex()

    override fun equals(other: Any?): Boolean = other is X25519PublicKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = cachedHashCode

    override fun toString(): String = "X25519PublicKey(${fingerprint()})"
}

class X25519KeyPair internal constructor(
    val privateKey: X25519PrivateKey,
    val publicKey: X25519PublicKey,
) {
    companion object {
        fun generate(random: SecureRandom = SecureRandom()): X25519KeyPair {
            val params = X25519PrivateKeyParameters(random)
            val privateKey = X25519PrivateKey(params.encoded)
            return X25519KeyPair(privateKey, X25519PublicKey(params.generatePublicKey().encoded))
        }

        /** Derives the matching public key from a private key's raw bytes - used by [PrekeyStore]
         * to reconstruct a keypair from stored private key material, mirroring
         * [Secp256k1KeyPair.fromPrivateKeyBytes]/[Ed25519KeyPair.fromPrivateKeySeed]. */
        fun fromPrivateKeyBytes(privateKeyBytes: ByteArray): X25519KeyPair {
            val privateKey = X25519PrivateKey(privateKeyBytes)
            val scalar = privateKey.bytes
            try {
                val params = X25519PrivateKeyParameters(scalar, 0)
                return X25519KeyPair(privateKey, X25519PublicKey(params.generatePublicKey().encoded))
            } finally {
                scalar.fill(0)
            }
        }

        /** Derives ONLY the public key matching an existing [privateKey], without wrapping the
         * result in a full [X25519KeyPair] - unlike [fromPrivateKeyBytes], which additionally
         * builds a brand-new [X25519PrivateKey] (itself holding its own copy of the scalar) as part
         * of assembling a complete keypair. Use this when the caller already owns a live
         * [X25519PrivateKey] and only needs its public half, so no SECOND, separately-owned,
         * separately-lifetime-managed private-key copy is retained on the heap - e.g.
         * `X3dh.initiate`'s check 7, which derives the initiator's own identity public key purely to
         * compare it against an already-verified [EncryptionKeyBinding]. Zeroes its own single
         * intermediate scalar copy in a `finally` block, mirroring [fromPrivateKeyBytes]. */
        fun publicKeyFor(privateKey: X25519PrivateKey): X25519PublicKey {
            val scalar = privateKey.bytes
            try {
                val params = X25519PrivateKeyParameters(scalar, 0)
                return X25519PublicKey(params.generatePublicKey().encoded)
            } finally {
                scalar.fill(0)
            }
        }
    }
}
