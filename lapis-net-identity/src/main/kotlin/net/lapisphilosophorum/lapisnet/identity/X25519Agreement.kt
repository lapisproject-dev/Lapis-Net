package net.lapisphilosophorum.lapisnet.identity

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

private const val X25519_AGREEMENT_SIZE = 32

/** Thrown when an X25519 agreement cannot produce a usable shared secret - either BouncyCastle's
 * own internal contributory-behaviour check rejected a degenerate (all-zero) output, or this
 * function's own redundant explicit check caught one BouncyCastle missed (see this file's doc
 * comment for why both checks exist). Both arguments are already validated against the twelve
 * known low-order points by [X25519PublicKey]'s own constructor, so this exception is not expected
 * to be reachable via any public API in this project today - kept as defence in depth. */
class X25519AgreementException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * The X25519 shared secret between [privateKey] and [publicKey] - 32 bytes.
 *
 * **What this actually returns, verified against the resolved jar rather than assumed - and the
 * opposite of what [ecdhSharedSecret] returns.** This is the RAW 32-byte shared u-coordinate,
 * **not** a hash of it - confirmed by reproducing RFC 7748 §6.1's published test vector
 * byte-for-byte against `bcprov-jdk18on:1.85`: Alice's private scalar `77076d0a…2a` and Bob's
 * public key `de9edb7d…2b4f` (and the mirror direction) both produce the shared secret
 * `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742` - pinned exactly by
 * `X25519AgreementTest`'s known-answer regression, cross-checked through both
 * `X25519PrivateKeyParameters.generateSecret` and `X25519Agreement`.
 *
 * **Consequence for callers - the explicit contrast to [ecdhSharedSecret]'s own doc comment.**
 * [ecdhSharedSecret]'s secp256k1 ECDH output is already `SHA-256(compressed shared point)`, a
 * uniformly distributed 32-byte string safe to use directly as HKDF input keying material. THIS
 * function's output is a raw field element - **not** uniformly distributed. HKDF-Extract over
 * this value is therefore load-bearing for entropy-smoothing in [X3dh]'s key schedule, the exact
 * opposite of the situation `ecdhSharedSecret`'s own doc comment describes for its output. **Never
 * use this function's output directly as an AEAD key or as HKDF input keying material without
 * HKDF-Extract's own hashing step running over it first.**
 *
 * **The redundant explicit all-zero check below is defence in depth, not the primary
 * mitigation.** BouncyCastle 1.85 DOES implement RFC 7748 §6.1's contributory-behaviour check
 * internally (`X25519.calculateAgreement` returns `false` on an all-zero output, surfaced by
 * `X25519PrivateKeyParameters.generateSecret` as an `IllegalStateException` - measured against the
 * resolved jar) - but that is an unpinned implementation detail of a dependency this project bumps
 * periodically, not a guarantee this function's own contract can rely on unconditionally.
 * `X25519KeyPairTest`'s BouncyCastle-pinning regression exists exactly to catch a future
 * BouncyCastle version silently changing this behaviour; this function's own explicit check below
 * must never return an all-zero secret regardless of what a future BouncyCastle does.
 *
 * **Both arguments are already validated by construction, so this function is unreachable with
 * degenerate input via any public API in this project.** [X25519PrivateKey]'s constructor runs
 * all-zero/all-ones sanity guards and [X25519PublicKey]'s constructor runs the canonical-encoding
 * and known-low-order-point checks (see that class's doc comment for the full, measured
 * twelve-value table) - exactly mirroring how [ecdhSharedSecret]'s doc comment describes
 * [Secp256k1PrivateKey]/[Secp256k1PublicKey]'s own equivalent constructor-time guards.
 *
 * **Exception discipline**: no BouncyCastle exception type ever escapes - everything funnels into
 * [X25519AgreementException], mirroring `HybridEcies.open`'s `MailDecryptionException` funnel and
 * `KeystoreEncryption.decrypt`'s.
 */
fun x25519SharedSecret(
    privateKey: X25519PrivateKey,
    publicKey: X25519PublicKey,
): ByteArray {
    val scalar = privateKey.bytes
    try {
        val shared = ByteArray(X25519_AGREEMENT_SIZE)
        try {
            X25519PrivateKeyParameters(scalar, 0)
                .generateSecret(X25519PublicKeyParameters(publicKey.bytes, 0), shared, 0)
        } catch (e: IllegalStateException) {
            throw X25519AgreementException("X25519 agreement produced a degenerate (all-zero) shared secret", e)
        } catch (e: RuntimeException) {
            throw X25519AgreementException("X25519 agreement failed", e)
        }
        if (shared.all { it == 0.toByte() }) {
            shared.fill(0)
            throw X25519AgreementException("X25519 agreement produced an all-zero shared secret")
        }
        return shared
    } finally {
        scalar.fill(0)
    }
}
