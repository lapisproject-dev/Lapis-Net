package net.lapisphilosophorum.lapisnet.identity

import fr.acinq.secp256k1.Secp256k1

private const val ECDH_OUTPUT_SIZE = 32

/**
 * The ECDH shared secret between [privateKey] and [publicKey] - 32 bytes.
 *
 * **What this actually returns, verified against the resolved jar rather than assumed.**
 * `fr.acinq.secp256k1:secp256k1-kmp:0.23.0`'s `Secp256k1.ecdh` delegates to libsecp256k1's
 * `secp256k1_ecdh` with its DEFAULT hash function, which is `SHA-256(compressed 33-byte
 * serialization of the shared point)` - NOT the raw X coordinate. Confirmed empirically by
 * [net.lapisphilosophorum.lapisnet.identity.EcdhAgreementTest]'s pinning regression, which
 * independently recomputes `SHA-256(pubKeyCompress(pubKeyTweakMul(peerPublicKey,
 * ourPrivateKey)))` via this same jar's own `pubKeyTweakMul`/`pubKeyCompress` primitives and
 * asserts it equals [ecdhSharedSecret]'s output byte-for-byte - not merely that both sides agree
 * on a shared value (symmetry alone would also hold for a raw-X construction).
 *
 * **Consequence for callers.** The result is already a uniformly distributed 32-byte string, so it
 * may be used directly as HKDF input keying material with no additional hashing step -
 * HKDF-Extract's own hashing is belt-and-braces here, not load-bearing for entropy-smoothing the
 * way it would be for a raw curve coordinate. A caller that adds its own pre-hash is not wrong,
 * just redundant.
 *
 * Neither argument can carry an invalid point: [Secp256k1PrivateKey]'s constructor runs
 * `secKeyVerify` and [Secp256k1PublicKey]'s runs `pubkeyParse`, so the underlying native call -
 * which DOES throw `fr.acinq.secp256k1.Secp256k1Exception` on an off-curve public key, confirmed
 * against the resolved jar - is unreachable with invalid input by construction. See
 * `HybridEciesAdversarialTest`'s off-curve-ephemeral-key case in `lapis-net-mail` for the
 * end-to-end proof that this guard is what stands between untrusted wire bytes and this function.
 */
fun ecdhSharedSecret(
    privateKey: Secp256k1PrivateKey,
    publicKey: Secp256k1PublicKey,
): ByteArray {
    val privateKeyBytes = privateKey.bytes
    try {
        val shared = Secp256k1.ecdh(privateKeyBytes, publicKey.bytes)
        check(shared.size == ECDH_OUTPUT_SIZE) {
            "Secp256k1.ecdh produced an unexpected shared-secret length: ${shared.size}"
        }
        return shared
    } finally {
        privateKeyBytes.fill(0)
    }
}
