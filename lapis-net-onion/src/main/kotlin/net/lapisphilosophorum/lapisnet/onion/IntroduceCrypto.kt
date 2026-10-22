package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import org.bouncycastle.crypto.hpke.HPKE

/**
 * Public-key encryption of the INTRODUCE payload: HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256),
 * HKDF-SHA256, ChaCha20-Poly1305, over BouncyCastle. `info` binds the service id and the auth key, `aad` the
 * version and the auth key. A fresh [HPKE] instance is created per call (not documented as thread-safe).
 * There is NO forward secrecy against a compromise of the service's encryption key within its lifetime
 * (the key rotates); the end-to-end session keys are forward secret through the ntor ephemerals.
 * Every failure funnels into the single undifferentiated [OnionHandshakeException].
 */
internal object IntroduceCrypto {
    private const val INFO_LABEL = "LapisNet:hs-introduce:v1"

    private fun hpke() = HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305)

    private fun info(
        serviceIdDigest: ByteArray,
        authKey: Ed25519PublicKey,
    ) = INFO_LABEL.toByteArray(Charsets.US_ASCII) + serviceIdDigest + authKey.bytes

    private fun aad(authKey: Ed25519PublicKey) = byteArrayOf(HsConstants.VERSION) + authKey.bytes

    /** Returns `(enc, ciphertext)`. */
    fun seal(
        serviceIdDigest: ByteArray,
        encKey: X25519PublicKey,
        authKey: Ed25519PublicKey,
        plaintext: ByteArray,
    ): Pair<ByteArray, ByteArray> =
        try {
            val h = hpke()
            val ctx = h.setupBaseS(h.deserializePublicKey(encKey.bytes), info(serviceIdDigest, authKey))
            ctx.encapsulation.copyOf() to ctx.seal(aad(authKey), plaintext)
        } catch (e: Exception) {
            throw OnionHandshakeException()
        }

    fun open(
        serviceIdDigest: ByteArray,
        encPrivate: X25519PrivateKey,
        encPublic: X25519PublicKey,
        authKey: Ed25519PublicKey,
        enc: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val sk = encPrivate.bytes
        try {
            val h = hpke()
            val pair = h.deserializePrivateKey(sk, encPublic.bytes)
            val ctx = h.setupBaseR(enc, pair, info(serviceIdDigest, authKey))
            return ctx.open(aad(authKey), ciphertext)
        } catch (e: Exception) {
            throw OnionHandshakeException()
        } finally {
            sk.fill(0)
        }
    }
}
