package net.lapisphilosophorum.lapisnet.onion

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * HMAC-SHA256 / HKDF-SHA256 for the ntor handshake. A deliberate small copy of the ratchet
 * module's `RatchetKdf` (which is `internal` there): importing it would couple two modules whose
 * isolation is a security property. A fresh [HMac]/generator is created per call (not thread-safe).
 */
internal object OnionKdf {
    fun hmacSha256(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    fun hkdfSha256(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info))
        val okm = ByteArray(length)
        generator.generateBytes(okm, 0, length)
        return okm
    }
}
