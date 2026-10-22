package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.encoders.Base32

/**
 * The address of an onion service: `base32(serviceKey(32) | checksum(2) | version(1))`, 56 lowercase
 * characters (the shape of a Tor v3 address). The key is a dedicated Ed25519 service key, NOT the Lapis
 * identity and NOT a libp2p transport key. No blinding is applied (see docs/anonymity.adoc): addresses
 * are enumerable by anyone who reads the public descriptor index.
 */
class OnionServiceAddress(
    val serviceKey: Ed25519PublicKey,
) {
    /** The id used in the end-to-end handshake. */
    fun serviceIdDigest(): ByteArray = domainSeparatedDigest(ID_DOMAIN, serviceKey.bytes)

    fun encode(): String {
        val key = serviceKey.bytes
        val raw = key + checksum(key) + byteArrayOf(VERSION)
        return Base32.toBase32String(raw).lowercase()
    }

    override fun equals(other: Any?): Boolean = other is OnionServiceAddress && serviceKey == other.serviceKey

    override fun hashCode(): Int = serviceKey.hashCode()

    /** Never prints the address: it identifies a service. */
    override fun toString(): String = "OnionServiceAddress(REDACTED)"

    companion object {
        private const val ID_DOMAIN = "LapisNet:onion-service-id:v1"
        private const val CHECKSUM_DOMAIN = "LapisNet:onion-address-checksum:v1"
        private const val VERSION: Byte = 1
        const val ENCODED_LENGTH = 56

        private fun checksum(key: ByteArray): ByteArray =
            domainSeparatedDigest(CHECKSUM_DOMAIN, key, byteArrayOf(VERSION)).copyOfRange(0, 2)

        /** Throws [IllegalArgumentException] (message without any echo of [text]) on any defect. */
        fun parse(text: String): OnionServiceAddress {
            require(text.length == ENCODED_LENGTH) { "invalid onion address" }
            require(text.all { it in 'a'..'z' || it in '2'..'7' }) { "invalid onion address" }
            val raw =
                try {
                    Base32.decode(text.uppercase())
                } catch (e: RuntimeException) {
                    throw IllegalArgumentException("invalid onion address")
                }
            require(raw.size == 35 && raw[34] == VERSION) { "invalid onion address" }
            val key = raw.copyOfRange(0, 32)
            require(Arrays.constantTimeAreEqual(raw.copyOfRange(32, 34), checksum(key))) { "invalid onion address" }
            val pub =
                try {
                    Ed25519PublicKey(key)
                } catch (e: IllegalArgumentException) {
                    throw IllegalArgumentException("invalid onion address")
                }
            return OnionServiceAddress(pub)
        }
    }
}
