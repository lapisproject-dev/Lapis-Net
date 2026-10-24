package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.X25519AgreementException
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Thrown by [SealedMailboxItemCodec.seal] when the envelope does not fit the fixed item size. */
class SealedMailboxItemTooLargeException : IllegalArgumentException("envelope exceeds the sealed item capacity")

/**
 * V0.10.0-F1: the fixed-size sealed envelope the anonymity-mode offline mailbox announces on the shared
 * topic. An item is an anonymous ECIES-style box addressed to the recipient's X25519 identity key
 * (the one bound into its prekey bundle):
 *
 * ```
 * version(1) | ephemeralX25519(32) | AEAD( notValidAfter(8) | envLen(2) | envelope | zero padding ) | tag(16)
 * ```
 *
 * Always exactly [SEALED_ITEM_BYTES] bytes, so every item looks alike on the topic and fits eight
 * 716-byte relay fragments. Key = HKDF-SHA256(X25519(ephemeral, recipient), salt = ephemeral || recipient,
 * info = [KDF_INFO]); the key is single-use, so the AEAD nonce is the all-zero nonce. Every
 * re-announcement seals afresh with a new ephemeral key, which keeps announcements unlinkable
 * (the recipient's `DmDedupKey` suppresses the resulting duplicates after opening).
 *
 * The sender is not authenticated here: the item carries no signature, and the ratchet decryption
 * inside the envelope is the only proof of who sent it. There is no forward secrecy for the sealing
 * layer (the long-term identity key is the recipient key); the ratchet content stays protected.
 *
 * [open] never throws and never reveals why an item was refused.
 */
object SealedMailboxItemCodec {
    const val SEALED_ITEM_BYTES = 5_728
    const val FRAGMENT_BYTES = 716
    const val FRAGMENT_COUNT = 8

    private const val VERSION: Byte = 1
    private const val KEY_SIZE = 32
    private const val TAG_SIZE = 16
    private const val TIME_SIZE = 8
    private const val LEN_SIZE = 2
    private const val HEADER_SIZE = 1 + KEY_SIZE
    private const val PLAINTEXT_SIZE = SEALED_ITEM_BYTES - HEADER_SIZE - TAG_SIZE
    private const val NONCE_SIZE = 12
    private val KDF_INFO = "LapisNet:anonymous-mailbox-item:v1".toByteArray(Charsets.US_ASCII)

    /** The largest [DmEnvelope] encoding a sealed item can carry (5,669 bytes). */
    const val MAX_ENVELOPE_BYTES = PLAINTEXT_SIZE - TIME_SIZE - LEN_SIZE

    /**
     * Fixed envelope overhead around the content plaintext: the envelope frame prefix and length
     * field, the ratchet header and the AEAD tag. The content plaintext must satisfy
     * `plaintext.size + ENVELOPE_OVERHEAD_BYTES <= MAX_ENVELOPE_BYTES` for an anonymity-mode send.
     */
    const val ENVELOPE_OVERHEAD_BYTES =
        DmEnvelopeCodec.DM_ENVELOPE_FIXED_PREFIX_SIZE + 2 +
            net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec.HEADER_SIZE + TAG_SIZE

    /** Items refused by [open] since start (diagnostics only, never any content). */
    val refusedCount = AtomicLong()

    fun seal(
        envelopeBytes: ByteArray,
        recipientKey: X25519PublicKey,
        notValidAfterEpochSecond: Long,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        if (envelopeBytes.isEmpty() ||
            envelopeBytes.size > MAX_ENVELOPE_BYTES
        ) {
            throw SealedMailboxItemTooLargeException()
        }
        val ephemeral = X25519KeyPair.generate(random)
        var shared: ByteArray? = null
        var key: ByteArray? = null
        val plaintext = ByteArray(PLAINTEXT_SIZE)
        try {
            shared = x25519SharedSecret(ephemeral.privateKey, recipientKey)
            key = deriveKey(shared, ephemeral.publicKey.bytes, recipientKey.bytes)
            ByteBuffer
                .wrap(plaintext)
                .putLong(notValidAfterEpochSecond)
                .putShort(envelopeBytes.size.toShort())
                .put(envelopeBytes)
            val header = byteArrayOf(VERSION) + ephemeral.publicKey.bytes
            val ciphertext = aead(Cipher.ENCRYPT_MODE, key, header, plaintext)
            return header + ciphertext
        } finally {
            shared?.fill(0)
            key?.fill(0)
            plaintext.fill(0)
            ephemeral.privateKey.destroy()
        }
    }

    /** Opens [item] with [ownPrivate]; `null` for anything that is not a valid, unexpired item for us. */
    fun open(
        item: ByteArray,
        ownPrivate: X25519PrivateKey,
        nowEpochSecond: Long,
    ): DmEnvelope? {
        if (item.size != SEALED_ITEM_BYTES || item[0] != VERSION) return refused()
        var shared: ByteArray? = null
        var key: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            val ephemeralBytes = item.copyOfRange(1, HEADER_SIZE)
            val ephemeral = X25519PublicKey(ephemeralBytes)
            val ownPublic = X25519KeyPair.publicKeyFor(ownPrivate)
            shared = x25519SharedSecret(ownPrivate, ephemeral)
            key = deriveKey(shared, ephemeralBytes, ownPublic.bytes)
            plaintext =
                aead(
                    Cipher.DECRYPT_MODE,
                    key,
                    item.copyOfRange(0, HEADER_SIZE),
                    item.copyOfRange(HEADER_SIZE, item.size),
                )
            val buffer = ByteBuffer.wrap(plaintext)
            val notValidAfter = buffer.getLong()
            val length = buffer.getShort().toInt() and 0xFFFF
            if (notValidAfter < nowEpochSecond) return refused()
            if (length < 1 || length > MAX_ENVELOPE_BYTES) return refused()
            val envelopeBytes = ByteArray(length)
            buffer.get(envelopeBytes)
            while (buffer.hasRemaining()) {
                if (buffer.get() != 0.toByte()) return refused()
            }
            return DmEnvelopeCodec.decode(envelopeBytes)
        } catch (e: GeneralSecurityException) {
            return refused()
        } catch (e: X25519AgreementException) {
            return refused()
        } catch (e: MalformedDmEnvelopeException) {
            return refused()
        } catch (e: RuntimeException) {
            return refused()
        } finally {
            shared?.fill(0)
            key?.fill(0)
            plaintext?.fill(0)
        }
    }

    private fun refused(): DmEnvelope? {
        refusedCount.incrementAndGet()
        return null
    }

    private fun aead(
        mode: Int,
        key: ByteArray,
        aad: ByteArray,
        input: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(ByteArray(NONCE_SIZE)))
        cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }

    private fun deriveKey(
        shared: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray,
    ): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(ephemeralPublic + recipientPublic, "HmacSHA256"))
        val prk = extract.doFinal(shared)
        try {
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(KDF_INFO)
            expand.update(0x01)
            return expand.doFinal()
        } finally {
            prk.fill(0)
        }
    }
}
