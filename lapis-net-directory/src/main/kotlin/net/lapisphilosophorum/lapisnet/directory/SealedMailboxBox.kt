package net.lapisphilosophorum.lapisnet.directory

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

/**
 * What a sealed mailbox item carries. The kind lives INSIDE the AEAD plaintext, never in the clear header:
 * a version byte or any other header field would tell every observer of the shared topic which items are
 * direct messages and which are mail.
 */
enum class SealedMailboxKind(
    val id: Byte,
) {
    DM(1),
    MAIL(2),
    ;

    companion object {
        fun fromId(id: Byte): SealedMailboxKind? = entries.firstOrNull { it.id == id }
    }
}

/** Thrown by [SealedMailboxBox.seal] when the payload does not fit the fixed item size. */
class SealedMailboxPayloadTooLargeException : IllegalArgumentException("payload exceeds the sealed item capacity")

/** A successfully opened item of any kind (for callers that dispatch on the kind). */
class OpenedMailboxItem(
    val kind: SealedMailboxKind,
    payload: ByteArray,
) {
    private val data = payload.copyOf()
    val payload: ByteArray get() = data.copyOf()

    override fun toString(): String = "REDACTED"
}

/**
 * The fixed-size sealed box the anonymity-mode offline mailbox announces on the shared topic (wave V0.10.0-F1,
 * generalised in F2 so direct messages and mail share one item format and one topic):
 *
 * ```
 * version(1) | ephemeralX25519(32) | AEAD( notValidAfter(8) | kind(1) | len(2) | payload | zero padding ) | tag(16)
 * ```
 *
 * Always exactly [ITEM_BYTES] bytes. Key = HKDF-SHA256(X25519(ephemeral, recipient), salt = ephemeral || recipient,
 * info = "LapisNet:anonymous-mailbox-item:v1"); the key is single-use, so the AEAD nonce is all zero. Each
 * sealing uses a fresh ephemeral key, which keeps re-announcements unlinkable.
 *
 * The sender is not authenticated and there is no forward secrecy for this layer (the long-term identity key is
 * the recipient key). [open] never throws and never reveals why an item was refused; an item of another kind than
 * the one expected also yields `null` and counts as nothing special.
 */
object SealedMailboxBox {
    const val ITEM_BYTES = 5_728
    private const val VERSION: Byte = 1
    private const val KEY_SIZE = 32
    private const val TAG_SIZE = 16
    private const val TIME_SIZE = 8
    private const val KIND_SIZE = 1
    private const val LEN_SIZE = 2
    private const val HEADER_SIZE = 1 + KEY_SIZE
    private const val PLAINTEXT_SIZE = ITEM_BYTES - HEADER_SIZE - TAG_SIZE
    private const val NONCE_SIZE = 12
    private val KDF_INFO = "LapisNet:anonymous-mailbox-item:v1".toByteArray(Charsets.US_ASCII)

    /** The largest payload one item can carry (5,668 bytes). */
    const val MAX_PAYLOAD_BYTES = PLAINTEXT_SIZE - TIME_SIZE - KIND_SIZE - LEN_SIZE

    /** Items refused by [open] since start (diagnostics only, never any content). A foreign kind is not a refusal. */
    val refusedCount = AtomicLong()

    fun seal(
        kind: SealedMailboxKind,
        payload: ByteArray,
        recipientKey: X25519PublicKey,
        notValidAfterEpochSecond: Long,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        if (payload.isEmpty() || payload.size > MAX_PAYLOAD_BYTES) throw SealedMailboxPayloadTooLargeException()
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
                .put(kind.id)
                .putShort(payload.size.toShort())
                .put(payload)
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

    /**
     * Opens [item] with [ownPrivate]. `null` for anything that is not a valid, unexpired item for us, and for an
     * item of another kind than [expected]. Never throws.
     */
    fun open(
        item: ByteArray,
        ownPrivate: X25519PrivateKey,
        nowEpochSecond: Long,
        expected: SealedMailboxKind,
    ): ByteArray? = openAny(item, ownPrivate, nowEpochSecond)?.takeIf { it.kind == expected }?.payload

    /** Like [open] but returns the kind too, for callers that serve several kinds from one pass. */
    fun openAny(
        item: ByteArray,
        ownPrivate: X25519PrivateKey,
        nowEpochSecond: Long,
    ): OpenedMailboxItem? {
        if (item.size != ITEM_BYTES || item[0] != VERSION) return refused()
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
            val kind = SealedMailboxKind.fromId(buffer.get()) ?: return refused()
            val length = buffer.getShort().toInt() and 0xFFFF
            if (notValidAfter < nowEpochSecond) return refused()
            if (length < 1 || length > MAX_PAYLOAD_BYTES) return refused()
            val payload = ByteArray(length)
            buffer.get(payload)
            while (buffer.hasRemaining()) {
                if (buffer.get() != 0.toByte()) return refused()
            }
            return OpenedMailboxItem(kind, payload).also { payload.fill(0) }
        } catch (e: GeneralSecurityException) {
            return refused()
        } catch (e: X25519AgreementException) {
            return refused()
        } catch (e: RuntimeException) {
            return refused()
        } finally {
            shared?.fill(0)
            key?.fill(0)
            plaintext?.fill(0)
        }
    }

    private fun refused(): OpenedMailboxItem? {
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
