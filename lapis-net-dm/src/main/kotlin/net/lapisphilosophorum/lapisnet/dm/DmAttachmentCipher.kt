package net.lapisphilosophorum.lapisnet.dm

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val DM_AES_KEY_SIZE = DmContentCodec.ATTACHMENT_KEY_SIZE
private const val DM_GCM_TAG_BITS = 128

/** Fixed, non-secret, domain-separating AAD tag - deliberately DIFFERENT from mail's
 * `"LapisNet:mail-attachment:v1"` (see [DmAttachmentCipherAdversarialTest]'s cross-domain
 * regression, which proves a mail-domain-authenticated blob does NOT decrypt under this tag). */
private val DM_ATTACHMENT_AAD = "LapisNet:dm-attachment:v1".toByteArray(Charsets.US_ASCII)

/** Thrown by [DmAttachmentCipher.decrypt] for EVERY failure to recover a plaintext - a wrong key, a
 * flipped ciphertext bit, or a failed GCM tag. Deliberately undifferentiated, mirroring
 * `MailAttachmentDecryptionException`'s identical reasoning: nothing here can be used as a
 * decryption oracle. */
class DmAttachmentDecryptionException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Everything [DmAttachmentCipher.encrypt] produces: the fresh key (the caller puts it into a
 * [DmAttachmentRef.encryptionKey], never logs it) and the resulting [EncryptedDmAttachmentBlob]. */
class EncryptedDmAttachment internal constructor(
    key: ByteArray,
    val blob: EncryptedDmAttachmentBlob,
) {
    private val storedKey: ByteArray = key.copyOf()

    /** Returns a fresh copy on every access. Never log this at any log level. */
    val key: ByteArray get() = storedKey.copyOf()
}

/**
 * Per-attachment AES-256-GCM encryption for DM attachments (V0.8.6). Follows the SAME
 * length-validated-before-allocation and AEAD discipline already established in `lapis-net-mail`'s
 * `MailAttachmentCipher` - no new crypto pattern, the existing one's shape reused, with its own
 * domain-separating AAD tag.
 *
 * **Why this is not a second, competing encryption mechanism.** The DM ratchet already encrypts the
 * plaintext this session carries (`DoubleRatchetSession.encrypt`), but that plaintext is capped at
 * [net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec.MAX_PLAINTEXT_BYTES] (65,459 bytes) -
 * an attachment physically cannot fit through it. What the ratchet carries instead is the CAPSULE:
 * a [DmAttachmentRef] (CID + a fresh AES-256 key), inside the ratchet-encrypted [DmContent]. The
 * attachment BLOB itself lives content-addressed in Nabu, encrypted under a key that only exists
 * inside that capsule - anyone who has not decrypted the ratchet message has, at best, a CID
 * pointing at indistinguishable-from-random ciphertext. This is exactly `MailAttachmentCipher`'s own
 * construction (since V0.9.3), with the Double Ratchet standing in for `HybridEcies` as the
 * key-transport layer.
 *
 * **Why this is duplicated here instead of a `lapis-net-dm` -> `lapis-net-mail` dependency.**
 * `lapis-net-dm` deliberately carries no edge onto its sibling `lapis-net-mail` - the precedent is
 * `DmFirstContactDeposit`, which duplicates `LightningProof`'s shape rather than depending on
 * `lapis-net-virtus`. Domain separation between the two ciphers is enforced by the distinct AAD tag
 * above, PROVEN by [DmAttachmentCipherAdversarialTest]'s cross-domain test - not merely asserted.
 */
object DmAttachmentCipher {
    /** Encrypts [plaintext] under a fresh, random AES-256 key and a fresh, random 96-bit nonce -
     * mirrors `MailAttachmentCipher.encrypt`'s identical always-fresh-key discipline.
     *
     * **A zero-byte [plaintext] is rejected** - an empty AES-GCM plaintext encrypts to a
     * tag-only ciphertext, which [EncryptedDmAttachmentBlob]'s constructor disallows. Unlike mail
     * (which can fall back to storing an attachment unencrypted, `AttachmentRef.encryptionKey =
     * null`), DM's [DmAttachmentRef.encryptionKey] is non-nullable (see that class's own doc
     * comment) - so a genuinely empty attachment is simply not representable in V0.8.6, a stated
     * scope cut, not a silent gap.
     */
    fun encrypt(
        plaintext: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): EncryptedDmAttachment {
        require(plaintext.isNotEmpty()) { "DM attachment plaintext must not be empty" }
        require(plaintext.size <= EncryptedDmAttachmentBlobCodec.MAX_PLAINTEXT_BYTES) {
            "DM attachment plaintext (${plaintext.size} bytes) exceeds the " +
                "${EncryptedDmAttachmentBlobCodec.MAX_PLAINTEXT_BYTES}-byte limit an encrypted attachment can carry"
        }
        val key = ByteArray(DM_AES_KEY_SIZE).also(random::nextBytes)
        require(!key.all { it == 0.toByte() }) {
            "generated DM attachment key must not be all-zero (likely broken RNG)"
        }
        val nonce = ByteArray(DM_GCM_NONCE_SIZE).also(random::nextBytes)
        val ciphertext = aesGcmEncrypt(key, nonce, DM_ATTACHMENT_AAD, plaintext)
        return EncryptedDmAttachment(key, EncryptedDmAttachmentBlob(nonce, ciphertext))
    }

    /** @throws DmAttachmentDecryptionException on any failure to recover the plaintext - wrong key,
     * tampered ciphertext, or tampered GCM tag. */
    fun decrypt(
        blob: EncryptedDmAttachmentBlob,
        key: ByteArray,
    ): ByteArray {
        require(key.size == DM_AES_KEY_SIZE) { "DM attachment key must be exactly $DM_AES_KEY_SIZE bytes" }
        return try {
            aesGcmDecrypt(key, blob.nonce, DM_ATTACHMENT_AAD, blob.ciphertext)
        } catch (e: AEADBadTagException) {
            throw DmAttachmentDecryptionException("decryption failed: tampered or mismatched ciphertext", e)
        } catch (e: GeneralSecurityException) {
            throw DmAttachmentDecryptionException("decryption failed: ${e.message}", e)
        } catch (e: RuntimeException) {
            throw DmAttachmentDecryptionException("decryption failed: ${e.message}", e)
        }
    }

    private fun aesGcmEncrypt(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(DM_GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(DM_GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
