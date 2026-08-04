package net.lapisphilosophorum.lapisnet.mail

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_SIZE = MessageBodyCodec.ATTACHMENT_KEY_SIZE
private const val GCM_TAG_BITS = 128

/** Fixed, non-secret, domain-separating AAD tag - see [MailAttachmentCipher]'s class doc comment
 * for why a message-specific binding (the way [HybridEcies]'s wrap/body AEADs use
 * [MailAadContext]) is unnecessary here. */
private val ATTACHMENT_AAD = "LapisNet:mail-attachment:v1".toByteArray(Charsets.US_ASCII)

/** Thrown by [MailAttachmentCipher.decrypt] for EVERY failure to recover a plaintext: a wrong key,
 * a flipped ciphertext bit, or a failed GCM tag. Deliberately a single, undifferentiated type,
 * mirroring [MailDecryptionException]'s identical reasoning: AES-GCM cannot distinguish "wrong
 * key" from "tampered input", and neither should this API, so nothing here can be used as a
 * decryption oracle. */
class MailAttachmentDecryptionException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Everything [MailAttachmentCipher.encrypt] produces: the fresh key (the caller is responsible
 * for putting it into an [AttachmentRef.encryptionKey], never for logging it) and the resulting
 * [EncryptedAttachmentBlob], ready for [EncryptedAttachmentBlobCodec.encode] and storage under its
 * own CID. */
class EncryptedAttachment internal constructor(
    key: ByteArray,
    val blob: EncryptedAttachmentBlob,
) {
    private val storedKey: ByteArray = key.copyOf()

    /** Returns a fresh copy on every access. Never log this at any log level. */
    val key: ByteArray get() = storedKey.copyOf()
}

/**
 * Per-attachment AES-256-GCM encryption for mail attachments (V0.9.3). Follows the SAME
 * length-validated-before-allocation and AEAD discipline already established in this module
 * ([HybridEcies], [SealedBodyCodec]) - no new crypto pattern, the existing one's shape reused.
 *
 * **Design decision: every encrypted attachment gets a fresh, independently-generated AES-256-GCM
 * key, generated at [encrypt] time - NEVER the [HybridEcies] body content key, regardless of the
 * enclosing message's own [EncryptionMode].** Four reasons:
 *
 * 1. Attachment encryption is explicitly ORTHOGONAL to body encryption (the "unencrypted
 *    newsletter with one encrypted PDF attachment" requirement) - a design that reuses the body
 *    key only helps the [EncryptionMode.HYBRID_ECIES] case and needs an entirely separate
 *    mechanism for [EncryptionMode.NONE] anyway. One uniform mechanism (always-fresh key) has a
 *    single code path and a single test surface for both.
 * 2. Reusing the [HybridEcies] content key would require plumbing a short-lived, sensitive
 *    symmetric key across a module boundary it currently never crosses ([HybridEcies.open] already
 *    `.fill(0)`s it immediately after use) - pure coupling cost for no benefit.
 * 3. Attachment fetch (`GET /api/mail/attachment/{cid}` in `lapis-net-browser`) is architecturally
 *    separate from - and may happen much later than, or never after - the body fetch/decrypt.
 *    [AttachmentRef.encryptionKey] already travels INSIDE the (possibly [HybridEcies]-sealed)
 *    [MessageBody], so it is trivially available the moment the recipient has decrypted the body
 *    once; no extra derivation step is needed.
 * 4. Confidentiality is identical either way for [EncryptionMode.HYBRID_ECIES] messages: the
 *    attachment key is only ever visible after a successful [HybridEcies.open], exactly the
 *    boundary a reused key would offer, with none of the coupling cost.
 *
 * **Known, accepted asymmetry for [EncryptionMode.NONE] messages, stated here rather than left an
 * undiscovered surprise**: an attachment's [AttachmentRef.encryptionKey] travels in the clear
 * inside the plaintext gossip frame - visible to anyone who computes and subscribes to the
 * recipient's [InboxTopics.forRecipient] topic, i.e. anyone already inside that narrow, already-weak
 * [EncryptionMode.NONE] confidentiality boundary that subject/body already have. Independent
 * attachment encryption in a [EncryptionMode.NONE] message therefore protects only against a
 * passive bystander who never fetches/decrypts that specific attachment blob - not against anyone
 * already observing the frame.
 *
 * **AAD choice: a fixed, non-secret, domain-separating constant, not a message-specific binding.**
 * Unlike [HybridEcies]'s wrap/body AEADs (which must resist a cross-envelope "wrap transplant"
 * because a wrap is a separate, reusable artifact carried at envelope level - see
 * [MailAadContext]'s class doc comment), an attachment's `(cid, encryptionKey)` pair lives INSIDE
 * the same signed [MessageBody] as every other [AttachmentRef] field - the envelope signature
 * already transitively authenticates the pairing, exactly as it does for [MessageBody.subject]/
 * [MessageBody.body] (see that class's own doc comment). There is no cross-envelope transplant
 * surface here to close with a context-specific AAD; a fixed domain tag is sufficient and simpler.
 */
object MailAttachmentCipher {
    /** Encrypts [plaintext] under a fresh, random AES-256 key and a fresh, random 96-bit nonce -
     * see this object's class doc comment for why the key is always fresh, never reused across
     * calls or derived from any other key in this system.
     *
     * **Known limitation: a zero-byte [plaintext] is rejected**, because an empty AES-GCM
     * plaintext encrypts to a tag-only ciphertext, which [EncryptedAttachmentBlob]'s constructor
     * disallows (minimum `GCM_TAG_SIZE + 1` bytes) - the exact same minimum [SealedBody] already
     * enforces. A genuinely empty attachment must stay unencrypted
     * ([AttachmentRef.encryptionKey] `= null`); no other cut exists for this rare case in V0.9.3.
     */
    fun encrypt(
        plaintext: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): EncryptedAttachment {
        require(plaintext.size <= EncryptedAttachmentBlobCodec.MAX_PLAINTEXT_BYTES) {
            "attachment plaintext (${plaintext.size} bytes) exceeds the " +
                "${EncryptedAttachmentBlobCodec.MAX_PLAINTEXT_BYTES}-byte limit an encrypted attachment can carry"
        }
        val key = ByteArray(AES_KEY_SIZE).also(random::nextBytes)
        // Mirrors HybridEcies.seal's identical SecureRandom sanity guard: an all-zero key is the
        // classic symptom of a broken or mocked SecureRandom, rejected here rather than silently
        // encrypting with a degenerate key.
        require(!key.all { it == 0.toByte() }) {
            "generated attachment key must not be all-zero (likely broken RNG)"
        }
        val nonce = ByteArray(GCM_NONCE_SIZE).also(random::nextBytes)
        val ciphertext = aesGcmEncrypt(key, nonce, ATTACHMENT_AAD, plaintext)
        return EncryptedAttachment(key, EncryptedAttachmentBlob(nonce, ciphertext))
    }

    /** @throws MailAttachmentDecryptionException on any failure to recover the plaintext - wrong
     * key, tampered ciphertext, or tampered GCM tag; mirrors [HybridEcies.open]'s
     * undifferentiated-failure-type discipline (see that function's doc comment). */
    fun decrypt(
        blob: EncryptedAttachmentBlob,
        key: ByteArray,
    ): ByteArray {
        require(key.size == AES_KEY_SIZE) { "attachment key must be exactly $AES_KEY_SIZE bytes" }
        return try {
            aesGcmDecrypt(key, blob.nonce, ATTACHMENT_AAD, blob.ciphertext)
        } catch (e: AEADBadTagException) {
            throw MailAttachmentDecryptionException("decryption failed: tampered or mismatched ciphertext", e)
        } catch (e: GeneralSecurityException) {
            throw MailAttachmentDecryptionException("decryption failed: ${e.message}", e)
        } catch (e: RuntimeException) {
            throw MailAttachmentDecryptionException("decryption failed: ${e.message}", e)
        }
    }

    private fun aesGcmEncrypt(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
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
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
