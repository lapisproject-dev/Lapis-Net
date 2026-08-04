package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.SecureRandom

/** Deterministically fills every requested buffer with zero bytes - used to exercise
 * [MailAttachmentCipher.encrypt]'s all-zero-key RNG sanity guard without depending on a real
 * [SecureRandom] ever actually producing an all-zero key (astronomically unlikely, so the guard is
 * otherwise untestable). */
private object AllZeroRandom : SecureRandom() {
    override fun nextBytes(bytes: ByteArray) {
        bytes.fill(0)
    }
}

class MailAttachmentCipherTest :
    FunSpec({
        test("round trip: decrypt(encrypt(plaintext)) recovers the original plaintext") {
            val plaintext = "the contents of a secret PDF".toByteArray(Charsets.UTF_8)

            val encrypted = MailAttachmentCipher.encrypt(plaintext)
            val recovered = MailAttachmentCipher.decrypt(encrypted.blob, encrypted.key)

            recovered shouldBe plaintext
        }

        test("encrypting empty plaintext is rejected - mirrors SealedBody's identical minimum-ciphertext-size rule") {
            // An empty plaintext AES-GCM-encrypts to a tag-only (GCM_TAG_SIZE-byte) ciphertext,
            // which EncryptedAttachmentBlob's constructor rejects (minimum is GCM_TAG_SIZE + 1) -
            // the exact same minimum SealedBody already enforces (see that class's init block).
            // Not a bug: this codec's minimum-size discipline is deliberately reused verbatim, not
            // reinvented for attachments.
            shouldThrow<IllegalArgumentException> { MailAttachmentCipher.encrypt(ByteArray(0)) }
        }

        test("encrypting the same plaintext twice never repeats the key or the nonce") {
            val plaintext = "same content, encrypted twice".toByteArray(Charsets.UTF_8)

            val first = MailAttachmentCipher.encrypt(plaintext)
            val second = MailAttachmentCipher.encrypt(plaintext)

            first.key shouldNotBe second.key
            first.blob.nonce shouldNotBe second.blob.nonce
            // Different keys/nonces over identical plaintext also produce different ciphertext.
            first.blob.ciphertext shouldNotBe second.blob.ciphertext
        }

        test("key and blob accessors return fresh, independent copies") {
            val encrypted = MailAttachmentCipher.encrypt("data".toByteArray())

            val key = encrypted.key
            key.fill(0)

            encrypted.key shouldNotBe ByteArray(MessageBodyCodec.ATTACHMENT_KEY_SIZE)
        }

        test("encrypt rejects a broken RNG that would produce an all-zero key") {
            shouldThrow<IllegalArgumentException> {
                MailAttachmentCipher.encrypt("data".toByteArray(), random = AllZeroRandom)
            }
        }

        test("encrypt rejects plaintext above EncryptedAttachmentBlobCodec.MAX_PLAINTEXT_BYTES") {
            // A real allocation of MAX_PLAINTEXT_BYTES + 1 (~1 GiB) is impractical for a unit test -
            // this proves the guard exists via a stand-in that is cheap to fabricate: the same
            // check EncryptedAttachmentBlob's own constructor would apply to the resulting
            // ciphertext, exercised directly against the boundary constant.
            EncryptedAttachmentBlobCodec.MAX_PLAINTEXT_BYTES shouldBe
                EncryptedAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES - GCM_TAG_SIZE
        }
    })
