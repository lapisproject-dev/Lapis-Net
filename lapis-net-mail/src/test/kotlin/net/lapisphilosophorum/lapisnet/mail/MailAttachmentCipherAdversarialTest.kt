package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

/** Adversarial coverage for [MailAttachmentCipher] - mirrors [HybridEciesAdversarialTest]'s file
 * split (crypto-adversarial cases kept separate from the happy-path round trip in
 * [MailAttachmentCipherTest]). */
class MailAttachmentCipherAdversarialTest :
    FunSpec({
        test("decrypt with the wrong key fails with MailAttachmentDecryptionException, not a raw AEAD exception") {
            val encrypted = MailAttachmentCipher.encrypt("secret bytes".toByteArray())
            val wrongKey = ByteArray(MessageBodyCodec.ATTACHMENT_KEY_SIZE) { (it + 1).toByte() }

            shouldThrow<MailAttachmentDecryptionException> {
                MailAttachmentCipher.decrypt(encrypted.blob, wrongKey)
            }
        }

        test("a single flipped ciphertext byte fails to decrypt") {
            val encrypted = MailAttachmentCipher.encrypt("secret bytes".toByteArray())
            val tamperedCiphertext = encrypted.blob.ciphertext
            tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0x01).toByte()
            val tampered = EncryptedAttachmentBlob(encrypted.blob.nonce, tamperedCiphertext)

            shouldThrow<MailAttachmentDecryptionException> {
                MailAttachmentCipher.decrypt(tampered, encrypted.key)
            }
        }

        test("a flipped trailing GCM tag byte fails to decrypt") {
            val encrypted = MailAttachmentCipher.encrypt("secret bytes".toByteArray())
            val tamperedCiphertext = encrypted.blob.ciphertext
            val lastIndex = tamperedCiphertext.size - 1
            tamperedCiphertext[lastIndex] = (tamperedCiphertext[lastIndex].toInt() xor 0x01).toByte()
            val tampered = EncryptedAttachmentBlob(encrypted.blob.nonce, tamperedCiphertext)

            shouldThrow<MailAttachmentDecryptionException> {
                MailAttachmentCipher.decrypt(tampered, encrypted.key)
            }
        }

        test(
            "a truncated encoded blob is rejected by EncryptedAttachmentBlobCodec.decode before ever reaching decrypt",
        ) {
            val encrypted = MailAttachmentCipher.encrypt("secret bytes".toByteArray())
            val encoded = EncryptedAttachmentBlobCodec.encode(encrypted.blob)
            val truncated = encoded.copyOf(encoded.size / 2)

            shouldThrow<MalformedEncryptedAttachmentBlobException> {
                EncryptedAttachmentBlobCodec.decode(truncated)
            }
        }

        test("decrypt rejects a key of the wrong length before touching the cipher") {
            val encrypted = MailAttachmentCipher.encrypt("secret bytes".toByteArray())

            shouldThrow<IllegalArgumentException> {
                MailAttachmentCipher.decrypt(encrypted.blob, ByteArray(31))
            }
        }

        // The design decision under test: an attachment ALWAYS gets its own fresh key, regardless
        // of the enclosing message's own EncryptionMode - see MailAttachmentCipher's class doc
        // comment for the full four-point justification. This proves no HYBRID_ECIES body content
        // key ever leaks into (or is derived for) an attachment's encryption.
        test(
            "encrypting the same attachment plaintext under a HYBRID_ECIES vs a NONE message produces independent keys",
        ) {
            val plaintext = "identical attachment content".toByteArray(Charsets.UTF_8)

            // A real HYBRID_ECIES body seal, whose content key MailAttachmentCipher must never see
            // or reuse.
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient), sentAtEpochSecond = 1)
            val sealed = HybridEcies.seal(body, sender, context)

            val encryptedUnderHybridMessage = MailAttachmentCipher.encrypt(plaintext)
            val encryptedUnderNoneMessage = MailAttachmentCipher.encrypt(plaintext)

            encryptedUnderHybridMessage.key shouldNotBe encryptedUnderNoneMessage.key
            // Neither attachment key equals or is derived from any wrap's raw bytes - proven
            // structurally: MailAttachmentCipher.encrypt never takes a SealedMessage/wrap as input
            // at all, so there is no code path by which sealed.wraps could reach it. This assertion
            // documents that structural fact for a reader who might otherwise wonder.
            sealed.wraps.map { it.wrappedKey } shouldNotContainAny
                listOf(encryptedUnderHybridMessage.key, encryptedUnderNoneMessage.key)
        }
    })

private infix fun List<ByteArray>.shouldNotContainAny(others: List<ByteArray>) {
    forEach { a -> others.forEach { b -> a.contentEquals(b) shouldBe false } }
}
