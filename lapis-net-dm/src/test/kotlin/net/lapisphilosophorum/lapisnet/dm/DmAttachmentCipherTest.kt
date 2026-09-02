package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class DmAttachmentCipherTest :
    FunSpec({
        test("roundtrip: encrypt then decrypt returns the original plaintext") {
            val plaintext = "the quick brown fox".toByteArray()
            val encrypted = DmAttachmentCipher.encrypt(plaintext)
            val decrypted = DmAttachmentCipher.decrypt(encrypted.blob, encrypted.key)
            decrypted shouldBe plaintext
        }

        test("two encrypt calls produce different keys and different nonces") {
            val plaintext = "same plaintext".toByteArray()
            val a = DmAttachmentCipher.encrypt(plaintext)
            val b = DmAttachmentCipher.encrypt(plaintext)
            a.key shouldNotBe b.key
            a.blob.nonce shouldNotBe b.blob.nonce
        }

        test("the generated key is exactly 32 bytes") {
            val encrypted = DmAttachmentCipher.encrypt("x".toByteArray())
            encrypted.key.size shouldBe 32
        }

        test("plaintext above MAX_PLAINTEXT_BYTES is rejected") {
            shouldThrow<IllegalArgumentException> {
                DmAttachmentCipher.encrypt(ByteArray(EncryptedDmAttachmentBlobCodec.MAX_PLAINTEXT_BYTES + 1))
            }
        }

        test("an empty plaintext is rejected") {
            shouldThrow<IllegalArgumentException> { DmAttachmentCipher.encrypt(ByteArray(0)) }
        }
    })
