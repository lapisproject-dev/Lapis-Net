package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Mirrors `lapis-net-mail`'s own `"LapisNet:mail-attachment:v1"` AAD constant, reproduced here
 * with pure JCE - deliberately NOT via a `testImplementation(project(":lapis-net-mail"))` dependency
 * (see [DmAttachmentCipher]'s class doc comment for why `lapis-net-dm` carries no edge onto its
 * sibling module at all, even in tests: the point of this test is to prove domain separation
 * WITHOUT needing that edge). */
private val MAIL_ATTACHMENT_AAD = "LapisNet:mail-attachment:v1".toByteArray(Charsets.US_ASCII)

private fun aesGcmEncrypt(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    plaintext: ByteArray,
): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(plaintext)
}

class DmAttachmentCipherAdversarialTest :
    FunSpec({
        test("decrypt with the wrong key fails") {
            val encrypted = DmAttachmentCipher.encrypt("secret payload".toByteArray())
            val wrongKey = ByteArray(32).also(SecureRandom()::nextBytes)
            shouldThrow<DmAttachmentDecryptionException> { DmAttachmentCipher.decrypt(encrypted.blob, wrongKey) }
        }

        test("a flipped ciphertext bit fails to decrypt") {
            val encrypted = DmAttachmentCipher.encrypt("secret payload".toByteArray())
            val tamperedCiphertext = encrypted.blob.ciphertext
            tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0x01).toByte()
            val tamperedBlob = EncryptedDmAttachmentBlob(encrypted.blob.nonce, tamperedCiphertext)
            shouldThrow<DmAttachmentDecryptionException> { DmAttachmentCipher.decrypt(tamperedBlob, encrypted.key) }
        }

        test("a tampered GCM tag (last byte) fails to decrypt") {
            val encrypted = DmAttachmentCipher.encrypt("secret payload".toByteArray())
            val tamperedCiphertext = encrypted.blob.ciphertext
            val lastIndex = tamperedCiphertext.size - 1
            tamperedCiphertext[lastIndex] = (tamperedCiphertext[lastIndex].toInt() xor 0x01).toByte()
            val tamperedBlob = EncryptedDmAttachmentBlob(encrypted.blob.nonce, tamperedCiphertext)
            shouldThrow<DmAttachmentDecryptionException> { DmAttachmentCipher.decrypt(tamperedBlob, encrypted.key) }
        }

        test("a tampered nonce fails to decrypt") {
            val encrypted = DmAttachmentCipher.encrypt("secret payload".toByteArray())
            val tamperedNonce = encrypted.blob.nonce
            tamperedNonce[0] = (tamperedNonce[0].toInt() xor 0x01).toByte()
            val tamperedBlob = EncryptedDmAttachmentBlob(tamperedNonce, encrypted.blob.ciphertext)
            shouldThrow<DmAttachmentDecryptionException> { DmAttachmentCipher.decrypt(tamperedBlob, encrypted.key) }
        }

        test("an all-zero RNG source is rejected (broken-RNG guard)") {
            val zeroRandom =
                object : SecureRandom() {
                    override fun nextBytes(bytes: ByteArray) {
                        bytes.fill(0)
                    }
                }
            shouldThrow<IllegalArgumentException> {
                DmAttachmentCipher.encrypt("payload".toByteArray(), random = zeroRandom)
            }
        }

        test("cross-domain: a blob authenticated under mail's AAD does not decrypt under DM's AAD") {
            val key = ByteArray(32).also(SecureRandom()::nextBytes)
            val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
            val plaintext = "shared plaintext".toByteArray()
            val mailCiphertext = aesGcmEncrypt(key, nonce, MAIL_ATTACHMENT_AAD, plaintext)
            val mailDomainBlob = EncryptedDmAttachmentBlob(nonce, mailCiphertext)

            shouldThrow<DmAttachmentDecryptionException> { DmAttachmentCipher.decrypt(mailDomainBlob, key) }
        }
    })
