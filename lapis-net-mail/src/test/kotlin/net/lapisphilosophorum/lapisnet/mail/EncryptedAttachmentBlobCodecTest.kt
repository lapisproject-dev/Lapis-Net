package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.SecureRandom

private fun freshBlob(ciphertextSize: Int = 64): EncryptedAttachmentBlob {
    val nonce = ByteArray(GCM_NONCE_SIZE).also(SecureRandom()::nextBytes)
    val ciphertext = ByteArray(ciphertextSize).also(SecureRandom()::nextBytes)
    return EncryptedAttachmentBlob(nonce, ciphertext)
}

class EncryptedAttachmentBlobCodecTest :
    FunSpec({
        test("decode(encode(blob)) round-trips") {
            val blob = freshBlob()

            EncryptedAttachmentBlobCodec.decode(EncryptedAttachmentBlobCodec.encode(blob)) shouldBe blob
        }

        test("decode rejects bad magic") {
            val bytes = EncryptedAttachmentBlobCodec.encode(freshBlob())
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedEncryptedAttachmentBlobException> { EncryptedAttachmentBlobCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val bytes = EncryptedAttachmentBlobCodec.encode(freshBlob())
            bytes[4] = 99

            shouldThrow<MalformedEncryptedAttachmentBlobException> { EncryptedAttachmentBlobCodec.decode(bytes) }
        }

        test("decode rejects non-zero reserved flag bits") {
            val bytes = EncryptedAttachmentBlobCodec.encode(freshBlob())
            bytes[5] = 1

            shouldThrow<MalformedEncryptedAttachmentBlobException> { EncryptedAttachmentBlobCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val bytes = EncryptedAttachmentBlobCodec.encode(freshBlob())

            shouldThrow<MalformedEncryptedAttachmentBlobException> {
                EncryptedAttachmentBlobCodec.decode(bytes.copyOf(bytes.size / 2))
            }
        }

        test("decode rejects trailing bytes") {
            val bytes = EncryptedAttachmentBlobCodec.encode(freshBlob())

            shouldThrow<MalformedEncryptedAttachmentBlobException> {
                EncryptedAttachmentBlobCodec.decode(bytes + byteArrayOf(1, 2, 3))
            }
        }

        test("decode rejects ciphertextLen at and below the GCM tag size") {
            fun buildWithCiphertextLen(len: Int): ByteArray {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write("LNEA".toByteArray(Charsets.US_ASCII))
                    writeByte(1)
                    writeByte(0)
                    write(ByteArray(GCM_NONCE_SIZE))
                    writeInt(len)
                }
                return out.toByteArray()
            }

            shouldThrow<MalformedEncryptedAttachmentBlobException> {
                EncryptedAttachmentBlobCodec.decode(buildWithCiphertextLen(0))
            }
            shouldThrow<MalformedEncryptedAttachmentBlobException> {
                EncryptedAttachmentBlobCodec.decode(buildWithCiphertextLen(GCM_TAG_SIZE))
            }
        }

        test("decode rejects an oversized declared ciphertextLen before allocating - not a truncation error") {
            // Declares far more bytes than the buffer actually has - MAX_CIPHERTEXT_BYTES is
            // checked BEFORE the read, so this must fail with the length-check message, never by
            // attempting (and failing) to allocate/read a huge buffer.
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNEA".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(ByteArray(GCM_NONCE_SIZE))
                writeInt(EncryptedAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES + 1)
            }

            val exception =
                shouldThrow<MalformedEncryptedAttachmentBlobException> {
                    EncryptedAttachmentBlobCodec.decode(out.toByteArray())
                }
            exception.message?.contains("invalid ciphertext length") shouldBe true
            exception.message?.contains("truncated") shouldBe false
        }

        test("decode rejects a negative declared ciphertextLen") {
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNEA".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(ByteArray(GCM_NONCE_SIZE))
                writeInt(-1)
            }

            shouldThrow<MalformedEncryptedAttachmentBlobException> {
                EncryptedAttachmentBlobCodec.decode(out.toByteArray())
            }
        }

        test("EncryptedAttachmentBlob constructor rejects a ciphertext at/below the GCM tag size") {
            shouldThrow<IllegalArgumentException> {
                EncryptedAttachmentBlob(ByteArray(GCM_NONCE_SIZE), ByteArray(GCM_TAG_SIZE))
            }
        }

        test("EncryptedAttachmentBlob constructor rejects a wrong-size nonce") {
            shouldThrow<IllegalArgumentException> {
                EncryptedAttachmentBlob(
                    ByteArray(11),
                    ByteArray(GCM_TAG_SIZE + 1),
                )
            }
            shouldThrow<IllegalArgumentException> {
                EncryptedAttachmentBlob(
                    ByteArray(13),
                    ByteArray(GCM_TAG_SIZE + 1),
                )
            }
        }

        test("nonce and ciphertext accessors return fresh, independent copies") {
            val blob = freshBlob()

            val nonce = blob.nonce
            nonce.fill(0)
            val ciphertext = blob.ciphertext
            ciphertext.fill(0)

            blob.nonce shouldNotBe ByteArray(GCM_NONCE_SIZE)
            blob.ciphertext shouldNotBe ByteArray(64)
        }

        test("toString does not contain nonce or ciphertext content") {
            val blob = freshBlob()

            val text = blob.toString()

            val nonceHex = blob.nonce.joinToString("") { "%02x".format(it) }
            text.contains(nonceHex) shouldBe false
        }

        test("a larger-than-16-bit ciphertext (would overflow SealedBodyCodec's 16-bit field) round-trips") {
            // Proves the 32-bit length field is real, not vestigial - 70,000 bytes exceeds
            // SealedBodyCodec.MAX_CIPHERTEXT_BYTES (65,515) and 0xFFFF outright.
            val blob = freshBlob(ciphertextSize = 70_000)

            EncryptedAttachmentBlobCodec.decode(EncryptedAttachmentBlobCodec.encode(blob)) shouldBe blob
        }
    })
