package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.security.SecureRandom

class EncryptedDmAttachmentBlobCodecTest :
    FunSpec({
        test("roundtrip") {
            val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
            val ciphertext = ByteArray(100).also(SecureRandom()::nextBytes)
            val blob = EncryptedDmAttachmentBlob(nonce, ciphertext)
            val decoded = EncryptedDmAttachmentBlobCodec.decode(EncryptedDmAttachmentBlobCodec.encode(blob))
            decoded shouldBe blob
        }

        test("decode rejects bad magic") {
            val bytes = EncryptedDmAttachmentBlobCodec.encode(EncryptedDmAttachmentBlob(ByteArray(12), ByteArray(20)))
            bytes[0] = 'X'.code.toByte()
            shouldThrow<MalformedEncryptedDmAttachmentBlobException> { EncryptedDmAttachmentBlobCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val bytes = EncryptedDmAttachmentBlobCodec.encode(EncryptedDmAttachmentBlob(ByteArray(12), ByteArray(20)))
            bytes[4] = 2
            shouldThrow<MalformedEncryptedDmAttachmentBlobException> { EncryptedDmAttachmentBlobCodec.decode(bytes) }
        }

        test("decode rejects non-zero flags") {
            val bytes = EncryptedDmAttachmentBlobCodec.encode(EncryptedDmAttachmentBlob(ByteArray(12), ByteArray(20)))
            bytes[5] = 1
            shouldThrow<MalformedEncryptedDmAttachmentBlobException> { EncryptedDmAttachmentBlobCodec.decode(bytes) }
        }

        test("decode rejects trailing bytes") {
            val bytes = EncryptedDmAttachmentBlobCodec.encode(EncryptedDmAttachmentBlob(ByteArray(12), ByteArray(20)))
            shouldThrow<MalformedEncryptedDmAttachmentBlobException> {
                EncryptedDmAttachmentBlobCodec.decode(bytes + byteArrayOf(0))
            }
        }

        test("blob construction rejects a ciphertext length outside 17..MAX") {
            shouldThrow<IllegalArgumentException> { EncryptedDmAttachmentBlob(ByteArray(12), ByteArray(16)) }
            shouldThrow<IllegalArgumentException> {
                EncryptedDmAttachmentBlob(
                    ByteArray(12),
                    ByteArray(
                        EncryptedDmAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES + 1,
                    ),
                )
            }
        }

        test("decode rejects an oversized declared ciphertext length with no matching bytes") {
            val out = java.io.ByteArrayOutputStream()
            java.io.DataOutputStream(out).apply {
                write("LNDA".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(ByteArray(12))
                writeInt(Int.MAX_VALUE / 2) // declared, but no bytes follow
            }
            shouldThrow<MalformedEncryptedDmAttachmentBlobException> {
                EncryptedDmAttachmentBlobCodec.decode(out.toByteArray())
            }
        }
    })
