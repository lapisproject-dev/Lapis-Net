package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.SecureRandom

private fun freshSealedBody(ciphertextSize: Int = 64): SealedBody {
    val nonce = ByteArray(GCM_NONCE_SIZE).also(SecureRandom()::nextBytes)
    val ciphertext = ByteArray(ciphertextSize).also(SecureRandom()::nextBytes)
    return SealedBody(nonce, ciphertext)
}

class SealedBodyCodecTest :
    FunSpec({
        test("decode(encode(sealed)) round-trips") {
            val sealed = freshSealedBody()

            SealedBodyCodec.decode(SealedBodyCodec.encode(sealed)) shouldBe sealed
        }

        test("decode rejects bad magic") {
            val bytes = SealedBodyCodec.encode(freshSealedBody())
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val bytes = SealedBodyCodec.encode(freshSealedBody())
            bytes[4] = 99

            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(bytes) }
        }

        test("decode rejects non-zero reserved flag bits") {
            val bytes = SealedBodyCodec.encode(freshSealedBody())
            bytes[5] = 1

            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val bytes = SealedBodyCodec.encode(freshSealedBody())

            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(bytes.copyOf(bytes.size / 2)) }
        }

        test("decode rejects trailing bytes") {
            val bytes = SealedBodyCodec.encode(freshSealedBody())

            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(bytes + byteArrayOf(1, 2, 3)) }
        }

        test("decode rejects ciphertextLen at and below the GCM tag size") {
            // Hand-built: magic(4) + version(1) + flags(1) + nonce(12) + ciphertextLen(2), no
            // ciphertext body - exercises the length check firing before any body bytes are read.
            fun buildWithCiphertextLen(len: Int): ByteArray {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write("LNSB".toByteArray(Charsets.US_ASCII))
                    writeByte(1)
                    writeByte(0)
                    write(ByteArray(GCM_NONCE_SIZE))
                    writeShort(len)
                }
                return out.toByteArray()
            }

            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(buildWithCiphertextLen(0)) }
            shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(buildWithCiphertextLen(GCM_TAG_SIZE)) }
        }

        test("decode rejects an oversized declared ciphertextLen before allocating - not a truncation error") {
            // Declares 0xFFFF bytes of ciphertext on a 25-byte buffer that has none of it -
            // MAX_CIPHERTEXT_BYTES (65,515) bounds it, but even the max is checked BEFORE the read.
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNSB".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(ByteArray(GCM_NONCE_SIZE))
                writeShort(0xFFFF)
            }

            val exception = shouldThrow<MalformedSealedBodyException> { SealedBodyCodec.decode(out.toByteArray()) }
            exception.message?.contains("invalid ciphertext length") shouldBe true
            exception.message?.contains("truncated") shouldBe false
        }

        test("the maximum ciphertext length (MAX_CIPHERTEXT_BYTES) round-trips") {
            val sealed = freshSealedBody(ciphertextSize = SealedBodyCodec.MAX_CIPHERTEXT_BYTES)

            SealedBodyCodec.decode(SealedBodyCodec.encode(sealed)) shouldBe sealed
        }

        test("SealedBody constructor rejects a ciphertext one byte above MAX_CIPHERTEXT_BYTES") {
            shouldThrow<IllegalArgumentException> {
                freshSealedBody(ciphertextSize = SealedBodyCodec.MAX_CIPHERTEXT_BYTES + 1)
            }
        }

        test("SealedBody constructor rejects a wrong-size nonce") {
            shouldThrow<IllegalArgumentException> { SealedBody(ByteArray(11), ByteArray(GCM_TAG_SIZE + 1)) }
            shouldThrow<IllegalArgumentException> { SealedBody(ByteArray(13), ByteArray(GCM_TAG_SIZE + 1)) }
        }

        test("nonce and ciphertext accessors return fresh, independent copies") {
            val sealed = freshSealedBody()

            val nonce = sealed.nonce
            nonce.fill(0)
            val ciphertext = sealed.ciphertext
            ciphertext.fill(0)

            sealed.nonce shouldNotBe ByteArray(GCM_NONCE_SIZE)
            sealed.ciphertext shouldNotBe ByteArray(64)
        }

        test("toString does not contain nonce or ciphertext content") {
            val sealed = freshSealedBody()

            val text = sealed.toString()

            val nonceHex = sealed.nonce.joinToString("") { "%02x".format(it) }
            text.contains(nonceHex) shouldBe false
        }
    })
