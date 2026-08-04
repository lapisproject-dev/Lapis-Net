package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class MailFrameCodecTest :
    FunSpec({
        test("decode(encode(envelopeBytes, bodyBytes)) round-trips an arbitrary pair") {
            val envelopeBytes = byteArrayOf(1, 2, 3, 4, 5)
            val bodyBytes = byteArrayOf(9, 8, 7)

            val frame = MailFrameCodec.decode(MailFrameCodec.encode(envelopeBytes, bodyBytes))

            frame.envelopeBytes shouldBe envelopeBytes
            frame.bodyBytes shouldBe bodyBytes
        }

        test("decode(encode(...)) round-trips an empty body section") {
            val envelopeBytes = byteArrayOf(1, 2, 3)
            val bodyBytes = ByteArray(0)

            val frame = MailFrameCodec.decode(MailFrameCodec.encode(envelopeBytes, bodyBytes))

            frame.envelopeBytes shouldBe envelopeBytes
            frame.bodyBytes shouldBe bodyBytes
        }

        test("decode rejects bad magic") {
            val bytes = MailFrameCodec.encode(byteArrayOf(1), byteArrayOf(2))
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val bytes = MailFrameCodec.encode(byteArrayOf(1), byteArrayOf(2))
            bytes[4] = 99

            shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(bytes) }
        }

        test("decode rejects non-zero reserved flag bits") {
            val bytes = MailFrameCodec.encode(byteArrayOf(1), byteArrayOf(2))
            bytes[5] = 1

            shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val bytes = MailFrameCodec.encode(byteArrayOf(1, 2, 3, 4, 5), byteArrayOf(6, 7, 8, 9, 10))

            shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(bytes.copyOf(bytes.size / 2)) }
        }

        test("decode rejects trailing bytes") {
            val bytes = MailFrameCodec.encode(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6)) + byteArrayOf(9, 9, 9)

            shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(bytes) }
        }

        test("encode rejects an empty envelope section and an oversized one") {
            shouldThrow<IllegalArgumentException> { MailFrameCodec.encode(ByteArray(0), ByteArray(0)) }
            shouldThrow<IllegalArgumentException> {
                MailFrameCodec.encode(ByteArray(MailFrameCodec.MAX_ENVELOPE_SECTION_BYTES + 1), ByteArray(0))
            }
        }

        test("encode rejects an oversized body section") {
            shouldThrow<IllegalArgumentException> {
                MailFrameCodec.encode(byteArrayOf(1), ByteArray(MessageBodyCodec.MAX_BODY_BLOB_SIZE + 1))
            }
        }

        test("decode rejects envelopeLen == 0 declared before allocation") {
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNMF".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                writeShort(0)
            }

            shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(out.toByteArray()) }
        }

        test("decode rejects a declared bodyLen the buffer cannot actually satisfy") {
            // MAX_ENVELOPE_SECTION_BYTES and MessageBodyCodec.MAX_BODY_BLOB_SIZE are both 0xFFFF -
            // the maximum an unsigned 16-bit length field can express at all - so there is no
            // "declared above the cap" case distinct from "declared above what the buffer actually
            // holds" for this codec's two length fields (unlike MessageEnvelopeCodec's
            // recipientCount, which is capped well below its field's numeric range). What IS still
            // testable, and matters just as much: a bodyLen that is well-formed by the cap but
            // truncated by the actual buffer must fail cleanly with EOFException -> "truncated",
            // never over-read past the buffer.
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNMF".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                writeShort(1)
                write(1)
                writeShort(500) // declares 500 body bytes, but none follow
            }

            val exception = shouldThrow<MalformedMailFrameException> { MailFrameCodec.decode(out.toByteArray()) }
            exception.message?.contains("truncated") shouldBe true
        }
    })
