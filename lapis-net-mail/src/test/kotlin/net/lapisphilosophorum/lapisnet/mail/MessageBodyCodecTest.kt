package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.file.Files

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class MessageBodyCodecTest :
    FunSpec({
        test("round-trips an empty body") {
            val body = MessageBody(subject = "", body = "")

            MessageBodyCodec.decode(MessageBodyCodec.encode(body)) shouldBe body
        }

        test("round-trips a full body with 16 attachments and 16 headers") {
            val attachments =
                (1..16).map {
                    AttachmentRef(
                        cid = testCid(it.toByte()),
                        name = "file-$it.txt",
                        mime = "text/plain",
                        size = it.toLong(),
                    )
                }
            val headers = (1..16).associate { "header-%02d".format(it) to "value-$it" }
            val body =
                MessageBody(subject = "hello", body = "# hi\n\nworld", attachments = attachments, headers = headers)

            MessageBodyCodec.decode(MessageBodyCodec.encode(body)) shouldBe body
        }

        test("headers round-trip sorted regardless of input map order, and encoding is CID-stable") {
            val attachments = emptyList<AttachmentRef>()
            val forward = linkedMapOf("z-key" to "1", "a-key" to "2", "m-key" to "3")
            val reversed = linkedMapOf("m-key" to "3", "a-key" to "2", "z-key" to "1")

            val bodyA = MessageBody(subject = "s", body = "b", attachments = attachments, headers = forward)
            val bodyB = MessageBody(subject = "s", body = "b", attachments = attachments, headers = reversed)

            bodyA.headers.keys.toList() shouldBe listOf("a-key", "m-key", "z-key")
            MessageBodyCodec.encode(bodyA) shouldBe MessageBodyCodec.encode(bodyB)
        }

        test("decode rejects headers in non-increasing key order") {
            val out = buildBodyBytesWithHeaders(listOf("b-key" to "1", "a-key" to "2"))

            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(out) }
        }

        test("decode rejects duplicate header keys") {
            val out = buildBodyBytesWithHeaders(listOf("a-key" to "1", "a-key" to "2"))

            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(out) }
        }

        test("decode rejects bad magic, bad version, non-zero reserved flags, truncation, and trailing bytes") {
            val body = MessageBody(subject = "s", body = "b")
            val bytes = MessageBodyCodec.encode(body)

            val badMagic = bytes.copyOf()
            badMagic[0] = 'X'.code.toByte()
            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(badMagic) }

            val badVersion = bytes.copyOf()
            badVersion[4] = 99
            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(badVersion) }

            // bit0 (0x01) is FLAG_ATTACHMENTS_MAY_HAVE_KEY as of V0.9.3 and is legitimately
            // settable - bit1 (0x02) remains reserved, so it is what this case exercises.
            val badFlags = bytes.copyOf()
            badFlags[5] = 2
            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(badFlags) }

            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(bytes.copyOf(2)) }

            val trailing = bytes + byteArrayOf(1, 2, 3)
            shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(trailing) }
        }

        test("decode rejects each declared length above its cap before allocation") {
            fun header(magic: String) = magic.toByteArray(Charsets.US_ASCII)

            // subjectLen above cap
            run {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write(header("LNMB"))
                    writeByte(1)
                    writeByte(0)
                    writeShort(MessageBodyCodec.MAX_SUBJECT_BYTES + 1)
                }
                val exception =
                    shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(out.toByteArray()) }
                exception.message?.contains("subject") shouldBe true
            }

            // attachmentCount above cap
            run {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write(header("LNMB"))
                    writeByte(1)
                    writeByte(0)
                    writeShort(0)
                    writeShort(0)
                    writeShort(MessageBodyCodec.MAX_ATTACHMENTS + 1)
                }
                val exception =
                    shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(out.toByteArray()) }
                exception.message?.contains("attachments") shouldBe true
            }

            // headerCount above cap
            run {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write(header("LNMB"))
                    writeByte(1)
                    writeByte(0)
                    writeShort(0)
                    writeShort(0)
                    writeShort(0)
                    writeShort(MessageBodyCodec.MAX_HEADERS + 1)
                }
                val exception =
                    shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(out.toByteArray()) }
                exception.message?.contains("headers") shouldBe true
            }
        }

        test("construction rejects oversized subject, body, attachment/header counts, and invalid attachment fields") {
            shouldThrow<IllegalArgumentException> {
                MessageBody(subject = "a".repeat(MessageBodyCodec.MAX_SUBJECT_BYTES + 1), body = "")
            }
            shouldThrow<IllegalArgumentException> {
                MessageBody(subject = "", body = "a".repeat(MessageBodyCodec.MAX_MARKDOWN_BYTES + 1))
            }
            shouldThrow<IllegalArgumentException> {
                val attachments =
                    (1..MessageBodyCodec.MAX_ATTACHMENTS + 1).map {
                        AttachmentRef(testCid(it.toByte()), "n$it", "text/plain", 1)
                    }
                MessageBody(subject = "", body = "", attachments = attachments)
            }
            shouldThrow<IllegalArgumentException> {
                val headers = (1..MessageBodyCodec.MAX_HEADERS + 1).associate { "k$it" to "v" }
                MessageBody(subject = "", body = "", headers = headers)
            }
            shouldThrow<IllegalArgumentException> { AttachmentRef(testCid(1), "n", "text/plain", -1) }
            shouldThrow<IllegalArgumentException> {
                AttachmentRef(testCid(1), "n", "text/plain", MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES + 1)
            }
            shouldThrow<IllegalArgumentException> { AttachmentRef(testCid(1), "", "text/plain", 1) }
            shouldThrow<IllegalArgumentException> { AttachmentRef(testCid(1), "n", "", 1) }
        }

        test("cidFor(bytes) agrees with NabuStorage.put(bytes)") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-cidfor"))
                val body = MessageBody(subject = "s", body = "b")
                val bytes = MessageBodyCodec.encode(body)

                val storedCid = storage.put(bytes)
                val computedCid = MessageBodyCodec.cidFor(bytes)

                computedCid shouldBe storedCid
            } finally {
                node.stop()
            }
        }

        test("markdown body is stored verbatim - not sanitized") {
            val raw = "<script>alert(1)</script> &amp; more"
            val body = MessageBody(subject = "s", body = raw)

            val roundTripped = MessageBodyCodec.decode(MessageBodyCodec.encode(body))

            roundTripped.body shouldBe raw
        }

        // V0.9.3 regression: a body with only UNENCRYPTED attachments must encode byte-identical
        // to what V0.9.1/V0.9.2 would have produced (flags byte literally 0x00) - see
        // MessageBodyCodec's class doc comment for the non-breaking justification this proves.
        test("a body with only unencrypted attachments encodes with flags byte 0x00 - byte-identical to pre-V0.9.3") {
            val attachments =
                (1..3).map { AttachmentRef(testCid(it.toByte()), "file-$it.txt", "text/plain", it.toLong()) }
            val body = MessageBody(subject = "s", body = "b", attachments = attachments)

            val bytes = MessageBodyCodec.encode(body)

            bytes[5] shouldBe 0.toByte() // flags byte: magic(4) + version(1) = offset 5
            MessageBodyCodec.decode(bytes) shouldBe body
        }

        test("round-trips attachments with a mix of encrypted and unencrypted attachment refs") {
            val key = ByteArray(MessageBodyCodec.ATTACHMENT_KEY_SIZE) { it.toByte() }
            val attachments =
                listOf(
                    AttachmentRef(testCid(1), "plain.txt", "text/plain", 10),
                    AttachmentRef(testCid(2), "secret.pdf", "application/pdf", 20, encryptionKey = key),
                )
            val body = MessageBody(subject = "s", body = "b", attachments = attachments)

            val bytes = MessageBodyCodec.encode(body)
            bytes[5] shouldBe 1.toByte() // FLAG_ATTACHMENTS_MAY_HAVE_KEY set

            val decoded = MessageBodyCodec.decode(bytes)
            decoded shouldBe body
            decoded.attachments[0].encryptionKey shouldBe null
            decoded.attachments[1].encryptionKey shouldBe key
        }

        test("AttachmentRef rejects a key of the wrong length") {
            shouldThrow<IllegalArgumentException> {
                AttachmentRef(testCid(1), "n", "text/plain", 1, encryptionKey = ByteArray(31))
            }
        }
    })

private fun buildBodyBytesWithHeaders(headers: List<Pair<String, String>>): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNMB".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0)
        writeShort(0) // subject
        writeShort(0) // body
        writeShort(0) // attachments
        writeShort(headers.size)
        headers.forEach { (key, value) ->
            val keyBytes = key.toByteArray(Charsets.UTF_8)
            writeShort(keyBytes.size)
            write(keyBytes)
            val valueBytes = value.toByteArray(Charsets.UTF_8)
            writeShort(valueBytes.size)
            write(valueBytes)
        }
    }
    return out.toByteArray()
}
