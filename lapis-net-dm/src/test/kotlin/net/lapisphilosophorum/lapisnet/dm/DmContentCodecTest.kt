package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.SecureRandom

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testAttachment(
    seed: Byte,
    size: Long = 100L,
): DmAttachmentRef =
    DmAttachmentRef(
        cid = testCid(seed),
        name = "file-$seed.bin",
        mime = "application/octet-stream",
        size = size,
        encryptionKey = ByteArray(32) { seed },
    )

private fun testDeposit(): DmFirstContactDeposit {
    val random = SecureRandom()
    val preimage = ByteArray(32).also(random::nextBytes)
    val paymentHash =
        java.security.MessageDigest
            .getInstance("SHA-256")
            .digest(preimage)
    return DmFirstContactDeposit(
        preimage = preimage,
        paymentHash = paymentHash,
        signedInvoice = "lnbc1testinvoice",
        requiredAmountMsat = 1_000_000L,
    )
}

private fun writeVarint(
    out: ByteArrayOutputStream,
    value: Long,
) {
    var x = value
    while (x < 0 || x >= 0x80) {
        out.write(((x and 0x7f) or 0x80).toInt())
        x = x ushr 7
    }
    out.write(x.toInt())
}

private fun maliciousCidBytes(declaredMultihashLength: Long): ByteArray {
    val sha2256TypeIndex = Multihash.Type.sha2_256.index
    val out = ByteArrayOutputStream()
    writeVarint(out, 1)
    writeVarint(out, Cid.Codec.Raw.type)
    writeVarint(out, sha2256TypeIndex.toLong())
    writeVarint(out, declaredMultihashLength)
    return out.toByteArray()
}

class DmContentCodecTest :
    FunSpec({
        test("roundtrip: text only") {
            val content = DmContent(body = "hello")
            val decoded = DmContentCodec.decode(DmContentCodec.encode(content))
            decoded.body shouldBe "hello"
            decoded.attachments shouldBe emptyList()
            decoded.firstContactDeposit shouldBe null
            decoded.kind shouldBe DmContentKind.TEXT
        }

        test("roundtrip: one attachment") {
            val content = DmContent(body = "see attached", attachments = listOf(testAttachment(1)))
            val decoded = DmContentCodec.decode(DmContentCodec.encode(content))
            decoded.attachments.size shouldBe 1
            decoded.attachments[0].cid shouldBe testCid(1)
            decoded.attachments[0].name shouldBe "file-1.bin"
            decoded.attachments[0].encryptionKey shouldBe ByteArray(32) { 1 }
            decoded.kind shouldBe DmContentKind.TEXT_WITH_ATTACHMENTS
        }

        test("roundtrip: four attachments (the max)") {
            val attachments = (1..4).map { testAttachment(it.toByte()) }
            val content = DmContent(body = "four files", attachments = attachments)
            val decoded = DmContentCodec.decode(DmContentCodec.encode(content))
            decoded.attachments.size shouldBe 4
        }

        test("roundtrip: with first-contact deposit section") {
            val deposit = testDeposit()
            val content = DmContent(body = "hi", firstContactDeposit = deposit)
            val decoded = DmContentCodec.decode(DmContentCodec.encode(content))
            decoded.firstContactDeposit shouldBe deposit
        }

        test("roundtrip: attachments AND deposit together") {
            val deposit = testDeposit()
            val content = DmContent(body = "hi", attachments = listOf(testAttachment(9)), firstContactDeposit = deposit)
            val decoded = DmContentCodec.decode(DmContentCodec.encode(content))
            decoded.attachments.size shouldBe 1
            decoded.firstContactDeposit shouldBe deposit
        }

        test("body over MAX_DM_BODY_BYTES is rejected at construction") {
            shouldThrow<IllegalArgumentException> {
                DmContent(body = "x".repeat(DmContentCodec.MAX_DM_BODY_BYTES + 1))
            }
        }

        test("a fifth attachment is rejected at construction") {
            shouldThrow<IllegalArgumentException> {
                DmContent(body = "x", attachments = (1..5).map { testAttachment(it.toByte()) })
            }
        }

        test("total attachment size over the cap is rejected at construction") {
            shouldThrow<IllegalArgumentException> {
                DmContent(
                    body = "x",
                    attachments =
                        listOf(
                            testAttachment(1, size = DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES),
                            testAttachment(2, size = 1L),
                        ),
                )
            }
        }

        test("duplicate CIDs within one DmContent are rejected at construction") {
            shouldThrow<IllegalArgumentException> {
                DmContent(
                    body = "x",
                    attachments =
                        listOf(
                            DmAttachmentRef(testCid(1), "a", "text/plain", 10, ByteArray(32) { 1 }),
                            DmAttachmentRef(testCid(1), "b", "text/plain", 10, ByteArray(32) { 2 }),
                        ),
                )
            }
        }

        test("decode rejects an unsupported version") {
            val bytes = DmContentCodec.encode(DmContent(body = "hi"))
            bytes[4] = 0x02 // version byte
            shouldThrow<MalformedDmContentException> { DmContentCodec.decode(bytes) }
        }

        test("decode rejects an unknown kind value") {
            val bytes = DmContentCodec.encode(DmContent(body = "hi")).copyOf()
            bytes[5] = 0x7F // kind byte - not 0 or 1
            shouldThrow<MalformedDmContentException> { DmContentCodec.decode(bytes) }
        }

        test("decode rejects set reserved flag bits") {
            val bytes = DmContentCodec.encode(DmContent(body = "hi")).copyOf()
            bytes[6] = 0x02 // flags byte - bit1 is reserved, not FLAG_FIRST_CONTACT_DEPOSIT
            shouldThrow<MalformedDmContentException> { DmContentCodec.decode(bytes) }
        }

        test("decode rejects an attachmentCount of 5") {
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNDC".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(1) // kind = TEXT_WITH_ATTACHMENTS
                writeByte(0)
                writeShort(0) // empty body
                writeShort(5) // attachmentCount - over the cap
            }
            shouldThrow<MalformedDmContentException> { DmContentCodec.decode(out.toByteArray()) }
        }

        test("decode rejects trailing bytes") {
            val bytes = DmContentCodec.encode(DmContent(body = "hi"))
            val withTrailing = bytes + byteArrayOf(0)
            shouldThrow<MalformedDmContentException> { DmContentCodec.decode(withTrailing) }
        }

        test("decode rejects a malicious CID declaring an oversized multihash length") {
            val out = ByteArrayOutputStream()
            val maliciousCid = maliciousCidBytes(0x7FFFFFFFL)
            DataOutputStream(out).apply {
                write("LNDC".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(1) // kind = TEXT_WITH_ATTACHMENTS
                writeByte(0)
                writeShort(0) // empty body
                writeShort(1) // attachmentCount
                writeShort(maliciousCid.size)
                write(maliciousCid)
            }
            // Never reaches Cid.cast() - CidBytesValidation.isSafeToCast rejects it first.
            CidBytesValidation.isSafeToCast(maliciousCid) shouldBe false
            shouldThrow<MalformedDmContentException> { DmContentCodec.decode(out.toByteArray()) }
        }

        test("maximal legal content encodes within RatchetMessageCodec.MAX_PLAINTEXT_BYTES") {
            val content =
                DmContent(
                    body = "x".repeat(DmContentCodec.MAX_DM_BODY_BYTES),
                    attachments =
                        (1..4).map {
                            DmAttachmentRef(
                                cid = testCid(it.toByte()),
                                name = "n".repeat(DmContentCodec.MAX_ATTACHMENT_NAME_BYTES),
                                mime = "m".repeat(DmContentCodec.MAX_ATTACHMENT_MIME_BYTES),
                                size = DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES / 4,
                                encryptionKey = ByteArray(32) { it.toByte() },
                            )
                        },
                    firstContactDeposit =
                        DmFirstContactDeposit(
                            preimage = ByteArray(32),
                            paymentHash = ByteArray(32),
                            signedInvoice = "l".repeat(DmContentCodec.MAX_SIGNED_INVOICE_BYTES),
                            requiredAmountMsat = 1_000_000L,
                        ),
                )
            val encoded = DmContentCodec.encode(content)
            encoded.size.toLong() shouldBeLessThanOrEqual RatchetMessageCodec.MAX_PLAINTEXT_BYTES.toLong()
        }
    })
