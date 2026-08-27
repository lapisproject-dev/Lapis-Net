package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun samplePointer(
    sender: Secp256k1KeyPair = DualKeyIdentity.generate().secp256k1KeyPair,
    recipient: Secp256k1KeyPair = DualKeyIdentity.generate().secp256k1KeyPair,
    blobCid: Cid = testCid(1),
    notValidAfterEpochSecond: Long = 1_000_000L,
): MailboxPointer =
    MailboxPointer.create(
        sender = sender,
        recipientIdentity = recipient.publicKey,
        blobCid = blobCid,
        notValidAfterEpochSecond = notValidAfterEpochSecond,
        nowEpochSecond = 0,
    )

/** Writes an unsigned LEB128 varint exactly as `io.ipfs.multihash.Multihash.putUvarint`/
 * `readVarint` define it - mirrors `MailCidLengthOverflowDosTest`'s identical helper. */
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

/** Hand-builds a candidate CID declaring [declaredMultihashLength] but supplying no actual hash
 * bytes after it - mirrors `MailCidLengthOverflowDosTest.maliciousCidBytes` exactly. */
private fun maliciousCidBytes(declaredMultihashLength: Long): ByteArray {
    val sha2256TypeIndex = Multihash.Type.sha2_256.index
    val out = ByteArrayOutputStream()
    writeVarint(out, 1) // CID version 1
    writeVarint(out, Cid.Codec.Raw.type) // codec
    writeVarint(out, sha2256TypeIndex.toLong()) // multihash type
    writeVarint(out, declaredMultihashLength) // multihash length - the attack payload
    return out.toByteArray()
}

class MailboxPointerCodecTest :
    FunSpec({
        test("round-trips through encode/decode") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val pointer = samplePointer(sender, recipient, testCid(7), 42_000L)

            val decoded = MailboxPointerCodec.decode(MailboxPointerCodec.encode(pointer))

            decoded.recipientIdentity shouldBe pointer.recipientIdentity
            decoded.senderIdentity shouldBe pointer.senderIdentity
            decoded.blobCid shouldBe pointer.blobCid
            decoded.notValidAfterEpochSecond shouldBe pointer.notValidAfterEpochSecond
            decoded.signature shouldBe pointer.signature
            MailboxPointer.verify(decoded) shouldBe true
        }

        test("contentId is deterministic for identical bytes") {
            val pointer = samplePointer()
            val a = MailboxPointerCodec.decode(MailboxPointerCodec.encode(pointer))
            val b = MailboxPointerCodec.decode(MailboxPointerCodec.encode(pointer))
            a.contentId() shouldBe b.contentId()
        }

        test("decode rejects bad magic") {
            val bytes = MailboxPointerCodec.encode(samplePointer())
            bytes[0] = 'X'.code.toByte()
            shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val bytes = MailboxPointerCodec.encode(samplePointer())
            bytes[4] = 99
            shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes) }
        }

        test("decode rejects a non-zero reserved flag byte") {
            val bytes = MailboxPointerCodec.encode(samplePointer())
            bytes[5] = 1
            shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes) }
        }

        test("decode rejects truncation at every field boundary") {
            val bytes = MailboxPointerCodec.encode(samplePointer())
            // Every prefix strictly shorter than the full encoding must be rejected - including
            // prefixes landing exactly at a field boundary (e.g. right after recipientIdentity,
            // right after senderIdentity, right after blobCidLen, right after blobCid bytes, right
            // after notValidAfterEpochSecond).
            for (cut in 1 until bytes.size) {
                shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes.copyOf(cut)) }
            }
        }

        test("decode rejects trailing bytes after a structurally complete pointer") {
            val bytes = MailboxPointerCodec.encode(samplePointer()) + byteArrayOf(0)
            shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes) }
        }

        test("decode rejects an oversized declared blobCidLen BEFORE allocation, not as a truncation error") {
            // Built from a REAL, full-size encoded pointer (>= MIN_POINTER_BYTES) with ONLY the
            // 2-byte blobCidLen field (offset MAILBOX_POINTER_FIXED_PREFIX_SIZE - 2) corrupted in
            // place - mirrors DmEnvelopeCodecTest's identical "corrupt the length field in place on
            // a real buffer" technique for ratchetMessageLength. Deliberately NOT a short, hand-built
            // 74-byte prefix-only buffer (this test's original construction, via the now-removed
            // pointerBytesDeclaringBlobCidLen helper): that shape is shorter than
            // MailboxPointerCodec.MIN_POINTER_BYTES (147) and would trip decode()'s own too-short
            // gate FIRST, never reaching blobCidLen's OWN range check at all - exactly the kind of
            // "test doesn't reach the code path it claims to guard" gap this rewrite avoids. Declares
            // far more than MailboxPointerCodec.MAX_CID_BYTES (128) and far more than the actual
            // remaining bytes in the buffer - if decode() ever allocated/consumed on the attacker's
            // declared length first this would surface as "truncated" instead of the length-range
            // rejection this test asserts.
            val bytes = MailboxPointerCodec.encode(samplePointer())
            val blobCidLenOffset = MailboxPointerCodec.MAILBOX_POINTER_FIXED_PREFIX_SIZE - 2
            bytes[blobCidLenOffset] = 0xFF.toByte()
            bytes[blobCidLenOffset + 1] = 0xFF.toByte() // 0xFFFF = 65_535

            val exception = shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes) }
            (exception.message ?: "").contains("invalid blobCid length") shouldBe true
        }

        test("decode rejects a declared blobCidLen of zero") {
            // Same "corrupt in place on a real, full-size buffer" technique as the oversized case
            // above, for the identical reason - a short hand-built buffer would trip the too-short
            // gate first and never actually exercise blobCidLen's own `!in 1..MAX_CID_BYTES` check.
            val bytes = MailboxPointerCodec.encode(samplePointer())
            val blobCidLenOffset = MailboxPointerCodec.MAILBOX_POINTER_FIXED_PREFIX_SIZE - 2
            bytes[blobCidLenOffset] = 0
            bytes[blobCidLenOffset + 1] = 0
            val exception = shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(bytes) }
            (exception.message ?: "").contains("invalid blobCid length") shouldBe true
        }

        test("encode rejects a blobCid whose encoded bytes exceed MAX_CID_BYTES") {
            // MailboxPointer.create/MailboxPointerCodec.encodeSignedBody both funnel through the
            // same require() - a genuine sha2-256 CIDv1 is nowhere near this cap (well under 40
            // bytes), so this only proves the guard exists, not that it is reachable via a real CID.
            // An identity-multihash CID (raw bytes copied verbatim, no fixed digest-length
            // constraint) is the simplest way to construct an oversized-but-otherwise-valid Cid.
            shouldThrow<IllegalArgumentException> {
                MailboxPointerCodec.encodeSignedBody(
                    recipientIdentity = DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                    senderIdentity = DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                    blobCid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.id, ByteArray(200)),
                    notValidAfterEpochSecond = 1L,
                )
            }
        }

        listOf(0x7FFFFFFFL, 1_073_741_824L).forEach { declaredLength ->
            test(
                "decode rejects a blobCid declaring an unsafe multihash length ($declaredLength) BEFORE Cid.cast " +
                    "ever allocates - mirrors MailCidLengthOverflowDosTest's technique",
            ) {
                val sender = DualKeyIdentity.generate().secp256k1KeyPair
                val recipient = DualKeyIdentity.generate().secp256k1KeyPair
                val maliciousCid = maliciousCidBytes(declaredLength)
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write("LNMP".toByteArray(Charsets.US_ASCII))
                    writeByte(1)
                    writeByte(0)
                    write(recipient.publicKey.bytes)
                    write(sender.publicKey.bytes)
                    writeShort(maliciousCid.size)
                    write(maliciousCid)
                    writeLong(1_000_000L)
                    write(ByteArray(64)) // placeholder signature - decode() must throw before checking it
                }

                val exception =
                    shouldThrow<MalformedMailboxPointerException> { MailboxPointerCodec.decode(out.toByteArray()) }
                (exception.message ?: "").contains("unsafe multihash length") shouldBe true
            }
        }

        test("verify returns false for a tampered notValidAfterEpochSecond") {
            val pointer = samplePointer()
            val bytes = MailboxPointerCodec.encode(pointer)
            // notValidAfterEpochSecond sits at MAILBOX_POINTER_FIXED_PREFIX_SIZE + blobCidBytes.size,
            // flip its last byte.
            val blobCidLen = pointer.blobCid.toBytes().size
            val notValidAfterOffset = MailboxPointerCodec.MAILBOX_POINTER_FIXED_PREFIX_SIZE + blobCidLen + 7
            bytes[notValidAfterOffset] = (bytes[notValidAfterOffset] + 1).toByte()
            val tampered = MailboxPointerCodec.decode(bytes)
            MailboxPointer.verify(tampered) shouldBe false
        }

        test("verify returns false for a signature by a different key") {
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val genuine = samplePointer(recipient = recipient)
            val impostor =
                MailboxPointer.create(
                    sender = DualKeyIdentity.generate().secp256k1KeyPair,
                    recipientIdentity = recipient.publicKey,
                    blobCid = genuine.blobCid,
                    notValidAfterEpochSecond = genuine.notValidAfterEpochSecond,
                    nowEpochSecond = 0,
                )
            val forged =
                MailboxPointer.fromDecoded(
                    recipientIdentity = genuine.recipientIdentity,
                    senderIdentity = genuine.senderIdentity,
                    blobCid = genuine.blobCid,
                    notValidAfterEpochSecond = genuine.notValidAfterEpochSecond,
                    signature = impostor.signature,
                )
            MailboxPointer.verify(forged) shouldBe false
        }

        test("create refuses a notValidAfterEpochSecond beyond MAX_TTL_WINDOW_SECONDS") {
            shouldThrow<IllegalArgumentException> {
                MailboxPointer.create(
                    sender = DualKeyIdentity.generate().secp256k1KeyPair,
                    recipientIdentity = DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                    blobCid = testCid(1),
                    notValidAfterEpochSecond = MailboxPointer.MAX_TTL_WINDOW_SECONDS + 1,
                    nowEpochSecond = 0,
                )
            }
        }
    })
