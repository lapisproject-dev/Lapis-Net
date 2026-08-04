package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class MessageEnvelopeCodecTest :
    FunSpec({
        test("decode(encode(envelope)) round-trips a minimal envelope") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            MessageEnvelopeCodec.decode(MessageEnvelopeCodec.encode(envelope)) shouldBe envelope
        }

        test("decode(encode(envelope)) round-trips 64 recipients with both optional CIDs present") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..MessageEnvelopeCodec.MAX_RECIPIENTS).map { Secp256k1KeyPair.generate().publicKey }
            val envelope =
                MessageEnvelope.create(
                    sender,
                    recipients,
                    testCid(1),
                    replyTo = testCid(2),
                    threadRoot = testCid(3),
                )

            MessageEnvelopeCodec.decode(MessageEnvelopeCodec.encode(envelope)) shouldBe envelope
        }

        test("decode(encode(envelope)) preserves recipient order exactly") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..5).map { Secp256k1KeyPair.generate().publicKey }
            val envelope = MessageEnvelope.create(sender, recipients, testCid(1))

            val roundTripped = MessageEnvelopeCodec.decode(MessageEnvelopeCodec.encode(envelope))

            roundTripped.recipients shouldBe recipients
        }

        test("decode rejects bad magic") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))
            bytes[4] = 99

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
        }

        test("decode rejects non-zero reserved flag bits") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))
            bytes[5] = (bytes[5].toInt() or 0x04).toByte()

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes.copyOf(bytes.size / 2)) }
        }

        test("decode rejects trailing bytes") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))
            val withTrailingGarbage = bytes + byteArrayOf(1, 2, 3)

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(withTrailingGarbage) }
        }

        test("decode rejects a sender key that is not a valid point on the curve") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))
            val invalidCurvePoint = byteArrayOf(0x02) + ByteArray(32)
            // sender starts right after magic(4) + version(1) + flags(1)
            invalidCurvePoint.copyInto(bytes, destinationOffset = 6)

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
        }

        test("decode rejects an oversized declared recipientCount before allocating - not a truncation error") {
            val sender = Secp256k1KeyPair.generate()
            // Hand-built: magic(4) + version(1) + flags(1) + sender(33) + recipientCount(2) = 41
            // bytes total, declaring 10_000 recipients that are never actually present. If decode()
            // allocated/consumed on the attacker's declared count first, this would surface as
            // "truncated" instead - the whole point of this test is that it must not.
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNME".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(sender.publicKey.bytes)
                writeShort(10_000)
            }

            val exception =
                shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(out.toByteArray()) }

            exception.message?.contains("too many recipients") shouldBe true
            exception.message?.contains("truncated") shouldBe false
        }

        test("decode rejects recipientCount == 0") {
            val sender = Secp256k1KeyPair.generate()
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNME".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(sender.publicKey.bytes)
                writeShort(0)
            }

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(out.toByteArray()) }
        }

        test("decode rejects contentCidLen == 0 and contentCidLen above the cap") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey

            fun buildWithContentCidLen(len: Int): ByteArray {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write("LNME".toByteArray(Charsets.US_ASCII))
                    writeByte(1)
                    writeByte(0)
                    write(sender.publicKey.bytes)
                    writeShort(1)
                    write(recipient.bytes)
                    writeLong(1000L)
                    writeByte(0) // NONE
                    writeShort(len)
                }
                return out.toByteArray()
            }

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(buildWithContentCidLen(0)) }
            shouldThrow<MalformedMessageEnvelopeException> {
                MessageEnvelopeCodec.decode(buildWithContentCidLen(MessageEnvelopeCodec.MAX_CID_BYTES + 1))
            }
        }

        test(
            "decode rejects MLS_ARCHIVE as reserved; a byte-flip to HYBRID_ECIES now fails on the missing wrap section",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val bytes = MessageEnvelopeCodec.encode(MessageEnvelope.create(sender, listOf(recipient), testCid(1)))
            val encryptionByteOffset = 4 + 1 + 1 + 33 + 2 + 33 * 1 + 8

            // MLS_ARCHIVE is still rejected outright as "reserved" - unchanged from V0.9.1.
            val mls = bytes.copyOf()
            mls[encryptionByteOffset] = 2
            val mlsException = shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(mls) }
            mlsException.message?.contains("reserved") shouldBe true

            // HYBRID_ECIES is now functional (V0.9.2) - flipping an otherwise-NONE envelope's byte
            // to 1 no longer fails with "reserved". It still fails, but for a DIFFERENT reason:
            // decode() now expects a wrap section after the (still-NONE-shaped) threadRoot/reply
            // fields, and the bytes that follow (the signature) do not parse as a valid wrap count.
            val hybrid = bytes.copyOf()
            hybrid[encryptionByteOffset] = 1
            val hybridException = shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(hybrid) }
            hybridException.message?.contains("reserved") shouldBe false

            val unknown = bytes.copyOf()
            unknown[encryptionByteOffset] = 7
            val unknownException =
                shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(unknown) }
            unknownException.message?.contains("unknown") shouldBe true
        }

        test(
            "encodeSignedBody's raw-field overload writes HYBRID_ECIES with a 0-wrap section, decode of those bytes throws",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey

            val body =
                MessageEnvelopeCodec.encodeSignedBody(
                    sender = sender.publicKey,
                    recipients = listOf(recipient),
                    sentAtEpochSecond = 1000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    contentCid = testCid(1),
                    replyTo = null,
                    threadRoot = null,
                    // wraps defaults to emptyList() - the raw overload writes the wrap section
                    // with whatever it is given, no consistency check against recipients.size.
                )
            val signature =
                sender.sign(
                    java.security.MessageDigest
                        .getInstance("SHA-256")
                        .digest(body),
                )
            val encoded = body + signature

            val exception = shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(encoded) }
            exception.message?.contains("wrap count") shouldBe true
        }

        test("encodeSignedBody's raw-field overload can emit an inconsistent wrapCount that decode then rejects") {
            // This is the adversarial-test-enablement contract the raw overload's doc comment
            // promises: it writes the wrap section with WHATEVER wraps it is given, so a caller can
            // deliberately construct a wrapCount that does not match recipients.size + 1.
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val wrongCountWraps =
                (1..3).map { EciesWrap(Secp256k1KeyPair.generate().publicKey, ByteArray(WRAPPED_KEY_SIZE)) }

            val body =
                MessageEnvelopeCodec.encodeSignedBody(
                    sender = sender.publicKey,
                    recipients = listOf(recipient),
                    sentAtEpochSecond = 1000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    contentCid = testCid(1),
                    replyTo = null,
                    threadRoot = null,
                    wraps = wrongCountWraps,
                )
            val signature =
                sender.sign(
                    java.security.MessageDigest
                        .getInstance("SHA-256")
                        .digest(body),
                )
            val encoded = body + signature

            val exception = shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(encoded) }
            exception.message?.contains("wrap count") shouldBe true
            exception.message?.contains("does not match recipient count") shouldBe true
        }

        test("an envelope at the recipient cap still encodes, signs, verifies, and round-trips") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..MessageEnvelopeCodec.MAX_RECIPIENTS).map { Secp256k1KeyPair.generate().publicKey }
            val envelope = MessageEnvelope.create(sender, recipients, testCid(1))

            MessageEnvelope.verify(envelope) shouldBe true
            MessageEnvelopeCodec.decode(MessageEnvelopeCodec.encode(envelope)) shouldBe envelope
        }
    })
