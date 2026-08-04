package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class MessageEnvelopeTest :
    FunSpec({
        test("create produces an envelope that verifies") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            MessageEnvelope.verify(envelope) shouldBe true
        }

        test("verify(expectedSender, envelope) is false for a different expected sender") {
            val sender = Secp256k1KeyPair.generate()
            val other = Secp256k1KeyPair.generate().publicKey
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            MessageEnvelope.verify(other, envelope) shouldBe false
        }

        test("tampering with recipients after decode invalidates the signature") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val other = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            val tampered =
                MessageEnvelope.fromDecoded(
                    sender = envelope.sender,
                    recipients = listOf(other),
                    sentAtEpochSecond = envelope.sentAtEpochSecond,
                    encryption = envelope.encryption,
                    contentCid = envelope.contentCid,
                    replyTo = envelope.replyTo,
                    threadRoot = envelope.threadRoot,
                    signature = envelope.signature,
                )

            MessageEnvelope.verify(tampered) shouldBe false
        }

        test("tampering with contentCid after decode invalidates the signature") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            val tampered =
                MessageEnvelope.fromDecoded(
                    sender = envelope.sender,
                    recipients = envelope.recipients,
                    sentAtEpochSecond = envelope.sentAtEpochSecond,
                    encryption = envelope.encryption,
                    contentCid = testCid(2),
                    replyTo = envelope.replyTo,
                    threadRoot = envelope.threadRoot,
                    signature = envelope.signature,
                )

            MessageEnvelope.verify(tampered) shouldBe false
        }

        test("tampering with sentAtEpochSecond after decode invalidates the signature") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            val tampered =
                MessageEnvelope.fromDecoded(
                    sender = envelope.sender,
                    recipients = envelope.recipients,
                    sentAtEpochSecond = envelope.sentAtEpochSecond + 1,
                    encryption = envelope.encryption,
                    contentCid = envelope.contentCid,
                    replyTo = envelope.replyTo,
                    threadRoot = envelope.threadRoot,
                    signature = envelope.signature,
                )

            MessageEnvelope.verify(tampered) shouldBe false
        }

        test("isAddressedTo is true for each listed recipient and false for an unrelated key") {
            val sender = Secp256k1KeyPair.generate()
            val recipientA = Secp256k1KeyPair.generate().publicKey
            val recipientB = Secp256k1KeyPair.generate().publicKey
            val unrelated = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipientA, recipientB), testCid(1))

            envelope.isAddressedTo(recipientA) shouldBe true
            envelope.isAddressedTo(recipientB) shouldBe true
            envelope.isAddressedTo(unrelated) shouldBe false
        }

        test("create rejects more than MAX_RECIPIENTS recipients") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..MessageEnvelopeCodec.MAX_RECIPIENTS + 1).map { Secp256k1KeyPair.generate().publicKey }

            shouldThrow<IllegalArgumentException> { MessageEnvelope.create(sender, recipients, testCid(1)) }
        }

        test("create rejects an empty recipient list") {
            val sender = Secp256k1KeyPair.generate()

            shouldThrow<IllegalArgumentException> { MessageEnvelope.create(sender, emptyList(), testCid(1)) }
        }

        test("create rejects a duplicated recipient") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.create(sender, listOf(recipient, recipient), testCid(1))
            }
        }

        test("create rejects HYBRID_ECIES without a complete wrap list") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey

            // Empty wraps.
            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.create(sender, listOf(recipient), testCid(1), encryption = EncryptionMode.HYBRID_ECIES)
            }

            // recipients.size wraps (missing the sender's own self-wrap - must be size + 1).
            val oneWrapTooFew =
                listOf(
                    EciesWrap(Secp256k1KeyPair.generate().publicKey, ByteArray(WRAPPED_KEY_SIZE)),
                )
            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.create(
                    sender,
                    listOf(recipient),
                    testCid(1),
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = oneWrapTooFew,
                )
            }
        }

        test("create accepts HYBRID_ECIES with recipients.size + 1 wraps") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val wraps =
                (0..1).map {
                    EciesWrap(Secp256k1KeyPair.generate().publicKey, ByteArray(WRAPPED_KEY_SIZE))
                }

            val envelope =
                MessageEnvelope.create(
                    sender,
                    listOf(recipient),
                    testCid(1),
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = wraps,
                )

            envelope.wraps.size shouldBe 2
            MessageEnvelope.verify(envelope) shouldBe true
        }

        test("create rejects MLS_ARCHIVE encryption") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.create(sender, listOf(recipient), testCid(1), encryption = EncryptionMode.MLS_ARCHIVE)
            }
        }

        test("signature returns a fresh, independent copy on every access") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            val firstAccess = envelope.signature
            firstAccess.fill(0)

            MessageEnvelope.verify(envelope) shouldBe true
        }

        test("contentId is deterministic, 32 bytes, and differs for a different sentAtEpochSecond") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelopeA = MessageEnvelope.create(sender, listOf(recipient), testCid(1), sentAtEpochSecond = 1000)
            val envelopeB = MessageEnvelope.create(sender, listOf(recipient), testCid(1), sentAtEpochSecond = 2000)

            envelopeA.contentId().size shouldBe 32
            envelopeA.contentId().contentEquals(envelopeA.contentId()) shouldBe true
            envelopeA.contentId().contentEquals(envelopeB.contentId()) shouldBe false
        }

        test("toString does not contain the signature or a full recipient key") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))

            val text = envelope.toString()

            val signatureHex = envelope.signature.joinToString("") { "%02x".format(it) }
            val recipientHex = recipient.bytes.joinToString("") { "%02x".format(it) }
            text.contains(signatureHex) shouldBe false
            text.contains(recipientHex) shouldBe false
        }
    })
