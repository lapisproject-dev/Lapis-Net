package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun sealFor(
    sender: Secp256k1KeyPair,
    recipients: List<Secp256k1KeyPair>,
    body: MessageBody = MessageBody(subject = "hello", body = "world"),
): SealedMessage {
    val context =
        MailAadContext.forNewMessage(
            sender = sender.publicKey,
            recipients = recipients.map { it.publicKey },
            sentAtEpochSecond = 1_000,
        )
    return HybridEcies.seal(body, sender, context)
}

private fun envelopeFor(
    sender: Secp256k1KeyPair,
    recipients: List<Secp256k1KeyPair>,
    sealed: SealedMessage,
): MessageEnvelope =
    MessageEnvelope.create(
        sender = sender,
        recipients = recipients.map { it.publicKey },
        contentCid = sealed.contentCid,
        sentAtEpochSecond = 1_000,
        encryption = EncryptionMode.HYBRID_ECIES,
        wraps = sealed.wraps,
    )

class HybridEciesTest :
    FunSpec({
        test("round trip: single recipient") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b", headers = mapOf("x" to "y"))
            val sealed = sealFor(sender, listOf(recipient), body)
            val envelope = envelopeFor(sender, listOf(recipient), sealed)

            val opened = HybridEcies.open(envelope, sealed.sealedBody, recipient)

            opened shouldBe body
        }

        test("round trip: multi-recipient - each opens independently and gets the identical body") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..5).map { Secp256k1KeyPair.generate() }
            val body = MessageBody(subject = "s", body = "b")
            val sealed = sealFor(sender, recipients, body)
            val envelope = envelopeFor(sender, recipients, sealed)

            recipients.forEach { recipient ->
                HybridEcies.open(envelope, sealed.sealedBody, recipient) shouldBe body
            }
        }

        test("the sender's own self-wrap opens their own sealed message") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val sealed = sealFor(sender, listOf(recipient), body)
            val envelope = envelopeFor(sender, listOf(recipient), sealed)

            HybridEcies.open(envelope, sealed.sealedBody, sender) shouldBe body
        }

        test("MailSender.send(encryption = HYBRID_ECIES) produces a SentMessage the sender can open locally") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("hybrid-ecies-sender-selfwrap"))
                val pubsub = GossipPubSub.attach(node)
                val sender = MailSender(pubsub, storage)
                val recipient = Secp256k1KeyPair.generate().publicKey

                val sent =
                    sender.send(
                        localIdentity = identity.secp256k1KeyPair,
                        recipients = listOf(recipient),
                        subject = "hi",
                        body = "encrypted hello",
                        encryption = EncryptionMode.HYBRID_ECIES,
                    )

                sent.sealedBody shouldNotBe null
                sent.envelope.encryption shouldBe EncryptionMode.HYBRID_ECIES
                val opened = HybridEcies.open(sent.envelope, sent.sealedBody!!, identity.secp256k1KeyPair)
                opened.subject shouldBe "hi"
                opened.body shouldBe "encrypted hello"
                pubsub.stop()
            } finally {
                node.stop()
            }
        }

        test("a non-recipient with a valid keypair cannot open") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val outsider = Secp256k1KeyPair.generate()
            val sealed = sealFor(sender, listOf(recipient))
            val envelope = envelopeFor(sender, listOf(recipient), sealed)

            shouldThrow<MailDecryptionException> { HybridEcies.open(envelope, sealed.sealedBody, outsider) }
        }

        test("wrap independence: a recipient opens correctly even when every OTHER wrap is garbage") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..5).map { Secp256k1KeyPair.generate() }
            val body = MessageBody(subject = "s", body = "b")
            val sealed = sealFor(sender, recipients, body)
            val context =
                MailAadContext.forNewMessage(
                    sender.publicKey,
                    recipients.map { it.publicKey },
                    sentAtEpochSecond = 1_000,
                )

            val targetSlot = 2
            val garbageWrap = EciesWrap(Secp256k1KeyPair.generate().publicKey, ByteArray(WRAPPED_KEY_SIZE))
            val tamperedWraps =
                sealed.wraps.mapIndexed { index, wrap -> if (index == targetSlot) wrap else garbageWrap }

            val opened =
                HybridEcies.openWithContext(
                    context,
                    sealed.contentCid,
                    tamperedWraps,
                    sealed.sealedBody,
                    recipients[targetSlot],
                )

            opened shouldBe body
        }

        test("maximum fan-out: 64 recipients (65 wraps) round-trips within the envelope-section byte budget") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..MessageEnvelopeCodec.MAX_RECIPIENTS).map { Secp256k1KeyPair.generate() }
            val body = MessageBody(subject = "s", body = "b")
            val sealed = sealFor(sender, recipients, body)
            val envelope = envelopeFor(sender, recipients, sealed)

            envelope.wraps.size shouldBe MessageEnvelopeCodec.MAX_RECIPIENTS + 1
            MessageEnvelope.verify(envelope) shouldBe true
            val encoded = MessageEnvelopeCodec.encode(envelope)
            (encoded.size <= MailFrameCodec.MAX_ENVELOPE_SECTION_BYTES) shouldBe true
            // Pins the ~7.9 KB worst-case arithmetic documented in MessageEnvelopeCodec's class doc
            // comment - a future accidental size regression would trip this.
            (encoded.size < 9_000) shouldBe true

            recipients.forEach { recipient ->
                HybridEcies.open(envelope, sealed.sealedBody, recipient) shouldBe body
            }
            HybridEcies.open(envelope, sealed.sealedBody, sender) shouldBe body
        }

        test("codec round trip through the wire: decode(encode(envelope)) still opens for every recipient") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..3).map { Secp256k1KeyPair.generate() }
            val body = MessageBody(subject = "s", body = "b")
            val sealed = sealFor(sender, recipients, body)
            val envelope = envelopeFor(sender, recipients, sealed)

            val decoded = MessageEnvelopeCodec.decode(MessageEnvelopeCodec.encode(envelope))

            decoded shouldBe envelope
            recipients.forEach { recipient ->
                HybridEcies.open(decoded, sealed.sealedBody, recipient) shouldBe body
            }
        }

        test(
            "MAX_PLAINTEXT_BYTES guard is unreachable via MessageBody's public API - the largest " +
                "constructible body still seals",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val context =
                MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), sentAtEpochSecond = 1_000)

            // The require() at HybridEcies.kt:153 guards against an encoded MessageBody exceeding
            // SealedBodyCodec.MAX_PLAINTEXT_BYTES (65,499) - but MessageBody's own per-field caps
            // (subject + markdown + attachments + headers, see MessageBodyCodec's class doc comment
            // for the arithmetic) sum to at most ~48 KB, so no body constructible through the public
            // API can ever trip it. This test builds the LARGEST body the public API allows - max
            // subject, max markdown, MAX_ATTACHMENTS attachments each with max-length name/mime, and
            // MAX_HEADERS headers each with max-length key/value - and pins that it still seals
            // successfully, well under the guard's threshold. See SealedBodyCodec.MAX_PLAINTEXT_BYTES's
            // doc comment for why the guard is defence-in-depth rather than a currently-reachable
            // rejection, and HybridEciesAdversarialTest for negative/tamper coverage of seal/open.
            val maxSubject = "s".repeat(MessageBodyCodec.MAX_SUBJECT_BYTES)
            val maxMarkdown = "b".repeat(MessageBodyCodec.MAX_MARKDOWN_BYTES)
            val attachmentCid =
                io.ipfs.cid.Cid.buildCidV1(
                    io.ipfs.cid.Cid.Codec.Raw,
                    io.ipfs.multihash.Multihash.Type.sha2_256,
                    ByteArray(32) { 7 },
                )
            val maxAttachments =
                (1..MessageBodyCodec.MAX_ATTACHMENTS).map {
                    AttachmentRef(
                        cid = attachmentCid,
                        name = "n".repeat(MessageBodyCodec.MAX_ATTACHMENT_NAME_BYTES),
                        mime = "m".repeat(MessageBodyCodec.MAX_ATTACHMENT_MIME_BYTES),
                        size = MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES,
                    )
                }
            val maxHeaders =
                (0 until MessageBodyCodec.MAX_HEADERS).associate { i ->
                    // Keys must be in strictly increasing unsigned-byte order once encoded/decoded -
                    // a single max-length-prefix char plus a distinguishing suffix keeps every key
                    // unique and near MAX_HEADER_KEY_BYTES.
                    ("h".repeat(MessageBodyCodec.MAX_HEADER_KEY_BYTES - 2) + "%02d".format(i)) to
                        "v".repeat(MessageBodyCodec.MAX_HEADER_VALUE_BYTES)
                }
            val maxBody =
                MessageBody(
                    subject = maxSubject,
                    body = maxMarkdown,
                    attachments = maxAttachments,
                    headers = maxHeaders,
                )
            val encodedSize = MessageBodyCodec.encode(maxBody).size
            (encodedSize < SealedBodyCodec.MAX_PLAINTEXT_BYTES) shouldBe true

            val sealed = HybridEcies.seal(maxBody, sender, context)
            sealed.sealedBodyBytes.size shouldNotBe 0
        }
    })
