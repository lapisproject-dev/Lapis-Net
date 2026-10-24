package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList

private class FakeTransport(
    val failWith: MailAnonymousFailure? = null,
) : AnonymousMailTransport {
    class Delivery(
        val recipients: List<Secp256k1PublicKey>,
        val frame: ByteArray,
        val blobs: List<ByteArray>,
        val sizeClass: AnonymousMailSizeClass,
    )

    val preflights = CopyOnWriteArrayList<Triple<List<Secp256k1PublicKey>, Int, List<Int>>>()
    val deliveries = CopyOnWriteArrayList<Delivery>()

    override fun preflight(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: Int,
        attachmentBlobSizes: List<Int>,
    ): AnonymousMailSizeClass {
        preflights += Triple(recipients, frameBytes, attachmentBlobSizes)
        failWith?.let { throw MailAnonymousDeliveryException(it) }
        return AnonymousMailSizing.classify(frameBytes, attachmentBlobSizes)
    }

    override fun deliver(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
        sizeClass: AnonymousMailSizeClass,
    ) {
        deliveries += Delivery(recipients, frameBytes, attachmentBlobs, sizeClass)
    }

    override fun close() {}
}

class MailSenderAnonymousTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-sender-anon"))
        val pubsub = GossipPubSub.attach(node)
        val published = CopyOnWriteArrayList<String>()
        pubsub.outboundTap = { topic, _ -> published += topic }

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        val sender = Secp256k1KeyPair.generate()
        val recipient = Secp256k1KeyPair.generate().publicKey

        fun anonymousSender(transport: AnonymousMailTransport? = FakeTransport()): MailSender =
            MailSender(pubsub, storage, anonymous = true).also { s ->
                transport?.let { s.installAnonymousTransport(it) }
            }

        test("an anonymous send never publishes to a topic and hands the frame to the transport") {
            val transport = FakeTransport()
            val mailSender = anonymousSender(transport)
            val before = published.size
            val sent =
                mailSender.send(sender, listOf(recipient), "s", "b", encryption = EncryptionMode.HYBRID_ECIES)
            published.size shouldBe before
            transport.deliveries.size shouldBe 1
            transport.deliveries.single().sizeClass shouldBe AnonymousMailSizeClass.INLINE
            transport.deliveries
                .single()
                .frame
                .contentEquals(sent.frameBytes) shouldBe true
            // the mail is stored locally so the sender's own views work
            storage.getLocal(sent.bodyCid) shouldBe MailFrameCodec.decode(sent.frameBytes).bodyBytes
        }

        test("republish is a no-op in anonymity mode") {
            val mailSender = anonymousSender()
            val sent = mailSender.send(sender, listOf(recipient), "s", "b")
            val before = published.size
            mailSender.republish(sent)
            published.size shouldBe before
        }

        test("without an installed transport the send fails with anonymity-not-ready and stores nothing") {
            val mailSender = anonymousSender(transport = null)
            val ex =
                shouldThrow<MailAnonymousDeliveryException> {
                    mailSender.send(
                        sender,
                        listOf(recipient),
                        "unique-subject-1",
                        "b",
                    )
                }
            ex.failure shouldBe MailAnonymousFailure.ANONYMITY_NOT_READY
            val bodyBytes = MessageBodyCodec.encode(MessageBody("unique-subject-1", "b"))
            storage.getLocal(MessageBodyCodec.cidFor(bodyBytes)) shouldBe null
        }

        test("a failed pre-flight stores nothing and never calls deliver") {
            val transport = FakeTransport(MailAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY)
            val mailSender = anonymousSender(transport)
            val ex =
                shouldThrow<MailAnonymousDeliveryException> {
                    mailSender.send(
                        sender,
                        listOf(recipient),
                        "unique-subject-2",
                        "b",
                    )
                }
            ex.failure shouldBe MailAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY
            transport.deliveries.size shouldBe 0
            storage.getLocal(
                MessageBodyCodec.cidFor(MessageBodyCodec.encode(MessageBody("unique-subject-2", "b"))),
            ) shouldBe
                null
        }

        test(
            "an attachment that is not held locally ends the send with attachments-unavailable, before the pre-flight",
        ) {
            val transport = FakeTransport()
            val mailSender = anonymousSender(transport)
            val foreign = MessageBodyCodec.cidFor(ByteArray(40) { 9 })
            val ref = AttachmentRef(foreign, "a.bin", "application/octet-stream", 40)
            val ex =
                shouldThrow<MailAnonymousDeliveryException> {
                    mailSender.send(sender, listOf(recipient), "s", "b", attachments = listOf(ref))
                }
            ex.failure shouldBe MailAnonymousFailure.ATTACHMENTS_UNAVAILABLE_ANONYMOUS
            transport.preflights.size shouldBe 0
            transport.deliveries.size shouldBe 0
        }

        test("a local attachment travels as a blob and forces the CIRCUIT class") {
            val transport = FakeTransport()
            val mailSender = anonymousSender(transport)
            val blob = ByteArray(300) { (it % 13).toByte() }
            val cid = storage.put(blob)
            mailSender.send(
                sender,
                listOf(recipient),
                "s",
                "b",
                attachments = listOf(AttachmentRef(cid, "a.bin", "x/y", 300)),
            )
            val d = transport.deliveries.single()
            d.sizeClass shouldBe AnonymousMailSizeClass.CIRCUIT
            d.blobs.single().contentEquals(blob) shouldBe true
            transport.preflights.single().third shouldBe listOf(300)
        }

        test("a too-large bundle is refused by the pre-flight before deliver is called") {
            val transport = FakeTransport()
            val mailSender = anonymousSender(transport)
            val big = ByteArray(AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES) { 1 }
            val cid = storage.put(big)
            val ex =
                shouldThrow<MailAnonymousDeliveryException> {
                    mailSender.send(
                        sender,
                        listOf(recipient),
                        "s",
                        "b",
                        attachments = listOf(AttachmentRef(cid, "a", "x/y", big.size.toLong())),
                    )
                }
            ex.failure shouldBe MailAnonymousFailure.MAIL_TOO_LARGE_ANONYMOUS
            transport.deliveries.size shouldBe 0
        }

        test("an anonymous sender with a DHT outbox is refused at construction") {
            shouldThrow<IllegalArgumentException> {
                MailSender(
                    pubsub,
                    storage,
                    outbox = DhtOutbox(),
                    anonymous = true,
                )
            }
        }

        test("the transport can be installed only once and not on a normal sender") {
            val mailSender = anonymousSender()
            shouldThrow<IllegalStateException> { mailSender.installAnonymousTransport(FakeTransport()) }
            shouldThrow<IllegalStateException> {
                MailSender(
                    pubsub,
                    storage,
                ).installAnonymousTransport(FakeTransport())
            }
        }
    })
