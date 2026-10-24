package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files

class InboxAnonymousSinkTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val keys = identity.secp256k1KeyPair
        val me = keys.publicKey
        val node = LapisNode.create(identity)
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-sink"))
        val pubsub = GossipPubSub.attach(node)
        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        val sender = Secp256k1KeyPair.generate()

        fun mail(
            attachments: List<AttachmentRef>,
            subject: String,
        ): ByteArray {
            val body = MessageBodyCodec.encode(MessageBody(subject = subject, body = "b", attachments = attachments))
            val envelope = MessageEnvelope.create(sender, listOf(me), MessageBodyCodec.cidFor(body))
            return MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelope), body)
        }

        fun ref(blob: ByteArray) = AttachmentRef(MessageBodyCodec.cidFor(blob), "a.bin", "x/y", blob.size.toLong())

        test("referenced blobs are stored, unreferenced ones are discarded and counted") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val sink = InboxAnonymousSink(inbox, storage) { null }
            val wanted = ByteArray(500) { 11 }
            val unwanted = ByteArray(500) { 12 }
            sink.acceptAnonymousMail(mail(listOf(ref(wanted)), "sink-1"), listOf(wanted, unwanted))
            storage.getLocal(MessageBodyCodec.cidFor(wanted))!!.contentEquals(wanted) shouldBe true
            storage.getLocal(MessageBodyCodec.cidFor(unwanted)) shouldBe null
            sink.discardedBlobCount() shouldBe 1
            sink.acceptedCount() shouldBe 1
        }

        test("a refused mail stores no blob at all") {
            val strict =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = { 0.0 },
                    isAcceptedContact = { false },
                )
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me, strict)
            val sink = InboxAnonymousSink(inbox, storage) { null }
            val blob = ByteArray(321) { 77 }
            sink.acceptAnonymousMail(mail(listOf(ref(blob)), "sink-2"), listOf(blob))
            storage.getLocal(MessageBodyCodec.cidFor(blob)) shouldBe null
            sink.acceptedCount() shouldBe 0
        }

        test("the CID is computed from the blob, so a forged blob under a referenced CID is not stored") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val sink = InboxAnonymousSink(inbox, storage) { null }
            val real = ByteArray(100) { 5 }
            val forged = ByteArray(100) { 6 }
            sink.acceptAnonymousMail(mail(listOf(ref(real)), "sink-3"), listOf(forged))
            storage.getLocal(MessageBodyCodec.cidFor(real)) shouldBe null
            storage.getLocal(MessageBodyCodec.cidFor(forged)) shouldBe null
        }

        test("a sealed body takes its attachment references from the caller's decrypting lambda") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val blob = ByteArray(64) { 3 }
            val referenced = setOf<Cid>(MessageBodyCodec.cidFor(blob))
            val sink = InboxAnonymousSink(inbox, storage) { referenced }
            val mailSender = MailSender(pubsub, storage, anonymous = true)
            var captured: ByteArray? = null
            mailSender.installAnonymousTransport(
                object : AnonymousMailTransport {
                    override fun preflight(
                        recipients: List<net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey>,
                        frameBytes: Int,
                        attachmentBlobSizes: List<Int>,
                    ) = AnonymousMailSizing.classify(frameBytes, attachmentBlobSizes)

                    override fun deliver(
                        recipients: List<net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey>,
                        frameBytes: ByteArray,
                        attachmentBlobs: List<ByteArray>,
                        sizeClass: AnonymousMailSizeClass,
                    ) {
                        captured = frameBytes
                    }

                    override fun close() {}
                },
            )
            mailSender.send(sender, listOf(me), "sealed", "b", encryption = EncryptionMode.HYBRID_ECIES)
            sink.acceptAnonymousMail(captured!!, listOf(blob))
            storage.getLocal(MessageBodyCodec.cidFor(blob))!!.contentEquals(blob) shouldBe true
        }

        test("garbage never throws") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val sink = InboxAnonymousSink(inbox, storage) { throw IllegalStateException("x") }
            sink.acceptAnonymousMail(ByteArray(0), emptyList())
            sink.acceptAnonymousMail(ByteArray(30) { 1 }, listOf(ByteArray(5)))
            sink.acceptAnonymousMail(ByteArray(2_000_000), emptyList())
        }
    })
