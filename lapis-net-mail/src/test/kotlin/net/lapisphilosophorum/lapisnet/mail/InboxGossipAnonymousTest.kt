package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files

/** Mail over circuits enters through [InboxGossip.anonymousIngest], which must decide exactly like the gossip validator. */
class InboxGossipAnonymousTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val me = identity.secp256k1KeyPair.publicKey
        val node = LapisNode.create(identity)
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-inbox-anon"))
        val pubsub = GossipPubSub.attach(node)
        val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        fun frame(
            sender: Secp256k1KeyPair,
            to: List<Secp256k1PublicKey> = listOf(me),
            subject: String = "s",
            tamperBody: Boolean = false,
        ): ByteArray {
            val body = MessageBodyCodec.encode(MessageBody(subject = subject, body = "b"))
            val envelope = MessageEnvelope.create(sender, to, MessageBodyCodec.cidFor(body))
            val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
            val sentBody = if (tamperBody) MessageBodyCodec.encode(MessageBody(subject = "other", body = "b")) else body
            return MailFrameCodec.encode(envelopeBytes, sentBody)
        }

        fun check(
            gates: List<MailAcceptanceGate>,
            contacts: Set<Secp256k1PublicKey> = emptySet(),
        ) = MailAcceptanceCheck(
            gates = gates,
            trustGraph = TrustGraph.fromEdges(emptyList()),
            karmaScoreOf = { 0.0 },
            isAcceptedContact = { it in contacts },
        )

        test("attachAnonymous subscribes to nothing") {
            val before = pubsub.subscribedTopics()
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            inbox.subscribed shouldBe false
            pubsub.subscribedTopics() shouldBe before
            (inbox.topic in pubsub.subscribedTopics()) shouldBe false
            inbox.stop() // null-safe
        }

        test("attach still subscribes the per-recipient topic and unsubscribes on stop") {
            val own = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            val inbox = InboxGossip.attach(pubsub, storage, own)
            inbox.subscribed shouldBe true
            (inbox.topic in pubsub.subscribedTopics()) shouldBe true
            inbox.stop()
            (inbox.topic in pubsub.subscribedTopics()) shouldBe false
        }

        test("a valid mail is accepted once; a duplicate is declined") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val bytes = frame(Secp256k1KeyPair.generate())
            inbox.anonymousIngest(bytes) shouldBe InboxIngestOutcome.ACCEPTED
            inbox.anonymousIngest(bytes) shouldBe InboxIngestOutcome.DUPLICATE
            inbox.messages().size shouldBe 1
        }

        test("wrong recipient, tampered body, garbage and an oversized blob are all refused and index nothing") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val sender = Secp256k1KeyPair.generate()
            val other = Secp256k1KeyPair.generate().publicKey
            inbox.anonymousIngest(frame(sender, to = listOf(other))) shouldBe InboxIngestOutcome.INVALID
            inbox.anonymousIngest(frame(sender, tamperBody = true)) shouldBe InboxIngestOutcome.INVALID
            inbox.anonymousIngest(ByteArray(64) { it.toByte() }) shouldBe InboxIngestOutcome.INVALID
            inbox.anonymousIngest(ByteArray(0)) shouldBe InboxIngestOutcome.INVALID
            inbox.anonymousIngest(ByteArray(200_000) { 1 }) shouldBe InboxIngestOutcome.INVALID
            val bytes = frame(sender)
            inbox.anonymousIngest(
                bytes.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() },
            ) shouldBe
                InboxIngestOutcome.INVALID
            inbox.messages().size shouldBe 0
        }

        test("acceptance parity: the gossip validator and the anonymous entrance decide identically") {
            val contact = Secp256k1KeyPair.generate()
            val stranger = Secp256k1KeyPair.generate()
            val configs =
                listOf(
                    null,
                    check(emptyList()),
                    check(listOf(MailAcceptanceGate.VeritasPath)),
                    check(listOf(MailAcceptanceGate.VeritasPath, MailAcceptanceGate.KarmaThreshold(3.0))),
                    check(listOf(MailAcceptanceGate.VeritasPath), contacts = setOf(contact.publicKey)),
                )
            for (config in configs) {
                for (sender in listOf(contact, stranger)) {
                    // fresh index and fresh frame per case: each decision is compared on equal footing
                    val bytes = frame(sender, subject = "parity-${System.nanoTime()}")
                    val viaGossip =
                        InboxGossip.onGossipMessage(bytes, from, storage, InboxIndex(), me, config) ==
                            ValidationResult.Valid
                    val inbox = InboxGossip.attachAnonymous(pubsub, storage, me, config)
                    val viaCircuit = inbox.anonymousIngest(bytes) == InboxIngestOutcome.ACCEPTED
                    viaCircuit shouldBe viaGossip
                }
            }
        }

        test("updateAcceptanceCheck takes effect on the anonymous entrance from the next message") {
            val inbox = InboxGossip.attachAnonymous(pubsub, storage, me)
            val sender = Secp256k1KeyPair.generate()
            inbox.anonymousIngest(frame(sender, subject = "one")) shouldBe InboxIngestOutcome.ACCEPTED
            inbox.updateAcceptanceCheck(check(listOf(MailAcceptanceGate.VeritasPath)))
            inbox.anonymousIngest(frame(sender, subject = "two")) shouldBe InboxIngestOutcome.INVALID
            inbox.updateAcceptanceCheck(null)
            inbox.anonymousIngest(frame(sender, subject = "three")) shouldBe InboxIngestOutcome.ACCEPTED
        }
    })
