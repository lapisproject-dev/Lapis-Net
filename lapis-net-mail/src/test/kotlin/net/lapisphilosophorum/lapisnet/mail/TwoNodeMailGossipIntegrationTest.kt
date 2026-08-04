package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - `LapisNode` + `NabuStorage` +
 * [GossipPubSub] + [InboxGossip]/[MailSender] fully attached on both, mirroring
 * `net.lapisphilosophorum.lapisnet.trust.TwoNodeVeritasGossipIntegrationTest`'s connectivity and
 * bounded-polling-against-one-deadline pattern exactly. Node A sends a message to node B's
 * identity; node B's inbox is polled with a bounded timeout, retrying the publish (not
 * re-signing) until it converges.
 */
class TwoNodeMailGossipIntegrationTest :
    FunSpec({
        test("a message sent on node A propagates to node B's inbox, decodes identically, and persists durably") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("mail-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("mail-gossip-b"))

                // GossipPubSub (and therefore InboxGossip, which subscribes through it) must be
                // attached BEFORE the nodes connect - Gossip is a ConnectionHandler and only sees
                // connection-established events for connections made after it registers.
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val inboxA = InboxGossip.attach(pubsubA, storageA, identityA.secp256k1KeyPair.publicKey)
                val inboxB = InboxGossip.attach(pubsubB, storageB, identityB.secp256k1KeyPair.publicKey)
                // Topic isolation control: a third, unrelated identity's inbox attached on the
                // SAME node B - must stay empty throughout, proving inbox topics do not leak into
                // each other on a shared node.
                val thirdIdentity = DualKeyIdentity.generate()
                val inboxThird = InboxGossip.attach(pubsubB, storageB, thirdIdentity.secp256k1KeyPair.publicKey)

                val senderOnA = MailSender(pubsubA, storageA)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                // GossipSub mesh formation (GRAFT) is asynchronous, so retry the publish via
                // republish() (not a fresh send()) - re-signing would mint a fresh envelope with a
                // different content id every round and defeat dedup on B. Mirrors
                // TwoNodeVeritasGossipIntegrationTest's identical retry-the-whole-announce-call
                // reasoning, adapted to MailSender's two-call send()/republish() split.
                val sent =
                    senderOnA.send(
                        localIdentity = identityA.secp256k1KeyPair,
                        recipients = listOf(identityB.secp256k1KeyPair.publicKey),
                        subject = "hello",
                        body = "# hi\n\nfrom node A",
                    )

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var inboxOnB = inboxB.messages()
                while (inboxOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    senderOnA.republish(sent)
                    Thread.sleep(500)
                    inboxOnB = inboxB.messages()
                }

                inboxOnB shouldHaveSize 1
                inboxOnB.single().envelope shouldBe sent.envelope
                inboxOnB.single().body shouldBe sent.body
                inboxOnB.single().envelope.isAddressedTo(identityB.secp256k1KeyPair.publicKey) shouldBe true

                // Durability on B: NabuStorage.put is idempotent/deterministic for identical
                // content, so re-putting A's already-sent bytes on A is safe and yields the same
                // Cid without double-storing anything new - mirrors
                // TwoNodeVeritasGossipIntegrationTest's identical closing assertion.
                val bodyBytes = MessageBodyCodec.encode(sent.body)
                storageB.get(storageA.put(bodyBytes)) shouldBe bodyBytes
                val envelopeBytes = MessageEnvelopeCodec.encode(sent.envelope)
                storageB.get(storageA.put(envelopeBytes)) shouldBe envelopeBytes

                // D7: GossipSub never delivers a node's own publishes to its own subscription, so
                // node A - despite being the sender - never sees this message in its own inbox.
                // This is a documented, deliberate gap (see MailSender.send's doc comment), not a
                // bug: assert it explicitly so a future reader does not mistake it for one.
                inboxA.messages().shouldBeEmpty()

                // Topic isolation: the unrelated third identity's inbox on the SAME node B never
                // received anything either - inbox topics do not cross-pollinate.
                inboxThird.messages().shouldBeEmpty()

                inboxA.stop()
                inboxB.stop()
                inboxThird.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }

        test("V0.9.2: a HYBRID_ECIES message sent on node A propagates sealed to node B, which decrypts it locally") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("mail-gossip-hybrid-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("mail-gossip-hybrid-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val inboxB = InboxGossip.attach(pubsubB, storageB, identityB.secp256k1KeyPair.publicKey)

                val senderOnA = MailSender(pubsubA, storageA)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val sent =
                    senderOnA.send(
                        localIdentity = identityA.secp256k1KeyPair,
                        recipients = listOf(identityB.secp256k1KeyPair.publicKey),
                        subject = "secret",
                        body = "# encrypted hi\n\nfrom node A",
                        encryption = EncryptionMode.HYBRID_ECIES,
                    )

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var inboxOnB = inboxB.messages()
                while (inboxOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    senderOnA.republish(sent)
                    Thread.sleep(500)
                    inboxOnB = inboxB.messages()
                }

                inboxOnB shouldHaveSize 1
                val received = inboxOnB.single()
                received.envelope shouldBe sent.envelope
                received.envelope.encryption shouldBe EncryptionMode.HYBRID_ECIES
                // The validator on B never decrypted it - it is still sealed in the index.
                (received.payload is InboxPayload.Sealed) shouldBe true
                received.body shouldBe null

                val sealedOnB = (received.payload as InboxPayload.Sealed).sealedBody
                val opened = HybridEcies.open(received.envelope, sealedOnB, identityB.secp256k1KeyPair)
                opened shouldBe sent.body

                inboxB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
