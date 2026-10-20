package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.OutboxEntry
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.OutboxIngestOutcome
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private fun seedCid(seed: Int): Cid =
    Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed.toByte() })

/**
 * V0.9.15 - [MailboxGossip.updateAcceptanceCheck] swaps the policy of BOTH entry paths (GossipSub validator and
 * [MailboxGossip.dhtConsumer]) at once, because both read one reference per call instead of a value captured at attach.
 */
class MailboxGossipAcceptanceUpdateTest :
    FunSpec({
        val strict: (DualKeyIdentity) -> DmAcceptanceCheck = {
            DmAcceptanceCheck(
                gates = listOf(AcceptanceGate.VeritasPath),
                trustGraph = TrustGraph.fromEdges(emptyList()),
                karmaScoreOf = KarmaScoreLookup { 0.0 },
            )
        }

        fun pointerFor(
            sender: Secp256k1KeyPair,
            recipient: DualKeyIdentity,
            seed: Int,
        ): MailboxPointer =
            MailboxPointer.create(
                sender,
                recipient.secp256k1KeyPair.publicKey,
                seedCid(seed),
                Instant.now().epochSecond + 3600,
            )

        fun entryOf(pointer: MailboxPointer) =
            OutboxEntry(
                OutboxEntryKind.DM_MAILBOX_POINTER,
                pointer.recipientIdentity,
                pointer.notValidAfterEpochSecond,
                MailboxPointerCodec.encode(pointer),
            )

        test(
            "T1/T2: the DHT consumer applies the gossip acceptance - a stranger's signed pointer is not tracked",
        ).config(
            timeout = 60.seconds,
        ) {
            val local = DualKeyIdentity.generate()
            val node = LapisNode.create(local)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mbx-update-dht"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = MailboxGossip.attach(pubsub, storage, local.secp256k1KeyPair.publicKey, strict(local))
                val stranger = DualKeyIdentity.generate()
                val consumer = gossip.dhtConsumer()
                val peerId = stranger.deriveLibp2pPeerId()

                // T1: a validly signed pointer from a sender with no trust path.
                val pointer = pointerFor(stranger.secp256k1KeyPair, local, 1)
                consumer.onDhtOutboxEntry(stranger.secp256k1KeyPair.publicKey, peerId, entryOf(pointer)) shouldBe
                    OutboxIngestOutcome.REJECTED
                gossip.pending() shouldBe emptyList()

                // T2: the same pointer, but the DHT value was published by somebody else than the pointer's sender.
                val trusted = DualKeyIdentity.generate()
                gossip.updateAcceptanceCheck(
                    DmAcceptanceCheck(
                        gates = listOf(AcceptanceGate.VeritasPath),
                        trustGraph =
                            TrustGraph.fromEdges(
                                listOf(
                                    Triple(
                                        local.secp256k1KeyPair.publicKey,
                                        trusted.secp256k1KeyPair.publicKey,
                                        1_000_000,
                                    ),
                                ),
                            ),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                    ),
                )
                // The pointer claims the trusted sender and is signed by the trusted key, but the DHT value
                // carrying it belongs to the stranger: re-publishing somebody else's pointer must fail.
                val claimsTrusted = pointerFor(trusted.secp256k1KeyPair, local, 2)
                consumer.onDhtOutboxEntry(
                    stranger.secp256k1KeyPair.publicKey,
                    peerId,
                    entryOf(claimsTrusted),
                ) shouldBe OutboxIngestOutcome.REJECTED
                gossip.pending() shouldBe emptyList()

                // The trusted sender's own value is accepted under the updated policy.
                consumer.onDhtOutboxEntry(
                    trusted.secp256k1KeyPair.publicKey,
                    trusted.deriveLibp2pPeerId(),
                    entryOf(claimsTrusted),
                ) shouldBe OutboxIngestOutcome.ACCEPTED
                gossip.pending().size shouldBe 1
                gossip.stop()
            } finally {
                node.stop()
            }
        }

        test("an update takes effect on the DHT path, in both directions").config(timeout = 60.seconds) {
            val local = DualKeyIdentity.generate()
            val node = LapisNode.create(local)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mbx-update-dht2"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = MailboxGossip.attach(pubsub, storage, local.secp256k1KeyPair.publicKey, null)
                val sender = DualKeyIdentity.generate()
                val consumer = gossip.dhtConsumer()
                val peerId = sender.deriveLibp2pPeerId()
                val key = sender.secp256k1KeyPair.publicKey

                // No check: accepted.
                consumer.onDhtOutboxEntry(key, peerId, entryOf(pointerFor(sender.secp256k1KeyPair, local, 1))) shouldBe
                    OutboxIngestOutcome.ACCEPTED
                // Strict: the same sender is declined from now on (the consumer object was created BEFORE the update).
                gossip.updateAcceptanceCheck(strict(local))
                consumer.onDhtOutboxEntry(key, peerId, entryOf(pointerFor(sender.secp256k1KeyPair, local, 2))) shouldBe
                    OutboxIngestOutcome.REJECTED
                // And open again.
                gossip.updateAcceptanceCheck(null)
                consumer.onDhtOutboxEntry(key, peerId, entryOf(pointerFor(sender.secp256k1KeyPair, local, 3))) shouldBe
                    OutboxIngestOutcome.ACCEPTED
                gossip.pending().size shouldBe 2
                gossip.stop()
            } finally {
                node.stop()
            }
        }

        test("an update takes effect on the GossipSub path as well (two real nodes)").config(timeout = 120.seconds) {
            val recipient = DualKeyIdentity.generate()
            val sender = DualKeyIdentity.generate()
            val nodeR = LapisNode.create(recipient)
            val nodeS = LapisNode.create(sender)
            nodeR.start(bootstrapPeers = emptyList())
            nodeS.start(bootstrapPeers = emptyList())
            try {
                val storageR = NabuStorage.attach(nodeR, Files.createTempDirectory("mbx-update-gossip-r"))
                val storageS = NabuStorage.attach(nodeS, Files.createTempDirectory("mbx-update-gossip-s"))
                val pubsubR = GossipPubSub.attach(nodeR)
                val pubsubS = GossipPubSub.attach(nodeS)
                val gossip =
                    MailboxGossip.attach(pubsubR, storageR, recipient.secp256k1KeyPair.publicKey, strict(recipient))
                nodeS.connect(PeerInfo(nodeR.peerId, nodeR.listenAddresses()))
                val topic = MailboxTopics.forRecipient(recipient.secp256k1KeyPair.publicKey)

                fun publishUntil(
                    firstSeed: Int,
                    seconds: Long,
                    done: () -> Boolean,
                ): Boolean {
                    val deadline = System.nanoTime() + seconds * 1_000_000_000L
                    var seed = firstSeed
                    while (System.nanoTime() < deadline) {
                        val pointer = pointerFor(sender.secp256k1KeyPair, recipient, seed++)
                        runCatching { pubsubS.publish(topic, MailboxPointerCodec.encode(pointer)) }
                        Thread.sleep(300)
                        if (done()) return true
                    }
                    return false
                }

                // Strict: nothing arrives, however long the mesh has to form.
                publishUntil(100, 6) { gossip.pending().isNotEmpty() } shouldBe false
                gossip.updateAcceptanceCheck(null)
                publishUntil(200, 30) { gossip.pending().isNotEmpty() } shouldBe true
                gossip.stop()
                storageS.stop()
            } finally {
                nodeS.stop()
                nodeR.stop()
            }
        }
    })
