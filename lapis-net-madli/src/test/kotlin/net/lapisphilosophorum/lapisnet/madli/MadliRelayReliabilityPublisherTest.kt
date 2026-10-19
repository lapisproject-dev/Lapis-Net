package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.networking.relay.RelayReliabilityCounts
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

private fun relayId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private val coreMetrics = MadliMetrics(500_000, 10_000_000L, 50, 900_000, 700_000, 10)

class MadliRelayReliabilityPublisherTest :
    FunSpec({
        test("disabled by default: publishes nothing") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-pub-a"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = MadliGossip.attach(pubsub, storage)
                val publisher =
                    MadliRelayReliabilityPublisher(
                        gossip,
                        identity.secp256k1KeyPair,
                        { mapOf(relayId(1) to RelayReliabilityCounts(10, 9)) },
                    )
                publisher.publishForDay(100L) shouldBe 0
                gossip.currentVectorsForObservedPeer(relayId(1)) shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test("enabled: publishes one signed v2 relay vector per relay with enough attempts") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-pub-b"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = MadliGossip.attach(pubsub, storage)
                val counts =
                    mapOf(
                        relayId(1) to RelayReliabilityCounts(10, 9),
                        relayId(2) to RelayReliabilityCounts(2, 2), // below minAttempts
                        relayId(3) to RelayReliabilityCounts(3, 0),
                    )
                val publisher =
                    MadliRelayReliabilityPublisher(
                        gossip,
                        identity.secp256k1KeyPair,
                        { counts },
                        enabled = true,
                        minAttempts = 3,
                    )

                publisher.publishForDay(100L) shouldBe 2

                val v1 = gossip.currentVectorsForObservedPeer(relayId(1)).single()
                v1.metrics shouldBe null
                v1.relayMetrics shouldBe MadliRelayMetrics(900_000, 10)
                v1.observer shouldBe identity.secp256k1KeyPair.publicKey
                v1.epochDay shouldBe 100L
                MadliDailyVector.verify(v1) shouldBe true
                MadliDailyVectorCodec.encode(v1)[4] shouldBe MadliDailyVectorCodec.VERSION_V2
                gossip.currentVectorsForObservedPeer(relayId(2)) shouldBe emptyList()
                gossip.currentVectorsForObservedPeer(relayId(3)).single().relayMetrics shouldBe MadliRelayMetrics(0, 3)
            } finally {
                node.stop()
            }
        }

        test("merges the relay block into this node's existing core vector instead of displacing it") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-pub-c"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = MadliGossip.attach(pubsub, storage)
                val observer = identity.secp256k1KeyPair
                gossip.announce(MadliDailyVector.create(observer, relayId(1), 100L, coreMetrics))

                val publisher =
                    MadliRelayReliabilityPublisher(
                        gossip,
                        observer,
                        { mapOf(relayId(1) to RelayReliabilityCounts(4, 3)) },
                        enabled = true,
                    )
                publisher.publishForDay(100L) shouldBe 1

                val tracked = gossip.currentVectorsForObservedPeer(relayId(1))
                tracked.size shouldBe 1 // replaced, not duplicated
                tracked.single().metrics shouldBe coreMetrics
                tracked.single().relayMetrics shouldBe MadliRelayMetrics(750_000, 4)
                MadliDailyVectorCodec.encode(tracked.single())[4] shouldBe MadliDailyVectorCodec.VERSION_V2
            } finally {
                node.stop()
            }
        }

        test("a published v2 vector arrives on a second node") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val madliA =
                    MadliGossip.attach(
                        pubsubA,
                        NabuStorage.attach(nodeA, Files.createTempDirectory("madli-pub-d1")),
                    )
                val madliB =
                    MadliGossip.attach(
                        pubsubB,
                        NabuStorage.attach(nodeB, Files.createTempDirectory("madli-pub-d2")),
                    )
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val publisher =
                    MadliRelayReliabilityPublisher(
                        madliA,
                        identityA.secp256k1KeyPair,
                        { mapOf(relayId(1) to RelayReliabilityCounts(5, 4)) },
                        enabled = true,
                    )
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                var onB = madliB.currentVectorsForObservedPeer(relayId(1))
                while (onB.isEmpty() && Instant.now().isBefore(deadline)) {
                    publisher.publishForDay(100L)
                    Thread.sleep(500)
                    onB = madliB.currentVectorsForObservedPeer(relayId(1))
                }
                onB.single().relayMetrics shouldBe MadliRelayMetrics(800_000, 5)
                MadliDailyVector.verify(onB.single()) shouldBe true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }

        test("v2 vectors are accepted by the gossip validator, malformed v2 is Invalid, replays are deduplicated") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-pub-e"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val observer = identity.secp256k1KeyPair
                val index = MadliVectorIndex()

                val core = MadliDailyVector.create(observer, relayId(1), 100L, coreMetrics)
                val combined =
                    MadliDailyVector.create(
                        observer,
                        relayId(1),
                        100L,
                        coreMetrics,
                        MadliRelayMetrics(400_000, 3),
                    )
                MadliGossip.onGossipMessage(MadliDailyVectorCodec.encode(core), from, storage, index) shouldBe
                    ValidationResult.Valid
                // Same (observer, peer, day) tuple: the combined vector replaces the core-only one.
                val combinedBytes = MadliDailyVectorCodec.encode(combined)
                MadliGossip.onGossipMessage(combinedBytes, from, storage, index) shouldBe ValidationResult.Valid
                index.vectorsForObservedPeer(relayId(1)) shouldBe listOf(combined)
                // Byte-identical replay: declined as a duplicate.
                MadliGossip.onGossipMessage(combinedBytes, from, storage, index) shouldBe ValidationResult.Invalid

                // Malformed v2 (unknown flag bit) is Invalid and never indexed.
                val bad = combinedBytes.copyOf()
                bad[4 + 1 + 33 + 2 + 34 + 8] = 0x0B
                MadliGossip.onGossipMessage(bad, from, storage, index) shouldBe ValidationResult.Invalid
                index.vectorsForObservedPeer(relayId(1)).size shouldBe 1
            } finally {
                node.stop()
            }
        }
    })
