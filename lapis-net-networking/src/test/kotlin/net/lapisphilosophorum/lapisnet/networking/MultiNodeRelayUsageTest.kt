package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Protocol
import io.libp2p.protocol.Ping
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.NodeReachability
import net.lapisphilosophorum.lapisnet.networking.relay.RelayCandidateRanker
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayReliabilityCounts
import java.time.Duration
import java.time.Instant
import java.util.concurrent.TimeUnit

/**
 * Real nodes, no mocks: the relay's usage ledger sees the bytes of a real circuit ("receiver pays"),
 * the endpoints credit the relay, reliability is observed on the client side, and the automatic
 * relay selection gets a PRIVATE node onto a relay on its own.
 */
class MultiNodeRelayUsageTest :
    FunSpec({
        fun relayInfo(relay: LapisNode) = PeerInfo(relay.peerId, relay.directListenAddresses())

        fun today(): Long = Math.floorDiv(Instant.now().toEpochMilli(), 86_400_000L)

        test("a real circuit debits both endpoints on the relay and credits the relay on both endpoints") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitAddress = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }

                val connection =
                    connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuitAddress)), relay = relay)
                nodeA.host.addProtocolHandler(Ping())
                nodeB.host.addProtocolHandler(Ping())
                repeat(5) {
                    Ping()
                        .dial(nodeA.host, nodeB.peerId, circuitAddress)
                        .controller
                        .get(30, TimeUnit.SECONDS)
                        .ping()
                        .get(30, TimeUnit.SECONDS)
                }
                connection.close().get(30, TimeUnit.SECONDS)

                // Nothing is settled while the circuit lives; it is booked exactly once at the end.
                awaitTrue(Duration.ofSeconds(30)) {
                    relay.relayUsageBalance(nodeA.peerId) < 0 && relay.relayUsageBalance(nodeB.peerId) < 0
                } shouldBe true
                val a = relay.relayUsageBalance(nodeA.peerId)
                val b = relay.relayUsageBalance(nodeB.peerId)
                // At least the Noise handshakes crossed the circuit in each direction ...
                (-a) shouldBeGreaterThan 200L
                (-b) shouldBeGreaterThan 200L
                // ... and nothing close to a megabyte did.
                (-a) shouldBeLessThan 1_000_000L
                (-b) shouldBeLessThan 1_000_000L

                // The endpoints credit the relay for what it carried to them.
                awaitTrue(Duration.ofSeconds(30)) {
                    nodeA.relayUsageBalance(relay.peerId) > 0 && nodeB.relayUsageBalance(relay.peerId) > 0
                } shouldBe true

                // Booked once: the numbers do not move any more.
                awaitStably(Duration.ofSeconds(5), Duration.ofSeconds(2)) {
                    relay.relayUsageBalance(nodeA.peerId) == a && relay.relayUsageBalance(nodeB.peerId) == b
                } shouldBe true
                relay.relayUsageSnapshot().keys shouldContain nodeA.peerId
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("an abruptly stopped endpoint still gets the circuit booked exactly once") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitAddress = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuitAddress)), relay = relay)

                nodeB.stop() // tears the circuit down from the target side

                awaitTrue(Duration.ofSeconds(30)) { relay.relayCircuitCount() == 0 } shouldBe true
                awaitTrue(Duration.ofSeconds(30)) { relay.relayUsageBalance(nodeA.peerId) < 0 } shouldBe true
                val a = relay.relayUsageBalance(nodeA.peerId)
                awaitStably(
                    Duration.ofSeconds(5),
                    Duration.ofSeconds(2),
                ) { relay.relayUsageBalance(nodeA.peerId) == a } shouldBe
                    true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("reservations and outgoing circuit dials are counted as reliability attempts against the relay") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitAddress = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuitAddress)), relay = relay)

                nodeB.relayReliabilityCounts(today())[relay.peerId] shouldBe RelayReliabilityCounts(1, 1)
                nodeA.relayReliabilityCounts(today())[relay.peerId] shouldBe RelayReliabilityCounts(1, 1)
                relay.relayReliabilityCounts(today()).size shouldBe 0
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("a PRIVATE node gets itself a relay reservation through startAutoRelay, ranked by the injected ranker") {
            val relay1 = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val relay2 = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val config =
                RelayConfig(
                    reachability = NodeReachability.PRIVATE,
                    autoRelay = AutoRelayConfig(targetRelayCount = 1, allowNonPublicCandidateAddresses = true),
                )
            val nodeB = LapisNode.create(DualKeyIdentity.generate(), relayConfig = config)
            try {
                relay1.start(bootstrapPeers = emptyList())
                relay2.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // The ranker prefers relay2 although the directory lists relay1 first.
                val ranker = RelayCandidateRanker { list -> list.sortedByDescending { it.peerId == relay2.peerId } }
                val selector = nodeB.startAutoRelay({ listOf(relayInfo(relay1), relayInfo(relay2)) }, ranker)
                selector.isRunning() shouldBe true

                awaitTrue(Duration.ofSeconds(30)) { nodeB.relayClient.reservations().isNotEmpty() } shouldBe true
                nodeB.relayClient.reservations().map { it.relay } shouldBe listOf(relay2.peerId)
                nodeB.listenAddresses().filter { it.has(Protocol.P2PCIRCUIT) } shouldHaveSize 1
            } finally {
                runCatching { nodeB.stop() }
                runCatching { relay1.stop() }
                runCatching { relay2.stop() }
            }
        }

        test("startAutoRelay on a node that is not declared PRIVATE does not reserve anything") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val node =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig = RelayConfig(autoRelay = AutoRelayConfig(allowNonPublicCandidateAddresses = true)),
                )
            try {
                relay.start(bootstrapPeers = emptyList())
                node.start(bootstrapPeers = emptyList())
                val selector = node.startAutoRelay({ listOf(relayInfo(relay)) })
                selector.isRunning() shouldBe false
                Thread.sleep(1_000)
                node.relayClient.reservations().size shouldBe 0
            } finally {
                runCatching { node.stop() }
                runCatching { relay.stop() }
            }
        }

        test("stopping the node stops the selector") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val config =
                RelayConfig(
                    reachability = NodeReachability.PRIVATE,
                    autoRelay = AutoRelayConfig(allowNonPublicCandidateAddresses = true),
                )
            val node = LapisNode.create(DualKeyIdentity.generate(), relayConfig = config)
            try {
                relay.start(bootstrapPeers = emptyList())
                node.start(bootstrapPeers = emptyList())
                val selector = node.startAutoRelay({ listOf(relayInfo(relay)) })
                selector.isRunning() shouldBe true
                node.stop()
                selector.isRunning() shouldBe false
            } finally {
                runCatching { node.stop() }
                runCatching { relay.stop() }
            }
        }
    })
