package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.Connection
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.pubsub.ValidationResult
import io.libp2p.protocol.IdentifyController
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchConfig
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.networking.transport.ReusePortSupport
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.TimeUnit

private fun punchConfig(mode: HolePunchMode = HolePunchMode.ON) =
    HolePunchConfig(
        mode = mode,
        allowNonPublicAddresses = true,
        relayCloseGrace = Duration.ofSeconds(2),
        punchTimeout = Duration.ofSeconds(10),
    )

private fun directConnectionTo(
    node: LapisNode,
    peer: PeerId,
): Connection? =
    node.host.network.connections.firstOrNull {
        it.secureSession().remoteId == peer && !it.closeFuture().isDone && !it.remoteAddress().has(Protocol.P2PCIRCUIT)
    }

/**
 * Real nodes on loopback: **R** is a relay, **A** and **B** are connected only through R. B accepts the
 * relayed connection and starts DCUtR; both then dial each other from their listener ports.
 *
 * Loopback proves the protocol, the role handling and the identity checks - NOT that a punch survives
 * a real home router or CGNAT, which this project has never been able to test.
 */
class MultiNodeHolePunchTest :
    FunSpec({
        fun relayInfo(relay: LapisNode) = PeerInfo(relay.peerId, relay.directListenAddresses())

        test("a relayed connection is replaced by a direct one, and the relayed one is released") {
            if (!ReusePortSupport.available) return@test
            val relay =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig = RelayConfig.relayServer(),
                    holePunchConfig = HolePunchConfig(mode = HolePunchMode.AUTO),
                )
            val nodeA = LapisNode.create(DualKeyIdentity.generate(), holePunchConfig = punchConfig())
            val nodeB = LapisNode.create(DualKeyIdentity.generate(), holePunchConfig = punchConfig())
            try {
                relay.start()
                nodeA.start()
                nodeB.start()
                nodeB.relayClient.reserve(relayInfo(relay))
                nodeA.relayClient.reserve(relayInfo(relay))
                val circuit = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }

                val relayed = connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuit)), relay = relay)
                relayed.remoteAddress().has(Protocol.P2PCIRCUIT) shouldBe true

                awaitTrue(Duration.ofSeconds(30)) {
                    directConnectionTo(nodeA, nodeB.peerId) != null && directConnectionTo(nodeB, nodeA.peerId) != null
                } shouldBe true

                val direct = directConnectionTo(nodeA, nodeB.peerId)!!
                direct.secureSession().remoteId shouldBe nodeB.peerId
                // The muxer roles agree: a stream opened on the punched connection is answered.
                val promise = nodeA.host.newStream<IdentifyController>(listOf("/ipfs/id/1.0.0"), direct)
                promise.controller
                    .get(10, TimeUnit.SECONDS)
                    .id()
                    .get(10, TimeUnit.SECONDS) shouldNotBe null

                awaitTrue(Duration.ofSeconds(20)) { relayed.closeFuture().isDone } shouldBe true
                nodeA.liveConnectionTo(nodeB.peerId)?.remoteAddress()?.has(Protocol.P2PCIRCUIT) shouldBe false
                nodeB.holePunching!!.status().succeeded shouldBe 1L
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("with hole punching off there is no dcutr and the relayed connection stays") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start()
                nodeA.start()
                nodeB.start()
                nodeB.holePunching shouldBe null
                nodeB.relayClient.reserve(relayInfo(relay))
                val circuit = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                val relayed = connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuit)), relay = relay)
                Thread.sleep(1500)
                relayed.closeFuture().isDone shouldBe false
                nodeA.host.network.connections
                    .filter {
                        it.secureSession().remoteId == nodeB.peerId &&
                            !it.remoteAddress().has(Protocol.P2PCIRCUIT)
                    }.shouldBeEmpty()
                nodeA.host
                    .getProtocols()
                    .none { it.protocolDescriptor.announceProtocols.contains("/libp2p/dcutr") } shouldBe true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test(
            "a peer without hole punching leaves the relayed connection alone and the failure is counted with a backoff",
        ) {
            if (!ReusePortSupport.available) return@test
            val relay =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig = RelayConfig.relayServer(),
                    holePunchConfig = HolePunchConfig(mode = HolePunchMode.AUTO),
                )
            val nodeA = LapisNode.create(DualKeyIdentity.generate()) // library default: no dcutr
            val nodeB = LapisNode.create(DualKeyIdentity.generate(), holePunchConfig = punchConfig())
            try {
                relay.start()
                nodeA.start()
                nodeB.start()
                nodeB.relayClient.reserve(relayInfo(relay))
                val circuit = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                val relayed = connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuit)), relay = relay)
                awaitTrue(Duration.ofSeconds(20)) { nodeB.holePunching!!.status().failed == 1L } shouldBe true
                nodeB.holePunching!!.status().succeeded shouldBe 0L
                relayed.closeFuture().isDone shouldBe false
                directConnectionTo(nodeA, nodeB.peerId) shouldBe null
                // still the connection every caller gets
                nodeA.liveConnectionTo(nodeB.peerId)?.remoteAddress()?.has(Protocol.P2PCIRCUIT) shouldBe true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("stopping the nodes leaves no hole-punch timer thread behind") {
            if (!ReusePortSupport.available) return@test
            awaitTrue(Duration.ofSeconds(10)) {
                Thread.getAllStackTraces().keys.none { it.name == "lapis-holepunch" && it.isAlive }
            } shouldBe true
        }

        test("gossip keeps working across the switch from the relayed to the direct connection, without duplicates") {
            if (!ReusePortSupport.available) return@test
            val relay =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig = RelayConfig.relayServer(),
                    holePunchConfig = HolePunchConfig(mode = HolePunchMode.AUTO),
                )
            val nodeA = LapisNode.create(DualKeyIdentity.generate(), holePunchConfig = punchConfig())
            val nodeB = LapisNode.create(DualKeyIdentity.generate(), holePunchConfig = punchConfig())
            try {
                relay.start()
                nodeA.start()
                nodeB.start()
                val gossipA = GossipPubSub.attach(nodeA)
                val gossipB = GossipPubSub.attach(nodeB)
                val received = Collections.synchronizedList(mutableListOf<String>())
                gossipA.subscribe("lapis-net-test:holepunch:v1") { bytes, _ ->
                    received.add(String(bytes))
                    ValidationResult.Valid
                }
                gossipB.subscribe("lapis-net-test:holepunch:v1") { _, _ -> ValidationResult.Valid }
                nodeB.relayClient.reserve(relayInfo(relay))
                nodeA.relayClient.reserve(relayInfo(relay))
                val circuit = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(nodeA, PeerInfo(nodeB.peerId, listOf(circuit)), relay = relay)
                awaitTrue(Duration.ofSeconds(30)) {
                    nodeA.liveConnectionTo(nodeB.peerId)?.remoteAddress()?.has(Protocol.P2PCIRCUIT) == false
                } shouldBe true
                Thread.sleep(3000) // let the mesh settle on the direct connection
                val deadline = Instant.now().plusSeconds(30)
                var n = 0
                while (received.none { it.startsWith("after-punch") } && Instant.now().isBefore(deadline)) {
                    runCatching { gossipB.publish("lapis-net-test:holepunch:v1", "after-punch-${n++}".toByteArray()) }
                    Thread.sleep(500)
                }
                (received.any { it.startsWith("after-punch") }) shouldBe true
                Thread.sleep(2000)
                // every published message arrived exactly once
                received
                    .groupingBy { it }
                    .eachCount()
                    .values
                    .all { it == 1 } shouldBe true
                gossipA.stop()
                gossipB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }
    })
