package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.libp2p.core.Connection
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import java.time.Duration
import java.time.Instant

private fun relayInfo(relay: LapisNode) = PeerInfo(relay.peerId, relay.directListenAddresses())

private fun LapisNode.directInfo() = PeerInfo(peerId, directListenAddresses())

/** [LapisNode.connect] must be handed the relayed connection A opened to B, not dial a second one.
 * `track()` registers an accepted connection only after the connection handlers ran, so callers poll. */
private fun awaitAccepted(
    node: LapisNode,
    peer: PeerId,
): Connection {
    val deadline = Instant.now().plusSeconds(30)
    while (Instant.now().isBefore(deadline)) {
        node.relayTransport.liveConnectionTo(peer)?.let { return it }
        Thread.sleep(20)
    }
    error("no accepted relayed connection from $peer appeared within 30 s")
}

private fun LapisNode.tableEntriesFor(peer: PeerId): List<Connection> =
    host.network.connections.filter { it.secureSession().remoteId == peer }

/**
 * Real nodes, no mocks. A reaches B only through the relay R; B - which accepted that relayed
 * connection through the stop protocol, so `NetworkImpl` does not know about it - then wants to talk
 * to A. Before the fix `LapisNode.connect` could not see the accepted connection and dialled A a
 * second time; now it hands back the existing one.
 */
class MultiNodeRelayConnectionReuseTest :
    FunSpec({
        test("connect() on the destination returns the relayed connection the peer already opened, not a second one") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(
                    nodeA,
                    PeerInfo(nodeB.peerId, listOf(circuitToB)),
                    relay = relay,
                    step = "A dials B through R",
                )

                val accepted = awaitAccepted(nodeB, nodeA.peerId)
                // The premise: NetworkImpl never saw it.
                nodeB.tableEntriesFor(nodeA.peerId) shouldBe emptyList()

                // B is handed A's DIRECT addresses - the old behaviour dialled one of them.
                val reused = nodeB.connect(nodeA.directInfo(), Duration.ofSeconds(45))

                reused shouldBeSameInstanceAs accepted
                reused.remoteAddress().has(Protocol.P2PCIRCUIT) shouldBe true
                reused.secureSession().remoteId shouldBe nodeA.peerId
                // Nothing new was dialled, on either side: B still has no table entry for A, and A
                // still holds exactly its one (relayed) connection to B.
                Thread.sleep(500)
                nodeB.tableEntriesFor(nodeA.peerId) shouldBe emptyList()
                val aToB = nodeA.tableEntriesFor(nodeB.peerId)
                aToB.size shouldBe 1
                aToB.single().remoteAddress().has(Protocol.P2PCIRCUIT) shouldBe true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("a closed relayed connection is not handed out - connect() dials afresh") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(
                    nodeA,
                    PeerInfo(nodeB.peerId, listOf(circuitToB)),
                    relay = relay,
                    step = "A dials B through R",
                )
                val accepted = awaitAccepted(nodeB, nodeA.peerId)

                accepted.close().get()
                accepted.closeFuture().get()

                val fresh = nodeB.connect(nodeA.directInfo(), Duration.ofSeconds(45))

                (fresh === accepted) shouldBe false
                fresh.closeFuture().isDone shouldBe false
                fresh.remoteAddress().has(Protocol.P2PCIRCUIT) shouldBe false
                fresh.secureSession().remoteId shouldBe nodeA.peerId
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("the match is on the authenticated peer id - another peer's relayed connection is never returned") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(
                    nodeA,
                    PeerInfo(nodeB.peerId, listOf(circuitToB)),
                    relay = relay,
                    step = "A dials B through R",
                )
                connectDiagnosed(
                    nodeC,
                    PeerInfo(nodeB.peerId, listOf(circuitToB)),
                    relay = relay,
                    step = "C dials B through R",
                )
                val fromA = awaitAccepted(nodeB, nodeA.peerId)
                val fromC = awaitAccepted(nodeB, nodeC.peerId)
                (fromA === fromC) shouldBe false

                val forA = nodeB.connect(nodeA.directInfo(), Duration.ofSeconds(45))
                val forC = nodeB.connect(nodeC.directInfo(), Duration.ofSeconds(45))

                forA shouldBeSameInstanceAs fromA
                forC shouldBeSameInstanceAs fromC
                forA.secureSession().remoteId shouldBe nodeA.peerId
                forC.secureSession().remoteId shouldBe nodeC.peerId
                nodeB.relayTransport.liveConnectionTo(relay.peerId) shouldBe null
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
                runCatching { relay.stop() }
            }
        }

        test("an existing direct connection is preferred over an accepted relayed one") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                connectDiagnosed(
                    nodeA,
                    PeerInfo(nodeB.peerId, listOf(circuitToB)),
                    relay = relay,
                    step = "A dials B through R",
                )
                val relayed = awaitAccepted(nodeB, nodeA.peerId)

                // Go around LapisNode.connect (which would now reuse the relayed one) to get B a real
                // direct connection to A as well.
                val direct =
                    nodeB.host.network
                        .connect(nodeA.peerId, *nodeA.directListenAddresses().toTypedArray())
                        .get(45, java.util.concurrent.TimeUnit.SECONDS)
                direct.remoteAddress().has(Protocol.P2PCIRCUIT) shouldBe false

                val chosen = nodeB.connect(nodeA.directInfo(), Duration.ofSeconds(45))

                chosen shouldBeSameInstanceAs direct
                (chosen === relayed) shouldBe false
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }
    })
