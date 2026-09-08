package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayException
import net.lapisphilosophorum.lapisnet.networking.relay.RelayServerLimits
import java.time.Duration
import java.time.Instant
import java.util.Collections

private const val TEST_TOPIC = "lapis-net-test:circuit-relay:v1"

/**
 * Three real nodes, no mocks: **R** is an opt-in relay, **B** sits behind it, and **A** is only
 * ever told B's `/p2p-circuit` address. A and B are never connected to each other, never dial each
 * other's TCP listen address, and never learn it - the only thing they share is R.
 *
 * This is the end-to-end proof of the NAT-traversal wave: without a working circuit relay, A simply
 * cannot reach B at all (which is exactly what `TwoNodeDirectDialTest`'s "direct-dialable peers
 * only" model has always meant), and the first test here would fail at the dial. With it, A dials
 * *through* R, completes an end-to-end Noise handshake with B over the relayed byte pipe, and real
 * application traffic (a GossipSub publish) crosses that connection.
 *
 * Mirrors `MultiNodeDhtProviderDiscoveryTest`'s shape: real [LapisNode]s on loopback, explicit
 * wiring only, bounded polling against a deadline rather than fixed sleeps.
 */
class MultiNodeCircuitRelayTest :
    FunSpec({
        fun relayInfo(relay: LapisNode) = PeerInfo(relay.peerId, relay.directListenAddresses())

        // LapisNode.connect wraps the underlying failure, and the interesting detail (the relay's
        // refusal status) lives in the cause chain rather than the top-level message.
        fun causeChain(error: Throwable): String =
            generateSequence(error) { it.cause }.mapNotNull { it.message }.joinToString(" | ")

        test("B advertises a /p2p-circuit address once it holds a reservation on R") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                nodeB.listenAddresses().filter { it.has(Protocol.P2PCIRCUIT) }.shouldBeEmpty()

                val reservation = nodeB.relayClient.reserve(relayInfo(relay))
                reservation.relay shouldBe relay.peerId
                reservation.expiresAt.isAfter(Instant.now()) shouldBe true

                val circuitAddresses = nodeB.listenAddresses().filter { it.has(Protocol.P2PCIRCUIT) }
                circuitAddresses.shouldNotBeEmpty()
                // <relay tcp addr>/p2p/<relay>/p2p-circuit/p2p/<B> - the relay half names R, and the
                // address as a whole resolves to B.
                circuitAddresses.forEach { address ->
                    address.toString() shouldContain "/p2p-circuit/"
                    address.getPeerId() shouldBe relay.peerId
                    val trailingPeerIdBytes = address.components.last().value
                    trailingPeerIdBytes?.let { PeerId(it) } shouldBe nodeB.peerId
                }
                // Direct addresses are unaffected - a relayed address is additional reachability,
                // never a replacement.
                nodeB.directListenAddresses().shouldNotBeEmpty()
            } finally {
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("A reaches B through R alone, and real gossip traffic crosses the relayed connection") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // GossipSub must attach before any connection is made - see TwoNodeGossipPubSubTest.
                val gossipA = GossipPubSub.attach(nodeA)
                val gossipB = GossipPubSub.attach(nodeB)

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitAddress =
                    nodeB
                        .listenAddresses()
                        .first { it.has(Protocol.P2PCIRCUIT) }

                val received = Collections.synchronizedList(mutableListOf<Pair<ByteArray, PeerId>>())
                val subscriptionA =
                    gossipA.subscribe(TEST_TOPIC) { bytes, from ->
                        received.add(bytes to from)
                        ValidationResult.Valid
                    }
                val subscriptionB = gossipB.subscribe(TEST_TOPIC) { _, _ -> ValidationResult.Valid }

                // The ONLY address A is ever given for B is the relayed one. A holds no direct
                // address for B and never dials one.
                val connection = nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitAddress)), Duration.ofSeconds(45))

                // The Noise session is end to end between A and B: the relay carried ciphertext and
                // could not have impersonated either side.
                connection.secureSession().remoteId shouldBe nodeB.peerId
                connection.remoteAddress().has(Protocol.P2PCIRCUIT) shouldBe true

                val payload = "application bytes travelling through a circuit relay".toByteArray()
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                var delivered = received.toList()
                while (delivered.isEmpty() && Instant.now().isBefore(deadline)) {
                    runCatching { gossipB.publish(TEST_TOPIC, payload) }
                    Thread.sleep(500)
                    delivered = received.toList()
                }

                delivered.shouldNotBeEmpty()
                delivered.first().first shouldBe payload
                delivered.first().second shouldBe nodeB.peerId

                subscriptionA.unsubscribe()
                subscriptionB.unsubscribe()
                gossipA.stop()
                gossipB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("a node that did not opt in to the relay server role refuses to reserve for anyone") {
            // The single most important safety property of this wave: relaying is opt-in, and the
            // default is not it.
            val notARelay = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                notARelay.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val error = shouldThrow<RelayException> { nodeB.relayClient.reserve(relayInfo(notARelay)) }
                error.message shouldContain "PERMISSION_DENIED"
                nodeB.listenAddresses().filter { it.has(Protocol.P2PCIRCUIT) }.shouldBeEmpty()
            } finally {
                runCatching { nodeB.stop() }
                runCatching { notARelay.stop() }
            }
        }

        test("a relay refuses a circuit to a peer that holds no reservation") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // B never reserves, so A hand-builds the circuit address it would have had.
                val circuitAddress =
                    relay
                        .directListenAddresses()
                        .first()
                        .withComponent(Protocol.P2PCIRCUIT)
                        .withP2P(nodeB.peerId)

                val error =
                    shouldThrow<LapisNodeException> {
                        nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitAddress)), Duration.ofSeconds(45))
                    }
                causeChain(error) shouldContain "NO_RESERVATION"
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("B refuses an inbound circuit offered by a relay it holds no reservation with") {
            // The relay still has a server-side reservation for B (its TTL has not run out), so R
            // happily tries to open the circuit - but B dropped its own side, and B is the party
            // that decides whether an offered circuit is one it could have asked for.
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = RelayConfig.relayServer())
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitAddress = nodeB.listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }
                nodeB.relayClient.holdsReservationWith(relay.peerId) shouldBe true

                nodeB.relayClient.release(relay.peerId)
                nodeB.relayClient.holdsReservationWith(relay.peerId) shouldBe false

                val error =
                    shouldThrow<LapisNodeException> {
                        nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitAddress)), Duration.ofSeconds(45))
                    }
                causeChain(error) shouldContain "PERMISSION_DENIED"
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }

        test("a relay stops granting reservations once its configured slot budget is full") {
            val relay =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig = RelayConfig.relayServer(RelayServerLimits(maxConcurrentReservations = 1)),
                )
            val first = LapisNode.create(DualKeyIdentity.generate())
            val second = LapisNode.create(DualKeyIdentity.generate())
            try {
                relay.start(bootstrapPeers = emptyList())
                first.start(bootstrapPeers = emptyList())
                second.start(bootstrapPeers = emptyList())

                first.relayClient.reserve(relayInfo(relay))
                val error = shouldThrow<RelayException> { second.relayClient.reserve(relayInfo(relay)) }
                error.message shouldContain "RESERVATION_REFUSED"

                // Renewing an existing reservation must not be mistaken for a new slot request,
                // or a well-behaved client would start being refused as soon as the relay filled.
                first.relayClient.reserve(relayInfo(relay)).relay shouldBe relay.peerId
            } finally {
                runCatching { first.stop() }
                runCatching { second.stop() }
                runCatching { relay.stop() }
            }
        }
    })
