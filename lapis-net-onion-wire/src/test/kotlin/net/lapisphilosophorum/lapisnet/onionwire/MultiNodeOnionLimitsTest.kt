package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.ClientCircuitBuilder
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionRelayLimits
import java.time.Clock
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalOnionApi::class)
class MultiNodeOnionLimitsTest :
    FunSpec({
        fun now() = Clock.systemUTC().millis() / 1000

        test("a CREATE flood is refused beyond the rate limit, the relay stays stable and usable") {
            val nodes = ArrayList<WireTestNode>()
            try {
                val limits =
                    OnionRelayLimits(
                        maxCircuitsTotal = 100,
                        maxCircuitsPerLink = 100,
                        createsPerSecondPerLink = 5,
                        createsPerSecondTotal = 1000,
                    )
                val r =
                    WireTestNode(relay = true, fastWireConfig(true, OnionWireConfig(relayLimits = limits))).also {
                        nodes +=
                            it
                    }
                val attacker = WireTestNode(relay = false).also { nodes += it }
                val honest = WireTestNode(relay = false).also { nodes += it }
                val links = attacker.wire.linksForTest()
                val link = links.linkTo(r.peerId, r.node.listenAddresses()).get(15, TimeUnit.SECONDS)
                val template = ClientCircuitBuilder(listOf(r.wire.currentDescriptor()!!.onionKeyBinding)).start().body
                repeat(100) { links.send(link, Cell(it + 1, CellCommand.CREATE, template)) }
                Thread.sleep(800)
                val count = r.wire.relayService!!.circuitCount()
                (count in 1..5) shouldBe true
                // another link is unaffected
                honest.connectTo(r)
                val client = honest.wire.diagnosticClient()
                client.build(listOf(r.wire.currentDescriptor()!!), 15.seconds).get(20, TimeUnit.SECONDS).close()
                client.close()
            } finally {
                nodes.forEach { it.close() }
            }
        }

        test("an extend to a relay without a verified descriptor is destroyed at once, nothing is left half-open") {
            val nodes = ArrayList<WireTestNode>()
            try {
                val c = WireTestNode(relay = false).also { nodes += it }
                val r1 = WireTestNode(relay = true).also { nodes += it }
                val stranger = WireTestNode(relay = true).also { nodes += it } // never connected to r1 or c
                c.connectTo(r1)
                val client = c.wire.diagnosticClient()
                val started = System.nanoTime()
                shouldThrow<ExecutionException> {
                    client
                        .build(listOf(r1.wire.currentDescriptor()!!, stranger.wire.currentDescriptor()!!), 20.seconds)
                        .get(25, TimeUnit.SECONDS)
                }
                ((System.nanoTime() - started) / 1_000_000_000L < 10) shouldBe true
                awaitTrue { r1.wire.relayService!!.circuitCount() == 0 } shouldBe true
                client.close()
            } finally {
                nodes.forEach { it.close() }
            }
        }

        test("an extend to an unreachable relay fails quickly and releases its state") {
            val nodes = ArrayList<WireTestNode>()
            try {
                val c = WireTestNode(relay = false).also { nodes += it }
                val r1 = WireTestNode(relay = true).also { nodes += it }
                c.connectTo(r1)
                // a relay with a valid descriptor whose only known address refuses connections
                val ghost = DualKeyIdentity.generate()
                val binding =
                    OnionKeyBinding.create(
                        ghost.secp256k1KeyPair,
                        X25519KeyPair.generate().publicKey,
                        now() + 86_400,
                    )
                val descriptor = OnionRelayDescriptor.create(ghost, binding, 0, now() + 3600, now())
                r1.wire.descriptors.add(descriptor, now())
                r1.peerDirectory.announce(
                    PeerRecord.create(ghost, listOf(Multiaddr("/ip4/127.0.0.1/tcp/1")), emptySet(), 0, now() + 3600),
                )
                val client = c.wire.diagnosticClient()
                shouldThrow<ExecutionException> {
                    client
                        .build(
                            listOf(r1.wire.currentDescriptor()!!, descriptor),
                            20.seconds,
                        ).get(25, TimeUnit.SECONDS)
                }
                awaitTrue { r1.wire.relayService!!.circuitCount() == 0 } shouldBe true
                client.close()
            } finally {
                nodes.forEach { it.close() }
            }
        }
    })
