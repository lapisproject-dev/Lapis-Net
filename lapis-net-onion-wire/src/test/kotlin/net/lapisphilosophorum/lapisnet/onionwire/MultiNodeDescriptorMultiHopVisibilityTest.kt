@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.time.Duration
import java.util.concurrent.CopyOnWriteArraySet
import kotlin.time.Duration.Companion.seconds

/**
 * Multi-hop visibility of a service descriptor (wave I). Six relays in a full mesh; A (anonymity mode ON) publishes its
 * service descriptor through circuits; M (normal node, meshed with every relay) holds it BEFORE L exists; L starts
 * afterwards and is meshed ONLY with M.
 *
 * A byte-identical repeat of a descriptor is ignored by every node that already holds it (it is not forwarded), so a
 * late subscriber that sits behind such a node can only see the descriptor through a NEW signed version. The test
 * asserts that L sees A's descriptor within the window and that L never connected to any relay (otherwise the test is
 * invalid and fails instead of passing). Loopback with a synthetic locator, not real networks. The timeline goes to
 * stdout (timestamps and booleans only).
 */
private const val MESSAGE_CACHE_WINDOW_MILLIS = 12_000L

class MultiNodeDescriptorMultiHopVisibilityTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val relays = List(6) { WireTestNode(relay = true).also { all += it } }
        val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        val m = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach {
            a.connectTo(it)
            m.connectTo(it)
        }
        val scanner = AnonymityLeakScanner(a)
        val locator = MapLocator()
        val dir = Files.createTempDirectory("multihop-visibility-test")
        val prekeys = PrekeyStore.create(dir.resolve("prekeys"), a.identity)
        val modeStore =
            InMemoryDirectoryModeStore(
                DirectoryModeState(DirectoryAnonymityMode.OFF, System.currentTimeMillis() - 5000),
            )
        val serviceKey = Ed25519KeyPair.generate()
        lateinit var runtime: AnonymityRuntime
        lateinit var l: WireTestNode
        val lRemotes = CopyOnWriteArraySet<PeerId>()
        val t0 = System.currentTimeMillis()

        fun at() = "t+${(System.currentTimeMillis() - t0) / 1000}s"

        test("descriptors converge; A publishes; M holds A's service descriptor before L exists") {
            val descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                (relays + a + m).all { n ->
                    descriptors.all { d -> n.wire.descriptors.current(d.identity, now()) != null }
                }
            } shouldBe true
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(10 + i, i)) }
            runtime =
                AnonymityRuntime.start(
                    a.wire,
                    a.identity,
                    a.dir,
                    { null },
                    locator,
                    modeStore,
                    prekeys,
                    serviceKey,
                    { t -> a.peerDirectory.announce(t) },
                    a.supervisor,
                    governor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
                )
            awaitTrue(Duration.ofSeconds(200)) {
                runtime.maintenanceTick()
                m.wire.serviceDescriptors.current(serviceKey.publicKey, now()) != null
            } shouldBe true
            println("TIMELINE ${at()} M holds A's service descriptor")
        }

        test("L, meshed only with M, receives A's service descriptor without any restart of A").config(
            timeout = 300.seconds,
        ) {
            val first =
                m.wire.serviceDescriptors
                    .current(serviceKey.publicKey, now())
                    .shouldNotBeNull()
            // GossipSub keeps a validated message in its message cache for about 5 heartbeats (1 s each) and offers it
            // to new mesh peers via IHAVE. L must start AFTER that window, otherwise it would fetch the descriptor from
            // M's cache and the test would not exercise the republication path at all.
            Thread.sleep(MESSAGE_CACHE_WINDOW_MILLIS)
            l = WireTestNode(relay = false).also { all += it }
            l.node.addConnectionHandler(
                ConnectionHandler { conn: Connection -> lRemotes += conn.secureSession().remoteId },
            )
            l.connectTo(m)
            println("TIMELINE ${at()} L started, connected to M only")
            var last = false
            val seen =
                awaitTrue(Duration.ofSeconds(120)) {
                    runtime.maintenanceTick()
                    val d = l.wire.serviceDescriptors.current(serviceKey.publicKey, now())
                    val ok = d != null
                    if (ok != last) println("TIMELINE ${at()} L holds A's service descriptor=$ok")
                    last = ok
                    ok
                }
            println(
                "TIMELINE ${at()} done, seen=$seen, sameSequenceAsFirst=${
                    l.wire.serviceDescriptors
                        .current(serviceKey.publicKey, now())
                        ?.sequenceNumber == first.sequenceNumber
                }",
            )
            seen shouldBe true
        }

        test("L never connected to any relay (otherwise the topology of this test is invalid)") {
            lRemotes.toSet() shouldBe setOf(m.node.peerId)
            relays.none { it.node.peerId in lRemotes } shouldBe true
        }

        test("A's own gossip carries nothing but the address-free tombstone") {
            scanner.leaks(scanner.gossip.map { it.second }, scanner.addressNeedles()) shouldBe emptyList()
            runtime.close()
        }
    })
