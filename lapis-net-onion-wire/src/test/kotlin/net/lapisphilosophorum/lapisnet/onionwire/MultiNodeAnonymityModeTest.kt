@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.EncryptedFileGuardStateStore
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardLoad
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds

/**
 * Real nodes on loopback: six relays in a full mesh, node A in anonymity mode ON (never a relay), node B in normal
 * mode. All relays sit on 127.0.0.1, which the real locator can not tell apart (every relay would be "unknown network"
 * and no diverse path exists), so the test injects a locator with synthetic, distinct /16 networks. Network diversity is
 * therefore verified only with that injected locator, NOT over real networks.
 */
class MultiNodeAnonymityModeTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val relays = List(6) { WireTestNode(relay = true).also { all += it } }
        val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        val b = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach {
            a.connectTo(it)
            b.connectTo(it)
        }
        val scanner = AnonymityLeakScanner(a)
        // wave J1a: the relays' own gossip, to see which of them published A's tombstone on its behalf
        val relayPeerRecords = CopyOnWriteArrayList<ByteArray>()
        relays.forEach { r ->
            r.pubsub.outboundTap = { topic, bytes ->
                if (topic == PeerDirectoryGossip.PEER_RECORD_GOSSIP_TOPIC) relayPeerRecords += bytes
            }
        }

        // what B receives on the peer-record topic (a second subscription; it never vetoes B's own validator)
        val tombstonesAtB = CopyOnWriteArrayList<PeerRecord>()
        b.pubsub.subscribe(PeerDirectoryGossip.PEER_RECORD_GOSSIP_TOPIC) { bytes, _ ->
            runCatching { PeerRecordCodec.decode(bytes) }
                .getOrNull()
                ?.takeIf { it.identity == a.key && it.addresses.isEmpty() }
                ?.let { tombstonesAtB += it }
            ValidationResult.Valid
        }

        fun relayedTombstonesOfA(): List<PeerRecord> =
            relayPeerRecords
                .mapNotNull { runCatching { PeerRecordCodec.decode(it) }.getOrNull() }
                .filter { it.identity == a.key && it.addresses.isEmpty() }
        val locator = MapLocator()
        val dir = Files.createTempDirectory("anonymity-mode-test")
        val prekeys = PrekeyStore.create(dir.resolve("prekeys"), a.identity)
        val modeStore =
            InMemoryDirectoryModeStore(
                DirectoryModeState(
                    DirectoryAnonymityMode.OFF,
                    System.currentTimeMillis() - 5000,
                ),
            )
        val serviceKey = Ed25519KeyPair.generate()
        lateinit var runtime: AnonymityRuntime

        test("descriptors converge, then A starts anonymity mode") {
            val descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                (relays + a + b).all { n ->
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
                    // the production path (no tombstone seam): the tombstone goes through a circuit to a relay
                    supervisor = a.supervisor,
                    governor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
                )
            runtime.status().mode shouldBe "on"
            runtime.status().incomplete shouldBe true
        }

        test(
            "A publishes presence through circuits over its persisted guard, and B resolves A as hidden",
        ).config(timeout = 240.seconds) {
            awaitTrue(Duration.ofSeconds(200)) {
                runtime.maintenanceTick()
                runtime.publications() >= 1
            } shouldBe true
            // the OFF-to-ON transition really happened on the production path: a relay published the address-free
            // tombstone of A before the anonymous record, and the mode is persisted as ON only after that
            relayedTombstonesOfA().isEmpty() shouldBe false
            modeStore.load()!!.mode shouldBe DirectoryAnonymityMode.ON
            // the relay's publication reached the mesh: B (normal mode) received A's address-free tombstone over
            // gossip, which retires A's old address-bearing record on peers that never see the anonymous record
            awaitTrue(Duration.ofSeconds(60)) { tombstonesAtB.isNotEmpty() } shouldBe true
            tombstonesAtB.first().sequenceNumber shouldBe relayedTombstonesOfA().first().sequenceNumber
            awaitTrue(Duration.ofSeconds(90)) {
                b.wire.anonymousDirectory().resolve(a.key) is DirectoryReachability.Hidden
            } shouldBe true
            b.wire
                .anonymousDirectory()
                .resolve(a.key)
                .shouldBeInstanceOf<DirectoryReachability.Hidden>()
            val status = runtime.status()
            status.guards shouldBe 2
            status.lastError.wire shouldBe "none"

            // the first hop of every circuit is the guard: A holds exactly one onion link, to the guard
            val guardFile = a.dir.resolve("onion").resolve("guards.bin")
            Files.exists(guardFile) shouldBe true
            EncryptedFileGuardStateStore(guardFile, a.identity).use { store ->
                val loaded = store.load().shouldBeInstanceOf<GuardLoad.Loaded>()
                relays.map { it.key }.contains(loaded.state.primary!!.identity) shouldBe true
            }
            a.wire.linkCount() shouldBe 1
        }

        test(
            "A publishes nothing from its own node, not even the tombstone, and the tombstone carries no address",
        ) {
            // wave J1a: the tombstone went through a circuit, so A's own outbound gossip stays empty
            scanner.gossip.size shouldBe 0
            val relayed = relayedTombstonesOfA()
            relayed.isEmpty() shouldBe false
            scanner.leaks(relayed.map { PeerRecordCodec.encode(it) }, scanner.addressNeedles()) shouldBe emptyList()
        }

        test("stopping sends DESTROY: the relays keep no circuit of A, and a restart reuses the same guard") {
            val guardFile = a.dir.resolve("onion").resolve("guards.bin")
            val before =
                EncryptedFileGuardStateStore(
                    guardFile,
                    a.identity,
                ).use { (it.load() as GuardLoad.Loaded).state.primary!!.identity }
            runtime.close()
            awaitTrue(Duration.ofSeconds(30)) { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe
                true
            runtime.status().activeCircuits shouldBe 0
            val second =
                AnonymityRuntime.start(
                    a.wire,
                    a.identity,
                    a.dir,
                    { null },
                    locator,
                    modeStore,
                    prekeys,
                    Ed25519KeyPair.generate(),
                    supervisor = a.supervisor,
                    governor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
                )
            try {
                EncryptedFileGuardStateStore(guardFile, a.identity).use {
                    (it.load() as GuardLoad.Loaded).state.primary!!.identity shouldBe before
                }
            } finally {
                second.close()
            }
        }
    })
