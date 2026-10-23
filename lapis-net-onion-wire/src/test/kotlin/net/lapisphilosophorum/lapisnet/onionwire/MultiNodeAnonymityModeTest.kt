@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
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
        var tombstone: PeerRecord? = null
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
                    { t ->
                        tombstone = t
                        a.peerDirectory.announce(t)
                    },
                    a.supervisor,
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
            "the leak scanner finds nothing of A's addresses or transport identity outside the address-free tombstone",
        ) {
            val t = tombstone.shouldNotBeNull()
            val tombstoneBytes = PeerRecordCodec.encode(t)
            scanner.gossip.size shouldBe 1
            scanner.gossip
                .single()
                .second
                .contentEquals(tombstoneBytes) shouldBe true
            scanner.leaks(scanner.gossip.map { it.second }, scanner.addressNeedles()) shouldBe emptyList()
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
                    { },
                    a.supervisor,
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
