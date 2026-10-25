@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.seconds

/**
 * Real nodes on loopback (wave V0.10.0-H): six relays, node A in anonymity mode with cover, slicing and the warm pool.
 * The relays sit on 127.0.0.1, so a locator with synthetic /16 networks is injected (diversity is verified only with it).
 */
class MultiNodeTrafficPaddingTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        val relays = List(6) { WireTestNode(relay = true).also { all += it } }
        val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { a.connectTo(it) }
        val locator = MapLocator()
        val prekeys = PrekeyStore.create(Files.createTempDirectory("padding-test").resolve("prekeys"), a.identity)
        val modeStore = InMemoryDirectoryModeStore()

        fun startA(padding: TrafficPaddingConfig) =
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
                padding = padding,
            )

        test("descriptors converge") {
            val ds = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                ds.all { d -> a.wire.descriptors.current(d.identity, System.currentTimeMillis() / 1000) != null }
            } shouldBe true
            ds.forEachIndexed { i, d -> locator.put(d, v4(10 + i, i)) }
        }

        test(
            "cover cells flow, the warm pool fills, a warm circuit is handed out once, and the circuits survive the DROPs",
        ).config(timeout = 240.seconds) {
            val cells = AtomicInteger()
            a.wire.linksForTest().egressTapForTest = { _, _ -> cells.incrementAndGet() }
            val padding =
                TrafficPaddingConfig(
                    coverMeanIntervalMillis = 200,
                    coverBudgetBytesPerSecond = 16_384,
                    coverBudgetBurstCells = 100,
                )
            val r = startA(padding)
            try {
                r.status().padding shouldBe "standard"
                awaitTrue(Duration.ofSeconds(150)) {
                    r.maintenanceTick()
                    r.warmPoolForTest().size() >= 1 && r.status().coverCellsSent >= 5
                } shouldBe true
                (r.warmPoolForTest().buildsStarted() >= 1) shouldBe true
                // every build was a real, admitted build: never more warm circuits than the target
                (r.warmPoolForTest().size() <= r.warmPoolForTest().target) shouldBe true
                val taken = r.warmPoolForTest().take(CircuitPurpose.MAILBOX_PUBLISH)
                (taken != null) shouldBe true
                // a taken circuit is no longer in the pool: one use only
                val sizeAfter = r.warmPoolForTest().size()
                r
                    .warmPoolForTest()
                    .take(CircuitPurpose.MAILBOX_PUBLISH)
                    ?.circuit
                    ?.close()
                (r.warmPoolForTest().size() <= sizeAfter) shouldBe true
                taken!!.circuit.close()
                // the relays kept their circuits although they received many DROPs
                (relays.sumOf { it.wire.relayService!!.circuitCount() } > 0) shouldBe true
                (cells.get() > 0) shouldBe true
            } finally {
                r.close()
            }
            val frozen = r.status().coverCellsSent
            r.shaperForTest()!!.queuedCells() shouldBe 0
            r.shaperForTest()!!.timerPending() shouldBe false
            r.coverForTest()!!.timerPending() shouldBe false
            r.warmPoolForTest().size() shouldBe 0
            Thread.sleep(600)
            r.status().coverCellsSent shouldBe frozen
            awaitTrue(Duration.ofSeconds(30)) { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe
                true
            a.wire.linksForTest().egress shouldBe null
            a.wire.linksForTest().egressTapForTest = null
        }

        test("padding off: no shaper, no cover, status says off, and a restart on the same directory works") {
            val r = startA(TrafficPaddingConfig.OFF)
            try {
                r.status().padding shouldBe "off"
                (r.shaperForTest() == null) shouldBe true
                (r.coverForTest() == null) shouldBe true
                a.wire.linksForTest().egress shouldBe null
            } finally {
                r.close()
            }
            startA(TrafficPaddingConfig.STANDARD).close()
        }

        test("a relay node never gets an egress shaper") {
            val relay = relays[0]
            val ex = runCatching { relay.wire.installEgressShaper(TrafficPaddingConfig.STANDARD) { _, _ -> } }
            (ex.exceptionOrNull() is IllegalStateException) shouldBe true
            relay.wire.linksForTest().egress shouldBe null
        }
    })
