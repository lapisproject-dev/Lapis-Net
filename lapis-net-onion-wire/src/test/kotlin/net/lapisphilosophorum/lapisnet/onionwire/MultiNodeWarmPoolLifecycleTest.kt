@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
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
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.seconds

/** A system clock that can be moved forward (aging of idle warm circuits without waiting minutes). */
private class OffsetClock : Clock() {
    val offsetMillis = AtomicLong(0)

    override fun getZone(): ZoneId = ZoneId.of("UTC")

    override fun withZone(zone: ZoneId?): Clock = this

    override fun instant(): Instant = Instant.now().plusMillis(offsetMillis.get())
}

/**
 * Warm pool lifecycle on real nodes (wave V0.10.0-H): aging (stale circuits are dropped by maintenance and never handed
 * out), eviction of the oldest idle circuit, and a real build at a full governor pool that evicts a warm circuit instead
 * of failing with POOL_FULL.
 */
class MultiNodeWarmPoolLifecycleTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        val relays = List(6) { WireTestNode(relay = true).also { all += it } }
        val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { a.connectTo(it) }
        val locator = MapLocator()
        val prekeys = PrekeyStore.create(Files.createTempDirectory("warm-pool-test").resolve("prekeys"), a.identity)
        val modeStore = InMemoryDirectoryModeStore()
        lateinit var descriptors: List<OnionRelayDescriptor>
        val clock = OffsetClock()
        // a closed runtime locks its governor: every run gets a fresh one
        var governor = CircuitBuildGovernor(clock, ratePerMinute = 600, burst = 100)

        fun startA(): AnonymityRuntime {
            governor = CircuitBuildGovernor(clock, ratePerMinute = 600, burst = 100)
            return AnonymityRuntime.start(
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
                clock = clock,
                governor = governor,
                padding = TrafficPaddingConfig(cover = false),
            )
        }

        fun fillPool(r: AnonymityRuntime) =
            awaitTrue(Duration.ofSeconds(150)) {
                r.maintenanceTick()
                r.warmPoolForTest().size() >= r.warmPoolForTest().target
            }

        fun realBuild(purpose: CircuitPurpose) =
            a.wire
                .circuitFactory()
                .build(descriptors.take(3), 20.seconds, purpose)

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                descriptors.all { d ->
                    a.wire.descriptors.current(d.identity, System.currentTimeMillis() / 1000) != null
                }
            } shouldBe true
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(10 + i, i)) }
        }

        test("an idle warm circuit older than the maximum age is never handed out and is closed by maintenance")
            .config(timeout = 240.seconds) {
                val r = startA()
                try {
                    fillPool(r) shouldBe true
                    val pool = r.warmPoolForTest()
                    (pool.size() >= 1) shouldBe true
                    clock.offsetMillis.set(7 * 60_000L) // older than the 6 minute maximum idle age
                    try {
                        pool.take(CircuitPurpose.MAILBOX_PUBLISH) shouldBe null
                        (pool.size() >= 1) shouldBe true // take() does not discard, maintenance does
                        pool.maintain()
                        pool.size() shouldBe 0
                    } finally {
                        clock.offsetMillis.set(0)
                    }
                    awaitTrue(Duration.ofSeconds(30)) { governor.poolOpenCount() == 0 || pool.size() > 0 } shouldBe true
                    // a fresh circuit is handed out again once the pool refilled
                    fillPool(r) shouldBe true
                    val taken = pool.take(CircuitPurpose.MAILBOX_PUBLISH)
                    (taken != null) shouldBe true
                    taken!!.circuit.close()
                } finally {
                    r.close()
                }
            }

        test("evictOne closes the oldest idle warm circuit and reports false on an empty pool")
            .config(timeout = 240.seconds) {
                val r = startA()
                try {
                    fillPool(r) shouldBe true
                    val pool = r.warmPoolForTest()
                    val before = pool.size()
                    pool.evictOne() shouldBe true
                    pool.size() shouldBe before - 1
                    while (pool.evictOne()) Unit
                    pool.size() shouldBe 0
                    pool.evictOne() shouldBe false
                    awaitTrue(Duration.ofSeconds(30)) { governor.poolOpenCount() == 0 } shouldBe true
                } finally {
                    r.close()
                }
            }

        test("a real build at a full pool evicts warm circuits first, and fails with POOL_FULL only when none is left")
            .config(timeout = 300.seconds) {
                val r = startA()
                val real = ArrayList<OnionClientCircuit>()
                try {
                    fillPool(r) shouldBe true
                    val pool = r.warmPoolForTest()
                    val warmCount = pool.size()
                    val max = governor.maxOpenClientCircuits
                    // fill the rest of the governor pool with real circuits
                    repeat(max - warmCount) {
                        real +=
                            realBuild(CircuitPurpose.MAILBOX_PUBLISH).get(60, TimeUnit.SECONDS)
                    }
                    governor.poolOpenCount() shouldBe max
                    // each further real build takes the place of one warm circuit
                    repeat(warmCount) { i ->
                        real += realBuild(CircuitPurpose.MAILBOX_PUBLISH).get(60, TimeUnit.SECONDS)
                        pool.size() shouldBe warmCount - 1 - i
                    }
                    awaitTrue(Duration.ofSeconds(30)) { governor.poolOpenCount() == max } shouldBe true
                    // no warm circuit left: the pool is full of real circuits, the build is refused
                    val e = shouldFail { realBuild(CircuitPurpose.MAILBOX_PUBLISH).get(30, TimeUnit.SECONDS) }
                    ((e.cause as? CircuitAdmissionException)?.kind) shouldBe CircuitAdmissionException.Kind.POOL_FULL
                } finally {
                    real.forEach { runCatching { it.close() } }
                    r.close()
                }
            }
    })

private inline fun shouldFail(block: () -> Unit): ExecutionException =
    try {
        block()
        throw AssertionError("expected the call to fail")
    } catch (e: ExecutionException) {
        e
    }
