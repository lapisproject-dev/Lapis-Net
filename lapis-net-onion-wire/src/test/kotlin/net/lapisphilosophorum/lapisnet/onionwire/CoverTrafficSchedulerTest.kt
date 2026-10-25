package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.plusOrMinus
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.CoverBudget
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.CoverTrafficScheduler
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList

/** The cover schedule, budget and shutdown behaviour (wave V0.10.0-H), on a manual clock. */
class CoverTrafficSchedulerTest :
    FunSpec({
        class FakeCircuit(
            override val linkId: LinkId = LinkId(1),
            private val hops: Int = 3,
        ) : CoverCircuit {
            @Volatile override var isClosed = false
            val drops = CopyOnWriteArrayList<Pair<Long, Int>>()
            var clock: WireTestClock? = null

            override fun hopCount() = hops

            override fun sendDrop(targetHop: Int): Boolean {
                drops += (clock?.millis() ?: 0L) to targetHop
                return true
            }
        }

        fun rig(
            config: TrafficPaddingConfig,
            circuits: List<FakeCircuit>,
            budget: (WireTestClock) -> CoverBudget = {
                CoverBudget(config.coverBudgetBytesPerSecond, config.coverBudgetBurstCells, it)
            },
        ): Triple<CoverTrafficScheduler, ManualSliceTimer, WireTestClock> {
            val clock = WireTestClock(5_000_000L)
            circuits.forEach { it.clock = clock }
            val timer = ManualSliceTimer(clock)
            return Triple(
                CoverTrafficScheduler(config, { circuits }, timer, budget(clock), SecureRandom()),
                timer,
                clock,
            )
        }

        test(
            "over 10000 simulated seconds the mean interval is the base rate and every interval stays in the jitter bounds",
        ) {
            val config = TrafficPaddingConfig(coverBudgetBytesPerSecond = 16_384, coverBudgetBurstCells = 1000)
            val c = FakeCircuit()
            val (s, timer, clock) = rig(config, listOf(c))
            s.start()
            timer.advanceBy(10_000_000L)
            val times = c.drops.map { it.first }
            val gaps = times.zipWithNext { a, b -> b - a }
            (gaps.size > 1000) shouldBe true
            gaps.all { it in 2_000L..6_000L } shouldBe true
            gaps.average() shouldBe (4_000.0 plusOrMinus 120.0)
            clock.millis() shouldBe 15_000_000L
        }

        test("the cover cell goes to hop 2 of an own circuit, never to the guard, and nothing is built") {
            val config = TrafficPaddingConfig()
            val c = FakeCircuit(hops = 3)
            val short = FakeCircuit(LinkId(2), hops = 1)
            val (s, timer, _) = rig(config, listOf(c, short))
            s.start()
            timer.advanceBy(600_000L)
            c.drops.isNotEmpty() shouldBe true
            c.drops.all { it.second == 2 } shouldBe true
            short.drops.isEmpty() shouldBe true // a one hop circuit would show the cover to its guard
        }

        test("without a circuit nothing is sent and the schedule keeps running without effect") {
            val (s, timer, _) = rig(TrafficPaddingConfig(), emptyList())
            s.start()
            timer.advanceBy(100_000L)
            s.sentCount() shouldBe 0L
            s.suppressedCount() shouldBe 0L
        }

        test(
            "the budget caps the cover: sent never exceeds budget times time plus burst, the rest is counted as suppressed",
        ) {
            // 1 KiB/s allows one cell per second, burst 2; the mean interval of 100 ms would send 10 per second
            val config =
                TrafficPaddingConfig(
                    coverMeanIntervalMillis = 100,
                    coverBudgetBytesPerSecond = 1024,
                    coverBudgetBurstCells = 2,
                )
            val c = FakeCircuit()
            val (s, timer, _) = rig(config, listOf(c))
            s.start()
            timer.advanceBy(100_000L)
            (s.sentCount() <= 100L + 2L) shouldBe true
            (s.sentCount() >= 90L) shouldBe true
            (s.suppressedCount() > 0L) shouldBe true
        }

        test("a spent budget never touches real traffic: the budget has no entry point for real cells") {
            val clock = WireTestClock()
            val b = CoverBudget(1024, 1, clock)
            b.tryAcquireCell() shouldBe true
            b.tryAcquireCell() shouldBe false
            clock.millis += 1000
            b.tryAcquireCell() shouldBe true
        }

        test("cover = false in the config is the caller's choice: tail cover still respects the budget") {
            val config = TrafficPaddingConfig(coverBudgetBytesPerSecond = 1024, coverBudgetBurstCells = 3)
            val c = FakeCircuit()
            val (s, _, _) = rig(config, listOf(c))
            s.tailCover(LinkId(1), 10) shouldBe 3
            s.tailCover(LinkId(9), 10) shouldBe 0 // no circuit on that link
            s.suppressedCount() shouldBe 7L
        }

        test("after close nothing is sent, the pending entry is cancelled and close is idempotent") {
            val c = FakeCircuit()
            val (s, timer, _) = rig(TrafficPaddingConfig(), listOf(c))
            s.start()
            timer.pending() shouldBe 1
            s.close()
            s.close()
            timer.advanceBy(1_000_000L)
            c.drops.size shouldBe 0
            timer.pending() shouldBe 0
            s.tailCover(LinkId(1), 3) shouldBe 0
            s.start() // a closed scheduler does not restart
            timer.pending() shouldBe 0
        }

        test("there is exactly one outstanding timer entry while running") {
            val c = FakeCircuit()
            val (s, timer, _) = rig(TrafficPaddingConfig(), listOf(c))
            s.start()
            s.start()
            repeat(50) {
                timer.pending() shouldBe 1
                timer.advanceBy(1_000L)
            }
        }
    })
