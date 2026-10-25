package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.OnionConstants
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** The egress shaper (wave V0.10.0-H) with a manual clock and timer: nothing here depends on real time. */
class EgressShaperTest :
    FunSpec({
        val slice = 50L
        val link1 = LinkId(1)
        val link2 = LinkId(2)

        class Rig(
            config: TrafficPaddingConfig = TrafficPaddingConfig(cover = false),
            maxQueuedNetty: Int = 256,
            perLinkCap: Int = EgressShaper.DEFAULT_PER_LINK_CAP,
            totalCap: Int = EgressShaper.DEFAULT_TOTAL_CAP,
        ) {
            val clock = WireTestClock(1_000_000L)
            val timer = ManualSliceTimer(clock)
            val written = CopyOnWriteArrayList<Triple<Long, Long, Cell>>() // time, link, cell
            val pending = HashMap<Long, Int>()
            val shaper =
                EgressShaper(
                    config,
                    { l, c ->
                        written += Triple(clock.millis(), l.value, c)
                        true
                    },
                    { pending[it.value] ?: 0 },
                    timer,
                    clock,
                    maxQueuedNetty,
                    perLinkCap,
                    totalCap,
                )

            fun cell(id: Int) = Cell(id + 1, CellCommand.RELAY, ByteArray(OnionConstants.BODY_SIZE))
        }

        test("a cell leaves only at the next slice boundary, never later than one slice after it was produced") {
            val r = Rig()
            r.clock.millis = 1_000_020L // 20 ms into a slice (1_000_000 is a multiple of 50)
            r.shaper.enqueue(link1, r.cell(1)) shouldBe true
            r.written.size shouldBe 0
            r.timer.advanceTo(1_000_049L)
            r.written.size shouldBe 0
            r.timer.advanceTo(1_000_050L)
            r.written.size shouldBe 1
            val (t, _, _) = r.written.single()
            (t % slice) shouldBe 0L
            (t - 1_000_020L <= slice) shouldBe true
        }

        test("the order of the cells of one link is kept and several links are served at the same boundary") {
            val r = Rig()
            for (i in 1..5) r.shaper.enqueue(link1, r.cell(i))
            r.shaper.enqueue(link2, r.cell(100))
            r.timer.advanceBy(slice)
            r.written.filter { it.second == 1L }.map { it.third.circuitId } shouldBe listOf(2, 3, 4, 5, 6)
            r.written.filter { it.second == 2L }.map { it.third.circuitId } shouldBe listOf(101)
            r.written.all { it.first % slice == 0L } shouldBe true
        }

        test("an idle shaper has no outstanding timer entry, and one burst leaves exactly one") {
            val r = Rig()
            r.timer.pending() shouldBe 0
            repeat(10) { r.shaper.enqueue(link1, r.cell(it)) }
            r.timer.pending() shouldBe 1
            r.timer.advanceBy(slice)
            // no tail configured to send (burstTailSlices > 0 but no sink): the owed tail slices still tick, then stop
            r.timer.advanceBy(10 * slice)
            r.timer.pending() shouldBe 0
            r.shaper.queuedCells() shouldBe 0
        }

        test("a slice with real cells is followed by at least burstTailSlices slices with one cover cell each") {
            val r = Rig(TrafficPaddingConfig(cover = true, burstTailSlices = 3))
            val tails = CopyOnWriteArrayList<Pair<Long, Long>>()
            r.shaper.tailSink = { link, n ->
                tails += r.clock.millis() to link.value
                EgressShaper.asCover { repeat(n) { r.shaper.enqueue(link, r.cell(900)) } }
            }
            repeat(3) { r.shaper.enqueue(link1, r.cell(it)) }
            r.timer.advanceBy(slice) // the real cells leave
            r.written.size shouldBe 3
            r.timer.advanceBy(10 * slice)
            tails.size shouldBe 3
            // consecutive slices, one cell each
            tails.map { it.first } shouldBe listOf(1_000_100L, 1_000_150L, 1_000_200L)
            r.written.count { it.third.circuitId == 901 } shouldBe 3
            r.timer.pending() shouldBe 0
        }

        test("cover cells enqueued as cover do not open a burst tail by themselves") {
            val r = Rig(TrafficPaddingConfig(cover = true, burstTailSlices = 3))
            val tails = AtomicInteger()
            r.shaper.tailSink = { _, _ -> tails.incrementAndGet() }
            EgressShaper.asCover { r.shaper.enqueue(link1, r.cell(1)) }
            r.timer.advanceBy(20 * slice)
            r.written.size shouldBe 1
            tails.get() shouldBe 0
        }

        test("two concurrent largest-class bundles on one link do not overflow the default cap") {
            val r = Rig()
            val refused = AtomicInteger()
            val threads =
                (0 until 2).map { t ->
                    Thread {
                        repeat(
                            EgressShaper.LARGEST_FRAME_CELLS,
                        ) { if (!r.shaper.enqueue(link1, r.cell(it + t))) refused.incrementAndGet() }
                    }
                }
            threads.forEach { it.start() }
            threads.forEach { it.join() }
            refused.get() shouldBe 0
            r.shaper.queuedCells() shouldBe 2 * EgressShaper.LARGEST_FRAME_CELLS
        }

        test("the per-link and the total cap refuse the cell, and the largest frame class fits") {
            val r = Rig(perLinkCap = 1280, totalCap = 1300)
            repeat(1153) { r.shaper.enqueue(link1, r.cell(it)) shouldBe true }
            repeat(1280 - 1153) { r.shaper.enqueue(link1, r.cell(it)) shouldBe true }
            r.shaper.enqueue(link1, r.cell(0)) shouldBe false
            // the total cap (1300) is reached with 20 cells of a second link
            repeat(20) { r.shaper.enqueue(link2, r.cell(it)) shouldBe true }
            r.shaper.enqueue(link2, r.cell(0)) shouldBe false
            r.shaper.queuedCells() shouldBe 1300
            shouldThrow<IllegalArgumentException> { Rig(perLinkCap = 1152) }
            shouldThrow<IllegalArgumentException> { Rig(perLinkCap = 1280, totalCap = 1279) }
        }

        test("a long transfer never exceeds the netty queue: per boundary at most maxQueued minus pending cells") {
            val r = Rig(maxQueuedNetty = 256)
            repeat(1153) { r.shaper.enqueue(link1, r.cell(it)) }
            r.pending[1L] = 100
            r.timer.advanceBy(slice)
            r.written.size shouldBe 156
            r.pending[1L] = 256 // full: nothing leaves
            r.timer.advanceBy(slice)
            r.written.size shouldBe 156
            r.pending[1L] = 0
            var guard = 0
            while (r.shaper.queuedCells() > 0 && guard++ < 50) {
                r.timer.advanceBy(slice)
                r.pending[1L] = 0
            }
            r.written.size shouldBe 1153
            r.written.map { it.third.circuitId } shouldBe (1..1153).toList()
        }

        test("closeAndFlush writes everything synchronously, in order, leaves no timer entry and is idempotent") {
            val r = Rig()
            repeat(7) { r.shaper.enqueue(link1, r.cell(it)) }
            r.shaper.closeAndFlush()
            r.written.map { it.third.circuitId } shouldBe (1..7).toList()
            r.shaper.queuedCells() shouldBe 0
            r.timer.advanceBy(10 * slice)
            r.timer.pending() shouldBe 0
            r.shaper.closeAndFlush()
            r.written.size shouldBe 7
            // later cells go straight to the link (a DESTROY must still leave)
            r.shaper.enqueue(link1, r.cell(99)) shouldBe true
            r.written
                .last()
                .third.circuitId shouldBe 100
        }

        test("a closed link loses its queue") {
            val r = Rig()
            repeat(4) { r.shaper.enqueue(link1, r.cell(it)) }
            r.shaper.linkClosed(link1)
            r.shaper.queuedCells() shouldBe 0
            r.timer.advanceBy(5 * slice)
            r.written.size shouldBe 0
        }

        test("a timer that was shut down never leaves cells behind: they are written at once") {
            val r = Rig()
            r.timer.shutdown = true
            r.shaper.enqueue(link1, r.cell(1)) shouldBe true
            r.written.size shouldBe 1
            r.shaper.queuedCells() shouldBe 0
        }

        test("a failing write drops the rest of the batch of that link") {
            val clock = WireTestClock(2_000_000L)
            val timer = ManualSliceTimer(clock)
            var writes = 0
            val shaper =
                EgressShaper(
                    TrafficPaddingConfig(cover = false),
                    { _, _ -> ++writes < 3 },
                    { 0 },
                    timer,
                    clock,
                    256,
                )
            repeat(10) { shaper.enqueue(link1, Cell(it + 1, CellCommand.RELAY, ByteArray(OnionConstants.BODY_SIZE))) }
            timer.advanceBy(50)
            writes shouldBe 3
            shaper.queuedCells() shouldBe 0
        }
    })
