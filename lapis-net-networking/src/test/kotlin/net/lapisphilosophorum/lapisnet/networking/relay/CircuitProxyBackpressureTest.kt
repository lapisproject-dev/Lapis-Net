package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.embedded.EmbeddedChannel
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.util.ResourceLeakDetector
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

/**
 * Hard stop for the feeding loop. If flow control did not engage, the test would push this much
 * through and fail on the assertions below rather than run forever - it is deliberately far larger
 * than any amount a working proxy should ever accept from a stalled peer.
 */
private const val MAX_OFFERED_BYTES = 64L * 1024 * 1024

private val LONG_STALL: Duration = Duration.ofHours(1)

/**
 * One circuit leg wired exactly like `HopReceiver.spliceCircuit` wires it, on real TCP channels:
 * `sourceStream` (where [CircuitProxyHandler] sits) stands in for the near leg's substream, the
 * source transport is a real, otherwise idle connection channel (only its event loop and `autoRead`
 * flag matter, which is precisely what production pulls), and the target is a real connection whose
 * far end does not read.
 */
private class LegRig(
    group: NioEventLoopGroup,
    stallTimeout: Duration,
    val stats: CircuitFlowStats = CircuitFlowStats(),
    sourceTransport: Channel? = null,
    val target: NonReadingLink = NonReadingLink(group),
    val closes: AtomicInteger = AtomicInteger(0),
    stallBudget: Duration? = null,
    stallBudgetWindow: Duration = Duration.ofHours(1),
    stallGrace: Duration = Duration.ZERO,
) : AutoCloseable {
    private val sourceLink: NonReadingLink? =
        if (sourceTransport == null) {
            NonReadingLink(group, serverAutoRead = true, applyProductionWaterMarks = false)
        } else {
            null
        }
    val source: Channel = sourceTransport ?: sourceLink!!.client
    val state = CircuitState("test-initiator -> test-target") { closes.incrementAndGet() }
    val leg = CircuitLeg(source, target.client, state)
    val gate = TransportReadGate.of(source, stallTimeout, stats, stallBudget, stallBudgetWindow, stallGrace)
    val sourceStream = EmbeddedChannel(CircuitProxyHandler(target.client, leg, gate))

    init {
        target.client.pipeline().addLast(CircuitReadResumer(leg, gate))
    }

    val sourceReading: Boolean get() = source.config().isAutoRead

    /** Delivers one chunk the way Netty would: on the source connection's own event loop. */
    fun feedChunk() {
        source
            .eventLoop()
            .submit { sourceStream.writeInbound(Unpooled.wrappedBuffer(ByteArray(CHUNK_BYTES))) }
            .get()
    }

    /** Feeds until the circuit was closed (or the safety cap trips). Returns bytes offered. */
    fun feedUntilClosed(): Long {
        var offered = 0L
        val deadline = Instant.now().plus(Duration.ofSeconds(30))
        while (closes.get() == 0 && offered < MAX_OFFERED_BYTES && Instant.now().isBefore(deadline)) {
            feedChunk()
            offered += CHUNK_BYTES
        }
        return offered
    }

    /**
     * Feeds until [minPausedLegs] legs of this rig's gauge are paused (or the safety cap trips).
     * Deliberately independent of the source's `autoRead`: with two legs on one connection, bytes
     * for the second leg may already be in flight when the first leg paused the connection. Driven
     * by the gauge rather than the target's writability because the kernel keeps absorbing bytes
     * after Netty first reports "not writable", which can flip it straight back. Returns bytes
     * offered.
     */
    fun feedUntilPaused(minPausedLegs: Int = 1): Long {
        var offered = 0L
        val deadline = Instant.now().plus(Duration.ofSeconds(30))
        while (stats.pausedLegs() < minPausedLegs && offered < MAX_OFFERED_BYTES && Instant.now().isBefore(deadline)) {
            feedChunk()
            offered += CHUNK_BYTES
        }
        return offered
    }

    override fun close() {
        runCatching { sourceStream.finishAndReleaseAll() }
        runCatching { target.close() }
        runCatching { sourceLink?.close() }
    }
}

/**
 * Proves the relay's forwarding path is genuinely flow-controlled: a circuit whose far end does not
 * read makes the relay **stop reading** from the near end, instead of buffering everything the near
 * end sends - and that the resulting pause is bounded in time and exactly scoped.
 *
 * Before flow control, `CircuitProxyHandler` forwarded with no backpressure at all, and the only
 * ceilings were `RelayServerLimits.circuitMaxBytes` (64 MiB) and `maxConcurrentCircuits` (128) - so a
 * peer that opened circuits and simply never read could park several GiB of relay heap at no cost to
 * itself. Flow control then bounded the heap but left the pause itself unbounded: pausing a
 * connection stalls every other stream on it. `circuitStallTimeout` closes that one circuit after a
 * bounded time; the tests below pin each property of that mechanism.
 *
 * The setup is the real thing: real TCP connections whose peer never reads, so the socket really
 * does back up and Netty's outbound buffer really does grow, on a real event loop.
 */
class CircuitProxyBackpressureTest :
    FunSpec({
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID)

        fun withGroup(block: (NioEventLoopGroup) -> Unit) {
            val group = NioEventLoopGroup(2)
            try {
                block(group)
            } finally {
                group.shutdownGracefully(0, 1, java.util.concurrent.TimeUnit.SECONDS)
            }
        }

        test("forwarding pauses the source and keeps queued bytes bounded when the target does not read") {
            withGroup { group ->
                LegRig(group, LONG_STALL).use { rig ->
                    var peakQueuedBytes = 0L
                    var offered = 0L
                    val deadline = Instant.now().plus(Duration.ofSeconds(30))
                    // Feed only while the proxy still wants to read - the loop *is* the assertion that
                    // autoRead is honoured, because Netty would stop delivering at exactly this point.
                    while (rig.sourceReading && offered < MAX_OFFERED_BYTES && Instant.now().isBefore(deadline)) {
                        rig.feedChunk()
                        offered += CHUNK_BYTES
                        peakQueuedBytes = maxOf(peakQueuedBytes, queuedBytes(rig.target.client))
                    }

                    // 1. Flow control engaged at all: the relay stopped pulling bytes in.
                    rig.sourceReading shouldBe false
                    rig.stats.pausedLegs() shouldBe 1
                    // 2. It engaged *early*. Everything the loop offered had to fit in the socket
                    //    buffers plus one water mark's worth of heap, so it is nowhere near the
                    //    circuitMaxBytes-sized flood the unbounded version accepted.
                    offered shouldBeLessThan 8L * 1024 * 1024
                    // 3. The heap footprint itself - what a relay pays per circuit - stayed at the
                    //    water mark plus at most the write in flight when it tripped.
                    peakQueuedBytes shouldBeGreaterThan 0L
                    peakQueuedBytes shouldBeLessThan
                        (CIRCUIT_WRITE_BUFFER_HIGH_WATER_MARK_BYTES + 2L * CHUNK_BYTES)

                    // 4. And it lifts again: once the far end drains, the resumer re-enables reading,
                    //    so a merely slow peer is throttled rather than cut off.
                    rig.target.startDraining()
                    awaitCondition(Duration.ofSeconds(30)) { rig.sourceReading } shouldBe true
                    rig.stats.pausedLegs() shouldBe 0
                    rig.closes.get() shouldBe 0
                }
            }
        }

        test("a second circuit on the same source connection cannot un-pause a leg that is still blocked") {
            withGroup { group ->
                LegRig(group, LONG_STALL).use { first ->
                    // Second leg reads from the SAME source connection but writes to its own,
                    // independently non-reading target.
                    LegRig(group, LONG_STALL, first.stats, first.source).use { second ->
                        first.feedUntilPaused()
                        first.sourceReading shouldBe false
                        // Pause the second leg too, then let ONLY the second target drain.
                        second.feedUntilPaused(2)
                        first.stats.pausedLegs() shouldBe 2
                        second.target.startDraining()
                        awaitCondition(Duration.ofSeconds(30)) { first.stats.pausedLegs() == 1 } shouldBe true
                        // The old pauschal "autoRead = true" would have re-enabled reading here while
                        // the first leg's target is still full.
                        first.sourceReading shouldBe false

                        // Ending the first circuit lifts the last pause.
                        first.gate.remove(first.leg)
                        awaitCondition(Duration.ofSeconds(5)) { first.sourceReading } shouldBe true
                        first.stats.pausedLegs() shouldBe 0
                    }
                }
            }
        }

        test("the stall timeout closes exactly the stalled circuit, once, and resumes the source") {
            withGroup { group ->
                LegRig(group, Duration.ofMillis(300)).use { rig ->
                    rig.feedUntilPaused()
                    rig.sourceReading shouldBe false

                    awaitCondition(Duration.ofSeconds(10)) { rig.closes.get() == 1 } shouldBe true
                    awaitCondition(Duration.ofSeconds(5)) { rig.sourceReading } shouldBe true
                    // Well past another full timeout: nothing may close a second time.
                    Thread.sleep(700)
                    rig.closes.get() shouldBe 1
                    rig.stats.stallClosures() shouldBe 1
                    rig.stats.pausedLegs() shouldBe 0
                }
            }
        }

        test("pausing an already paused leg does not re-arm the timer") {
            withGroup { group ->
                LegRig(group, Duration.ofMillis(800)).use { rig ->
                    val pausedAt = Instant.now()
                    rig.feedUntilPaused()
                    // Keep re-pausing for 1.5x the timeout. A re-arming implementation would push the
                    // deadline out on every call (last call ~1.4 s, so it would fire no earlier than
                    // ~2.2 s); the real one fires ~0.8 s after the FIRST pause.
                    var closedAt: Instant? = null
                    repeat(14) {
                        rig.gate.pause(rig.leg)
                        Thread.sleep(100)
                        if (closedAt == null && rig.closes.get() == 1) closedAt = Instant.now()
                    }
                    (closedAt != null) shouldBe true
                    (Duration.between(pausedAt, closedAt!!).toMillis() < 1_300L) shouldBe true
                }
            }
        }

        test("a slow but reading peer is throttled, never cut off (no stall budget configured)") {
            withGroup { group ->
                LegRig(group, Duration.ofSeconds(1), target = NonReadingLink(group, smallBuffers = false)).use { rig ->
                    val end = Instant.now().plus(Duration.ofSeconds(3))
                    var nextDrain = Instant.now()
                    var pauseEpisodes = 0
                    var wasReading = true
                    while (Instant.now().isBefore(end)) {
                        if (!Instant.now().isBefore(nextDrain)) {
                            rig.target.drainBriefly(30)
                            nextDrain = Instant.now().plusMillis(100)
                        }
                        if (rig.sourceReading) rig.feedChunk() else Thread.sleep(5)
                        if (wasReading && !rig.sourceReading) pauseEpisodes++
                        wasReading = rig.sourceReading
                    }
                    // The scenario is only meaningful if the leg really was paused, repeatedly.
                    (pauseEpisodes >= 2) shouldBe true
                    rig.closes.get() shouldBe 0
                    rig.stats.stallClosures() shouldBe 0
                }
            }
        }

        /**
         * Drives one slower-than-the-sender but reading receiver for [duration] through [rig]: it
         * drains 30 ms out of every 100 ms, so the source is paused in many short episodes of a few
         * milliseconds each. Returns the number of pause episodes seen. Stops early once the circuit
         * was closed.
         */
        fun driveSlowReader(
            rig: LegRig,
            duration: Duration,
        ): Int {
            val end = Instant.now().plus(duration)
            var nextDrain = Instant.now()
            var pauseEpisodes = 0
            var wasReading = true
            while (Instant.now().isBefore(end) && rig.closes.get() == 0) {
                if (!Instant.now().isBefore(nextDrain)) {
                    rig.target.drainBriefly(30)
                    nextDrain = Instant.now().plusMillis(100)
                }
                if (rig.sourceReading) rig.feedChunk() else Thread.sleep(5)
                if (wasReading && !rig.sourceReading) pauseEpisodes++
                wasReading = rig.sourceReading
            }
            return pauseEpisodes
        }

        // The budget here has the production shape (a tenth of the window), unlike the 60 s / 10 min
        // of the test above it scaled down by 1:120 - which is what hid the regression: with a budget
        // that large relative to the test's runtime a slow reader never gets near exhausting it.
        test("a slow but reading peer is not cut off under a production-shaped budget and grace") {
            withGroup { group ->
                LegRig(
                    group,
                    Duration.ofSeconds(1),
                    target = NonReadingLink(group, smallBuffers = false),
                    stallBudget = Duration.ofMillis(500),
                    stallBudgetWindow = Duration.ofSeconds(5),
                    stallGrace = Duration.ofSeconds(1),
                ).use { rig ->
                    val pauseEpisodes = driveSlowReader(rig, Duration.ofSeconds(5))
                    // Only meaningful if the leg really was paused over and over.
                    (pauseEpisodes >= 20) shouldBe true
                    rig.closes.get() shouldBe 0
                    rig.stats.stallClosures() shouldBe 0
                }
            }
        }

        test("the same slow reader IS cut off once the grace is switched off - the test above is sensitive") {
            withGroup { group ->
                LegRig(
                    group,
                    Duration.ofSeconds(1),
                    target = NonReadingLink(group, smallBuffers = false),
                    stallBudget = Duration.ofMillis(500),
                    stallBudgetWindow = Duration.ofSeconds(5),
                    stallGrace = Duration.ZERO,
                ).use { rig ->
                    driveSlowReader(rig, Duration.ofSeconds(15))
                    rig.closes.get() shouldBe 1
                }
            }
        }

        test("only the part of a pause beyond the grace is charged to the budget") {
            withGroup { group ->
                val budget = Duration.ofMillis(300)
                val grace = Duration.ofMillis(600)
                LegRig(group, LONG_STALL, stallBudget = budget, stallGrace = grace).use { rig ->
                    rig.feedUntilPaused()
                    val pausedAt = Instant.now()
                    awaitCondition(Duration.ofSeconds(10)) { rig.closes.get() == 1 } shouldBe true
                    val pausedFor = Duration.between(pausedAt, Instant.now()).toMillis()
                    // The first 600 ms are free, then the 300 ms budget runs dry: ~900 ms in total.
                    // Without the grace the same leg would have been cut after ~300 ms.
                    (pausedFor >= 700L) shouldBe true
                    (pausedFor < 3_000L) shouldBe true
                }
            }
        }

        test("with the budget used up a brief pause that drains within the grace is left alone") {
            withGroup { group ->
                val budget = Duration.ofMillis(300)
                val grace = Duration.ofSeconds(1)
                LegRig(group, LONG_STALL, stallBudget = budget, stallGrace = grace).use { first ->
                    first.feedUntilPaused()
                    awaitCondition(Duration.ofSeconds(10)) { first.closes.get() == 1 } shouldBe true
                    awaitCondition(Duration.ofSeconds(5)) { first.sourceReading } shouldBe true
                    // The grace is not renewed for free right after a closure (see the sybil-chain
                    // test below): let the connection be readable for a full grace first.
                    Thread.sleep(grace.toMillis() + 100)
                    // Budget is now used up (a full non-reading episode just exhausted it).
                    // Big socket buffers on this target so it drains within milliseconds once it reads
                    // (a closed 4 KiB window would take seconds - longer than the grace under test).
                    LegRig(
                        group,
                        LONG_STALL,
                        first.stats,
                        first.source,
                        target = NonReadingLink(group, smallBuffers = false),
                        stallBudget = budget,
                        stallGrace = grace,
                    ).use { second ->
                        second.feedUntilPaused()
                        // Paused, not closed: the old behaviour cut it at once.
                        second.stats.pausedLegs() shouldBe 1
                        second.closes.get() shouldBe 0
                        second.target.startDraining()
                        awaitCondition(Duration.ofSeconds(10)) { second.sourceReading } shouldBe true
                        // Well past the grace: the drained pause must not be closed late either.
                        Thread.sleep(1_300)
                        second.closes.get() shouldBe 0
                        second.stats.stallClosures() shouldBe 1
                        second.stats.pausedLegs() shouldBe 0
                    }
                }
            }
        }

        test("with the budget used up a pause that outlasts the grace is closed") {
            withGroup { group ->
                val budget = Duration.ofMillis(300)
                val grace = Duration.ofMillis(700)
                LegRig(group, LONG_STALL, stallBudget = budget, stallGrace = grace).use { first ->
                    first.feedUntilPaused()
                    awaitCondition(Duration.ofSeconds(10)) { first.closes.get() == 1 } shouldBe true
                    awaitCondition(Duration.ofSeconds(5)) { first.sourceReading } shouldBe true
                    Thread.sleep(grace.toMillis() + 100) // full grace available again, see the chain test
                    LegRig(group, LONG_STALL, first.stats, first.source, stallBudget = budget, stallGrace = grace)
                        .use { second ->
                            second.feedUntilPaused()
                            second.closes.get() shouldBe 0
                            awaitCondition(Duration.ofSeconds(10)) { second.closes.get() == 1 } shouldBe true
                            awaitCondition(Duration.ofSeconds(5)) { second.sourceReading } shouldBe true
                            second.stats.stallClosures() shouldBe 2
                        }
                }
            }
        }

        test("a chain of circuits cannot get a fresh free grace each right after the previous one was cut") {
            withGroup { group ->
                val budget = Duration.ofMillis(300)
                val grace = Duration.ofMillis(800)
                val chain = 4
                LegRig(group, LONG_STALL, stallBudget = budget, stallGrace = grace).use { first ->
                    first.feedUntilPaused()
                    // First episode: the grace is free, then the budget runs dry and the circuit is cut.
                    awaitCondition(Duration.ofSeconds(10)) { first.closes.get() == 1 } shouldBe true
                    awaitCondition(Duration.ofSeconds(5)) { first.sourceReading } shouldBe true
                    // Budget used up. Further circuits (other identities in production) on the same
                    // victim connection, each prepared and paused straight after the previous cut.
                    // Each would have a full 800 ms uncharged grace without the fix (4 x 800 ms).
                    var pausedMillis = 0L
                    repeat(chain) {
                        LegRig(group, LONG_STALL, first.stats, first.source, stallBudget = budget, stallGrace = grace)
                            .use { next ->
                                next.feedUntilPaused()
                                val pausedAt = Instant.now()
                                awaitCondition(Duration.ofSeconds(10)) { next.closes.get() == 1 } shouldBe true
                                pausedMillis += Duration.between(pausedAt, Instant.now()).toMillis()
                                awaitCondition(Duration.ofSeconds(5)) { next.sourceReading } shouldBe true
                            }
                    }
                    first.stats.stallClosures() shouldBe (chain + 1).toLong()
                    // A pause is bounded by the time the connection was readable before it, so the
                    // chain's total pause stays far below the chain x grace of the unfixed gate.
                    (pausedMillis < grace.toMillis() * chain / 2) shouldBe true
                }
            }
        }

        test("a circuit end just before the grace does not stop the next leg getting a full grace") {
            // Pins a KNOWN limitation (docs/architecture.adoc, connectionStallGrace): the "no fresh
            // free grace" cap reads only stall closures. A pause that the attacker ends itself by
            // resetting its stream or dropping its own relay connection (CircuitState.markEnded +
            // gate.remove, no reading needed) leaves no timestamp, so the next circuit - another
            // identity in production - starts a new episode with a full uncharged grace. The pause
            // per episode is bounded by the grace; the share of time is not.
            withGroup { group ->
                val budget = Duration.ofMillis(300)
                val grace = Duration.ofMillis(800)
                LegRig(group, LONG_STALL, stallBudget = budget, stallGrace = grace).use { first ->
                    first.feedUntilPaused()
                    awaitCondition(Duration.ofSeconds(10)) { first.closes.get() == 1 } shouldBe true
                    awaitCondition(Duration.ofSeconds(5)) { first.sourceReading } shouldBe true
                    // Budget used up; the last closure is more than one grace ago.
                    Thread.sleep(grace.toMillis() + 100)
                    LegRig(group, LONG_STALL, first.stats, first.source, stallBudget = budget, stallGrace = grace)
                        .use { ended ->
                            ended.feedUntilPaused()
                            val firstPauseAt = Instant.now()
                            Thread.sleep(grace.toMillis() / 2)
                            // The attacker ends its own pause: a circuit end, not a stall closure.
                            ended.state.markEnded()
                            ended.gate.remove(ended.leg)
                            awaitCondition(Duration.ofSeconds(5)) { ended.sourceReading } shouldBe true
                            ended.closes.get() shouldBe 0
                            LegRig(
                                group,
                                LONG_STALL,
                                first.stats,
                                first.source,
                                stallBudget = budget,
                                stallGrace = grace,
                            ).use { next ->
                                next.feedUntilPaused()
                                awaitCondition(Duration.ofSeconds(10)) { next.closes.get() == 1 } shouldBe true
                                val totalPausedMillis = Duration.between(firstPauseAt, Instant.now()).toMillis()
                                // Nothing was charged or closed for the ended leg: only the first
                                // circuit and this one count as stall closures.
                                first.stats.stallClosures() shouldBe 2L
                                // Half a grace for the ended leg plus a full grace for the next one.
                                (totalPausedMillis >= grace.toMillis() * 6 / 5) shouldBe true
                            }
                        }
                }
            }
        }

        test("a circuit that ends while paused cancels its timer and closes nothing") {
            withGroup { group ->
                LegRig(group, Duration.ofMillis(500)).use { rig ->
                    rig.feedUntilPaused()
                    rig.sourceReading shouldBe false
                    rig.state.markEnded()
                    rig.gate.remove(rig.leg)
                    awaitCondition(Duration.ofSeconds(5)) { rig.sourceReading } shouldBe true
                    Thread.sleep(1_000)
                    rig.closes.get() shouldBe 0
                    rig.stats.stallClosures() shouldBe 0
                    rig.stats.pausedLegs() shouldBe 0
                }
            }
        }

        test("bytes that arrive after the circuit was closed are released, not leaked or forwarded") {
            withGroup { group ->
                LegRig(group, LONG_STALL).use { rig ->
                    rig.state.closeForStall(rig.stats)
                    val buffer = Unpooled.wrappedBuffer(ByteArray(CHUNK_BYTES))
                    rig.source
                        .eventLoop()
                        .submit { rig.sourceStream.writeInbound(buffer) }
                        .get()
                    buffer.refCnt() shouldBe 0
                    queuedBytes(rig.target.client) shouldBe 0L
                }
            }
        }

        test("a non-reader that reopens its circuit cannot keep the connection paused beyond the stall budget") {
            withGroup { group ->
                val stall = Duration.ofMillis(300)
                val budget = Duration.ofMillis(600)
                val start = Instant.now()
                LegRig(group, stall, stallBudget = budget).use { first ->
                    first.feedUntilPaused()
                    awaitCondition(Duration.ofSeconds(10)) { first.closes.get() == 1 } shouldBe true
                    awaitCondition(Duration.ofSeconds(5)) { first.sourceReading } shouldBe true
                    // Same source connection (the victim's), a fresh circuit each time: exactly the
                    // reopen cycle. Without the budget each episode would again last the full stall.
                    LegRig(group, stall, first.stats, first.source, stallBudget = budget).use { second ->
                        second.feedUntilPaused()
                        awaitCondition(Duration.ofSeconds(10)) { second.closes.get() == 1 } shouldBe true
                        awaitCondition(Duration.ofSeconds(5)) { second.sourceReading } shouldBe true
                        // Second episode was cut at the remaining budget (~300 ms), not the full stall
                        // timeout plus slack: both episodes together stay near the budget.
                        LegRig(group, stall, first.stats, first.source, stallBudget = budget).use { third ->
                            val thirdStart = Instant.now()
                            third.feedUntilClosed()
                            awaitCondition(Duration.ofSeconds(10)) { third.closes.get() == 1 } shouldBe true
                            // Budget used up: closed at once instead of after another stall timeout.
                            (Duration.between(thirdStart, Instant.now()).toMillis() < 250L) shouldBe true
                            third.sourceReading shouldBe true
                            third.stats.pausedLegs() shouldBe 0
                            third.stats.stallClosures() shouldBe 3
                            // Three cycles, ~3 x 300 ms if unbounded; the budget keeps the paused time to ~600 ms.
                            (Duration.between(start, Instant.now()).toMillis() < 1_600L) shouldBe true
                        }
                    }
                }
            }
        }

        test("the stall budget drains again over the window") {
            withGroup { group ->
                val budget = Duration.ofMillis(300)
                val window = Duration.ofMillis(900)
                LegRig(group, LONG_STALL, stallBudget = budget, stallBudgetWindow = window).use { first ->
                    first.feedUntilPaused()
                    awaitCondition(Duration.ofSeconds(10)) { first.closes.get() == 1 } shouldBe true
                    // A full window later the bucket is empty: a new pause is granted, not cut off.
                    Thread.sleep(1_200)
                    LegRig(
                        group,
                        LONG_STALL,
                        first.stats,
                        first.source,
                        stallBudget = budget,
                        stallBudgetWindow = window,
                    ).use { second ->
                        second.feedUntilPaused()
                        second.stats.pausedLegs() shouldBe 1
                        second.closes.get() shouldBe 0
                        second.sourceReading shouldBe false
                    }
                }
            }
        }

        test("without a stall budget the per-circuit timeout is the only bound (budget is opt-in on the gate)") {
            withGroup { group ->
                LegRig(group, Duration.ofMillis(200)).use { first ->
                    repeat(3) {
                        val before = first.stats.stallClosures()
                        LegRig(group, Duration.ofMillis(200), first.stats, first.source).use { rig ->
                            rig.feedUntilPaused()
                            awaitCondition(Duration.ofSeconds(10)) { first.stats.stallClosures() > before } shouldBe
                                true
                        }
                    }
                }
            }
        }
    })
