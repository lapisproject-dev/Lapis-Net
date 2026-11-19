package net.lapisphilosophorum.lapisnet.storage

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.util.Random
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private fun cidOf(text: String): Cid =
    Cid.buildCidV1(
        Cid.Codec.Raw,
        Multihash.Type.sha2_256,
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray()),
    )

/** A fake clock in nanoseconds, moved by the test (and by the fake target, to model slow provides). */
private class FakeClock {
    val now = AtomicLong(1_000_000_000L)

    fun advance(d: Duration) {
        now.addAndGet(d.inWholeNanoseconds)
    }
}

private class FakeTarget(
    private val clock: FakeClock? = null,
) : BlockProvideTarget {
    data class Call(
        val cid: Cid,
        val timeout: java.time.Duration,
        val fanout: Int,
    )

    val calls = CopyOnWriteArrayList<Call>()
    val served: MutableSet<Cid> =
        java.util.concurrent.ConcurrentHashMap
            .newKeySet()

    @Volatile var stopped = false

    @Volatile var result: (Cid) -> Int = { 1 }

    @Volatile var provideDuration: Duration = Duration.ZERO

    override fun provide(
        cid: Cid,
        timeout: java.time.Duration,
        fanout: Int,
    ): Int {
        calls += Call(cid, timeout, fanout)
        clock?.advance(provideDuration)
        return result(cid)
    }

    override fun isServed(cid: Cid): Boolean = cid in served

    override fun isStopped(): Boolean = stopped
}

private val FAST =
    BlockProvideConfig(
        maxTracked = 8,
        reprovideInterval = 1.hours,
        reprovideJitterFraction = 0.1,
        firstProvideDelayMax = 2.minutes,
        maxProvidesPerCycle = 2,
        perProvideTimeout = 10.seconds,
        cycleBudget = 20.seconds,
        fanout = 10,
        failureRetryMin = 5.minutes,
    )

class BlockProvideSchedulerTest :
    FunSpec({
        fun scheduler(
            target: FakeTarget,
            clock: FakeClock,
            config: BlockProvideConfig = FAST,
            seed: Long = 42,
        ) = BlockProvideScheduler(target, config, { clock.now.get() }, Random(seed))

        test("a tracked CID is announced only after the random first delay, then again after the jittered interval") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock)
            val cid = cidOf("a").also { target.served += it }
            s.track(cid) shouldBe true
            // never due before firstProvideDelayMax has passed in full? Only "at most" - check it is not due at t0+0
            // unless the drawn delay is 0; then advance past the max and it must be announced exactly once
            clock.advance(2.minutes + 1.milliseconds)
            s.runCycle().announced shouldBe 1
            target.calls.single().fanout shouldBe 10
            target.calls.single().timeout shouldBe java.time.Duration.ofSeconds(10)
            // not again within 54 minutes (1 h - 10 %)
            clock.advance(53.minutes)
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.NOTHING_DUE
            target.calls.size shouldBe 1
            // certainly due after 66 minutes (1 h + 10 %)
            clock.advance(13.minutes + 1.milliseconds)
            s.runCycle().announced shouldBe 1
            target.calls.size shouldBe 2
        }

        test("the first delay is drawn from 0..firstProvideDelayMax, so a new CID is not announced at once") {
            // many CIDs: with a uniform delay over 2 min, not all of them may be due 1 s after tracking
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(maxTracked = 64, maxProvidesPerCycle = 64), seed = 7)
            repeat(64) { i ->
                cidOf("d$i").also {
                    target.served += it
                    s.track(it)
                }
            }
            clock.advance(1.seconds)
            s.runCycle().attempted.shouldBeLessThanOrEqual(8)
            clock.advance(2.minutes)
            s.runCycle()
            target.calls.size shouldBe 64
        }

        test("jitter of the re-provide stays inside reprovideInterval +/- 10 %") {
            repeat(20) { seed ->
                val clock = FakeClock()
                val target = FakeTarget(clock)
                val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO), seed.toLong())
                val cid = cidOf("j$seed").also { target.served += it }
                s.track(cid)
                s.runCycle().announced shouldBe 1
                val announcedAt = clock.now.get()
                // find the first due time by stepping in 30 s steps
                var due = -1L
                for (step in 1..200) {
                    clock.advance(30.seconds)
                    if (s.runCycle().announced == 1) {
                        due = clock.now.get() - announcedAt
                        break
                    }
                }
                due shouldBeGreaterThanOrEqual (54.minutes).inWholeNanoseconds
                due shouldBeLessThanOrEqual (66.minutes + 30.seconds).inWholeNanoseconds
            }
        }

        test("at most maxProvidesPerCycle announcements per cycle, and none after the cycle budget") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO, maxProvidesPerCycle = 5))
            repeat(8) { i ->
                cidOf("c$i").also {
                    target.served += it
                    s.track(it)
                }
            }
            target.provideDuration = 9.seconds
            val r = s.runCycle()
            // 9 s + 9 s = 18 s < 20 s budget, the third starts at 18 s, after it 27 s >= 20 s -> stop
            r.attempted shouldBe 3
            r.endedBy shouldBe BlockProvideScheduler.EndReason.BUDGET_EXHAUSTED
            target.provideDuration = Duration.ZERO
            s.runCycle().attempted shouldBe 5
            s.runCycle().attempted shouldBe 0
        }

        test("maxTracked evicts the oldest entry; track is idempotent and does not renew; untrack; close") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(maxTracked = 3))
            val a = cidOf("a")
            val b = cidOf("b")
            val c = cidOf("c")
            val d = cidOf("d")
            s.track(a)
            s.track(b)
            s.track(c)
            s.track(a) shouldBe true // no renewal: a stays the oldest
            s.track(d)
            s.isTracked(a) shouldBe false
            s.isTracked(b) shouldBe true
            s.trackedCount() shouldBe 3
            s.stats().evicted shouldBe 1
            s.untrack(b)
            s.isTracked(b) shouldBe false
            s.close()
            s.trackedCount() shouldBe 0
            s.track(a) shouldBe false
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.CLOSED
        }

        test("zero peers and a general failure back off exponentially up to the interval; success resets") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            val cid = cidOf("b").also { target.served += it }
            s.track(cid)
            target.result = { 0 }
            s.runCycle().announced shouldBe 0
            s.stats().zeroSent shouldBe 1
            clock.advance(5.minutes - 1.milliseconds)
            s.runCycle().attempted shouldBe 0
            clock.advance(1.milliseconds)
            s.runCycle().attempted shouldBe 1 // second failure -> 10 min
            target.result = { throw NabuStorageException("walk failed") }
            clock.advance(10.minutes)
            s.runCycle().attempted shouldBe 1 // third failure -> 20 min
            s.stats().failed shouldBe 1
            clock.advance(20.minutes - 1.milliseconds)
            s.runCycle().attempted shouldBe 0
            clock.advance(1.milliseconds)
            target.result = { 3 }
            s.runCycle().announced shouldBe 1
            // reset: the next one is the regular interval, not a backoff
            clock.advance(50.minutes)
            s.runCycle().attempted shouldBe 0
            s.backoffNanos(1) shouldBe 5.minutes.inWholeNanoseconds
            s.backoffNanos(4) shouldBe 40.minutes.inWholeNanoseconds
            s.backoffNanos(5) shouldBe 1.hours.inWholeNanoseconds
            s.backoffNanos(30) shouldBe 1.hours.inWholeNanoseconds
        }

        test("a RuntimeException from provide is counted as a failure and never escapes") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            target.served += cidOf("r").also { s.track(it) }
            target.result = { throw IllegalStateException("boom") }
            s.runCycle().announced shouldBe 0
            s.stats().failed shouldBe 1
        }

        test("busy DHT ends the cycle, the CID stays due and no failure is counted") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            val cid =
                cidOf("busy").also {
                    target.served += it
                    s.track(it)
                }
            target.result = { throw NabuStorageBusyException() }
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.BUSY
            s.stats().failed shouldBe 0
            s.stats().busySkips shouldBe 1
            target.result = { 1 }
            s.runCycle().announced shouldBe 1
            target.calls.map { it.cid } shouldContainExactly listOf(cid, cid)
        }

        test("a stopped storage ends the cycle with STORAGE_STOPPED") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            target.served += cidOf("s").also { s.track(it) }
            target.result = {
                target.stopped = true
                throw NabuStorageException("storage is stopped")
            }
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.STORAGE_STOPPED
            s.stats().failed shouldBe 0
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.STORAGE_STOPPED
            target.calls.size shouldBe 1
        }

        test("a CID that is not in the served store is dropped and never announced") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            val cid = cidOf("private")
            s.track(cid)
            s.runCycle().attempted shouldBe 0
            s.isTracked(cid) shouldBe false
            s.stats().notServedDropped shouldBe 1
            target.calls.shouldBeEmpty()
        }

        test("an interrupt carried by NabuStorageException becomes InterruptedException; so does a pre-set flag") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            repeat(2) { i -> target.served += cidOf("i$i").also { s.track(it) } }
            target.result = {
                Thread.currentThread().interrupt()
                throw NabuStorageException("interrupted while announcing")
            }
            try {
                shouldThrow<InterruptedException> { s.runCycle() }
                target.calls.size shouldBe 1
            } finally {
                Thread.interrupted()
            }
            target.result = { 1 }
            Thread.currentThread().interrupt()
            try {
                shouldThrow<InterruptedException> { s.runCycle() }
                target.calls.size shouldBe 1
            } finally {
                Thread.interrupted()
            }
        }

        test("AnonymousStorageRefusedException closes the scheduler; nothing is announced afterwards") {
            val clock = FakeClock()
            val target = FakeTarget(clock)
            val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
            repeat(2) { i -> target.served += cidOf("a$i").also { s.track(it) } }
            target.result = { throw AnonymousStorageRefusedException("providing a block is not available") }
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.CLOSED
            target.calls.size shouldBe 1
            s.track(cidOf("later")) shouldBe false
            s.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.CLOSED
            target.calls.size shouldBe 1
        }

        test("concurrent track calls stay bounded and never wait for a running provide") {
            val clock = FakeClock()
            val release = CountDownLatch(1)
            val entered = CountDownLatch(1)
            val target = FakeTarget(clock)
            target.result = {
                entered.countDown()
                release.await(30, TimeUnit.SECONDS)
                1
            }
            val s = scheduler(target, clock, FAST.copy(maxTracked = 50, firstProvideDelayMax = Duration.ZERO))
            target.served += cidOf("first").also { s.track(it) }
            val pool = Executors.newFixedThreadPool(5)
            try {
                val cycle = pool.submit<BlockProvideScheduler.CycleResult> { s.runCycle() }
                entered.await(30, TimeUnit.SECONDS) shouldBe true
                // while provide blocks: 4 threads x 10 000 track calls must finish without waiting for it
                val workers =
                    (0 until 4).map { t ->
                        pool.submit {
                            repeat(10_000) { i -> s.track(cidOf("t$t-$i")) }
                        }
                    }
                workers.forEach { it.get(30, TimeUnit.SECONDS) }
                s.trackedCount().shouldBeLessThanOrEqual(50)
                release.countDown()
                cycle.get(30, TimeUnit.SECONDS)
            } finally {
                release.countDown()
                pool.shutdownNow()
            }
        }

        test("invalid configurations are rejected") {
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(maxTracked = 0) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(maxTracked = 4097) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(reprovideInterval = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(reprovideJitterFraction = 0.6) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(reprovideJitterFraction = -0.1) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(firstProvideDelayMax = (-1).seconds) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(maxProvidesPerCycle = 0) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(cycleInterval = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(cycleJitter = (-1).seconds) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(initialDelay = (-1).seconds) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(perProvideTimeout = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> {
                BlockProvideConfig(perProvideTimeout = 30.seconds, cycleBudget = 20.seconds)
            }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(fanout = 0) }
            shouldThrow<IllegalArgumentException> { BlockProvideConfig(failureRetryMin = Duration.ZERO) }
        }

        test("no log line of the scheduler contains a CID, at any level") {
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            try {
                val clock = FakeClock()
                val target = FakeTarget(clock)
                val s = scheduler(target, clock, FAST.copy(firstProvideDelayMax = Duration.ZERO))
                val cids = (0 until 6).map { cidOf("log$it") }
                cids.forEach { s.track(it) }
                cids.take(4).forEach { target.served += it }
                target.result =
                    { c ->
                        if (c == cids[0]) {
                            0
                        } else if (c == cids[1]) {
                            throw NabuStorageException("x")
                        } else {
                            1
                        }
                    }
                repeat(6) {
                    s.runCycle()
                    clock.advance(2.hours) // also triggers the hourly summary
                }
                target.result = { throw AnonymousStorageRefusedException("refused") }
                clock.advance(2.hours)
                cids.forEach { s.track(it) }
                s.runCycle()
                val schedulerEvents = appender.list.filter { it.loggerName.contains("BlockProvideScheduler") }
                schedulerEvents.isNotEmpty() shouldBe true
                for (event in schedulerEvents) {
                    for (cid in cids) {
                        event.formattedMessage.contains(cid.toString()) shouldBe false
                    }
                }
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
            }
        }
    })
