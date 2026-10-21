package net.lapisphilosophorum.lapisnet.madli

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.comparables.shouldBeLessThanOrEqualTo
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import java.nio.ByteBuffer
import java.nio.file.Files
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.ceil
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** Monotonic test clock; the production code never sleeps, so neither do the tests. */
private class ManualClock {
    private val ms = AtomicLong(1_000_000)

    fun now(): Long = ms.get()

    fun advance(millis: Long) {
        ms.addAndGet(millis)
    }
}

/** Collects submitted refresh tasks; [runAll] runs them on the calling thread. */
private class QueueExecutor {
    private val tasks = ConcurrentLinkedQueue<Runnable>()

    @Volatile var accept = true
    val size: Int get() = tasks.size

    fun submit(task: Runnable): Boolean {
        if (!accept) return false
        tasks += task
        return true
    }

    fun runAll() {
        while (true) (tasks.poll() ?: return).run()
    }
}

/** A fake grant source with a change counter, call counting, optional failure and an optional blocking gate. */
private class FakeSource(
    private val clock: ManualClock,
    @Volatile var grants: List<VeritasGrant>,
) {
    val version = AtomicLong(1)
    val reads = AtomicInteger(0)
    val readTimes = CopyOnWriteArrayList<Long>()
    val active = AtomicInteger(0)
    val maxActive = AtomicInteger(0)

    @Volatile var failFromRead = Int.MAX_VALUE

    @Volatile var gate: CountDownLatch? = null

    @Volatile var entered: CountDownLatch? = null

    fun read(): List<VeritasGrant> {
        val n = reads.incrementAndGet()
        readTimes += clock.now()
        val now = active.incrementAndGet()
        maxActive.accumulateAndGet(now) { a, b -> maxOf(a, b) }
        try {
            entered?.countDown()
            gate?.await()
            if (n >= failFromRead) error("simulated failure")
            return grants
        } finally {
            active.decrementAndGet()
        }
    }

    fun fingerprint(ignored: Collection<VeritasGrant>): List<Byte> =
        ByteBuffer
            .allocate(8)
            .putLong(version.get())
            .array()
            .toList()
}

private fun weightFor(
    local: Secp256k1KeyPair,
    source: FakeSource,
    clock: ManualClock,
    executor: (Runnable) -> Boolean,
    window: Duration = 5.seconds,
    onSkipSummary: (Long, Long) -> Unit = { _, _ -> },
    onFailureLog: (String, Int) -> Unit = { _, _ -> },
) = CachedVeritasObserverWeight(
    version = { source.version.get() },
    grantsSource = source::read,
    fingerprintOf = source::fingerprint,
    localIdentity = local.publicKey,
    refreshExecutor = executor,
    refreshWindow = window,
    nowMillis = clock::now,
    onSkipSummary = onSkipSummary,
    onFailureLog = onFailureLog,
)

/** Mirrors the flood: every iteration is one grant change, one reader, one executor drain, one tick per window. */
private fun flood(
    weights: CachedVeritasObserverWeight,
    source: FakeSource,
    clock: ManualClock,
    exec: QueueExecutor,
    observer: Secp256k1PublicKey,
    millis: Int,
) {
    var lastTick = clock.now()
    repeat(millis) {
        source.version.incrementAndGet()
        clock.advance(1)
        weights.weightOf(observer)
        exec.runAll()
        if (clock.now() - lastTick >= 5_000) {
            lastTick = clock.now()
            weights.tick()
            exec.runAll()
        }
    }
}

class CachedVeritasObserverWeightTest :
    FunSpec({
        val local = Secp256k1KeyPair.generate()
        val observer = Secp256k1KeyPair.generate().publicKey
        val oneGrant = listOf(VeritasGrant.create(local, observer, MAX_TRUST_MICROS))

        test("a change inside the window keeps the old weight without recomputing; the next window picks it up") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            val weights = weightFor(local, source, clock, exec::submit)
            repeat(1_000) { weights.weightOf(observer) shouldBe 1.0 }
            source.reads.get() shouldBe 1
            source.version.set(2)
            repeat(1_000) { weights.weightOf(observer) shouldBe 1.0 }
            source.reads.get() shouldBe 1
            exec.size shouldBe 0
            clock.advance(5_000)
            weights.weightOf(observer) shouldBe 1.0
            exec.size shouldBe 1
            exec.runAll()
            source.reads.get() shouldBe 2
            repeat(1_000) { weights.weightOf(observer) shouldBe 1.0 }
            source.reads.get() shouldBe 2
            exec.size shouldBe 0
        }

        test("flood of grant changes: at most ceil(T/W)+1 recomputations in T, the rest is skipped") {
            for (seconds in listOf(10, 20)) {
                val clock = ManualClock()
                val exec = QueueExecutor()
                val source = FakeSource(clock, oneGrant)
                val weights = weightFor(local, source, clock, exec::submit)
                flood(weights, source, clock, exec, observer, seconds * 1_000)
                val stats = weights.stats()
                stats.recomputations shouldBeLessThanOrEqualTo (ceil(seconds / 5.0).toLong() + 1)
                stats.skippedRefreshRequests shouldBeLessThanOrEqualTo (seconds * 1_000L * 2)
                (stats.skippedRefreshRequests >= seconds * 1_000L - 10) shouldBe true
                stats.inFlight shouldBe false
            }
        }

        test("single-flight: concurrent readers on a stale snapshot start exactly one refresh and never block") {
            val clock = ManualClock()
            val source = FakeSource(clock, oneGrant)
            val pool = Executors.newFixedThreadPool(8)
            val submitted = AtomicInteger(0)
            val weights =
                weightFor(local, source, clock, { task ->
                    submitted.incrementAndGet()
                    pool.execute(task)
                    true
                })
            weights.weightOf(observer) shouldBe 1.0 // initial blocking computation
            val gate = CountDownLatch(1)
            source.gate = gate
            source.entered = CountDownLatch(1)
            source.version.incrementAndGet()
            clock.advance(5_000)
            val barrier = CyclicBarrier(16)
            val results = CopyOnWriteArrayList<Double>()
            val threads =
                List(16) {
                    Thread {
                        barrier.await()
                        results += weights.weightOf(observer)
                    }.also { it.start() }
                }
            threads.forEach { it.join(5_000) }
            threads.none { it.isAlive } shouldBe true // returned while the refresh is still blocked on the gate
            results.size shouldBe 16
            results.all { it == 1.0 } shouldBe true
            source.entered!!.await(5, TimeUnit.SECONDS) shouldBe true
            submitted.get() shouldBe 1
            weights.stats().inFlight shouldBe true
            gate.countDown()
            pool.shutdown()
            pool.awaitTermination(5, TimeUnit.SECONDS) shouldBe true
            source.maxActive.get() shouldBe 1
            weights.stats().inFlight shouldBe false
        }

        test("concurrent first callers share one initial computation") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            val weights = weightFor(local, source, clock, exec::submit)
            val barrier = CyclicBarrier(16)
            val results = CopyOnWriteArrayList<Double>()
            val threads =
                List(16) {
                    Thread {
                        barrier.await()
                        results += weights.weightOf(observer)
                    }.also { it.start() }
                }
            threads.forEach { it.join(10_000) }
            results.size shouldBe 16
            results.all { it == 1.0 } shouldBe true
            weights.stats().recomputations shouldBe 1
            source.maxActive.get() shouldBe 1
        }

        test("a revoking grant (same grant count) changes the weight after at most one window plus one run") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
            val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-weight-test"))
            val pubsub = GossipPubSub.attach(node)
            val veritas = VeritasGossip.attach(pubsub, storage)
            try {
                val self = identity.secp256k1KeyPair
                val target = Secp256k1KeyPair.generate().publicKey
                val clock = ManualClock()
                val exec = QueueExecutor()
                val weights =
                    CachedVeritasObserverWeight(
                        version = veritas::grantsVersion,
                        grantsSource = veritas::currentGrants,
                        fingerprintOf = { veritas.currentGrantsFingerprint(it) },
                        localIdentity = self.publicKey,
                        refreshExecutor = exec::submit,
                        nowMillis = clock::now,
                    )

                fun direct() =
                    MadliAggregator.veritasObserverWeight(
                        TrustGraph.fromGrants(veritas.currentGrants()),
                        self.publicKey,
                    )(target)

                weights.weightOf(target) shouldBe 0.0 // no grant yet
                val grant = VeritasGrant.create(self, target, MAX_TRUST_MICROS)
                veritas.announce(grant)
                weights.weightOf(target) shouldBe 0.0 // inside the window: stale, bounded
                clock.advance(5_000)
                weights.weightOf(target) shouldBe 0.0 // refresh only queued
                exec.runAll()
                weights.weightOf(target) shouldBe 1.0
                weights.weightOf(target) shouldBe direct()

                // revocation replaces the edge: the grant count stays 1, only the content changes
                val revoke = VeritasGrant.create(self, target, MIN_TRUST_MICROS, previous = grant)
                veritas.announce(revoke)
                veritas.currentGrants().size shouldBe 1
                weights.weightOf(target) shouldBe 1.0 // still inside the window
                clock.advance(5_000)
                weights.weightOf(target)
                exec.runAll()
                weights.weightOf(target) shouldBe 0.0
                weights.weightOf(target) shouldBe direct()

                // idle guarantee: the safety tick alone catches up, no reader involved
                veritas.announce(VeritasGrant.create(self, target, MAX_TRUST_MICROS, previous = revoke))
                clock.advance(5_000)
                val before = weights.stats().recomputations
                weights.tick()
                exec.runAll()
                weights.stats().recomputations shouldBe before + 1
                weights.weightOf(target) shouldBe 1.0
                weights.weightOf(target) shouldBe direct()
            } finally {
                runCatching { veritas.stop() }
                runCatching { pubsub.stop() }
                runCatching { storage.stop() }
                runCatching { node.stop() }
            }
        }

        test("idle node with an unlucky tick phase catches up within two windows plus jitter plus one run") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            val weights = weightFor(local, source, clock, exec::submit)
            val window = 5_000L
            val jitter = window / 10

            val t0 = clock.now()
            weights.weightOf(observer) shouldBe 1.0 // first call: synchronous run starts the window at t0
            clock.advance(1)
            source.version.incrementAndGet() // revocation arrives right after the run read its version; readers stop
            clock.advance(window - 2) // a tick just before the window end is rejected by the gate
            weights.tick()
            exec.runAll()
            weights.stats().skippedRefreshRequests shouldBe 1
            source.reads.get() shouldBe 1
            // the next tick comes one interval later (plus jitter): only then is the weight recomputed
            clock.advance(window + jitter)
            weights.tick()
            exec.runAll()
            source.reads.get() shouldBe 2
            (clock.now() - t0) shouldBeLessThanOrEqualTo (2 * window + jitter)
        }

        test("stop: supervisor shutdown interrupts a running refresh, leaves no thread and blocks new submissions") {
            val clock = ManualClock()
            val source = FakeSource(clock, oneGrant)
            val supervisor = NodeServiceSupervisor("test-ow", poolSize = 2)
            val weights =
                CachedVeritasObserverWeight.startSupervised(
                    version = { source.version.get() },
                    grantsSource = source::read,
                    fingerprintOf = source::fingerprint,
                    localIdentity = local.publicKey,
                    supervisor = supervisor,
                    refreshWindow = 5.seconds,
                    nowMillis = clock::now,
                )
            weights.weightOf(observer) shouldBe 1.0
            source.gate = CountDownLatch(1) // never released: only the interrupt ends the run
            source.entered = CountDownLatch(1)
            source.version.incrementAndGet()
            clock.advance(5_000)
            weights.weightOf(observer) shouldBe 1.0
            source.entered!!.await(5, TimeUnit.SECONDS) shouldBe true
            supervisor.stopAll()
            supervisor.isTerminated() shouldBe true
            val stats = weights.stats()
            stats.stopped shouldBe true
            stats.inFlight shouldBe false
            val recomputations = stats.recomputations
            clock.advance(60_000)
            weights.weightOf(observer) shouldBe 1.0 // last snapshot
            weights.stats().recomputations shouldBe recomputations
            weights.stats().inFlight shouldBe false
            Thread
                .getAllStackTraces()
                .keys
                .none { it.name.startsWith("test-ow-worker") && it.isAlive } shouldBe true
        }

        test("failing refreshes keep the old weight, back off exponentially (capped), log rate-limited and recover") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            val failureLogs = CopyOnWriteArrayList<Int>()
            val weights = weightFor(local, source, clock, exec::submit, onFailureLog = { _, n -> failureLogs += n })
            weights.weightOf(observer) shouldBe 1.0
            source.failFromRead = 2
            source.version.incrementAndGet()
            clock.advance(5_000)
            weights.weightOf(observer) shouldBe 1.0
            exec.runAll()
            weights.weightOf(observer) shouldBe 1.0 // old weight stays
            weights.stats().consecutiveFailures shouldBe 1
            val firstFailureAt = source.readTimes.last()
            repeat(600) {
                clock.advance(1_000)
                weights.tick()
                exec.runAll()
            }
            val times = source.readTimes.drop(1)
            val gaps = times.zipWithNext { a, b -> b - a }
            gaps.take(5) shouldBe listOf(10_000L, 20_000L, 40_000L, 60_000L, 60_000L)
            (times.first() - firstFailureAt) shouldBe 0L
            gaps.all { it <= 60_000L } shouldBe true
            (failureLogs.size <= ceil(600 / 60.0).toInt() + 1) shouldBe true
            failureLogs.first() shouldBe 1
            weights.weightOf(observer) shouldBe 0.0 // failing > maxStaleness with a changed index: fail closed

            // recovery: the new grants (none) become visible, counters reset
            source.failFromRead = Int.MAX_VALUE
            source.grants = emptyList()
            repeat(120) {
                clock.advance(1_000)
                weights.tick()
                exec.runAll()
            }
            weights.stats().consecutiveFailures shouldBe 0
            weights.weightOf(observer) shouldBe 0.0
        }

        test("persistent refresh failure fails closed after maxStaleness so a revocation cannot stay masked") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            val weights = weightFor(local, source, clock, exec::submit)
            weights.weightOf(observer) shouldBe 1.0
            // the grants are revoked while every refresh fails permanently (e.g. a flooded index)
            source.failFromRead = 2
            source.grants = emptyList()
            source.version.incrementAndGet()
            clock.advance(5_000)
            weights.weightOf(observer) shouldBe 1.0 // within the staleness bound the old snapshot may answer
            exec.runAll()
            weights.stats().consecutiveFailures shouldBe 1
            weights.weightOf(observer) shouldBe 1.0
            clock.advance(59_000)
            weights.weightOf(observer) shouldBe 1.0
            clock.advance(2_000)
            weights.weightOf(observer) shouldBe 0.0 // bound exceeded: no reputation influence
            repeat(300) {
                clock.advance(1_000)
                weights.tick()
                exec.runAll()
                weights.weightOf(observer) shouldBe 0.0
            }
            // the failure ends: the revoked state becomes effective and the weight is served again
            source.failFromRead = Int.MAX_VALUE
            repeat(120) {
                clock.advance(1_000)
                weights.tick()
                exec.runAll()
            }
            weights.stats().consecutiveFailures shouldBe 0
            weights.weightOf(observer) shouldBe 0.0
        }

        test("a failing first computation yields 0.0 without a second blocking run; the async retry recovers") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            source.failFromRead = 1
            val weights = weightFor(local, source, clock, exec::submit)
            weights.weightOf(observer) shouldBe 0.0
            weights.weightOf(observer) shouldBe 0.0
            source.reads.get() shouldBe 1
            exec.size shouldBe 0 // backoff
            source.failFromRead = Int.MAX_VALUE
            clock.advance(10_000)
            weights.weightOf(observer) shouldBe 0.0
            exec.size shouldBe 1
            exec.runAll()
            weights.weightOf(observer) shouldBe 1.0
            weights.stats().consecutiveFailures shouldBe 0
        }

        test("skip summaries are rate-limited and carry only counters (no keys can reach the log hook)") {
            for (seconds in listOf(10, 120)) {
                val clock = ManualClock()
                val exec = QueueExecutor()
                val source = FakeSource(clock, oneGrant)
                val summaries = CopyOnWriteArrayList<Pair<Long, Long>>()
                val weights =
                    weightFor(local, source, clock, exec::submit, onSkipSummary = { d, t ->
                        summaries +=
                            d to t
                    })
                flood(weights, source, clock, exec, observer, seconds * 1_000)
                val maxSummaries = seconds / 60 + 1
                summaries.size shouldBeLessThanOrEqualTo maxSummaries
                summaries.sumOf { it.first } shouldBeLessThanOrEqualTo weights.stats().skippedRefreshRequests
                if (summaries.isNotEmpty()) summaries.sumOf { it.first } shouldBe summaries.last().second
            }
        }

        test("construction is validated") {
            val clock = ManualClock()
            val source = FakeSource(clock, oneGrant)
            shouldThrow<IllegalArgumentException> { weightFor(local, source, clock, { true }, window = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { weightFor(local, source, clock, { true }, window = 11.minutes) }
        }

        test("an executor that rejects releases the single-flight slot, a later request succeeds") {
            val clock = ManualClock()
            val exec = QueueExecutor()
            val source = FakeSource(clock, oneGrant)
            val weights = weightFor(local, source, clock, exec::submit)
            weights.weightOf(observer) shouldBe 1.0
            source.version.incrementAndGet()
            clock.advance(5_000)
            exec.accept = false
            weights.weightOf(observer) shouldBe 1.0
            weights.stats().inFlight shouldBe false
            exec.accept = true
            weights.weightOf(observer) shouldBe 1.0
            exec.size shouldBe 1
            exec.runAll()
            source.reads.get() shouldBe 2
        }
    })
