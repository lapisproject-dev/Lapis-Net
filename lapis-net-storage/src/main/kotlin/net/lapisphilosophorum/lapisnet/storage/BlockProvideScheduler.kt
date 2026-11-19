package net.lapisphilosophorum.lapisnet.storage

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import java.security.SecureRandom
import java.util.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private val logger = KotlinLogging.logger {}

/** What [BlockProvideScheduler] needs from storage; [NabuStorage.asProvideTarget] adapts a real storage, tests use a fake. */
interface BlockProvideTarget {
    /** Network announce; same contract as [NabuStorage.provide] (returns the number of `ADD_PROVIDER` messages sent). */
    fun provide(
        cid: Cid,
        timeout: java.time.Duration,
        fanout: Int,
    ): Int

    /** `true` iff [cid] is in the SERVED (public) blockstore - never the unserved/private one. No network I/O. */
    fun isServed(cid: Cid): Boolean

    /** `true` once the storage is stopped; the scheduler then ends its cycle instead of counting a failure. */
    fun isStopped(): Boolean = false
}

/**
 * Limits of [BlockProvideScheduler] (wave Q20). The defaults are provisional, not measured in a pilot deployment.
 *
 * @property maxTracked hard cap of CIDs this node tracks and announces; the oldest-tracked one is evicted beyond it
 * @property reprovideInterval how often each CID is announced again, `+/- reprovideJitterFraction`
 * @property firstProvideDelayMax a newly tracked CID becomes due after a random delay in `0..max`, so the first holder to
 *   announce right after a post was gossiped is not obviously its author
 * @property maxProvidesPerCycle announcements per cycle (the protocol has one key per `ADD_PROVIDER`; no wire batching)
 * @property cycleBudget no new announcement is started after this much time in one cycle; together with
 *   [perProvideTimeout] it bounds how long a supervisor thread is occupied
 * @property fanout closest peers each announcement goes to (clamped to [DhtLimits.provideFanout] by the storage)
 * @property failureRetryMin first retry delay after a failed or peerless announcement; doubles up to [reprovideInterval]
 */
data class BlockProvideConfig(
    val maxTracked: Int = 256,
    val reprovideInterval: Duration = 1.hours,
    val reprovideJitterFraction: Double = 0.1,
    val firstProvideDelayMax: Duration = 2.minutes,
    val maxProvidesPerCycle: Int = 2,
    val cycleInterval: Duration = 15.seconds,
    val cycleJitter: Duration = 3.seconds,
    val initialDelay: Duration = 60.seconds,
    val perProvideTimeout: Duration = 10.seconds,
    val cycleBudget: Duration = 20.seconds,
    val fanout: Int = 10,
    val failureRetryMin: Duration = 5.minutes,
) {
    init {
        require(maxTracked in 1..MAX_TRACKED_LIMIT) { "maxTracked must be in 1..$MAX_TRACKED_LIMIT" }
        require(reprovideInterval.isPositive()) { "reprovideInterval must be positive" }
        require(reprovideJitterFraction in 0.0..0.5) { "reprovideJitterFraction must be in 0.0..0.5" }
        require(!firstProvideDelayMax.isNegative()) { "firstProvideDelayMax must not be negative" }
        require(maxProvidesPerCycle >= 1) { "maxProvidesPerCycle must be positive" }
        require(cycleInterval.isPositive()) { "cycleInterval must be positive" }
        require(!cycleJitter.isNegative()) { "cycleJitter must not be negative" }
        require(!initialDelay.isNegative()) { "initialDelay must not be negative" }
        require(perProvideTimeout.isPositive()) { "perProvideTimeout must be positive" }
        require(cycleBudget >= perProvideTimeout) { "cycleBudget must be at least perProvideTimeout" }
        require(fanout >= 1) { "fanout must be positive" }
        require(failureRetryMin.isPositive()) { "failureRetryMin must be positive" }
    }

    companion object {
        const val MAX_TRACKED_LIMIT = 4096
    }
}

/**
 * Wave Q20: announces (DHT `provide`) a bounded set of blocks this node holds, and re-announces them periodically.
 * Provider records do not age on the peers that hold them (they are LRU-bounded and in memory only), but those peers
 * restart and the closest peers change as nodes come and go - hence the re-provide.
 *
 * [track] is O(1), takes only this object's own lock and does no I/O: it is called from the GossipSub validator
 * thread. [runCycle] runs on a supervisor thread, announces sequentially (at most ONE DHT operation permit at a time)
 * and never holds the lock while it talks to the network. Which due CIDs a cycle announces is chosen at random, not by
 * age, and a newly tracked CID waits a random delay first: own and received posts follow the same path.
 *
 * Nothing here logs a CID: the CID is the access token of a block. Only numbers are logged.
 */
class BlockProvideScheduler(
    private val target: BlockProvideTarget,
    val config: BlockProvideConfig = BlockProvideConfig(),
    private val clockNanos: () -> Long = System::nanoTime,
    private val random: Random = SecureRandom(),
) : AutoCloseable {
    private class Entry(
        var nextDueNanos: Long,
        var failures: Int = 0,
    )

    private val lock = Any()
    private val entries = LinkedHashMap<Cid, Entry>()
    private var closed = false

    private var attempted = 0L
    private var announced = 0L
    private var zeroSent = 0L
    private var failed = 0L
    private var busySkips = 0L
    private var notServedDropped = 0L
    private var evicted = 0L
    private var lastSummaryNanos = clockNanos()

    /**
     * Starts tracking [cid]. O(1), non-blocking, no I/O. Idempotent: an already tracked CID keeps its position and its
     * due time. Beyond [BlockProvideConfig.maxTracked] the oldest-tracked entry is evicted. `false` after [close].
     */
    fun track(cid: Cid): Boolean {
        synchronized(lock) {
            if (closed) return false
            if (entries.containsKey(cid)) return true
            val delayMax = config.firstProvideDelayMax.inWholeNanoseconds
            val delay = if (delayMax <= 0) 0L else (random.nextDouble() * delayMax).toLong()
            entries[cid] = Entry(clockNanos() + delay)
            while (entries.size > config.maxTracked) {
                val eldest = entries.keys.iterator()
                eldest.next()
                eldest.remove()
                evicted++
            }
            return true
        }
    }

    /** Stops tracking [cid] (no network: an existing provider record simply stops being renewed). */
    fun untrack(cid: Cid) {
        synchronized(lock) { entries.remove(cid) }
    }

    /** Number of CIDs currently tracked. */
    fun trackedCount(): Int = synchronized(lock) { entries.size }

    /** `true` iff [cid] is currently tracked (tests). */
    fun isTracked(cid: Cid): Boolean = synchronized(lock) { entries.containsKey(cid) }

    /**
     * One cycle, meant for `NodeServiceSupervisor.launchPeriodic`. Announces at most
     * [BlockProvideConfig.maxProvidesPerCycle] due CIDs, sequentially, and starts none after
     * [BlockProvideConfig.cycleBudget]. Never throws except [InterruptedException].
     *
     * @throws InterruptedException if the thread is interrupted (also when a [NabuStorageException] carried the flag)
     */
    fun runCycle(): CycleResult {
        val start = clockNanos()
        val picked = pickDue(start) ?: return CycleResult(0, 0, EndReason.CLOSED)
        if (picked.isEmpty()) {
            maybeSummary(start)
            return CycleResult(0, 0, EndReason.NOTHING_DUE)
        }
        var attemptedHere = 0
        var announcedHere = 0
        var reason = EndReason.CAP_REACHED
        for (cid in picked) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException()
            if (isClosed()) {
                reason = EndReason.CLOSED
                break
            }
            if (clockNanos() - start >= config.cycleBudget.inWholeNanoseconds) {
                reason = EndReason.BUDGET_EXHAUSTED
                break
            }
            if (target.isStopped()) {
                reason = EndReason.STORAGE_STOPPED
                break
            }
            val served =
                try {
                    target.isServed(cid)
                } catch (e: NabuStorageException) {
                    if (Thread.currentThread().isInterrupted) throw InterruptedException()
                    if (target.isStopped()) {
                        reason = EndReason.STORAGE_STOPPED
                        break
                    }
                    onFailure(cid)
                    continue
                } catch (e: RuntimeException) {
                    onFailure(cid)
                    continue
                }
            if (!served) {
                synchronized(lock) {
                    if (entries.remove(cid) != null) notServedDropped++
                }
                continue
            }
            attemptedHere++
            synchronized(lock) { attempted++ }
            val outcome =
                try {
                    Outcome.Sent(target.provide(cid, config.perProvideTimeout.toJavaDuration(), config.fanout))
                } catch (e: AnonymousStorageRefusedException) {
                    Outcome.Refused
                } catch (e: NabuStorageBusyException) {
                    Outcome.Busy
                } catch (e: NabuStorageException) {
                    if (Thread.currentThread().isInterrupted) throw InterruptedException()
                    if (target.isStopped()) Outcome.Stopped else Outcome.Failed
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw e
                } catch (e: RuntimeException) {
                    Outcome.Failed
                }
            when (outcome) {
                is Outcome.Sent ->
                    if (outcome.count > 0) {
                        announcedHere++
                        onSuccess(cid)
                    } else {
                        synchronized(lock) { zeroSent++ }
                        reschedule(cid, failure = true)
                    }
                Outcome.Busy -> {
                    synchronized(lock) { busySkips++ }
                    reason = EndReason.BUSY
                    break
                }
                Outcome.Stopped -> {
                    reason = EndReason.STORAGE_STOPPED
                    break
                }
                Outcome.Refused -> {
                    // must never happen: the scheduler is not created in anonymity mode
                    logger.warn { "post body provide refused by storage in anonymity mode - scheduler closed" }
                    close()
                    reason = EndReason.CLOSED
                    break
                }
                Outcome.Failed -> onFailure(cid)
            }
        }
        if (Thread.currentThread().isInterrupted) throw InterruptedException()
        logger.debug { "provide cycle: attempted=$attemptedHere announced=$announcedHere end=$reason" }
        maybeSummary(clockNanos())
        return CycleResult(attemptedHere, announcedHere, reason)
    }

    /** Counters (numbers only). */
    fun stats(): ProvideStats =
        synchronized(lock) {
            ProvideStats(entries.size, attempted, announced, zeroSent, failed, busySkips, notServedDropped, evicted)
        }

    /** Clears the tracked set; a later [track] is a no-op and [runCycle] returns [EndReason.CLOSED]. Idempotent. */
    override fun close() {
        synchronized(lock) {
            closed = true
            entries.clear()
        }
    }

    private fun isClosed(): Boolean = synchronized(lock) { closed }

    /** `null` when closed; otherwise up to `maxProvidesPerCycle` due CIDs, chosen at random. */
    private fun pickDue(now: Long): List<Cid>? =
        synchronized(lock) {
            if (closed) return null
            val due = ArrayList<Cid>()
            for ((cid, entry) in entries) {
                if (entry.nextDueNanos - now <= 0) due += cid
            }
            if (due.size <= config.maxProvidesPerCycle) {
                due.shuffle(random)
                return due
            }
            // partial Fisher-Yates: the first maxProvidesPerCycle positions become a uniform random sample
            for (i in 0 until config.maxProvidesPerCycle) {
                val j = i + random.nextInt(due.size - i)
                val tmp = due[i]
                due[i] = due[j]
                due[j] = tmp
            }
            return due.subList(0, config.maxProvidesPerCycle).toList()
        }

    private fun onSuccess(cid: Cid) {
        synchronized(lock) {
            announced++
            val entry = entries[cid] ?: return
            entry.failures = 0
            entry.nextDueNanos = clockNanos() + jitteredReprovideNanos()
        }
    }

    private fun onFailure(cid: Cid) {
        synchronized(lock) { failed++ }
        reschedule(cid, failure = true)
    }

    private fun reschedule(
        cid: Cid,
        failure: Boolean,
    ) {
        synchronized(lock) {
            val entry = entries[cid] ?: return
            if (failure) {
                entry.failures = (entry.failures + 1).coerceAtMost(MAX_BACKOFF_EXPONENT)
                entry.nextDueNanos = clockNanos() + backoffNanos(entry.failures)
            }
        }
    }

    /** `min(failureRetryMin * 2^(n-1), reprovideInterval)` for the n-th consecutive failure. */
    internal fun backoffNanos(failures: Int): Long {
        val base = config.failureRetryMin.inWholeNanoseconds
        val cap = config.reprovideInterval.inWholeNanoseconds
        val shift = (failures - 1).coerceIn(0, MAX_BACKOFF_EXPONENT)
        val value = if (base > (cap shr shift)) cap else base shl shift
        return minOf(value, cap)
    }

    private fun jitteredReprovideNanos(): Long {
        val interval = config.reprovideInterval.inWholeNanoseconds
        val fraction = config.reprovideJitterFraction
        if (fraction <= 0.0) return interval
        val offset = (random.nextDouble() * 2.0 - 1.0) * fraction * interval
        return (interval + offset.toLong()).coerceAtLeast(1L)
    }

    private fun maybeSummary(now: Long) {
        val summary =
            synchronized(lock) {
                if (now - lastSummaryNanos < SUMMARY_INTERVAL_NANOS) return
                lastSummaryNanos = now
                ProvideStats(entries.size, attempted, announced, zeroSent, failed, busySkips, notServedDropped, evicted)
            }
        logger.info {
            "post body provides: tracked=${summary.tracked} attempted=${summary.attempted} " +
                "announced=${summary.announced} zeroSent=${summary.zeroSent} failed=${summary.failed} " +
                "busySkips=${summary.busySkips} notServedDropped=${summary.notServedDropped} evicted=${summary.evicted}"
        }
    }

    private sealed interface Outcome {
        data class Sent(
            val count: Int,
        ) : Outcome

        data object Busy : Outcome

        data object Stopped : Outcome

        data object Refused : Outcome

        data object Failed : Outcome
    }

    /** Result of one [runCycle]: announcements started, announcements that reached at least one peer, why it ended. */
    data class CycleResult(
        val attempted: Int,
        val announced: Int,
        val endedBy: EndReason,
    )

    /** Why a [runCycle] ended. */
    enum class EndReason {
        NOTHING_DUE,
        CAP_REACHED,
        BUDGET_EXHAUSTED,
        BUSY,
        STORAGE_STOPPED,
        CLOSED,
    }

    /** Counters of a [BlockProvideScheduler]; numbers only. */
    data class ProvideStats(
        val tracked: Int,
        val attempted: Long,
        val announced: Long,
        val zeroSent: Long,
        val failed: Long,
        val busySkips: Long,
        val notServedDropped: Long,
        val evicted: Long,
    )

    private companion object {
        const val MAX_BACKOFF_EXPONENT = 30
        val SUMMARY_INTERVAL_NANOS: Long = 1.hours.inWholeNanoseconds
    }
}
