package net.lapisphilosophorum.lapisnet.madli

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

private fun logSkipSummary(
    skippedSinceLastSummary: Long,
    totalSkipped: Long,
) {
    logger.debug {
        "observer-weight refresh throttled: $skippedSinceLastSummary requests skipped ($totalSkipped total)"
    }
}

private fun logRefreshFailure(
    exceptionType: String,
    consecutiveFailures: Int,
) {
    logger.warn { "observer-weight refresh failed ($exceptionType), consecutive failures: $consecutiveFailures" }
}

/**
 * Counters of a [CachedVeritasObserverWeight] (diagnostics and tests).
 *
 * @property recomputations runs of the grant source, including the initial one and failed attempts
 * @property graphRebuilds [TrustGraph.fromGrants] calls (skipped when the content fingerprint is unchanged)
 * @property failures refreshes that threw
 * @property consecutiveFailures failures since the last success
 * @property skippedRefreshRequests refresh requests the throttle rejected (window, active run, backoff, stopped)
 */
data class ObserverWeightRefreshStats(
    val recomputations: Long,
    val graphRebuilds: Long,
    val failures: Long,
    val consecutiveFailures: Int,
    val skippedRefreshRequests: Long,
    val inFlight: Boolean,
    val stopped: Boolean,
)

/**
 * The Veritas observer weight for Madli aggregation ([MadliAggregator.veritasObserverWeight]) over a trust-graph
 * snapshot, with a bounded recomputation rate.
 *
 * **Stale-while-revalidate.** [weightOf] never recomputes on the caller's thread (except the very first call, see
 * below). When the grant index changed, it asks the throttle for a refresh and answers from the existing snapshot.
 * Without that bound, a steady stream of valid grants would cost one full grant resolution + fingerprint + trust-graph
 * rebuild per change. The throttle admits a refresh only if (a) the instance is not stopped, (b) no refresh is
 * running (single-flight: at most one task per instance can exist, so there is no queue), and (c) at least one
 * `refreshWindow` has passed since the previous run started (after a failure: the exponential backoff instead). Both
 * triggers - a reader noticing a newer version and the periodic safety tick - go through this one gate, so tick jitter
 * cannot exceed the rate.
 *
 * **Safety rule (revocation).** The weight may lag behind the grant index by at most two windows plus the tick jitter
 * (window / 10) plus the duration of a run (after failures: by at most the capped backoff), never longer. Not one
 * window: the safety tick has its own free phase and the gate rejects a tick that falls just before the window end
 * (counted only as skipped), so an idle instance is caught up by the following tick, about one interval later. Readers
 * that keep asking shorten this to one window plus a run. Every run rebuilds the snapshot completely from the current
 * grants (no merge with the old state), so a revocation is effective after the next successful run. The version is read
 * BEFORE the grants, so a change during a run leaves the snapshot looking stale and is picked up by the next run.
 *
 * **Fail closed on persistent failure.** The backoff only bounds the next ATTEMPT, not how current the weight is. If
 * refreshes keep failing (e.g. an attacker floods the grant index so that [TrustGraph.fromGrants] rejects the edge
 * count on every run), the old snapshot must not keep answering indefinitely, or a revocation would never take
 * effect. Therefore, once the grant index has changed since the snapshot AND refreshes have been failing for longer
 * than `maxStaleness`, [weightOf] returns `0.0` (no reputation influence) until a refresh succeeds again. A snapshot
 * whose version still matches the index is exact and is never degraded by failures.
 *
 * **Scheduling delay.** The bounds above assume the refresh task starts promptly. In production it shares the
 * supervisor's bounded pool with blocking periodic jobs (DHT walks, republishing); if all workers are busy in network
 * I/O, the one-shot waits in the queue and the revocation delay grows by the longest timeout of those jobs. There is
 * no further security impact (single-flight: the queue cannot grow through this class).
 *
 * **First call.** Without any snapshot there is no safe default (a default weight would either over-trust or be
 * wrong), so the very first [weightOf] computes synchronously under a lock (concurrent first callers share that one
 * computation). The caller is the relay auto-select thread, and an attacker can trigger this path once per instance.
 * If that first computation fails, [weightOf] returns `0.0` (no reputation influence) and refreshes go through the
 * throttle asynchronously from then on.
 *
 * Runs execute on the supplied executor (the supervisor's bounded pool); a run is index-scan CPU work and contains no
 * network I/O. Failures keep the old weight, back off exponentially and are logged rate-limited with the exception
 * type only - never keys or grant contents.
 */
class CachedVeritasObserverWeight internal constructor(
    private val version: () -> Long,
    private val grantsSource: () -> Collection<VeritasGrant>,
    private val fingerprintOf: (Collection<VeritasGrant>) -> List<Byte>,
    private val localIdentity: Secp256k1PublicKey,
    private val refreshExecutor: (Runnable) -> Boolean,
    private val refreshWindow: Duration = DEFAULT_REFRESH_WINDOW,
    private val maxBackoff: Duration = DEFAULT_MAX_BACKOFF,
    private val maxStaleness: Duration = maxBackoff,
    private val nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val onSkipSummary: (skippedSinceLastSummary: Long, totalSkipped: Long) -> Unit = ::logSkipSummary,
    private val onFailureLog: (exceptionType: String, consecutiveFailures: Int) -> Unit = ::logRefreshFailure,
    private val logInterval: Duration = DEFAULT_LOG_INTERVAL,
) : AutoCloseable {
    init {
        require(refreshWindow.isPositive() && refreshWindow <= MAX_REFRESH_WINDOW) {
            "refreshWindow must be in (0, $MAX_REFRESH_WINDOW]"
        }
        require(maxBackoff >= refreshWindow) { "maxBackoff must not be below refreshWindow" }
        require(maxStaleness.isPositive()) { "maxStaleness must be positive" }
        require(logInterval.isPositive()) { "logInterval must be positive" }
    }

    private class Snapshot(
        val version: Long,
        val fingerprint: List<Byte>,
        val weight: (Secp256k1PublicKey) -> Double,
    )

    @Volatile private var snapshot: Snapshot? = null

    @Volatile private var initAttempted = false

    @Volatile private var stopped = false

    @Volatile private var nextAllowedAtMillis = Long.MIN_VALUE

    /** Start of the first failed run since the last success; [Long.MIN_VALUE] while healthy. */
    @Volatile private var failingSinceMillis = Long.MIN_VALUE
    private val initLock = Any()
    private val inFlight = AtomicBoolean(false)
    private val recomputations = AtomicLong(0)
    private val graphRebuilds = AtomicLong(0)
    private val failures = AtomicLong(0)
    private val consecutiveFailures = AtomicInteger(0)
    private val skipped = AtomicLong(0)
    private val skippedAtLastSummary = AtomicLong(0)
    private val lastSummaryAtMillis = AtomicLong(nowMillis())
    private val lastFailureLogAtMillis = AtomicLong(Long.MIN_VALUE)

    /**
     * Hot path: one version read. Never blocks except for the very first call (see class KDoc); a stale snapshot is
     * answered immediately while the throttle decides about a background refresh.
     */
    fun weightOf(observer: Secp256k1PublicKey): Double {
        val current = snapshot ?: return weightWithoutSnapshot(observer)
        if (current.version == version()) return current.weight(observer)
        val now = nowMillis()
        requestRefresh(now)
        // fail closed: a stale snapshot must not outlive a persistently failing refresh (revocations would never apply)
        val failingSince = failingSinceMillis
        if (failingSince != Long.MIN_VALUE && now - failingSince > maxStaleness.inWholeMilliseconds) return 0.0
        return current.weight(observer)
    }

    private fun weightWithoutSnapshot(observer: Secp256k1PublicKey): Double {
        if (stopped) return 0.0
        if (!initAttempted) {
            val initial = synchronized(initLock) { snapshot ?: if (initAttempted) null else initialise() }
            if (initial != null) return initial.weight(observer)
        }
        requestRefresh(nowMillis())
        return 0.0
    }

    /** Runs under [initLock]; marks the initialisation as attempted whatever the outcome. */
    private fun initialise(): Snapshot? {
        val start = nowMillis()
        try {
            val fresh = compute(null)
            if (stopped) return null
            snapshot = fresh
            onSuccess(start)
            return fresh
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            return null
        } catch (e: Throwable) {
            onFailure(start, e)
            return null
        } finally {
            initAttempted = true
        }
    }

    /** Safety trigger, called by the periodic job: catches up an idle instance after the last change. */
    internal fun tick() {
        val current = snapshot
        if (current == null) {
            if (!initAttempted) return // nobody has asked for a weight yet
        } else if (current.version == version()) {
            return
        }
        requestRefresh(nowMillis())
    }

    private fun requestRefresh(now: Long) {
        if (stopped || now < nextAllowedAtMillis || !inFlight.compareAndSet(false, true)) {
            skipRequest(now)
            return
        }
        val accepted =
            try {
                refreshExecutor(Runnable { runRefresh() })
            } catch (_: Throwable) {
                false
            }
        if (!accepted) inFlight.set(false)
    }

    private fun runRefresh() {
        try {
            if (stopped) return
            val start = nowMillis()
            try {
                val fresh = compute(snapshot)
                if (stopped) return
                snapshot = fresh
                onSuccess(start)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (e: Throwable) {
                onFailure(start, e)
            }
        } finally {
            inFlight.set(false)
        }
    }

    /** The version is read before the grants: a change while computing leaves the result stale (revocation safe). */
    private fun compute(previous: Snapshot?): Snapshot {
        val observedVersion = version()
        recomputations.incrementAndGet()
        val grants = grantsSource()
        val fingerprint = fingerprintOf(grants)
        if (previous != null && previous.fingerprint == fingerprint) {
            return Snapshot(observedVersion, fingerprint, previous.weight)
        }
        graphRebuilds.incrementAndGet()
        return Snapshot(
            observedVersion,
            fingerprint,
            MadliAggregator.veritasObserverWeight(TrustGraph.fromGrants(grants), localIdentity),
        )
    }

    private fun onSuccess(start: Long) {
        nextAllowedAtMillis = start + refreshWindow.inWholeMilliseconds
        failingSinceMillis = Long.MIN_VALUE
        val recovered = consecutiveFailures.getAndSet(0)
        if (recovered > 0) logger.info { "observer-weight refresh recovered after $recovered failed attempts" }
    }

    private fun onFailure(
        start: Long,
        error: Throwable,
    ) {
        failures.incrementAndGet()
        val consecutive = consecutiveFailures.incrementAndGet()
        if (consecutive == 1) failingSinceMillis = start
        nextAllowedAtMillis =
            start + NodeServiceSupervisor.backoffDelay(refreshWindow, consecutive, maxBackoff).inWholeMilliseconds
        val lastLog = lastFailureLogAtMillis.get()
        if (consecutive == 1 || start - lastLog >= logInterval.inWholeMilliseconds) {
            lastFailureLogAtMillis.set(start)
            // exception type and counter only - never keys or grant contents
            onFailureLog(error.javaClass.simpleName, consecutive)
        }
    }

    private fun skipRequest(now: Long) {
        skipped.incrementAndGet()
        val last = lastSummaryAtMillis.get()
        if (now - last < logInterval.inWholeMilliseconds || !lastSummaryAtMillis.compareAndSet(last, now)) return
        val total = skipped.get()
        val delta = total - skippedAtLastSummary.getAndSet(total)
        // only numbers cross this hook, so keys cannot reach a log through it
        if (delta > 0) onSkipSummary(delta, total)
    }

    /** Stops all further refreshes; a run still active discards its result. Idempotent. */
    fun stop() {
        stopped = true
    }

    override fun close() = stop()

    fun stats(): ObserverWeightRefreshStats =
        ObserverWeightRefreshStats(
            recomputations = recomputations.get(),
            graphRebuilds = graphRebuilds.get(),
            failures = failures.get(),
            consecutiveFailures = consecutiveFailures.get(),
            skippedRefreshRequests = skipped.get(),
            inFlight = inFlight.get(),
            stopped = stopped,
        )

    companion object {
        val DEFAULT_REFRESH_WINDOW: Duration = 5.seconds
        val DEFAULT_MAX_BACKOFF: Duration = 60.seconds
        val DEFAULT_LOG_INTERVAL: Duration = 60.seconds
        private val MAX_REFRESH_WINDOW: Duration = 10.minutes

        /**
         * Production wiring: refreshes run as one-shot tasks on [supervisor]'s bounded pool, a safety tick runs once
         * per window, and the stop is registered there (so `stopAll` ends everything).
         */
        fun startSupervised(
            veritas: VeritasGossip,
            localIdentity: Secp256k1PublicKey,
            supervisor: NodeServiceSupervisor,
            refreshWindow: Duration = DEFAULT_REFRESH_WINDOW,
        ): CachedVeritasObserverWeight =
            startSupervised(
                version = veritas::grantsVersion,
                grantsSource = veritas::currentGrants,
                fingerprintOf = { veritas.currentGrantsFingerprint(it) },
                localIdentity = localIdentity,
                supervisor = supervisor,
                refreshWindow = refreshWindow,
            )

        internal fun startSupervised(
            version: () -> Long,
            grantsSource: () -> Collection<VeritasGrant>,
            fingerprintOf: (Collection<VeritasGrant>) -> List<Byte>,
            localIdentity: Secp256k1PublicKey,
            supervisor: NodeServiceSupervisor,
            refreshWindow: Duration = DEFAULT_REFRESH_WINDOW,
            nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
        ): CachedVeritasObserverWeight {
            val weight =
                CachedVeritasObserverWeight(
                    version = version,
                    grantsSource = grantsSource,
                    fingerprintOf = fingerprintOf,
                    localIdentity = localIdentity,
                    refreshExecutor = { task ->
                        supervisor.launchOneShot("madli-observer-weight-refresh") { task.run() }
                    },
                    refreshWindow = refreshWindow,
                    maxBackoff = maxOf(DEFAULT_MAX_BACKOFF, refreshWindow),
                    nowMillis = nowMillis,
                )
            supervisor.register("madli-observer-weight") { weight.stop() }
            try {
                supervisor.launchPeriodic(
                    "madli-observer-weight-tick",
                    interval = refreshWindow,
                    jitter = refreshWindow / 10,
                    initialDelay = refreshWindow,
                ) { weight.tick() }
            } catch (e: Throwable) {
                weight.stop()
                throw e
            }
            return weight
        }
    }
}

/**
 * Drives [MadliRelayReliabilityPublisher] at the intended cadence: the relay reliability of the PREVIOUS UTC day,
 * published at most once per day (the caller wakes this up as often as it likes, e.g. every six hours). A day is only
 * marked done after a pass that did not throw.
 */
class DailyRelayReliabilityPublication(
    private val publisher: MadliRelayReliabilityPublisher,
    private val today: () -> Long = { currentEpochDayUtc() },
) {
    @Volatile private var lastPublishedDay: Long = Long.MIN_VALUE

    /** Publishes yesterday's vectors unless that already happened. @return the number of announced vectors. */
    fun runOnce(): Int {
        val day = today() - 1
        if (day == lastPublishedDay) return 0
        val announced = publisher.publishForDay(day)
        lastPublishedDay = day
        return announced
    }
}
