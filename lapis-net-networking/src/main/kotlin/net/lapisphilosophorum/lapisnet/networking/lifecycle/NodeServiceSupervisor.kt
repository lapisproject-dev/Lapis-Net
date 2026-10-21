package net.lapisphilosophorum.lapisnet.networking.lifecycle

import io.github.oshai.kotlinlogging.KotlinLogging
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Owns every background activity an entry point starts around a [net.lapisphilosophorum.lapisnet.networking.LapisNode]
 * (periodic DHT maintenance, record republishing, Madli publishing, ...) and the stop actions of the components it
 * attaches, so that a stop - or a failed start - leaves no thread behind.
 *
 * **Plain threads, not coroutines.** This module has no coroutine dependency and the library calls it schedules
 * (DHT walks, Nabu I/O) are blocking anyway; a cancelled job is interrupted via [java.util.concurrent.Future.cancel],
 * which is what a `runInterruptible` would do.
 *
 *  - **Never `GlobalScope`/an unnamed pool**: one bounded, named, daemon pool per supervisor.
 *  - **Periodic jobs** ([launchPeriodic]) re-schedule themselves with `interval +/- jitter`; a failing run backs off
 *    exponentially up to `maxBackoff` (never a tight retry loop) and a success resets the backoff.
 *  - **[stopAll]** first cancels (and interrupts) every job, then runs the registered stop actions in reverse
 *    registration order (LIFO = reverse start order), each on its own daemon thread with a per-component timeout and
 *    an overall budget. A component that does not stop in time is logged (name only, never content) and skipped.
 *    Idempotent.
 */
class NodeServiceSupervisor(
    val name: String,
    poolSize: Int = DEFAULT_POOL_SIZE,
    private val random: Random = Random.Default,
) : AutoCloseable {
    private val threadCounter = AtomicInteger(0)
    private val executor =
        ScheduledThreadPoolExecutor(
            poolSize,
            ThreadFactory { runnable ->
                Thread(runnable, "$name-worker-${threadCounter.incrementAndGet()}").also { it.isDaemon = true }
            },
        ).also {
            it.removeOnCancelPolicy = true
            it.setExecuteExistingDelayedTasksAfterShutdownPolicy(false)
            it.setContinueExistingPeriodicTasksAfterShutdownPolicy(false)
        }
    private val stopActions = CopyOnWriteArrayList<Pair<String, () -> Unit>>()
    private val jobs = CopyOnWriteArrayList<PeriodicJob>()
    private val stopped = AtomicBoolean(false)

    /** A handle on one periodic job. */
    class PeriodicJob internal constructor(
        val name: String,
    ) {
        @Volatile internal var future: ScheduledFuture<*>? = null
        private val cancelled = AtomicBoolean(false)
        private val runs = AtomicLong(0)
        private val failures = AtomicLong(0)

        /** Number of completed runs (successful or not). */
        val runCount: Long get() = runs.get()

        /** Number of runs that threw. */
        val failureCount: Long get() = failures.get()

        val isCancelled: Boolean get() = cancelled.get()

        internal fun markRun(failed: Boolean) {
            runs.incrementAndGet()
            if (failed) failures.incrementAndGet()
        }

        fun cancel() {
            if (cancelled.compareAndSet(false, true)) future?.cancel(true)
        }
    }

    /** Registers [stop] to run during [stopAll] (reverse registration order). */
    fun register(
        componentName: String,
        stop: () -> Unit,
    ) {
        stopActions += componentName to stop
    }

    /**
     * Runs [block] first after [initialDelay], then every `interval +/- jitter`. A throwing run is logged (job name and
     * exception type only) and followed by an exponentially growing delay (see [backoffDelay]).
     */
    fun launchPeriodic(
        jobName: String,
        interval: Duration,
        jitter: Duration,
        initialDelay: Duration,
        maxBackoff: Duration = DEFAULT_MAX_BACKOFF,
        block: () -> Unit,
    ): PeriodicJob {
        require(interval.isPositive()) { "interval must be positive" }
        require(!jitter.isNegative()) { "jitter must not be negative" }
        require(!initialDelay.isNegative()) { "initialDelay must not be negative" }
        check(!stopped.get()) { "supervisor '$name' is stopped" }
        val job = PeriodicJob(jobName)
        jobs += job
        var consecutiveFailures = 0

        lateinit var tick: Runnable

        fun scheduleNext(delay: Duration) {
            if (stopped.get() || job.isCancelled) return
            try {
                job.future = executor.schedule(tick, delay.inWholeMilliseconds.coerceAtLeast(0), TimeUnit.MILLISECONDS)
            } catch (_: java.util.concurrent.RejectedExecutionException) {
                // shut down concurrently - nothing more to schedule
            }
        }
        tick =
            Runnable {
                if (stopped.get() || job.isCancelled) return@Runnable
                var failed = false
                try {
                    block()
                    consecutiveFailures = 0
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return@Runnable
                } catch (e: Throwable) {
                    // Throwable, not Exception: an escaping Error (StackOverflowError, NoClassDefFoundError, an
                    // AssertionError, even OOM) would otherwise vanish into the ScheduledFuture and the job would
                    // never be rescheduled, silently. Rescheduling with backoff is the safe default for all of them.
                    failed = true
                    consecutiveFailures++
                    if (e is Error) {
                        logger.error(
                            e,
                        ) {
                            "periodic job '${job.name}' died with ${e.javaClass.simpleName}; backing off and rescheduling"
                        }
                    } else {
                        logger.warn { "periodic job '${job.name}' failed (${e.javaClass.simpleName}); backing off" }
                    }
                }
                job.markRun(failed)
                val next =
                    if (failed) {
                        backoffDelay(interval, consecutiveFailures, maxBackoff)
                    } else {
                        jittered(interval, jitter)
                    }
                scheduleNext(next)
            }
        scheduleNext(initialDelay)
        return job
    }

    /**
     * Runs [block] once on this supervisor's bounded pool. Returns `false` (and runs nothing) if the supervisor is
     * stopped or the pool rejects. A throwing block is logged (task name and exception type only), never rethrown.
     * Interrupted by [stopAll] like every other job.
     */
    fun launchOneShot(
        taskName: String,
        block: () -> Unit,
    ): Boolean {
        if (stopped.get()) return false
        return try {
            executor.execute {
                try {
                    block()
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                } catch (e: Throwable) {
                    logger.warn { "one-shot task '$taskName' failed (${e.javaClass.simpleName})" }
                }
            }
            true
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            false
        }
    }

    private fun jittered(
        interval: Duration,
        jitter: Duration,
    ): Duration {
        val jitterMillis = jitter.inWholeMilliseconds
        if (jitterMillis <= 0) return interval
        val offset = random.nextLong(-jitterMillis, jitterMillis + 1)
        return (interval.inWholeMilliseconds + offset).coerceAtLeast(1L).milliseconds
    }

    /** Number of worker threads this supervisor's pool currently holds (diagnostics and tests). */
    fun workerThreadCount(): Int = executor.poolSize

    /** `true` once [stopAll] has run and the worker pool has terminated (diagnostics and tests). */
    fun isTerminated(): Boolean = executor.isTerminated

    /**
     * Cancels every job, then runs the registered stop actions in reverse order. Each action gets [perComponent] to
     * finish, the whole call is bounded by [overall]. Idempotent: a second call does nothing.
     */
    fun stopAll(
        perComponent: Duration = DEFAULT_PER_COMPONENT_TIMEOUT,
        overall: Duration = DEFAULT_OVERALL_TIMEOUT,
    ) {
        if (!stopped.compareAndSet(false, true)) return
        val deadlineNanos = System.nanoTime() + overall.inWholeNanoseconds
        jobs.forEach { it.cancel() }
        executor.shutdownNow()
        runCatching {
            val wait = minOf(perComponent.inWholeNanoseconds, remainingNanos(deadlineNanos))
            if (!executor.awaitTermination(wait.coerceAtLeast(0), TimeUnit.NANOSECONDS)) {
                logger.warn { "supervisor '$name': background jobs did not terminate within $perComponent" }
            }
        }
        for ((componentName, action) in stopActions.reversed()) {
            runStopAction(componentName, action, perComponent, deadlineNanos)
        }
        stopActions.clear()
    }

    private fun runStopAction(
        componentName: String,
        action: () -> Unit,
        perComponent: Duration,
        deadlineNanos: Long,
    ) {
        val finished = java.util.concurrent.CompletableFuture<Unit>()
        val thread =
            Thread({
                try {
                    action()
                    finished.complete(Unit)
                } catch (t: Throwable) {
                    finished.completeExceptionally(t)
                }
            }, "$name-stop-$componentName")
        thread.isDaemon = true
        thread.start()
        val wait = minOf(perComponent.inWholeNanoseconds, remainingNanos(deadlineNanos)).coerceAtLeast(0)
        try {
            finished.get(wait, TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            logger.warn { "supervisor '$name': component '$componentName' did not stop in time; continuing" }
        } catch (e: java.util.concurrent.ExecutionException) {
            logger.warn {
                "supervisor '$name': component '$componentName' failed to stop (${e.cause?.javaClass?.simpleName})"
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun remainingNanos(deadlineNanos: Long): Long = deadlineNanos - System.nanoTime()

    /** Same as [stopAll] with the default timeouts. */
    override fun close() = stopAll()

    companion object {
        const val DEFAULT_POOL_SIZE = 4
        val DEFAULT_MAX_BACKOFF: Duration = 300.seconds
        val DEFAULT_PER_COMPONENT_TIMEOUT: Duration = 5.seconds
        val DEFAULT_OVERALL_TIMEOUT: Duration = 15.seconds

        /**
         * The delay after the [consecutiveFailures]-th consecutive failure: `interval * 2^failures`, capped at
         * [maxBackoff] (and never below [interval]).
         */
        fun backoffDelay(
            interval: Duration,
            consecutiveFailures: Int,
            maxBackoff: Duration,
        ): Duration {
            require(consecutiveFailures >= 1) { "consecutiveFailures must be >= 1" }
            val shift = consecutiveFailures.coerceAtMost(20)
            val scaled = interval.inWholeMilliseconds.coerceAtLeast(1L) * (1L shl shift)
            val capped = minOf(scaled, maxBackoff.inWholeMilliseconds)
            return maxOf(capped, interval.inWholeMilliseconds).milliseconds
        }
    }
}
