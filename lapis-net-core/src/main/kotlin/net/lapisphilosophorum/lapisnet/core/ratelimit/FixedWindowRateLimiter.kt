package net.lapisphilosophorum.lapisnet.core.ratelimit

import java.time.Duration

/** Simple fixed-window rate limiter bounding a caller's operation RATE, not merely its concurrency.
 * A concurrency bound (e.g. a [java.util.concurrent.Semaphore]) alone only throttles CONCURRENT
 * attempts - a purely SEQUENTIAL attacker, one attempt at a time, never contends with a concurrency
 * bound at all. This class closes that gap: at most `maxPerWindow` [tryAcquire] successes are
 * granted per rolling fixed `window`, regardless of how sequential or concurrent the callers are.
 *
 * **V0.8.7 extraction**: originally a `private class` inline in
 * `net.lapisphilosophorum.lapisnet.dm.DmSessionManager` (that module's own
 * `prekeyConsumptionRateLimiter` field), promoted to this shared, public location so
 * `net.lapisphilosophorum.lapisnet.call.CallManager`'s invite-flood rate limiter can reuse the exact
 * same, already-reviewed implementation rather than a second copy-pasted one - two call sites was
 * judged the threshold worth de-duplicating at.
 *
 * Deliberately a plain fixed-window counter, not a smoother token bucket or sliding log - this
 * codebase's usual "generous headroom, provisional magnitude, not derived from pilot data" numeric-cap
 * convention (see `DmSessionManager.MAX_LIVE_SESSIONS`) applies here too: the goal is to turn an
 * unbounded drain into a bounded one, not to perfectly smooth request admission.
 *
 * Thread-safe via a single `synchronized` block per [tryAcquire] call - callers that sit behind their
 * own additional concurrency bound (e.g. `DmSessionManager.prekeyConsumptionSemaphore`) never see
 * meaningful contention here; callers that do not still get a correct, if serialized, answer.
 */
class FixedWindowRateLimiter(
    private val maxPerWindow: Int,
    private val window: Duration,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    private var windowStartMillis = clockMillis()
    private var countInWindow = 0

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clockMillis()
        if (now - windowStartMillis >= window.toMillis()) {
            windowStartMillis = now
            countInWindow = 0
        }
        if (countInWindow >= maxPerWindow) return false
        countInWindow++
        return true
    }
}
