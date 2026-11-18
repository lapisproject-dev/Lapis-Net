@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.time.Clock
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Client-side circuit policy (wave V0.10.0-E): a token bucket for circuit builds (default 6 per minute, burst 3), an
 * exponential backoff after failed builds (5 s up to 5 min), a pool of at most [maxOpenClientCircuits] outgoing client
 * circuits (directory publication and rendezvous client; the long-lived introduction circuits of a hosted service are
 * bounded by the host's intro count and only pay the rate), a maximum circuit age of [lifetime], and a [lockdown] after
 * which nothing new is built. Every new target gets a new circuit: a warm circuit (wave V0.10.0-H) is built in advance
 * and then serves exactly one use; there is no circuit reuse anywhere.
 *
 * The handle of a circuit is an opaque object; nothing here logs or exposes targets.
 */
@ExperimentalOnionApi
class CircuitBuildGovernor(
    private val clock: Clock = Clock.systemUTC(),
    val maxOpenClientCircuits: Int = 4,
    private val ratePerMinute: Int = 6,
    private val burst: Int = 3,
    val lifetime: Duration = 10.minutes,
    private val backoffMin: Duration = 5.seconds,
    private val backoffMax: Duration = 5.minutes,
    /**
     * Separate budget for the rendezvous circuits a hosted service builds because REMOTE parties asked for them
     * (INTRODUCE). They are attacker-triggerable, so they never share tokens or backoff with the node's own circuits
     * (introduction, publication, own client circuits), and over budget they are dropped, not delayed.
     */
    private val serviceRendezvousPerMinute: Int = 60,
    private val serviceRendezvousBurst: Int = 10,
    /**
     * Wave V0.10.0-J2 (Q8): lookup circuits are pool circuits with an ADDITIONAL bucket of their own (on top of the
     * general one), so that lookups can never use up the budget the node's publications need. At most
     * [maxOpenLookupCircuits] lookup circuit is open (or being built) at a time; over the bucket a lookup is delayed.
     */
    val maxOpenLookupCircuits: Int = 1,
    private val lookupBuildsPerMinute: Int = 2,
) {
    sealed interface Admission {
        data object Granted : Admission

        class Delayed(
            val retryAfter: Duration,
        ) : Admission

        data object PoolFull : Admission

        /** Over the budget of an attacker-triggerable purpose: refused at once, never queued. */
        data object Dropped : Admission

        data object Locked : Admission
    }

    private class Open(
        val handle: Any,
        var purpose: CircuitPurpose?,
        var targetKey: String,
        val builtAtMillis: Long,
    )

    init {
        require(maxOpenClientCircuits > 0 && ratePerMinute > 0 && burst > 0) { "limits must be positive" }
        require(serviceRendezvousPerMinute > 0 && serviceRendezvousBurst > 0) { "limits must be positive" }
        require(maxOpenLookupCircuits in 1..maxOpenClientCircuits && lookupBuildsPerMinute > 0) {
            "lookup limits must be positive and fit the pool"
        }
        require(lifetime.isPositive() && backoffMin.isPositive() && backoffMax >= backoffMin) { "times inconsistent" }
    }

    private val lock = Any()
    private var tokens: Double = burst.toDouble()
    private var lastRefillMillis: Long = clock.millis()
    private var consecutiveFailures = 0
    private var blockedUntilMillis = 0L
    private var rendezvousTokens: Double = serviceRendezvousBurst.toDouble()
    private var rendezvousRefillMillis: Long = clock.millis()
    private var pendingPool = 0
    private var pendingLookup = 0
    private var lookupTokens: Double = lookupBuildsPerMinute.toDouble()
    private var lookupRefillMillis: Long = clock.millis()
    private var locked = false
    private val open = ArrayList<Open>()
    private val counters = HashMap<CircuitPurpose?, LongArray>()
    private var maxConsecutiveFailuresSeen = 0

    /** Coarse diagnostic counters per purpose (no targets): admissions by outcome and failed builds. */
    class AdmissionCounts(
        val granted: Long,
        val delayed: Long,
        val poolFull: Long,
        val dropped: Long,
        val locked: Long,
        val failed: Long,
    )

    private fun count(
        purpose: CircuitPurpose?,
        slot: Int,
    ) {
        counters.getOrPut(purpose) { LongArray(COUNTER_SLOTS) }[slot]++
    }

    /** Snapshot of the diagnostic counters, per purpose (`null` = warm circuits). */
    fun admissionStats(): Map<CircuitPurpose?, AdmissionCounts> =
        synchronized(lock) {
            counters.mapValues { (_, c) -> AdmissionCounts(c[0], c[1], c[2], c[3], c[4], c[5]) }
        }

    /** Highest number of consecutive failed builds seen so far (the backoff exponent). */
    fun maxConsecutiveFailuresSeen(): Int = synchronized(lock) { maxConsecutiveFailuresSeen }

    private fun isServiceRendezvous(purpose: CircuitPurpose?): Boolean = purpose == CircuitPurpose.RENDEZVOUS_RECEIVER

    private fun isPool(purpose: CircuitPurpose?): Boolean =
        purpose == null ||
            purpose == CircuitPurpose.DIRECTORY_PUBLISH ||
            purpose == CircuitPurpose.MAILBOX_PUBLISH ||
            purpose == CircuitPurpose.LOOKUP ||
            purpose == CircuitPurpose.RENDEZVOUS_SENDER ||
            purpose == CircuitPurpose.INTRODUCE

    private fun refill(now: Long) {
        val elapsed = (now - lastRefillMillis).coerceAtLeast(0)
        lastRefillMillis = now
        tokens = minOf(burst.toDouble(), tokens + elapsed * ratePerMinute / 60_000.0)
    }

    private fun refillLookup(now: Long) {
        val elapsed = (now - lookupRefillMillis).coerceAtLeast(0)
        lookupRefillMillis = now
        lookupTokens =
            minOf(lookupBuildsPerMinute.toDouble(), lookupTokens + elapsed * lookupBuildsPerMinute / 60_000.0)
    }

    /** Asks to start building a circuit for [purpose] towards [targetKey]. A `Granted` must be answered by [onBuilt] or [onFailed]. */
    fun admit(
        purpose: CircuitPurpose?,
        targetKey: String,
    ): Admission =
        synchronized(lock) {
            val a = admitUncounted(purpose)
            count(
                purpose,
                when (a) {
                    Admission.Granted -> 0
                    is Admission.Delayed -> 1
                    Admission.PoolFull -> 2
                    Admission.Dropped -> 3
                    Admission.Locked -> 4
                },
            )
            a
        }

    private fun admitUncounted(purpose: CircuitPurpose?): Admission {
        if (locked) return Admission.Locked
        val now = clock.millis()
        if (isServiceRendezvous(purpose)) {
            // own bucket, no backoff: failures of attacker-named rendezvous points must not block the node's own builds
            val elapsed = (now - rendezvousRefillMillis).coerceAtLeast(0)
            rendezvousRefillMillis = now
            rendezvousTokens =
                minOf(
                    serviceRendezvousBurst.toDouble(),
                    rendezvousTokens + elapsed * serviceRendezvousPerMinute / 60_000.0,
                )
            if (rendezvousTokens < 1.0) return Admission.Dropped
            rendezvousTokens -= 1.0
            return Admission.Granted
        }
        if (now <
            blockedUntilMillis
        ) {
            return Admission.Delayed((blockedUntilMillis - now).coerceAtLeast(1).milliseconds)
        }
        val pool = isPool(purpose)
        if (pool &&
            open.count { isPool(it.purpose) } + pendingPool >= maxOpenClientCircuits
        ) {
            return Admission.PoolFull
        }
        val lookup = purpose == CircuitPurpose.LOOKUP
        if (lookup) {
            if (open.count { it.purpose == CircuitPurpose.LOOKUP } + pendingLookup >= maxOpenLookupCircuits) {
                return Admission.PoolFull
            }
            refillLookup(now)
            if (lookupTokens < 1.0) {
                val ms = ((1.0 - lookupTokens) * 60_000.0 / lookupBuildsPerMinute).toLong().coerceAtLeast(1)
                return Admission.Delayed(ms.milliseconds)
            }
        }
        refill(now)
        if (tokens < 1.0) {
            val ms = ((1.0 - tokens) * 60_000.0 / ratePerMinute).toLong().coerceAtLeast(1)
            return Admission.Delayed(ms.milliseconds)
        }
        tokens -= 1.0
        if (lookup) {
            lookupTokens -= 1.0
            pendingLookup++
        }
        if (pool) pendingPool++
        return Admission.Granted
    }

    /**
     * Like [admit], but for a speculative build (the warm pool of wave V0.10.0-H): `true` only if the build is granted
     * RIGHT NOW (same bucket, backoff and pool bounds). Never delays, never queues. A `true` must be answered by
     * [onBuilt] or [onFailed], exactly like a `Granted`.
     */
    fun tryAdmitNow(
        purpose: CircuitPurpose?,
        targetKey: String,
    ): Boolean =
        synchronized(lock) {
            // a speculative build leaves at least one token for a real one
            if (!locked) {
                refill(clock.millis())
                if (tokens < 1.0 + WARM_TOKEN_RESERVE) return false
            }
            admit(purpose, targetKey) == Admission.Granted
        }

    /**
     * Changes the purpose and target of an open circuit (a warm circuit is handed to its one use). The slot is kept and
     * the age is NOT reset: the lifetime runs from the build. A purpose change inside the pool does not change the count.
     * `false` (nothing changed) when the change would exceed [maxOpenLookupCircuits] (wave V0.10.0-J2).
     */
    fun retag(
        handle: Any,
        purpose: CircuitPurpose?,
        targetKey: String,
    ): Boolean =
        synchronized(lock) {
            val entry = open.firstOrNull { it.handle === handle } ?: return@synchronized true
            if (purpose == CircuitPurpose.LOOKUP &&
                entry.purpose != CircuitPurpose.LOOKUP &&
                open.count { it.purpose == CircuitPurpose.LOOKUP } + pendingLookup >= maxOpenLookupCircuits
            ) {
                return@synchronized false
            }
            entry.purpose = purpose
            entry.targetKey = targetKey
            true
        }

    /** The circuit [handle] was built. Not registered if it is already [closed]. */
    fun onBuilt(
        handle: Any,
        purpose: CircuitPurpose?,
        targetKey: String,
        closed: Boolean = false,
    ) = synchronized(lock) {
        if (isPool(purpose) && pendingPool > 0) pendingPool--
        if (purpose == CircuitPurpose.LOOKUP && pendingLookup > 0) pendingLookup--
        if (!isServiceRendezvous(purpose)) {
            consecutiveFailures = 0
            blockedUntilMillis = 0
        }
        if (!closed && !locked) open += Open(handle, purpose, targetKey, clock.millis())
    }

    /** A granted build failed. Starts or lengthens the backoff. */
    fun onFailed(purpose: CircuitPurpose?) =
        synchronized(lock) {
            if (isPool(purpose) && pendingPool > 0) pendingPool--
            if (purpose == CircuitPurpose.LOOKUP && pendingLookup > 0) pendingLookup--
            if (isServiceRendezvous(purpose)) return@synchronized
            count(purpose, 5)
            consecutiveFailures = (consecutiveFailures + 1).coerceAtMost(MAX_FAILURES)
            if (consecutiveFailures > maxConsecutiveFailuresSeen) maxConsecutiveFailuresSeen = consecutiveFailures
            val factor = 1L shl (consecutiveFailures - 1).coerceAtMost(MAX_SHIFT)
            val delay = minOf(backoffMax.inWholeMilliseconds, backoffMin.inWholeMilliseconds * factor)
            blockedUntilMillis = clock.millis() + delay
        }

    fun onClosed(handle: Any) {
        synchronized(lock) { open.removeAll { it.handle === handle } }
    }

    /** The handles older than [lifetime] at [now]; the caller closes them (and calls [onClosed]). */
    fun expired(now: Instant): List<Any> =
        synchronized(lock) {
            val limit = now.toEpochMilli() - lifetime.inWholeMilliseconds
            open.filter { it.builtAtMillis <= limit }.map { it.handle }
        }

    /** All open handles (shutdown). */
    fun allHandles(): List<Any> = synchronized(lock) { open.map { it.handle } }

    /** No new circuit is admitted from now on. */
    fun lockdown() = synchronized(lock) { locked = true }

    fun isLocked(): Boolean = synchronized(lock) { locked }

    fun openCount(): Int = synchronized(lock) { open.size }

    /** Currently open lookup circuits (wave V0.10.0-J2). */
    fun lookupOpenCount(): Int = synchronized(lock) { open.count { it.purpose == CircuitPurpose.LOOKUP } }

    /** Currently open pooled client circuits (without long-lived introduction circuits). */
    fun poolOpenCount(): Int = synchronized(lock) { open.count { isPool(it.purpose) } }

    private companion object {
        const val WARM_TOKEN_RESERVE = 1.0
        const val COUNTER_SLOTS = 6
        const val MAX_SHIFT = 20
        const val MAX_FAILURES = 64
    }
}
