package net.lapisphilosophorum.lapisnet.networking.relay

import io.libp2p.core.PeerId
import java.time.Instant

/**
 * Attempts and successes this node observed against one relay in one UTC day.
 *
 * [reliabilityMicros] is the fixed-point success fraction (`0..1_000_000`) that a Madli relay
 * vector carries - integer arithmetic only, as the value ends up in a signed structure.
 */
data class RelayReliabilityCounts(
    val attempts: Int,
    val successes: Int,
) {
    init {
        require(attempts >= 0) { "attempts must be >= 0: $attempts" }
        require(successes in 0..attempts) { "successes must be in 0..attempts: $successes / $attempts" }
    }

    /** `floor(successes * 1_000_000 / attempts)`. Requires at least one attempt. */
    fun reliabilityMicros(): Int {
        require(attempts > 0) { "no attempts recorded" }
        return (successes.toLong() * 1_000_000L / attempts.toLong()).toInt()
    }
}

/**
 * Client-side observation of how reliably relays serve this node, bucketed by UTC day. Fed by
 * [RelayReservationClient] (reserve and renew) and [LapisRelayTransport.dial] (outgoing circuit
 * dials through a relay). **Incoming circuits are not counted:** a failure to deliver one is
 * not observable on the receiving side.
 *
 * Known imprecision, accepted: an outgoing dial can fail for a reason that is not the relay's
 * fault (e.g. the target is offline, or answers its stop leg with a non-OK status that the relay
 * forwards; capped at one counted failure per relay/target/day). Refusals with `NO_RESERVATION` are not counted at all; `CONNECTION_FAILED` is, because
 * the relay chooses that status and excluding it would let a hostile relay hide its failures. The
 * value is thus a noisy, slightly pessimistic estimate; the Veritas-weighted median over many
 * observers in [net.lapisphilosophorum.lapisnet.madli] averages that noise out.
 *
 * Bounded: at most [maxTrackedRelays] relays per day (relays with a reservation attempt displace
 * dial-only entries when full, so an attacker flooding dials to fake relays cannot starve the real
 * ones; at most one failed dial per relay/target/day is counted) and the current plus the previous UTC day
 * (older buckets are dropped on every write), so a hostile directory cannot grow it. Counters
 * saturate at [Int.MAX_VALUE]. Thread-safe.
 */
class RelayReliabilityTracker internal constructor(
    private val maxTrackedRelays: Int = DEFAULT_MAX_TRACKED_RELAYS,
    private val clock: () -> Instant = Instant::now,
) {
    private class Counter(
        var attempts: Int = 0,
        var successes: Int = 0,
        /** Set once a reservation / renewal was attempted against this relay: it is a relay this
         * node really uses, so a flood of dial observations must never push it out. */
        var held: Boolean = false,
    )

    private val days = HashMap<Long, LinkedHashMap<PeerId, Counter>>()

    /** Per day: the (relay, target) pairs whose failed circuit dial was already counted. */
    private val failedDialPairs = HashMap<Long, HashSet<Pair<PeerId, PeerId>>>()

    init {
        require(maxTrackedRelays > 0) { "maxTrackedRelays must be > 0" }
    }

    /**
     * Records one reserve / renew attempt (a relay this node holds or tries to hold a reservation
     * with). Such a relay is always tracked: when the day's bucket is full, the non-reservation
     * entry with the fewest attempts is evicted to make room.
     */
    @Synchronized
    internal fun recordReservationAttempt(
        relay: PeerId,
        success: Boolean,
    ) = record(relay, success, held = true)

    /**
     * Records one outgoing circuit dial through [relay] to [target]. At most ONE failed dial per
     * `(relay, target)` pair and UTC day is counted: a target that holds a reservation on an honest
     * relay can make every dial to it fail (never answering its stop leg, or answering non-OK, which
     * the relay forwards), so without this limit one hostile reservation, advertised as an attractive
     * circuit address, would drive an honest relay's reliability down with every dial. Successes are
     * not limited. The pair set is itself bounded; once full, further failures that day are ignored
     * (the conservative direction for the metric's integrity).
     */
    @Synchronized
    internal fun recordDial(
        relay: PeerId,
        target: PeerId,
        success: Boolean,
    ) {
        if (!success) {
            val today = currentEpochDay()
            failedDialPairs.keys.removeIf { it < today - 1 }
            val pairs = failedDialPairs.getOrPut(today) { HashSet() }
            if (relay to target !in pairs) {
                if (pairs.size >= MAX_FAILED_DIAL_PAIRS) return
                pairs.add(relay to target)
            } else {
                return
            }
        }
        record(relay, success, held = false)
    }

    /** Compatibility entry point for callers without a target (counts like a plain observation). */
    @Synchronized
    internal fun recordAttempt(
        relay: PeerId,
        success: Boolean,
    ) = record(relay, success, held = false)

    private fun record(
        relay: PeerId,
        success: Boolean,
        held: Boolean,
    ) {
        val today = currentEpochDay()
        days.keys.removeIf { it < today - 1 }
        val bucket = days.getOrPut(today) { LinkedHashMap() }
        val counter =
            bucket[relay] ?: run {
                if (bucket.size >= maxTrackedRelays) {
                    // Full. Only a relay we hold a reservation with may displace something, and only a
                    // dial-only entry (fewest attempts first) - never first-come-wins starvation.
                    if (!held) return
                    val victim =
                        bucket.entries
                            .filter { !it.value.held }
                            .minByOrNull { it.value.attempts }
                            ?: return
                    bucket.remove(victim.key)
                }
                Counter().also { bucket[relay] = it }
            }
        if (held) counter.held = true
        if (counter.attempts < Int.MAX_VALUE) {
            counter.attempts++
            if (success) counter.successes++
        }
    }

    /** The counts per relay for [epochDay] (UTC days since the Unix epoch). Only the current and
     * the previous day are retained; any other day yields an empty map. */
    @Synchronized
    fun countsForDay(epochDay: Long): Map<PeerId, RelayReliabilityCounts> {
        val bucket = days[epochDay] ?: return emptyMap()
        return bucket.mapValues { (_, c) -> RelayReliabilityCounts(c.attempts, c.successes) }
    }

    private fun currentEpochDay(): Long = Math.floorDiv(clock().toEpochMilli(), 86_400_000L)

    companion object {
        const val DEFAULT_MAX_TRACKED_RELAYS = 256
        internal const val MAX_FAILED_DIAL_PAIRS = 4096
    }
}
