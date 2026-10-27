package net.lapisphilosophorum.lapisnet.directory

import java.security.SecureRandom
import java.util.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Early republication schedule for the directory objects of a node in anonymity mode. GossipSub hands no history to
 * late subscribers and there is no catch-up path, so an object published before a peer subscribed stays invisible to
 * that peer until the hourly republication. A short, bounded staggering after the first successful publication closes
 * that window without a readiness signal (a readiness signal would only measure the own neighbourhood, never the
 * receivers two hops away).
 *
 * [plan] turns [offsets] (relative to an anchor) into absolute slot times, each moved by a random fraction of up to
 * [jitterFraction] of its offset. Slots are strictly increasing and at least [MIN_GAP] apart.
 */
class DirectoryRepublishSchedule(
    val offsets: List<Duration> = DEFAULT_OFFSETS,
    private val jitterFraction: Double = DEFAULT_JITTER,
    private val random: Random = SecureRandom(),
) {
    init {
        require(offsets.size <= MAX_STEPS) { "too many steps" }
        require(offsets.all { it.isPositive() }) { "offsets must be positive" }
        require(offsets.zipWithNext().all { (a, b) -> b > a }) { "offsets must be strictly increasing" }
        require(jitterFraction in 0.0..MAX_JITTER) { "invalid jitter" }
    }

    /** Absolute slot times in epoch milliseconds, strictly increasing, consecutive slots at least [MIN_GAP] apart. */
    fun plan(anchorMillis: Long): LongArray {
        val out = LongArray(offsets.size)
        var previous = Long.MIN_VALUE
        for ((i, offset) in offsets.withIndex()) {
            val base = offset.inWholeMilliseconds
            val shift = ((random.nextDouble() * 2.0 - 1.0) * jitterFraction * base).toLong()
            var slot = anchorMillis + base + shift
            if (i > 0) slot = maxOf(slot, previous + MIN_GAP.inWholeMilliseconds)
            out[i] = slot
            previous = slot
        }
        return out
    }

    companion object {
        /** Five slots after the first successful publication. */
        val DEFAULT_OFFSETS: List<Duration> = listOf(5.seconds, 15.seconds, 45.seconds, 2.minutes, 5.minutes)
        const val DEFAULT_JITTER = 0.2
        const val MAX_JITTER = 0.3
        const val MAX_STEPS = 8
        val MIN_GAP: Duration = 3.seconds
    }
}

/**
 * A rolling-window limiter: at most [maxPerWindow] acquisitions within [windowMillis]. Used to keep a publisher below
 * the per-author rate that receivers enforce.
 */
class PublicationRateGuard(
    private val maxPerWindow: Int,
    private val windowMillis: Long,
    private val clockMillis: () -> Long,
) {
    private val stamps = ArrayDeque<Long>()

    init {
        require(maxPerWindow > 0) { "maxPerWindow must be positive" }
        require(windowMillis > 0) { "window must be positive" }
    }

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clockMillis()
        evict(now)
        if (stamps.size >= maxPerWindow) return false
        stamps.addLast(now)
        return true
    }

    /** The earliest time at which [tryAcquire] would succeed (now, if it would succeed already). */
    @Synchronized
    fun nextAllowedAtMillis(): Long {
        val now = clockMillis()
        evict(now)
        return if (stamps.size < maxPerWindow) now else stamps.first() + windowMillis
    }

    private fun evict(now: Long) {
        while (stamps.isNotEmpty() && now - stamps.first() >= windowMillis) stamps.removeFirst()
    }
}
