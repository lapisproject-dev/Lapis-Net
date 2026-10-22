package net.lapisphilosophorum.lapisnet.onionwire

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.relay.RelayReliabilityCounts
import java.time.Clock
import java.util.TreeMap
import java.util.concurrent.atomic.AtomicLong

/** Per relay and per day: how often this node tried to reach it for an extend and what came of it. */
data class OnionRelayQualityCounts(
    val extendAttempts: Int,
    val extendLinkSuccesses: Int,
    val destroyedByTarget: Int,
) {
    /**
     * Successes in the sense of [RelayReliabilityCounts]: a reachable link that the target did not answer with a
     * PROTOCOL/AUTH_FAILED destroy. `null` if there was no attempt.
     */
    fun toReliabilityCounts(): RelayReliabilityCounts? {
        if (extendAttempts <= 0) return null
        val good = (extendLinkSuccesses - destroyedByTarget).coerceIn(0, extendAttempts)
        return RelayReliabilityCounts(extendAttempts, good)
    }
}

/**
 * Local, bounded relay quality bookkeeping (LRU of [maxTracked] identities, day buckets, [RETENTION_DAYS] days).
 * It is NEVER published and not connected to MadliGossip in this wave; turning the numbers into Madli metrics and
 * a weighting for path selection is wave E. The numbers are link-level only (reachability and early destroys); they
 * cannot attribute a failure to a specific hop.
 */
class OnionRelayQualityTracker(
    private val clock: Clock = Clock.systemUTC(),
    private val maxTracked: Int = 1024,
) {
    private class Counter {
        var attempts = 0
        var linkSuccesses = 0
        var destroyed = 0
    }

    private val lock = Any()
    private val perRelay =
        object : LinkedHashMap<Secp256k1PublicKey, TreeMap<Long, Counter>>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Secp256k1PublicKey, TreeMap<Long, Counter>>,
            ) = size > maxTracked
        }

    private val createsAccepted = AtomicLong()
    private val createsRejected = AtomicLong()

    private fun day(): Long = clock.millis() / 86_400_000L

    private fun update(
        relay: Secp256k1PublicKey,
        block: (Counter) -> Unit,
    ) = synchronized(lock) {
        val days = perRelay.getOrPut(relay) { TreeMap() }
        val today = day()
        block(days.getOrPut(today) { Counter() })
        while (days.isNotEmpty() && days.firstKey() <= today - RETENTION_DAYS) days.remove(days.firstKey())
    }

    fun recordExtendAttempt(relay: Secp256k1PublicKey) = update(relay) { it.attempts++ }

    fun recordExtendLinkSuccess(relay: Secp256k1PublicKey) = update(relay) { it.linkSuccesses++ }

    fun recordDestroyedByTarget(relay: Secp256k1PublicKey) = update(relay) { it.destroyed++ }

    fun recordCreateAccepted() = createsAccepted.incrementAndGet()

    fun recordCreateRejected() = createsRejected.incrementAndGet()

    /** This node's own view of CREATEs it accepted (self observation, not evidence about others). */
    fun ownCreateCounts(): Pair<Long, Long> = createsAccepted.get() to createsRejected.get()

    fun counts(epochDay: Long): Map<Secp256k1PublicKey, OnionRelayQualityCounts> =
        synchronized(lock) {
            perRelay
                .mapNotNull { (relay, days) ->
                    days[epochDay]?.let {
                        relay to
                            OnionRelayQualityCounts(
                                it.attempts,
                                it.linkSuccesses,
                                it.destroyed,
                            )
                    }
                }.toMap()
        }

    fun trackedRelays(): Int = synchronized(lock) { perRelay.size }

    companion object {
        const val RETENTION_DAYS = 7L
    }
}
