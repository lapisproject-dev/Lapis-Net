package net.lapisphilosophorum.lapisnet.madli

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder

/** The consumer-facing aggregated Madli view of one observed peer, in the same units as
 * [MadliMetrics] (fixed-point/raw integers). Null-when-no-signal is expressed by
 * [MadliAggregator.aggregate] returning `null`, mirroring [TrustPathFinder]'s null-means-no-path
 * discipline. */
data class AggregatedMadli(
    val reachabilityMicros: Int,
    val medianBandwidthBytesPerSec: Long,
    val medianLatencyMillis: Int,
    val deliveryIntegrityMicros: Int,
    val routingHelpfulnessMicros: Int,
)

/**
 * Veritas-weighted, decay-weighted, weighted-MEDIAN aggregation of [MadliDailyVector]s about one
 * observed peer - the module's headline deliverable. Three manipulation defenses are combined:
 *
 *  1. **Veritas-weighting (anti-Sybil).** Each observer's contribution is scaled by the consumer's
 *     own Veritas score of that observer via [veritasObserverWeight] - a Sybil cluster with no
 *     external Veritas path from the consumer's own identity gets weight `0.0` and contributes
 *     nothing, no matter how many fabricated vectors it publishes.
 *  2. **Weighted MEDIAN, not mean (anti-selective-service / anti-minority-liar).** If 90% of
 *     (Veritas-weighted) observers report a peer as slow and 10% report it as fast, the weighted
 *     median follows the 90% majority - a peer that selectively serves a small minority of
 *     observers well cannot pull the aggregate value toward that minority's report the way a mean
 *     would.
 *  3. **One representative vector per observer per metric (anti-backdated-flooding).** `aggregate`
 *     groups the input by [MadliDailyVector.observer] and, independently for each of the five
 *     metrics, feeds the weighted median only ONE `(value, weight)` sample per observer - that
 *     observer's single vector with the highest decayed weight for THAT metric (i.e. their
 *     freshest/least-aged observation about the peer for that metric's half-life). This is load-
 *     bearing, not cosmetic: `MadliVectorIndex`'s invariant B allows up to
 *     `MAX_TRACKED_DAYS_PER_OBSERVER_PEER` (128) distinct-`epochDay` vectors per
 *     `(observer, observedPeer)` pair, and `MadliGossip.onGossipMessage`'s validator deliberately
 *     never checks `epochDay` against wall-clock time (see that class's doc comment on validator
 *     determinism) - so invariant B alone does not stop an attacker from fabricating and gossiping
 *     128 backdated vectors about a target peer in a single burst. Without this per-observer cap,
 *     folding every one of those 128 vectors into the median as an independent sample would
 *     multiply that one observer's effective influence by `sum_{d=0}^{127} 0.5^(d / halfLife)` -
 *     roughly 10.6x for a 7-day half-life, 41.5x for 30 days, 81.7x for 90 days - letting a single
 *     NON-majority observer outweigh many genuinely independent honest observers who each
 *     published only their one truthful vector for today. Capping each observer to one
 *     representative sample per metric closes that gap structurally: no matter how many
 *     distinct-day vectors an observer has tracked, they can never contribute more than one
 *     vector's worth of weight to any single metric - vector VOLUME stops being a lever, leaving
 *     only genuine Veritas-weighted headcount (defense 1) and report accuracy (defense 2) as
 *     manipulation surfaces. See `MadliAggregatorTest`'s backdated-flooding regression test (the
 *     module's read-time closure of `MadliVectorIndex`'s invariant B doc comment) and
 *     `MadliSybilResistanceSimulationTest` for the adversarial simulation proving all three
 *     defenses hold against a synthetic Sybil cluster and a selective-service attacker, plus the
 *     documented residual (a trusted MAJORITY that lies still wins the median - an explicitly
 *     accepted, tested boundary, not a silent gap; that scenario is about genuine headcount among
 *     DISTINCT observers with one vector each, orthogonal to this defense).
 *
 * Each metric is decayed by **its own** half-life ([MadliHalfLives]), so one vector contributes
 * with a different weight to each of the five output fields - correct, since Reachability ages
 * fast while Delivery-Integrity ages slow. A consequence of defense 3 above: the SAME observer may
 * have a different "representative vector" selected for different metrics, if their tracked
 * vectors' `epochDay`s differ in a way that changes which one is freshest under that metric's own
 * half-life - expected and correct, since each metric's recency-relevance is independent.
 */
object MadliAggregator {
    /**
     * Aggregates [vectors] (all about ONE observed peer) into a single [AggregatedMadli], or
     * `null` if no vector carries positive observer weight. Each metric is a WEIGHTED MEDIAN over
     * `(metricValue, weight)` pairs with **at most one pair per observer** (see this object's doc
     * comment, defense 3): for each of the five metrics, and for each observer with one or more
     * vectors in [vectors], the observer's single vector with the highest
     * `decayFactor(thatMetric'sHalfLife, atEpochDay - vector.epochDay)` is selected as that
     * observer's sole contribution to that metric - ties (identical decayed weight, possible when
     * two of an observer's vectors share an `epochDay` in a hand-built test collection) are broken
     * deterministically by largest `epochDay`, then by smallest content-id bytes, so the selection
     * is reproducible across nodes. `weight = observerWeight(vector.observer) *
     * decayFactor(...)`. Vectors with `observerWeight(vector.observer) <= 0` are dropped entirely
     * before any metric is computed - a Sybil observer with weight `0` contributes nothing to any
     * of the five metrics. Trust-free core: [observerWeight] is injected, mirroring
     * `KarmaWeightCalculator`'s injected `votesByVoter` - the actual Veritas lookup is supplied by
     * [veritasObserverWeight] one call up. Read-only; never mutates [vectors].
     */
    fun aggregate(
        vectors: Collection<MadliDailyVector>,
        observerWeight: (Secp256k1PublicKey) -> Double,
        atEpochDay: Long,
        halfLives: MadliHalfLives = MadliHalfLives(),
    ): AggregatedMadli? {
        val weighted =
            vectors
                .filter { it.metrics != null }
                .map { vector -> WeightedVector(vector, observerWeight(vector.observer)) }
                .filter { it.observerWeight > 0.0 }
        if (weighted.isEmpty()) return null

        val byObserver: Collection<List<WeightedVector>> = weighted.groupBy { it.vector.observer }.values

        /**
         * One `(value, weight)` pair per observer group in [byObserver] - the observer's own
         * highest-decayed-weight vector for THIS metric's [halfLifeDays], per this object's doc
         * comment on defense 3. This is the single chokepoint that bounds one observer's influence
         * on a metric to one vector's worth of weight, regardless of [byObserver]'s group sizes.
         */
        fun decayedPairsLong(
            halfLifeDays: Double,
            valueOf: (MadliDailyVector) -> Long,
        ): List<Pair<Long, Double>> =
            byObserver.map { group -> representativeFor(group, halfLifeDays, atEpochDay, valueOf) }

        return AggregatedMadli(
            reachabilityMicros =
                weightedMedianLong(
                    decayedPairsLong(halfLives.reachabilityDays) { it.coreMetrics().reachabilityMicros.toLong() },
                ).toInt(),
            medianBandwidthBytesPerSec =
                weightedMedianLong(
                    decayedPairsLong(halfLives.bandwidthDays) { it.coreMetrics().medianBandwidthBytesPerSec },
                ),
            medianLatencyMillis =
                weightedMedianLong(
                    decayedPairsLong(halfLives.latencyDays) { it.coreMetrics().medianLatencyMillis.toLong() },
                ).toInt(),
            deliveryIntegrityMicros =
                weightedMedianLong(
                    decayedPairsLong(
                        halfLives.deliveryIntegrityDays,
                    ) { it.coreMetrics().deliveryIntegrityMicros.toLong() },
                ).toInt(),
            routingHelpfulnessMicros =
                weightedMedianLong(
                    decayedPairsLong(
                        halfLives.routingHelpfulnessDays,
                    ) { it.coreMetrics().routingHelpfulnessMicros.toLong() },
                ).toInt(),
        )
    }

    /**
     * Veritas-weighted, decay-weighted, weighted-MEDIAN relay reliability (micros, `0..1_000_000`)
     * of one observed peer, over the vectors in [vectors] that carry a relay block; `null` if no
     * such vector has positive observer weight. Same manipulation defenses as [aggregate]: vectors
     * with `observerWeight <= 0` are dropped, at most ONE representative sample per observer (the
     * freshest under [MadliHalfLives.relayReliabilityDays]), weighted median instead of mean.
     * Vectors without a relay block are filtered out BEFORE grouping, so they can neither
     * contribute nor displace an observer's relay-carrying vector.
     */
    fun aggregateRelayReliability(
        vectors: Collection<MadliDailyVector>,
        observerWeight: (Secp256k1PublicKey) -> Double,
        atEpochDay: Long,
        halfLives: MadliHalfLives = MadliHalfLives(),
    ): Int? {
        val weighted =
            vectors
                .filter { it.relayMetrics != null }
                .map { vector -> WeightedVector(vector, observerWeight(vector.observer)) }
                .filter { it.observerWeight > 0.0 }
        if (weighted.isEmpty()) return null
        val pairs =
            weighted.groupBy { it.vector.observer }.values.map { group ->
                representativeFor(group, halfLives.relayReliabilityDays, atEpochDay) {
                    requireNotNull(it.relayMetrics).relayReliabilityMicros.toLong()
                }
            }
        return weightedMedianLong(pairs).toInt()
    }

    /**
     * The production Veritas-weighting adapter (the ONLY function in this module referencing
     * `lapis-net-trust`): `weight = TrustPathFinder.trustMicros(graph, localIdentity, observer) /
     * MAX_TRUST_MICROS`, in `0.0..1.0`. No path -> `0.0` (Sybil-cluster-with-no-external-Veritas
     * defense); self (`observer == localIdentity`) -> `1.0` via [TrustPathFinder]'s self-trust
     * axiom. Structurally identical to `lapis-net-browser`'s `KarmaScoring.weightedContribution`,
     * hosted here because Madli has no application-layer consumer this wave (see this module's
     * `build.gradle.kts`).
     */
    fun veritasObserverWeight(
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
    ): (Secp256k1PublicKey) -> Double =
        { observer ->
            TrustPathFinder.trustMicros(graph, localIdentity, observer).toDouble() /
                MAX_TRUST_MICROS.toDouble()
        }

    private fun MadliDailyVector.coreMetrics(): MadliMetrics =
        requireNotNull(metrics) { "core aggregation requires core metrics (filtered earlier)" }

    private data class WeightedVector(
        val vector: MadliDailyVector,
        val observerWeight: Double,
    )

    /**
     * Selects the single `(value, weight)` pair from [group] (all vectors from ONE observer) with
     * the highest `weight = w.observerWeight * decayFactor(halfLifeDays, atEpochDay -
     * w.vector.epochDay)` - the observer's freshest/least-aged observation for this specific
     * metric's half-life, per this object's doc comment on defense 3 (anti-backdated-flooding).
     * [group] must be non-empty (guaranteed by [Map.values] over a non-empty
     * [Iterable.groupBy] result). Ties (equal decayed weight) are broken deterministically by
     * largest `epochDay`, then by smallest content-id bytes ([compareContentIdBytes]) - mirrors
     * `MadliVectorIndex`'s own invariant-B eviction tie-break discipline, so the selection is
     * reproducible given the same input on every node.
     */
    private fun representativeFor(
        group: List<WeightedVector>,
        halfLifeDays: Double,
        atEpochDay: Long,
        valueOf: (MadliDailyVector) -> Long,
    ): Pair<Long, Double> {
        var best: MadliDailyVector? = null
        var bestWeight = -1.0
        for (w in group) {
            val ageDays = (atEpochDay - w.vector.epochDay).toDouble()
            val weight = w.observerWeight * MadliDecayCalculator.decayFactor(halfLifeDays, ageDays)
            val current = best
            val isBetter =
                when {
                    current == null -> true
                    weight != bestWeight -> weight > bestWeight
                    w.vector.epochDay != current.epochDay -> w.vector.epochDay > current.epochDay
                    else -> compareContentIdBytes(w.vector.contentId(), current.contentId()) < 0
                }
            if (isBetter) {
                best = w.vector
                bestWeight = weight
            }
        }
        val winner = requireNotNull(best) { "representativeFor requires a non-empty group" }
        return valueOf(winner) to bestWeight
    }

    /** Tiny numeric slop for detecting an exact 50/50 weight split in [weightedMedianLong] -
     * distinguishes a genuine tie from a cumulative weight that merely happens to land close to,
     * but not exactly on, the threshold. */
    private const val MEDIAN_TIE_EPSILON = 1e-9

    /**
     * Given `(value, weight)` pairs with `weight >= 0`, sorts ascending by value (stable) and
     * returns the smallest value whose cumulative weight reaches `totalWeight / 2.0` - UNLESS that
     * cumulative weight lands EXACTLY on the threshold (within [MEDIAN_TIE_EPSILON]) and a next,
     * distinct-or-not value follows, in which case the result is the average of that boundary
     * value and the next value (the standard even-weight-split median convention). This
     * symmetric tie-break matters: the naive "always return the lower boundary value" rule is
     * low-biased at an exact 50/50 split - an attacker holding exactly half the effective weight
     * (not a majority) could otherwise force the aggregate toward their own fabricated LOW value
     * purely because they control which side of the tie is "reported low", while the honest side
     * cannot symmetrically counter by reporting high. [pairs] must be non-empty. If every weight is
     * exactly `0.0` (e.g. every contribution has decayed to numeric zero - reachable even when
     * every vector's RAW `observerWeight` is positive, if [atEpochDay] is far enough past every
     * vector's `epochDay` that the decay factor itself underflows to `0.0`; see
     * `MadliAggregatorTest`'s dedicated regression test), falls back to the plain (unweighted)
     * median of the sorted values, so the function never divides by zero or silently returns a
     * meaningless result.
     */
    private fun weightedMedianLong(pairs: List<Pair<Long, Double>>): Long {
        require(pairs.isNotEmpty()) { "weightedMedianLong requires at least one pair" }
        val sorted = pairs.sortedBy { it.first }
        val totalWeight = sorted.sumOf { it.second }
        if (totalWeight <= 0.0) return sorted[sorted.size / 2].first

        val threshold = totalWeight / 2.0
        var cumulative = 0.0
        for (i in sorted.indices) {
            val (value, weight) = sorted[i]
            cumulative += weight
            if (cumulative >= threshold) {
                val next = sorted.getOrNull(i + 1)
                val isExactTie = Math.abs(cumulative - threshold) < MEDIAN_TIE_EPSILON
                return if (isExactTie && next != null) {
                    // Average of the two middle values at an exact 50/50 split - e.g. two
                    // equal-weight observers reporting 100 and 300 resolve to 200, not 100.
                    value + (next.first - value) / 2
                } else {
                    value
                }
            }
        }
        return sorted.last().first
    }
}

/** Unsigned lexicographic byte-order comparator, mirroring
 * [net.lapisphilosophorum.lapisnet.madli]'s own `MadliContentIdBytesComparator` in
 * `MadliVectorIndex.kt` (file-private there, so not reusable directly) - used only for
 * [MadliAggregator]'s representative-vector-selection tie-break, so the selection is fully
 * deterministic even when two of an observer's vectors tie exactly on decayed weight. */
private fun compareContentIdBytes(
    a: ByteArray,
    b: ByteArray,
): Int {
    val len = minOf(a.size, b.size)
    for (i in 0 until len) {
        val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
        if (diff != 0) return diff
    }
    return a.size - b.size
}
