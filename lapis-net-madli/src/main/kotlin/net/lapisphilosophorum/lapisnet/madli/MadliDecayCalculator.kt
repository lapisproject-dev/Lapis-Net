package net.lapisphilosophorum.lapisnet.madli

/**
 * The five metric-specific decay half-lives in DAYS, defaults per the vault design. Configurable
 * per view/node (vault TODO "Konfigurierbarkeit der Halbwertszeiten pro View/Knoten"). Each metric
 * decays independently: Reachability/Latency age fast (network conditions change quickly),
 * Delivery-Integrity ages very slowly (a track record of not corrupting/dropping data is a durable
 * signal), Bandwidth/Routing-Helpfulness sit in between.
 */
data class MadliHalfLives(
    val reachabilityDays: Double = 7.0,
    val bandwidthDays: Double = 30.0,
    val latencyDays: Double = 7.0,
    val deliveryIntegrityDays: Double = 90.0,
    val routingHelpfulnessDays: Double = 30.0,
    val relayReliabilityDays: Double = 14.0,
) {
    init {
        require(
            reachabilityDays > 0 &&
                bandwidthDays > 0 &&
                latencyDays > 0 &&
                deliveryIntegrityDays > 0 &&
                routingHelpfulnessDays > 0 &&
                relayReliabilityDays > 0,
        ) { "half-lives must be positive" }
    }
}

/**
 * Pure time-decay math for Madli's local, read-time aggregation heuristics, per this wave's
 * generalization of `LtrWeightCalculator`'s single-half-life pattern to five independently
 * configurable half-lives (one per [MadliMetrics] field, see [MadliHalfLives]). No I/O, no side
 * effects - every function here is a deterministic function of its inputs plus a caller-supplied
 * "now" (`atEpochDay`), so tests never need to depend on wall-clock time.
 *
 * `Double` is correct here, unlike [MadliMetrics]'s fixed-point fields - see that class's doc
 * comment: this is a local, read-time-only ranking heuristic, never signed, never part of any
 * [MadliDailyVectorCodec]-encoded byte sequence, and never compared for cross-node consensus,
 * exactly the `LtrWeightCalculator` justification.
 */
object MadliDecayCalculator {
    /**
     * `0.5^(ageDays / halfLifeDays)`. `ageDays` is coerced to `>= 0` (future-dated vectors clamp
     * to a decay factor of exactly `1.0`, never above - the same load-bearing clamp
     * `LtrWeightCalculator.decayedWeightMsat` documents: a negative exponent with base `0.5` would
     * inflate weight above face value, and this is also the mechanism that defuses a future-dated
     * [MadliDailyVector.epochDay] left structurally unchecked by [MadliDailyVectorCodec]/
     * [MadliGossip] - see those classes' doc comments).
     */
    fun decayFactor(
        halfLifeDays: Double,
        ageDays: Double,
    ): Double = Math.pow(0.5, ageDays.coerceAtLeast(0.0) / halfLifeDays)
}
