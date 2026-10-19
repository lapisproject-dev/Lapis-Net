package net.lapisphilosophorum.lapisnet.madli

/**
 * The relay-reliability observation for one (observer, observed-peer, day) tuple: how reliably the
 * observed peer served as a circuit relay (reservation, renewal and outgoing circuit dials) as seen
 * by the observer. Carried in the optional relay block of a v2 [MadliDailyVector].
 *
 * Fixed-point integer ([relayReliabilityMicros] is a fraction in `0..1_000_000`), never a `Double`,
 * for the same reason as [MadliMetrics]: it is embedded in a signed, cross-node-compared structure.
 *
 * **This is a reputation of the relay as infrastructure, observed by the client.** It is distinct
 * from the local, bilateral usage ledger a serving node keeps (which is never gossiped).
 *
 * [relayAttemptCount] is ADVISORY and self-declared, like [MadliMetrics.observationCount]; the
 * Veritas-weighting in [MadliAggregator] is the actual manipulation defense.
 */
data class MadliRelayMetrics(
    val relayReliabilityMicros: Int,
    val relayAttemptCount: Int,
) {
    init {
        require(relayReliabilityMicros in 0..MadliMetrics.MAX_METRIC_MICROS) {
            "relayReliabilityMicros out of range: $relayReliabilityMicros"
        }
        require(relayAttemptCount >= 0) { "relayAttemptCount must be >= 0: $relayAttemptCount" }
    }
}
