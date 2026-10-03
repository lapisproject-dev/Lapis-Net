package net.lapisphilosophorum.lapisnet.madli

import io.libp2p.core.PeerId

/** Weights for combining an [AggregatedMadli] into a single routing score, per the vault's usage
 * profiles ("Pin-Partner", "DHT-Hop", "Bitswap-Provider"). Physical metrics (bandwidth, latency)
 * are normalized here, at read time, never in the signed vector - see [MadliMetrics]'s doc
 * comment. */
data class MadliRoutingProfile(
    val reachabilityWeight: Double,
    val latencyWeight: Double,
    val bandwidthWeight: Double,
    val deliveryIntegrityWeight: Double,
) {
    companion object {
        /** Vault "Provider-Discovery" row: order by Reachability + Latency + Bandwidth, all equal
         * weight (Delivery-Integrity included at parity too, since a provider that corrupts data
         * is worse than a merely slow one). */
        val PROVIDER_ORDERING = MadliRoutingProfile(1.0, 1.0, 1.0, 1.0)

        /** Latency-dominant - a DHT hop should favor the fastest responder above all else. */
        val DHT_HOP = MadliRoutingProfile(1.0, 2.0, 0.5, 1.0)

        /** Long-run reachability+integrity dominant - a pin partner is chosen for durability, not
         * raw speed. */
        val PIN_PARTNER = MadliRoutingProfile(2.0, 0.5, 0.5, 2.0)
    }
}

/**
 * A pure, local, unit-testable peer-ordering function - the thing a future
 * `NabuStorage.get(cid, peers = orderedSet)` call would consume (see `docs/architecture.adoc`'s
 * Madli section for the honest scope note: this hook is structurally ready but not yet wired into
 * a live Bitswap fetch this wave, since `NabuStorage.findProviders()` did not work end-to-end then -
 * repaired in V0.9.8, but the hook is still not wired).
 * No I/O.
 */
object MadliRoutingPolicy {
    /** Reference bandwidth (100 MB/s) the logarithmic bandwidth term saturates around - chosen as
     * a generous "excellent home/small-datacenter uplink" reference point, not derived from any
     * measured fleet data. Scores above/below this reference still vary monotonically; this only
     * sets where the log curve's steepest part sits. */
    private const val BANDWIDTH_REFERENCE_BYTES_PER_SEC = 100_000_000.0

    /** Higher is better. Latency is inverted (lower RTT -> higher score) via a bounded
     * `1/(1+ms/1000)` form (1.0 at zero latency, asymptotically approaching 0 as latency grows);
     * bandwidth via a saturating `ln(1+bw)/ln(1+reference)` form (diminishing returns above the
     * reference, never negative); Reachability/Delivery-Integrity contribute directly as their
     * `0.0..1.0` micros fraction. Pure; the exact curve shape is a modeling choice, not
     * load-bearing - monotonicity and boundedness are what [MadliRoutingPolicyTest] verifies, not
     * exact score values. */
    fun routingScore(
        madli: AggregatedMadli,
        profile: MadliRoutingProfile = MadliRoutingProfile.PROVIDER_ORDERING,
    ): Double {
        val reachabilityScore = madli.reachabilityMicros.toDouble() / MadliMetrics.MAX_METRIC_MICROS
        val deliveryIntegrityScore = madli.deliveryIntegrityMicros.toDouble() / MadliMetrics.MAX_METRIC_MICROS
        val latencyScore = 1.0 / (1.0 + madli.medianLatencyMillis / 1000.0)
        val bandwidthScore =
            Math.log1p(madli.medianBandwidthBytesPerSec.toDouble()) / Math.log1p(BANDWIDTH_REFERENCE_BYTES_PER_SEC)

        return profile.reachabilityWeight * reachabilityScore +
            profile.latencyWeight * latencyScore +
            profile.bandwidthWeight * bandwidthScore +
            profile.deliveryIntegrityWeight * deliveryIntegrityScore
    }

    /**
     * Orders [candidates] best-first by [routingScore]. A peer with no Madli history
     * ([madliOf] returns `null`) sorts LAST - the vault's bootstrap deprioritization ("a fresh
     * node with no Madli gets deprioritized in routing until it earns observations").
     * Deterministic: ties (including all-null) are broken by ascending peerId bytes, so ordering
     * is stable and reproducible across nodes/runs given the same inputs.
     */
    fun orderPeers(
        candidates: Collection<PeerId>,
        madliOf: (PeerId) -> AggregatedMadli?,
        profile: MadliRoutingProfile = MadliRoutingProfile.PROVIDER_ORDERING,
    ): List<PeerId> =
        candidates.sortedWith(
            compareByDescending<PeerId> { peer ->
                madliOf(peer)?.let { routingScore(it, profile) }
                    ?: Double.NEGATIVE_INFINITY
            }.thenBy(PeerIdBytesComparator) { it },
        )
}

/** Unsigned lexicographic byte-order comparator over `PeerId.bytes` - [MadliRoutingPolicy.orderPeers]'s
 * deterministic tie-break, mirroring `lapis-net-trust`'s `Secp256k1PublicKeyBytesComparator`. */
private object PeerIdBytesComparator : Comparator<PeerId> {
    override fun compare(
        a: PeerId,
        b: PeerId,
    ): Int {
        val ba = a.bytes
        val bb = b.bytes
        val len = minOf(ba.size, bb.size)
        for (i in 0 until len) {
            val diff = (ba[i].toInt() and 0xFF) - (bb[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return ba.size - bb.size
    }
}
