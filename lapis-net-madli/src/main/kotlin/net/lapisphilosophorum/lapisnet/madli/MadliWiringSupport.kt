package net.lapisphilosophorum.lapisnet.madli

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant

/**
 * The Veritas observer weight for Madli aggregation ([MadliAggregator.veritasObserverWeight]) over a trust-graph snapshot
 * that is rebuilt only when the latest-grant content changed (a revocation replaces an edge without changing the count). Building a [TrustGraph] per relay candidate
 * (the relay ranker asks once per observer) would be wasteful. Thread-safe: the snapshot is an immutable value swapped
 * through a volatile field.
 */
class CachedVeritasObserverWeight internal constructor(
    private val version: () -> Long,
    private val grantsSource: () -> Collection<VeritasGrant>,
    private val fingerprintOf: (Collection<VeritasGrant>) -> List<Byte>,
    private val localIdentity: Secp256k1PublicKey,
) {
    constructor(veritas: VeritasGossip, localIdentity: Secp256k1PublicKey) : this(
        version = veritas::grantsVersion,
        grantsSource = veritas::currentGrants,
        fingerprintOf = { veritas.currentGrantsFingerprint(it) },
        localIdentity = localIdentity,
    )

    private class Snapshot(
        val version: Long,
        val fingerprint: List<Byte>,
        val weight: (Secp256k1PublicKey) -> Double,
    )

    @Volatile private var snapshot: Snapshot? = null

    /**
     * O(1) on the hot path: staleness is decided from the index's change counter. Only when that counter moved is the
     * (expensive) latest-grant resolution + fingerprint computed, and the trust graph is rebuilt only if the
     * fingerprint actually changed.
     */
    fun weightOf(observer: Secp256k1PublicKey): Double {
        val version = version()
        val current = snapshot
        if (current != null && current.version == version) return current.weight(observer)
        synchronized(this) {
            val again = snapshot
            if (again != null && again.version == version) return again.weight(observer)
            val grants = grantsSource()
            val fingerprint = fingerprintOf(grants)
            val fresh =
                if (again != null && again.fingerprint == fingerprint) {
                    Snapshot(version, fingerprint, again.weight)
                } else {
                    Snapshot(
                        version,
                        fingerprint,
                        MadliAggregator.veritasObserverWeight(TrustGraph.fromGrants(grants), localIdentity),
                    )
                }
            snapshot = fresh
            return fresh.weight(observer)
        }
    }
}

/**
 * Drives [MadliRelayReliabilityPublisher] at the intended cadence: the relay reliability of the PREVIOUS UTC day,
 * published at most once per day (the caller wakes this up as often as it likes, e.g. every six hours). A day is only
 * marked done after a pass that did not throw.
 */
class DailyRelayReliabilityPublication(
    private val publisher: MadliRelayReliabilityPublisher,
    private val today: () -> Long = { currentEpochDayUtc() },
) {
    @Volatile private var lastPublishedDay: Long = Long.MIN_VALUE

    /** Publishes yesterday's vectors unless that already happened. @return the number of announced vectors. */
    fun runOnce(): Int {
        val day = today() - 1
        if (day == lastPublishedDay) return 0
        val announced = publisher.publishForDay(day)
        lastPublishedDay = day
        return announced
    }
}
