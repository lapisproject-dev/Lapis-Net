package net.lapisphilosophorum.lapisnet.madli

import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.relay.RelayCandidateRanker

/**
 * Orders relay candidates by their Veritas-weighted Madli relay reliability - the bridge between
 * the reputation layer and the automatic relay selection in `lapis-net-networking` (which cannot
 * depend on this module, hence the injected [RelayCandidateRanker]).
 *
 * **Advisory, never a gate.** A candidate without any signal is ranked LAST but is still
 * returned, so a fresh relay with no Madli history can still earn observations (the vault's
 * bootstrap rule), and a ranker with no data at all degrades to the tie-break order.
 *
 * Score = aggregated relay reliability (`0.0..1.0`) plus, when core metrics exist, a small
 * reachability tie-weight ([REACHABILITY_TIE_WEIGHT]). Local `Double` heuristic: never signed,
 * never compared across nodes. Ties are broken by ascending PeerId bytes, so the order is
 * deterministic.
 *
 * @param vectorsFor tracked vectors about one observed peer, e.g. [MadliGossip.currentVectorsForObservedPeer]
 * @param observerWeight the consumer's Veritas weight of an observer, e.g.
 * [MadliAggregator.veritasObserverWeight]; a weight of `0` removes the observer entirely
 */
class MadliRelayRanker(
    private val vectorsFor: (PeerId) -> List<MadliDailyVector>,
    private val observerWeight: (Secp256k1PublicKey) -> Double,
    private val epochDay: () -> Long = { currentEpochDayUtc() },
    private val halfLives: MadliHalfLives = MadliHalfLives(),
) : RelayCandidateRanker {
    override fun rank(candidates: List<PeerInfo>): List<PeerInfo> {
        if (candidates.size < 2) return candidates
        val day = epochDay()
        val scored = candidates.map { it to score(it.peerId, day) }
        return scored
            .sortedWith(
                compareByDescending<Pair<PeerInfo, Double?>> { it.second ?: Double.NEGATIVE_INFINITY }
                    .thenBy(PeerIdBytesComparator) { it.first.peerId },
            ).map { it.first }
    }

    /**
     * The local relay reliability score of [peer] (about `0.0..1.25`), or `null` without any Veritas-weighted
     * observation. Public accessor for the onion path selection (wave V0.10.0-E), which clamps it to `[0, 1]` and
     * treats `null` as "no history". Local heuristic, never signed.
     */
    fun relayReliability(peer: PeerId): Double? = score(peer)

    /** The score of [peer], or `null` when no observer with positive weight reported a relay
     * reliability for it. */
    internal fun score(peer: PeerId): Double? = score(peer, epochDay())

    private fun score(
        peer: PeerId,
        day: Long,
    ): Double? {
        val vectors = vectorsFor(peer)
        val reliability =
            MadliAggregator.aggregateRelayReliability(vectors, observerWeight, day, halfLives) ?: return null
        val reachability = MadliAggregator.aggregate(vectors, observerWeight, day, halfLives)?.reachabilityMicros
        return reliability.toDouble() / MadliMetrics.MAX_METRIC_MICROS +
            REACHABILITY_TIE_WEIGHT * ((reachability ?: 0).toDouble() / MadliMetrics.MAX_METRIC_MICROS)
    }

    companion object {
        /** Weight of the (core) reachability aggregate relative to relay reliability. */
        const val REACHABILITY_TIE_WEIGHT = 0.25
    }
}
