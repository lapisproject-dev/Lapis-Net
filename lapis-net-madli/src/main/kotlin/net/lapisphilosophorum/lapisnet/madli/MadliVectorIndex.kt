package net.lapisphilosophorum.lapisnet.madli

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps a [MadliDailyVector.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * `KarmaContentId`/`LtrContentId` exactly, duplicated locally rather than reused for the same
 * module-boundary reason those classes document. Internal: only [MadliVectorIndex] (same package)
 * needs this.
 */
internal data class MadliContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is MadliContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Bounded, in-memory index of [MadliDailyVector]s received (locally created or via gossip), keyed
 * by content id, by observed peer, and by `(observer, observedPeer)` pair. Mirrors
 * `KarmaVoteIndex`/`LtrRecordIndex`'s two-cap eviction/persistence pattern precisely (an evicting
 * in-memory tracking cap vs. a separate, non-evicting, hard-capped persistence cap) - see those
 * classes' doc comments for the full round-2/round-3 reasoning this structure is copied from.
 *
 * **THREE secondary indices, not two - the module's central manipulation-resistance surface.**
 * [vectorsByObservedPeer] answers "every vector about this observed peer" (feeds
 * [MadliAggregator]); [vectorsByObserverPeer] answers "every vector this observer has published
 * about this one observed peer" (feeds invariant B below); [currentByObserverPeerDay] answers "the
 * single current vector for this exact (observer, observedPeer, epochDay) tuple" (feeds invariant
 * A below). **All three MUST be cleaned in lockstep on both eviction and replacement** - the
 * hard-won `KarmaVoteIndex` lesson: an eviction that only cleans some of them would leave the
 * others holding a stale reference to a vector no longer reachable via [votesByContentId]'s dedup
 * check, silently corrupting [vectorsForObservedPeer]'s aggregation input for as long as this
 * process runs.
 *
 * **Invariant A - at most ONE tracked vector per `(observer, observedPeer, epochDay)` -
 * replace-on-conflict, most-recent-arrival wins.** Exactly Karma's per-`(voter, target)` replace,
 * keyed by the day-tuple instead. When a new vector arrives whose [ObserverPeerDayKey] already
 * maps to a *different* content-id (necessarily different [MadliMetrics], since an exact
 * content-id duplicate is caught earlier), the old vector is removed from every index before the
 * new one is added. Only the observer can sign vectors attributed to itself, so replace only ever
 * lets an observer correct **its own** report for a day - harmless. This stops "one observer
 * publishes many vectors about one peer for the same day". Exception (replay guard): a vector
 * without a relay-reliability block never replaces one that has it (see [isDowngrade]).
 *
 * **Invariant B - at most [MAX_TRACKED_DAYS_PER_OBSERVER_PEER] distinct-day vectors per
 * `(observer, observedPeer)` pair - evict the smallest `epochDay` when exceeded. The
 * anti-backdating defense.** Without this, one observer could publish hundreds of distinct-
 * `epochDay` vectors about one peer (each a distinct tuple, so invariant A doesn't catch them) and
 * stack decay-weighted contributions in [MadliAggregator] indefinitely. Eviction is deterministic
 * (smallest `epochDay`, tie-broken by lexicographically-smallest content-id) so honest nodes
 * converge on the same tracked set from the same input.
 */
class MadliVectorIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_VECTORS,
    private val maxPersisted: Int = MAX_PERSISTED_VECTORS,
    private val maxDaysPerObserverPeer: Int = MAX_TRACKED_DAYS_PER_OBSERVER_PEER,
) {
    /** Public entry point - always uses the `MAX_*` defaults. The internal constructor above
     * exists purely as a test seam, mirroring `KarmaVoteIndex`'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_VECTORS, MAX_PERSISTED_VECTORS, MAX_TRACKED_DAYS_PER_OBSERVER_PEER)

    private val vectorsByObservedPeer = HashMap<PeerId, MutableList<MadliDailyVector>>()
    private val vectorsByObserverPeer = HashMap<ObserverPeerKey, MutableList<MadliDailyVector>>()
    private val currentByObserverPeerDay = HashMap<ObserverPeerDayKey, MadliDailyVector>()

    /** Key for [vectorsByObserverPeer] - feeds invariant B (per-pair distinct-day cap). */
    private data class ObserverPeerKey(
        val observer: Secp256k1PublicKey,
        val observedPeer: PeerId,
    )

    /** Key for [currentByObserverPeerDay] - feeds invariant A (one vector per exact tuple). */
    private data class ObserverPeerDayKey(
        val observer: Secp256k1PublicKey,
        val observedPeer: PeerId,
        val epochDay: Long,
    )

    /** Backed by a [LinkedHashMap] constructed with access-order tracking enabled, exactly
     * mirroring `KarmaVoteIndex.votesByContentId`/`LtrRecordIndex.recordsByContentId` - see those
     * fields' doc comments for why this is FIFO-equivalent in practice, not true LRU.
     *
     * [removeEldestEntry] cleans [vectorsByObservedPeer], [vectorsByObserverPeer], AND
     * [currentByObserverPeerDay] off the evicted entry's value - see this class's doc comment for
     * why keeping every secondary index in sync here, in one place, is this class's single
     * highest-risk correctness property. */
    private val vectorsByContentId =
        object : LinkedHashMap<MadliContentId, MadliDailyVector>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<MadliContentId, MadliDailyVector>): Boolean {
                if (size <= maxTracked) return false
                removeFromSecondaryIndices(eldest.value)
                return true
            }
        }

    /** Removes [evicted] from every secondary index that isn't [vectorsByContentId] itself -
     * shared by [removeEldestEntry] (global LRU eviction), [add]'s invariant-A replacement path,
     * and [add]'s invariant-B distinct-day eviction path - every place a vector already tracked in
     * [vectorsByContentId] can stop being tracked. Idempotent no-ops safely if [evicted] is already
     * absent from a given bucket. [currentByObserverPeerDay] is only cleared if it still points at
     * EXACTLY [evicted] - a newer vector for the same tuple may already have overwritten that slot
     * via [add]'s replacement path, and this must never clobber that newer entry. */
    private fun removeFromSecondaryIndices(evicted: MadliDailyVector) {
        val peerBucket = vectorsByObservedPeer[evicted.observedPeer]
        peerBucket?.remove(evicted)
        if (peerBucket != null && peerBucket.isEmpty()) vectorsByObservedPeer.remove(evicted.observedPeer)

        val observerPeerKey = ObserverPeerKey(evicted.observer, evicted.observedPeer)
        val observerPeerBucket = vectorsByObserverPeer[observerPeerKey]
        observerPeerBucket?.remove(evicted)
        if (observerPeerBucket != null && observerPeerBucket.isEmpty()) vectorsByObserverPeer.remove(observerPeerKey)

        val dayKey = ObserverPeerDayKey(evicted.observer, evicted.observedPeer, evicted.epochDay)
        if (currentByObserverPeerDay[dayKey] == evicted) currentByObserverPeerDay.remove(dayKey)
    }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * `KarmaVoteIndex.persistedContentIds`/`LtrRecordIndex.persistedContentIds` exactly. */
    private val persistedContentIds = HashSet<MadliContentId>()

    /**
     * Adds [vector] to the index. Returns `true` iff it was newly added (including the
     * invariant-A replacement case); `false` for an exact duplicate (by content id) or a
     * signature-invalid vector - **never throws**, mirroring `KarmaVoteIndex.add`'s "last line of
     * defense before untrusted gossip data reaches this node's in-memory state" contract exactly,
     * including the defensive re-verification of [vector]'s signature.
     *
     * Enforces invariant A (replace-on-conflict per exact tuple) and invariant B (evict smallest
     * `epochDay` beyond [maxDaysPerObserverPeer] distinct days per `(observer, observedPeer)`
     * pair) - see this class's doc comment.
     */
    @Synchronized
    fun add(vector: MadliDailyVector): Boolean =
        runCatching {
            if (!MadliDailyVector.verify(vector)) return@runCatching false
            val id = MadliContentId(vector.contentId())
            if (vectorsByContentId.containsKey(id)) return@runCatching false

            val dayKey = ObserverPeerDayKey(vector.observer, vector.observedPeer, vector.epochDay)
            currentByObserverPeerDay[dayKey]?.let { previous ->
                if (isDowngrade(previous, vector)) return@runCatching false
                vectorsByContentId.remove(MadliContentId(previous.contentId()))
                removeFromSecondaryIndices(previous)
            }

            vectorsByContentId[id] = vector
            vectorsByObservedPeer.getOrPut(vector.observedPeer) { mutableListOf() }.add(vector)
            val observerPeerKey = ObserverPeerKey(vector.observer, vector.observedPeer)
            val observerPeerBucket = vectorsByObserverPeer.getOrPut(observerPeerKey) { mutableListOf() }
            observerPeerBucket.add(vector)
            currentByObserverPeerDay[dayKey] = vector

            // Invariant B: evict the smallest-epochDay vector once this (observer, observedPeer)
            // pair exceeds maxDaysPerObserverPeer distinct-day entries.
            if (observerPeerBucket.size > maxDaysPerObserverPeer) {
                val toEvict =
                    observerPeerBucket.minWithOrNull(
                        compareBy<MadliDailyVector> { it.epochDay }
                            .thenBy(MadliContentIdBytesComparator) { it.contentId() },
                    )
                if (toEvict != null) {
                    vectorsByContentId.remove(MadliContentId(toEvict.contentId()))
                    removeFromSecondaryIndices(toEvict)
                }
            }

            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [vector] is not already tracked
     * by content id. Mirrors `KarmaVoteIndex.canAccept`'s contract exactly.
     */
    @Synchronized
    fun canAccept(vector: MadliDailyVector): Boolean {
        if (vectorsByContentId.containsKey(MadliContentId(vector.contentId()))) return false
        val current =
            currentByObserverPeerDay[ObserverPeerDayKey(vector.observer, vector.observedPeer, vector.epochDay)]
        return current == null || !isDowngrade(current, vector)
    }

    /**
     * Replay guard for invariant A: `true` iff [candidate] would replace [current] although it
     * carries LESS information - [current] has a relay-reliability block and [candidate] does not.
     * The relay-reliability publisher merges the observer's older core-only vector into a v2
     * vector, so a core-only vector for the same tuple always exists and is replayable by any peer
     * once it left the GossipSub seen-cache; with pure most-recent-arrival-wins that replay would
     * erase the observer's relay block network-wide (a hostile relay could use it to remove
     * negative reports about itself). A vector with a relay block therefore always beats one
     * without, independent of arrival order. The observer can still correct its own report by
     * publishing another vector that carries a relay block.
     */
    private fun isDowngrade(
        current: MadliDailyVector,
        candidate: MadliDailyVector,
    ): Boolean = current.relayMetrics != null && candidate.relayMetrics == null

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [vectorsByContentId]'s evicting
     * cap. Mirrors `KarmaVoteIndex.tryReservePersistence`'s contract exactly, including atomic
     * reserve-before-put semantics and idempotency per content id.
     */
    @Synchronized
    fun tryReservePersistence(vector: MadliDailyVector): Boolean {
        val id = MadliContentId(vector.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** Every tracked [MadliDailyVector] about [peer], in insertion order - the input
     * [MadliAggregator.aggregate] folds over. */
    @Synchronized
    internal fun vectorsForObservedPeer(peer: PeerId): List<MadliDailyVector> =
        vectorsByObservedPeer[peer]?.toList() ?: emptyList()

    /** The currently tracked vector for the exact `(observer, peer, epochDay)` tuple, if any. */
    @Synchronized
    internal fun vectorFor(
        observer: Secp256k1PublicKey,
        peer: PeerId,
        epochDay: Long,
    ): MadliDailyVector? = currentByObserverPeerDay[ObserverPeerDayKey(observer, peer, epochDay)]

    /** Every distinct observed [PeerId] with at least one tracked vector. */
    @Synchronized
    internal fun allObservedPeers(): Set<PeerId> = vectorsByObservedPeer.keys.toSet()

    companion object {
        /**
         * Upper bound on distinct vectors tracked from gossip. Same provisional-magnitude caveat
         * as `KarmaVoteIndex.MAX_TRACKED_VOTES` applies: chosen for parity with that existing
         * precedent rather than derived from real pilot usage data - revisit once real traffic is
         * observed.
         */
        const val MAX_TRACKED_VECTORS = 64_000

        /**
         * Upper bound on distinct vectors this node will durably persist via `NabuStorage.put()`
         * from gossip - see [tryReservePersistence] and `KarmaVoteIndex.MAX_PERSISTED_VOTES`'s doc
         * comment for the full reasoning this mirrors. Same provisional-magnitude caveat as
         * [MAX_TRACKED_VECTORS] applies.
         */
        const val MAX_PERSISTED_VECTORS = 64_000

        /**
         * Upper bound on distinct-`epochDay` vectors tracked per `(observer, observedPeer)` pair -
         * the anti-backdating defense, see this class's doc comment on invariant B. Generous above
         * the longest configured half-life (90 days, [MadliHalfLives.deliveryIntegrityDays]) -
         * anything older than roughly double that half-life already decays to near-zero anyway, so
         * this cap does not meaningfully truncate legitimate long-running observation history while
         * still hard-bounding how many distinct-day contributions a single observer can stack for
         * one observed peer.
         */
        const val MAX_TRACKED_DAYS_PER_OBSERVER_PEER = 128
    }
}

/** Unsigned lexicographic byte-order comparator over content-id byte arrays - used only for
 * [MadliVectorIndex]'s invariant-B eviction tie-break, so eviction is fully deterministic even
 * when two candidates share the same smallest `epochDay`. */
private object MadliContentIdBytesComparator : Comparator<ByteArray> {
    override fun compare(
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
}
