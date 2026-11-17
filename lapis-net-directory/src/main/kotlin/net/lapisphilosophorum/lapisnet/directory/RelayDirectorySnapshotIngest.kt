package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Clock

private val logger = KotlinLogging.logger {}

/** What one [RelayDirectorySnapshotIngest.ingest] did. Counters only: no identity, peer id or address. */
data class SnapshotIngestReport(
    val accepted: Int = 0,
    val confirmed: Int = 0,
    val staleOrReplayed: Int = 0,
    val expired: Int = 0,
    val invalid: Int = 0,
    val overBudget: Int = 0,
    val capacity: Int = 0,
    val recordsAccepted: Int = 0,
    val recordsSkipped: Int = 0,
    /** `true` when the source was (or just became) blocked for too many invalid entries; nothing further was used. */
    val sourceBlocked: Boolean = false,
) {
    /** Entries not used for any reason (invalid, over budget, capacity, stale, expired). */
    val rejected: Int get() = staleOrReplayed + expired + invalid + overBudget + capacity
}

/**
 * Takes a relay directory snapshot into the local view with the SAME validation as gossip (wave V0.10.0-J1b), plus
 * limits of its own because one source delivers many entries at once:
 *
 *  - Each descriptor: [OnionRelayDescriptorIndex.precheck] (duplicates, replays and stale versions cost nothing), then
 *    the new-identity budget, then [OnionRelayDescriptorIndex.add] (full signature, binding, possession and onion-key
 *    checks, expiry, strictly increasing sequence numbers). Never published again.
 *  - New identities are limited to [maxNewIdentitiesPerFetch] per snapshot and [maxSnapshotOwnedIdentities] in total
 *    (at most half the index), so a source can not fill the bounded index with validly signed Sybil descriptors: the
 *    index refuses NEW identities once full, and honest relays arriving through gossip would be locked out. Updates of
 *    tracked identities are not budgeted. The gossip validator and its rate limits stay unchanged; the snapshot path's
 *    own budget is bounded by the fetch rate of the controller times [OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES].
 *  - The peer record of an entry is used only if its descriptor is the current one afterwards (accepted or already
 *    known), and only after [PeerRecord.verify], [verifyBinding], [verifyPossession], expiry, and identity AND peer id
 *    equal to the descriptor's; it is never re-published.
 *  - More than a quarter of the entries cryptographically invalid: the rest is discarded and the source blocked for
 *    [blockMillis].
 *  - Provenance: the distinct sources (peer ids of the connections the snapshots came over) that delivered a validly
 *    signed, current descriptor of an identity (also when it was not taken for the budget or the capacity), at most [MAX_SOURCES_PER_IDENTITY] each, for at most [MAX_PROVENANCE_IDENTITIES]
 *    identities (LRU). Gossip is deliberately NOT a provenance source: its `from` field is not authenticated in this
 *    codebase (NOP router validator) and a Sybil source could gossip its own entries to confirm them.
 *
 * Thread-safe.
 */
class RelayDirectorySnapshotIngest(
    private val index: OnionRelayDescriptorIndex,
    private val recordSink: (PeerRecord, ByteArray) -> Boolean,
    private val clock: Clock = Clock.systemUTC(),
    private val maxNewIdentitiesPerFetch: Int = DEFAULT_MAX_NEW_IDENTITIES_PER_FETCH,
    private val maxSnapshotOwnedIdentities: Int = DEFAULT_MAX_SNAPSHOT_OWNED_IDENTITIES,
    private val blockMillis: Long = DEFAULT_BLOCK_MILLIS,
) {
    init {
        require(maxNewIdentitiesPerFetch > 0 && maxSnapshotOwnedIdentities >= maxNewIdentitiesPerFetch) {
            "invalid snapshot budgets"
        }
    }

    private val lock = Any()
    private val owned = HashSet<Secp256k1PublicKey>()
    private val provenance =
        object : LinkedHashMap<Secp256k1PublicKey, LinkedHashSet<PeerId>>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Secp256k1PublicKey, LinkedHashSet<PeerId>>,
            ): Boolean = size > MAX_PROVENANCE_IDENTITIES
        }
    private val blockedUntil =
        object : LinkedHashMap<PeerId, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, Long>): Boolean =
                size > MAX_BLOCKED_SOURCES
        }

    /**
     * Number of distinct snapshot sources that delivered a validly signed descriptor of [identity]: the current one, and
     * deliberately also an older version (REPLAYED_OR_STALE: sources cache their snapshot, so versions differ) and an
     * entry that was not taken for the budget or the capacity. It says "this source knows the relay", not "this source
     * delivered the descriptor now in the index".
     */
    fun sourcesFor(identity: Secp256k1PublicKey): Int = synchronized(lock) { provenance[identity]?.size ?: 0 }

    /** Identities in the index that were first introduced by a snapshot (tests, status). */
    fun snapshotOwnedCount(): Int = synchronized(lock) { owned.size }

    fun isBlocked(source: PeerId): Boolean =
        synchronized(lock) {
            val until = blockedUntil[source] ?: return@synchronized false
            if (clock.millis() >= until) {
                blockedUntil.remove(source)
                false
            } else {
                true
            }
        }

    fun ingest(
        source: PeerId,
        snapshot: RelayDirectorySnapshot,
    ): SnapshotIngestReport {
        if (isBlocked(source)) return SnapshotIngestReport(sourceBlocked = true)
        val now = clock.millis() / 1000
        pruneOwned(now)
        val entries = snapshot.entries.take(OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES)
        val invalidLimit = entries.size / 4
        var accepted = 0
        var confirmed = 0
        var stale = 0
        var expired = 0
        var invalid = 0
        var overBudget = 0
        var capacity = 0
        var recordsAccepted = 0
        var recordsSkipped = 0
        var newThisFetch = 0
        var blocked = false
        for (entry in entries) {
            val d = entry.descriptor
            val pre = index.precheck(d, now)
            val current: Boolean =
                when (pre) {
                    DescriptorIngestOutcome.EXPIRED -> {
                        expired++
                        false
                    }
                    DescriptorIngestOutcome.REPLAYED_OR_STALE -> {
                        stale++
                        // an older, validly signed version still shows that this source knows the relay (sources
                        // cache their snapshot for up to 30 s, so versions differ between sources): provenance only
                        if (OnionRelayDescriptor.verify(d, now)) noteSource(d.identity, source)
                        false
                    }
                    // the exact current descriptor: the signature was checked when it was first taken
                    DescriptorIngestOutcome.DUPLICATE -> {
                        confirmed++
                        true
                    }
                    else -> {
                        val isNew = index.current(d.identity, now) == null
                        if (isNew && !reserveNew(newThisFetch)) {
                            overBudget++
                            // not taken, but a validly signed descriptor still says "this source knows relay X": it
                            // counts as provenance, so that a flood of new identities from a first source can not keep
                            // the honest relays it also served from being confirmed by a second source
                            if (OnionRelayDescriptor.verify(d, now)) noteSource(d.identity, source) else invalid++
                            false
                        } else {
                            when (index.add(d, now)) {
                                DescriptorIngestOutcome.ACCEPTED -> {
                                    if (isNew) {
                                        newThisFetch++
                                        synchronized(lock) { owned += d.identity }
                                    }
                                    accepted++
                                    true
                                }
                                DescriptorIngestOutcome.DUPLICATE -> {
                                    confirmed++
                                    true
                                }
                                DescriptorIngestOutcome.INVALID -> {
                                    invalid++
                                    false
                                }
                                DescriptorIngestOutcome.CAPACITY -> {
                                    // add() verified it before refusing for capacity: provenance, as for over-budget
                                    capacity++
                                    noteSource(d.identity, source)
                                    false
                                }
                                DescriptorIngestOutcome.EXPIRED -> {
                                    expired++
                                    false
                                }
                                DescriptorIngestOutcome.REPLAYED_OR_STALE -> {
                                    stale++
                                    false
                                }
                            }
                        }
                    }
                }
            if (current) {
                noteSource(d.identity, source)
                when (ingestRecord(d, entry.recordBytes, now)) {
                    RecordOutcome.ACCEPTED -> recordsAccepted++
                    RecordOutcome.SKIPPED -> recordsSkipped++
                    RecordOutcome.INVALID -> invalid++
                }
            }
            if (invalid > invalidLimit) {
                block(source)
                blocked = true
                break
            }
        }
        val report =
            SnapshotIngestReport(
                accepted,
                confirmed,
                stale,
                expired,
                invalid,
                overBudget,
                capacity,
                recordsAccepted,
                recordsSkipped,
                blocked,
            )
        logger.debug {
            "relay directory snapshot: accepted=${report.accepted} confirmed=${report.confirmed} " +
                "rejected=${report.rejected} records=${report.recordsAccepted} blocked=${report.sourceBlocked}"
        }
        return report
    }

    private enum class RecordOutcome { ACCEPTED, SKIPPED, INVALID }

    private fun ingestRecord(
        d: OnionRelayDescriptor,
        bytes: ByteArray?,
        now: Long,
    ): RecordOutcome {
        if (bytes == null) return RecordOutcome.SKIPPED
        val record =
            try {
                PeerRecordCodec.decode(bytes)
            } catch (e: MalformedPeerRecordException) {
                return RecordOutcome.INVALID
            }
        if (!PeerRecord.verify(record) ||
            !record.verifyBinding() ||
            !record.verifyPossession()
        ) {
            return RecordOutcome.INVALID
        }
        // a validly signed record of ANOTHER relay or peer id is an attempt to redirect the dial: invalid, not skipped
        if (record.identity != d.identity || record.peerId != d.peerId) return RecordOutcome.INVALID
        if (record.notValidAfterEpochSecond < now) return RecordOutcome.SKIPPED
        if (record.directAddresses.none { !MultiaddrHygiene.isBlockedPrivateOrLocal(it) }) return RecordOutcome.SKIPPED
        return if (runCatching { recordSink(record, bytes) }.getOrDefault(false)) {
            RecordOutcome.ACCEPTED
        } else {
            RecordOutcome.SKIPPED
        }
    }

    private fun reserveNew(newThisFetch: Int): Boolean =
        newThisFetch < maxNewIdentitiesPerFetch && synchronized(lock) { owned.size < maxSnapshotOwnedIdentities }

    private fun noteSource(
        identity: Secp256k1PublicKey,
        source: PeerId,
    ) {
        synchronized(lock) {
            val set = provenance.getOrPut(identity) { LinkedHashSet() }
            if (source !in set && set.size >= MAX_SOURCES_PER_IDENTITY) set.remove(set.first())
            set += source
        }
    }

    private fun block(source: PeerId) {
        synchronized(lock) { blockedUntil[source] = clock.millis() + blockMillis }
        logger.debug { "relay directory source blocked for too many invalid entries" }
    }

    /**
     * Forgets ownership of identities whose descriptor left the index, so the budget frees up. Provenance is NOT pruned
     * here: it is bounded only by the LRU of [MAX_PROVENANCE_IDENTITIES] identities (an identity whose descriptor
     * returns keeps its earlier sources).
     */
    private fun pruneOwned(now: Long) {
        synchronized(lock) {
            owned.retainAll { index.current(it, now) != null }
        }
    }

    companion object {
        const val DEFAULT_MAX_NEW_IDENTITIES_PER_FETCH = 64
        const val DEFAULT_MAX_SNAPSHOT_OWNED_IDENTITIES = 512
        const val DEFAULT_BLOCK_MILLIS = 3_600_000L
        const val MAX_SOURCES_PER_IDENTITY = 4
        const val MAX_PROVENANCE_IDENTITIES = 4096
        private const val MAX_BLOCKED_SOURCES = 1024

        /** An ingest that hands verified records to [peerDirectory] (never re-published). */
        fun of(
            index: OnionRelayDescriptorIndex,
            peerDirectory: PeerDirectoryGossip,
            clock: Clock = Clock.systemUTC(),
        ): RelayDirectorySnapshotIngest =
            RelayDirectorySnapshotIngest(
                index,
                { record, bytes -> peerDirectory.ingestFromSnapshot(record, bytes) },
                clock,
            )
    }
}
