package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/** What [AnonymousPeerRecordIndex.add] did with a record. */
enum class AnonymousIngestOutcome {
    ACCEPTED,
    DUPLICATE,
    REPLAYED_OR_STALE,
    INVALID,
    EXPIRED,
    CAPACITY,
}

/**
 * Bounded in-memory store of the current [AnonymousPeerRecord] per identity (wave V0.10.0-D), with the discipline of
 * [OnionServiceDescriptorIndex]: one current record per identity; the sequence number must STRICTLY increase; the
 * high-water marks survive eviction (LRU of `maxHighWaterMarks`); equivocation (same sequence number, different
 * content) is ignored; a full index first drops expired records and then refuses NEW identities with
 * [AnonymousIngestOutcome.CAPACITY] - it never evicts a valid entry to make room for a stranger. Updates of known
 * identities always get through. That is the same Sybil boundary as in wave C and is documented, not solved.
 *
 * Shares an [IdentitySupersession] with the [PeerRecordIndex] it is built on: an accepted anonymous record removes
 * the identity's address-bearing [PeerRecord] (`seq <=` the new one) and blocks its replay; an accepted [PeerRecord]
 * newer than the anonymous one hides the anonymous one (the way back to normal mode). Thread-safe.
 */
class AnonymousPeerRecordIndex(
    private val peerRecords: PeerRecordIndex,
    private val capacity: Int = DEFAULT_CAPACITY,
    private val maxHighWaterMarks: Int = MAX_HIGH_WATER_MARKS,
) {
    init {
        require(capacity > 0 && maxHighWaterMarks >= capacity) { "invalid index capacities" }
    }

    private val supersession: IdentitySupersession get() = peerRecords.supersession
    private val lock = Any()
    private val records = HashMap<Secp256k1PublicKey, AnonymousPeerRecord>()
    private val highWater =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > maxHighWaterMarks
        }

    /** Cheap check WITHOUT signature verification and without spending any rate budget; `null` if possibly new. */
    fun precheck(
        record: AnonymousPeerRecord,
        nowEpochSecond: Long,
    ): AnonymousIngestOutcome? {
        if (record.notValidAfterEpochSecond < nowEpochSecond) return AnonymousIngestOutcome.EXPIRED
        synchronized(lock) {
            if (records[record.identity] == record) return AnonymousIngestOutcome.DUPLICATE
            if (isStaleLocked(record)) return AnonymousIngestOutcome.REPLAYED_OR_STALE
        }
        return null
    }

    private fun isStaleLocked(record: AnonymousPeerRecord): Boolean {
        val mark = highWater[record.identity]
        if (mark != null && record.sequenceNumber <= mark) return true
        return record.sequenceNumber < supersession.anonymousRecordFloor(record.identity)
    }

    fun add(
        record: AnonymousPeerRecord,
        nowEpochSecond: Long,
    ): AnonymousIngestOutcome {
        if (record.notValidAfterEpochSecond < nowEpochSecond) return AnonymousIngestOutcome.EXPIRED
        if (!AnonymousPeerRecord.verify(record, nowEpochSecond)) return AnonymousIngestOutcome.INVALID
        synchronized(lock) {
            val current = records[record.identity]
            if (current != null && current == record) return AnonymousIngestOutcome.DUPLICATE
            if (isStaleLocked(record)) return AnonymousIngestOutcome.REPLAYED_OR_STALE
            if (current == null && records.size >= capacity) {
                evictExpiredLocked(nowEpochSecond)
                if (records.size >= capacity) return AnonymousIngestOutcome.CAPACITY
            }
            records[record.identity] = record
            highWater[record.identity] = record.sequenceNumber
            // The shared floor is raised under the same lock that publishes the record: a concurrent PeerRecord
            // can not slip in between.
            supersession.raiseAnonymous(record.identity, record.sequenceNumber)
        }
        peerRecords.supersede(record.identity, record.sequenceNumber)
        return AnonymousIngestOutcome.ACCEPTED
    }

    /** The current, unexpired, not-superseded record of [identity] (a revocation counts: see [isRevoked]). */
    fun currentIncludingRevocation(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): AnonymousPeerRecord? =
        synchronized(lock) {
            val r = records[identity] ?: return null
            if (r.notValidAfterEpochSecond < nowEpochSecond) return null
            if (r.sequenceNumber < supersession.anonymousRecordFloor(identity)) return null
            r
        }

    /** The current record that announces an onion presence, or `null` if there is none, it expired, or it is revoked. */
    fun current(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): AnonymousPeerRecord? = currentIncludingRevocation(identity, nowEpochSecond)?.takeIf { !it.revoked }

    fun isRevoked(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): Boolean = currentIncludingRevocation(identity, nowEpochSecond)?.revoked == true

    fun evictExpired(nowEpochSecond: Long): Int = synchronized(lock) { evictExpiredLocked(nowEpochSecond) }

    private fun evictExpiredLocked(nowEpochSecond: Long): Int {
        val expired = records.values.filter { it.notValidAfterEpochSecond < nowEpochSecond }
        for (r in expired) records.remove(r.identity)
        return expired.size
    }

    fun size(): Int = synchronized(lock) { records.size }

    companion object {
        const val DEFAULT_CAPACITY = 16_384
        const val MAX_HIGH_WATER_MARKS = 65_536
    }
}
