package net.lapisphilosophorum.lapisnet.storage

import io.libp2p.core.PeerId
import java.time.Instant

/**
 * Bounded, in-memory store of validated IPNS records, one per publisher (V0.9.13). Replaces the
 * `BoundedRecordStore` that sat behind Nabu's record handling: that one was keyed by `Multihash`,
 * which Nabu's `GET_VALUE` (`Cid.cast` of the key suffix) does not reliably hit for identity-multihash
 * (Ed25519) names. This store is keyed by [PeerId] and only [IpnsValueResponder] and [NabuStorage] use it.
 *
 * LRU-capped at [maxSize] publishers: an attacker minting identities can displace records, but cannot
 * grow the heap (see the residual-risk note in docs/architecture.adoc: eviction by Sybil identities is accepted).
 * Expired records are dropped when they are looked at. All methods are synchronized.
 */
internal class BoundedIpnsRecordStore(
    private val maxSize: Int,
) {
    init {
        require(maxSize > 0) { "maxSize must be positive" }
    }

    private val records =
        object : LinkedHashMap<PeerId, ValidatedIpnsRecord>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, ValidatedIpnsRecord>): Boolean =
                size > maxSize
        }

    /**
     * Stores [record] if it supersedes what is held (higher sequence, or same sequence and later
     * expiry; an expired held record counts as absent). Returns `true` if the record is now held:
     * stored just now, or already held byte-identically (an idempotent republish). Returns `false` if
     * a different, at-least-as-new record stays - including equal sequence and expiry with other
     * content, where the held record wins.
     */
    @Synchronized
    fun putIfNewer(
        record: ValidatedIpnsRecord,
        now: Instant,
    ): Boolean {
        val held = records[record.publisher]
        if (held != null && !held.notValidAfter.isBefore(now)) {
            if (held.sameRecordAs(record)) return true
            if (!record.isNewerThan(held)) return false
        }
        records[record.publisher] = record
        return true
    }

    /** The held record of [publisher] if it has not expired as of [now]; an expired one is removed. */
    @Synchronized
    fun get(
        publisher: PeerId,
        now: Instant,
    ): ValidatedIpnsRecord? {
        val held = records[publisher] ?: return null
        if (held.notValidAfter.isBefore(now)) {
            records.remove(publisher)
            return null
        }
        return held
    }

    @Synchronized
    fun size(): Int = records.size
}
