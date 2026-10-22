package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor

/**
 * Bounded in-memory store of the current [OnionServiceDescriptor] per service key (wave V0.10.0-C), with the
 * same discipline as [OnionRelayDescriptorIndex]: one current descriptor per service key; the sequence number
 * must STRICTLY increase; high-water marks survive eviction (LRU of [maxHighWaterMarks]); equivocation (the
 * same sequence number with different content) is ignored; a full index first drops expired descriptors and
 * then refuses NEW service keys with [DescriptorIngestOutcome.CAPACITY] - it never evicts a valid entry to make
 * room for a stranger. The index is public and enumerable: see docs/anonymity.adoc for what that means.
 * Thread-safe.
 */
class OnionServiceDescriptorIndex(
    private val maxTracked: Int = 4096,
    private val maxHighWaterMarks: Int = 16384,
) {
    init {
        require(maxTracked > 0 && maxHighWaterMarks >= maxTracked) { "invalid index capacities" }
    }

    private val lock = Any()
    private val records = HashMap<Ed25519PublicKey, OnionServiceDescriptor>()
    private val highWater =
        object : LinkedHashMap<Ed25519PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Ed25519PublicKey, Long>): Boolean =
                size > maxHighWaterMarks
        }

    /** Cheap check WITHOUT signature verification: EXPIRED, DUPLICATE or REPLAYED_OR_STALE, or `null` if possibly new. */
    fun precheck(
        d: OnionServiceDescriptor,
        nowEpochSecond: Long,
    ): DescriptorIngestOutcome? {
        if (d.notValidAfterEpochSecond < nowEpochSecond) return DescriptorIngestOutcome.EXPIRED
        synchronized(lock) {
            if (records[d.serviceKey] == d) return DescriptorIngestOutcome.DUPLICATE
            val mark = highWater[d.serviceKey]
            if (mark != null && d.sequenceNumber <= mark) return DescriptorIngestOutcome.REPLAYED_OR_STALE
        }
        return null
    }

    fun add(
        d: OnionServiceDescriptor,
        nowEpochSecond: Long,
    ): DescriptorIngestOutcome {
        if (d.notValidAfterEpochSecond < nowEpochSecond) return DescriptorIngestOutcome.EXPIRED
        if (!OnionServiceDescriptor.verify(d, nowEpochSecond)) return DescriptorIngestOutcome.INVALID
        synchronized(lock) {
            val current = records[d.serviceKey]
            if (current != null && current == d) return DescriptorIngestOutcome.DUPLICATE
            val mark = highWater[d.serviceKey]
            if (mark != null && d.sequenceNumber <= mark) return DescriptorIngestOutcome.REPLAYED_OR_STALE
            if (current == null && records.size >= maxTracked) {
                evictExpiredLocked(nowEpochSecond)
                if (records.size >= maxTracked) return DescriptorIngestOutcome.CAPACITY
            }
            records[d.serviceKey] = d
            highWater[d.serviceKey] = d.sequenceNumber
            return DescriptorIngestOutcome.ACCEPTED
        }
    }

    fun current(
        serviceKey: Ed25519PublicKey,
        nowEpochSecond: Long,
    ): OnionServiceDescriptor? =
        synchronized(lock) { records[serviceKey]?.takeIf { it.notValidAfterEpochSecond >= nowEpochSecond } }

    fun evictExpired(nowEpochSecond: Long): Int = synchronized(lock) { evictExpiredLocked(nowEpochSecond) }

    private fun evictExpiredLocked(nowEpochSecond: Long): Int {
        val expired = records.values.filter { it.notValidAfterEpochSecond < nowEpochSecond }
        for (d in expired) records.remove(d.serviceKey)
        return expired.size
    }

    fun size(): Int = synchronized(lock) { records.size }
}
