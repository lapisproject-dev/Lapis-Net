package net.lapisphilosophorum.lapisnet.directory

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.nio.ByteBuffer

/** What [OnionRelayDescriptorIndex.add] did with a descriptor. */
enum class DescriptorIngestOutcome {
    ACCEPTED,
    DUPLICATE,
    REPLAYED_OR_STALE,
    INVALID,
    EXPIRED,
    CAPACITY,
}

/**
 * Bounded in-memory store of the current [OnionRelayDescriptor] per relay identity (no persistence).
 *
 * Rules: one current descriptor per identity; the sequence number must STRICTLY increase; the
 * per-identity high-water marks survive eviction of the descriptor itself (otherwise an evicted
 * relay's old descriptor could be replayed), bounded by an LRU of [maxHighWaterMarks] entries; the same
 * sequence number with different content (equivocation) is ignored, not swapped in. A full index
 * first drops expired descriptors, then refuses NEW identities with [DescriptorIngestOutcome.CAPACITY]
 * - it never evicts a valid, honest entry to make room for a stranger - while updates of tracked
 * identities are always accepted. Thread-safe.
 */
class OnionRelayDescriptorIndex(
    private val maxTracked: Int = 1024,
    private val maxHighWaterMarks: Int = 4096,
) {
    init {
        require(maxTracked > 0 && maxHighWaterMarks >= maxTracked) { "invalid index capacities" }
    }

    private val lock = Any()
    private val records = HashMap<Secp256k1PublicKey, OnionRelayDescriptor>()
    private val byDigest = HashMap<ByteBuffer, Secp256k1PublicKey>()
    private val byPeer = HashMap<PeerId, Secp256k1PublicKey>()
    private val highWater =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > maxHighWaterMarks
        }

    private fun digestKey(d: OnionRelayDescriptor) = ByteBuffer.wrap(d.relayIdDigest())

    /**
     * Cheap pre-check WITHOUT signature verification: the outcome [add] would return for an EXPIRED, DUPLICATE or
     * REPLAYED_OR_STALE descriptor, or `null` if the descriptor could be new (then only [add] decides). Never accepts anything.
     */
    fun precheck(
        d: OnionRelayDescriptor,
        nowEpochSecond: Long,
    ): DescriptorIngestOutcome? {
        if (d.notValidAfterEpochSecond < nowEpochSecond) return DescriptorIngestOutcome.EXPIRED
        synchronized(lock) {
            if (records[d.identity] == d) return DescriptorIngestOutcome.DUPLICATE
            val mark = highWater[d.identity]
            if (mark != null && d.sequenceNumber <= mark) return DescriptorIngestOutcome.REPLAYED_OR_STALE
        }
        return null
    }

    fun add(
        d: OnionRelayDescriptor,
        nowEpochSecond: Long,
    ): DescriptorIngestOutcome {
        if (d.notValidAfterEpochSecond < nowEpochSecond) return DescriptorIngestOutcome.EXPIRED
        if (!OnionRelayDescriptor.verify(d, nowEpochSecond)) return DescriptorIngestOutcome.INVALID
        synchronized(lock) {
            val current = records[d.identity]
            if (current != null && current == d) return DescriptorIngestOutcome.DUPLICATE
            val mark = highWater[d.identity]
            if (mark != null && d.sequenceNumber <= mark) return DescriptorIngestOutcome.REPLAYED_OR_STALE
            if (current == null && records.size >= maxTracked) {
                evictExpiredLocked(nowEpochSecond)
                if (records.size >= maxTracked) return DescriptorIngestOutcome.CAPACITY
            }
            if (current != null) {
                byDigest.remove(digestKey(current))
                byPeer.remove(current.peerId)
            }
            records[d.identity] = d
            byDigest[digestKey(d)] = d.identity
            byPeer[d.peerId] = d.identity
            highWater[d.identity] = d.sequenceNumber
            return DescriptorIngestOutcome.ACCEPTED
        }
    }

    fun current(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): OnionRelayDescriptor? =
        synchronized(lock) { records[identity]?.takeIf { it.notValidAfterEpochSecond >= nowEpochSecond } }

    fun byRelayIdDigest(
        digest: ByteArray,
        nowEpochSecond: Long,
    ): OnionRelayDescriptor? =
        synchronized(lock) {
            val identity = byDigest[ByteBuffer.wrap(digest)] ?: return@synchronized null
            records[identity]?.takeIf { it.notValidAfterEpochSecond >= nowEpochSecond }
        }

    /** The current descriptor of the relay whose libp2p transport peer id is [peerId] (wave V0.10.0-F1), or `null`. */
    fun byPeerId(
        peerId: PeerId,
        nowEpochSecond: Long,
    ): OnionRelayDescriptor? =
        synchronized(lock) {
            val identity = byPeer[peerId] ?: return@synchronized null
            records[identity]?.takeIf { it.notValidAfterEpochSecond >= nowEpochSecond }
        }

    fun snapshot(
        nowEpochSecond: Long,
        limit: Int = maxTracked,
    ): List<OnionRelayDescriptor> =
        synchronized(lock) {
            records.values.filter { it.notValidAfterEpochSecond >= nowEpochSecond }.take(limit.coerceAtLeast(0))
        }

    fun evictExpired(nowEpochSecond: Long): Int = synchronized(lock) { evictExpiredLocked(nowEpochSecond) }

    private fun evictExpiredLocked(nowEpochSecond: Long): Int {
        val expired = records.values.filter { it.notValidAfterEpochSecond < nowEpochSecond }
        for (d in expired) {
            records.remove(d.identity)
            byDigest.remove(digestKey(d))
            byPeer.remove(d.peerId)
        }
        return expired.size
    }

    fun size(): Int = synchronized(lock) { records.size }

    internal fun digestMapSize(): Int = synchronized(lock) { byDigest.size }
}
