package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Cross-type downgrade protection between [PeerRecord] (address-bearing) and [AnonymousPeerRecord] of ONE identity
 * (wave V0.10.0-D). Both record types share the sequence-number scale (epoch milliseconds), so they are comparable:
 *
 * - once an anonymous record with sequence `S` was accepted, [PeerRecord]s with `seq <= S` are stale (an old
 *   address record can not be replayed to re-expose the node);
 * - once a [PeerRecord] with sequence `S` was accepted, anonymous records with `seq < S` are stale (the way
 *   back to normal mode). On a tie the anonymous record wins, the privacy-preserving choice.
 *
 * In-memory and LRU-bounded, like the per-index high-water marks. For identities without an anonymous record the
 * floors are [Long.MIN_VALUE] and the pre-existing [PeerRecordIndex] behaviour is unchanged. Thread-safe.
 */
internal class IdentitySupersession(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) {
    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    private fun lru() =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > maxEntries
        }

    private val anonymousHigh = lru()
    private val peerHigh = lru()

    /** [PeerRecord]s of [identity] with a sequence number `<=` this value are stale. */
    fun peerRecordFloor(identity: Secp256k1PublicKey): Long =
        synchronized(anonymousHigh) { anonymousHigh[identity] } ?: Long.MIN_VALUE

    /** Anonymous records of [identity] with a sequence number `<` this value are stale. */
    fun anonymousRecordFloor(identity: Secp256k1PublicKey): Long =
        synchronized(peerHigh) { peerHigh[identity] } ?: Long.MIN_VALUE

    /** Records that an anonymous record with [sequenceNumber] was accepted (monotonic). */
    fun raiseAnonymous(
        identity: Secp256k1PublicKey,
        sequenceNumber: Long,
    ) {
        synchronized(anonymousHigh) {
            val old = anonymousHigh[identity]
            if (old == null || sequenceNumber > old) anonymousHigh[identity] = sequenceNumber
        }
    }

    /** Records that a [PeerRecord] with [sequenceNumber] was accepted (monotonic). */
    fun raisePeerRecord(
        identity: Secp256k1PublicKey,
        sequenceNumber: Long,
    ) {
        synchronized(peerHigh) {
            val old = peerHigh[identity]
            if (old == null || sequenceNumber > old) peerHigh[identity] = sequenceNumber
        }
    }

    companion object {
        const val DEFAULT_MAX_ENTRIES = 128_000
    }
}
