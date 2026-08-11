package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Instant

/** One entry in a [DmStore] conversation - either an inbound [DmInboundMessage] or an outbound
 * message this node itself sent, recorded by the caller from [DmSessionManager.send]'s own
 * plaintext argument (this class has no visibility into `send()`'s internals). */
sealed class DmHistoryEntry {
    abstract val peer: Secp256k1PublicKey
    abstract val plaintext: ByteArray
    abstract val epochSecond: Long

    data class Inbound(
        override val peer: Secp256k1PublicKey,
        override val plaintext: ByteArray,
        override val epochSecond: Long,
    ) : DmHistoryEntry()

    data class Outbound(
        override val peer: Secp256k1PublicKey,
        override val plaintext: ByteArray,
        override val epochSecond: Long,
    ) : DmHistoryEntry()
}

/**
 * Bounded, per-peer, IN-MEMORY-ONLY conversation history. Bounded on TWO axes: history length per
 * peer ([DmStore.MAX_HISTORY_PER_PEER]) and the number of distinct peers tracked at all
 * ([DmStore.MAX_TRACKED_PEERS], LRU-evicted) - see [historyByPeer]'s own doc comment for the latter.
 *
 * **Explicit, deliberate V0.8.4 scope cut, not an oversight: this class persists nothing to disk.**
 * The plan for this wave asked to "decide and document the at-rest encryption approach for stored
 * plaintext history (recommend: reuse `KeystoreEncryption`) - or, if scope permits, defer
 * conversation-history persistence entirely to a later wave and keep [DmStore] in-memory-only for
 * V0.8.4, as long as that scope cut is explicit and documented, not silent." This wave already
 * carries the highest structural risk in the codebase to date (a new stream protocol, a new wire
 * format, a new session state machine, and the mandatory adversarial suite this all demands) -
 * inventing a THIRD at-rest encryption scheme (after `KeystoreFileFormat`/`PrekeyStoreFileFormat`
 * and `DoubleRatchetSessionCodec`) has no spare review budget in this wave. Durable [DoubleRatchetSession]
 * persistence (a DIFFERENT concern - it is what makes a process restart resume rather than
 * re-handshake) **is** required and implemented, in [DmSessionManager] - this class is purely a
 * caller-convenience conversation-history cache, never consulted by [DmSessionManager] itself.
 *
 * A later wave (plausibly bundled with V0.8.5's offline-mailbox work, since both need durable
 * storage) should revisit whether [DmStore] should persist via [net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption]
 * at that point.
 *
 * Not wired to [DmSessionManager] automatically - a caller populates it explicitly, e.g.
 * `dmSessionManager.addInboundListener { message -> dmStore.recordInbound(message) }` and its own
 * call to `dmStore.recordOutbound(...)` alongside every [DmSessionManager.send] call.
 */
class DmStore(
    private val maxHistoryPerPeer: Int = MAX_HISTORY_PER_PEER,
    private val maxTrackedPeers: Int = MAX_TRACKED_PEERS,
) {
    /** Bounds history LENGTH per peer via [maxHistoryPerPeer] (below) - this bounds the NUMBER of
     * distinct peers tracked, via LRU eviction once [maxTrackedPeers] is exceeded, mirroring
     * [DmSessionManager.liveSessionCache]'s identical access-ordered `removeEldestEntry` pattern
     * (the same bounded-structure discipline this codebase applies everywhere else, e.g.
     * `PeerRecordIndex.MAX_TRACKED_RECORDS`). */
    private val historyByPeer =
        object : LinkedHashMap<Secp256k1PublicKey, ArrayDeque<DmHistoryEntry>>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Secp256k1PublicKey, ArrayDeque<DmHistoryEntry>>,
            ): Boolean = size > maxTrackedPeers
        }

    @Synchronized
    fun recordInbound(message: DmInboundMessage) {
        record(DmHistoryEntry.Inbound(message.sender, message.plaintext, message.receivedAtEpochSecond))
    }

    @Synchronized
    fun recordOutbound(
        peer: Secp256k1PublicKey,
        plaintext: ByteArray,
        epochSecond: Long = Instant.now().epochSecond,
    ) {
        record(DmHistoryEntry.Outbound(peer, plaintext, epochSecond))
    }

    private fun record(entry: DmHistoryEntry) {
        val deque = historyByPeer.getOrPut(entry.peer) { ArrayDeque() }
        deque.addLast(entry)
        while (deque.size > maxHistoryPerPeer) deque.removeFirst()
    }

    /** Oldest-first snapshot of the history recorded for [peer] so far. */
    @Synchronized
    fun historyFor(peer: Secp256k1PublicKey): List<DmHistoryEntry> = historyByPeer[peer]?.toList() ?: emptyList()

    companion object {
        /** Generous, provisional magnitude - not derived from pilot data, same framing as this
         * codebase's every other numeric cap. */
        const val MAX_HISTORY_PER_PEER = 500

        /** Generous headroom, provisional magnitude - not derived from pilot data, same framing as
         * [MAX_HISTORY_PER_PEER] and every sibling numeric cap in this codebase (e.g.
         * `PeerRecordIndex.MAX_TRACKED_RECORDS`). Bounds the number of distinct peers [DmStore] keeps
         * conversation history for at once - see [historyByPeer]'s own doc comment. */
        const val MAX_TRACKED_PEERS = 4_096
    }
}
