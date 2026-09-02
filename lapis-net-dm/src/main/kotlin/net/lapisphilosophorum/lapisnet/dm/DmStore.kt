package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Instant

/** How an outbound [DmHistoryEntry.Outbound] entry was actually delivered - mirrors
 * [DmSendOutcome], plus `UNDELIVERED` for the case neither transport worked - intended for a caller
 * that wants to still record the attempt rather than silently dropping it from history (e.g. a
 * future `lapis-net-browser` send route, not yet built this wave). Nothing in `lapis-net-dm` itself
 * produces this state today: [DmSessionManager.send]/`sendAuto` currently either succeed with
 * [SENT]/[QUEUED_FOR_PICKUP] or throw. */
enum class DmDeliveryState {
    SENT,
    QUEUED_FOR_PICKUP,
    UNDELIVERED,
}

/** One entry in a [DmStore] conversation - either an inbound [DmInboundMessage] or an outbound
 * message this node itself sent. **V0.8.6: carries [content] (a decoded [DmContent]), not a raw
 * [plaintext][DmContent] - unlike the V0.8.4 shape, which stored the raw [ByteArray] plaintext**,
 * so a future caller (e.g. a browser UI, not yet built this wave) can render body text and
 * attachment metadata without re-decoding. */
sealed class DmHistoryEntry {
    abstract val peer: Secp256k1PublicKey
    abstract val content: DmContent
    abstract val epochSecond: Long

    data class Inbound(
        override val peer: Secp256k1PublicKey,
        override val content: DmContent,
        override val epochSecond: Long,
        /** `true` iff [DmAcceptancePolicy.classifyDelivered] quarantined this message - see
         * [DmInboundMessage.quarantined]'s own doc comment. */
        val quarantined: Boolean = false,
    ) : DmHistoryEntry()

    data class Outbound(
        override val peer: Secp256k1PublicKey,
        override val content: DmContent,
        override val epochSecond: Long,
        val deliveryState: DmDeliveryState,
    ) : DmHistoryEntry()
}

/**
 * Bounded, per-peer, IN-MEMORY-ONLY conversation history. Bounded on TWO axes: history length per
 * peer ([DmStore.MAX_HISTORY_PER_PEER]) and the number of distinct peers tracked at all
 * ([DmStore.MAX_TRACKED_PEERS], LRU-evicted) - see [historyByPeer]'s own doc comment for the latter.
 *
 * **Explicit, deliberate scope cut, not an oversight, carried forward unchanged into V0.8.6: this
 * class persists nothing to disk.** See the V0.8.4 history for the original reasoning (this wave's
 * highest-structural-risk-to-date carried no spare review budget for a third at-rest encryption
 * scheme). `docs/roadmap.adoc`'s V0.8.6 section restates this as an explicit scope cut once more,
 * rather than letting it quietly age into an assumption: conversation history and
 * [DmAcceptedContacts]' accept-decisions still do not survive a process restart.
 *
 * Not wired to [DmSessionManager] automatically - a caller populates it explicitly, e.g.
 * `dmSessionManager.addInboundListener { message -> dmStore.recordInbound(message) }` and its own
 * call to `dmStore.recordOutbound(...)` alongside every send.
 */
class DmStore(
    private val maxHistoryPerPeer: Int = MAX_HISTORY_PER_PEER,
    private val maxTrackedPeers: Int = MAX_TRACKED_PEERS,
) {
    /** Bounds history LENGTH per peer via [maxHistoryPerPeer] (below) - this bounds the NUMBER of
     * distinct peers tracked, via LRU eviction once [maxTrackedPeers] is exceeded, mirroring
     * [DmSessionManager.liveSessionCache]'s identical access-ordered `removeEldestEntry` pattern.
     *
     * **Access-ordered - [peers] must NOT return this map's own iteration order.** A plain
     * `LinkedHashMap(accessOrder = true)`'s iteration order tracks the most-recently-ACCESSED key,
     * not the most-recently-ACTIVE conversation, and [historyFor] itself is a read that reorders
     * this map - so [peers] sorts explicitly by each peer's [lastEntryFor] epoch instead of trusting
     * map order (see [peers]' own doc comment). */
    private val historyByPeer =
        object : LinkedHashMap<Secp256k1PublicKey, ArrayDeque<DmHistoryEntry>>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Secp256k1PublicKey, ArrayDeque<DmHistoryEntry>>,
            ): Boolean = size > maxTrackedPeers
        }

    @Synchronized
    fun recordInbound(message: DmInboundMessage) {
        record(
            DmHistoryEntry.Inbound(message.sender, message.content, message.receivedAtEpochSecond, message.quarantined),
        )
    }

    @Synchronized
    fun recordOutbound(
        peer: Secp256k1PublicKey,
        content: DmContent,
        deliveryState: DmDeliveryState,
        epochSecond: Long = Instant.now().epochSecond,
    ) {
        record(DmHistoryEntry.Outbound(peer, content, epochSecond, deliveryState))
    }

    private fun record(entry: DmHistoryEntry) {
        val deque = historyByPeer.getOrPut(entry.peer) { ArrayDeque() }
        deque.addLast(entry)
        while (deque.size > maxHistoryPerPeer) deque.removeFirst()
    }

    /** Oldest-first snapshot of the history recorded for [peer] so far. */
    @Synchronized
    fun historyFor(peer: Secp256k1PublicKey): List<DmHistoryEntry> = historyByPeer[peer]?.toList() ?: emptyList()

    /** Every peer with at least one history entry, sorted by [lastEntryFor]'s own
     * [DmHistoryEntry.epochSecond] DESCENDING (most recently active conversation first) -
     * **deliberately NOT [historyByPeer]'s own map-iteration order**, which tracks access recency,
     * not conversation activity, and would otherwise reshuffle on every [historyFor] read. */
    @Synchronized
    fun peers(): List<Secp256k1PublicKey> =
        historyByPeer.keys
            .sortedByDescending { peer -> historyByPeer[peer]?.lastOrNull()?.epochSecond ?: Long.MIN_VALUE }

    /** The most recent entry recorded for [peer], or `null` if none exists. */
    @Synchronized
    fun lastEntryFor(peer: Secp256k1PublicKey): DmHistoryEntry? = historyByPeer[peer]?.lastOrNull()

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
