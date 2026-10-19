package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * The bounded, in-memory queue of mail pointers that arrived through the DHT and still have to be fetched
 * (V0.9.14). No clock and no network: expiry is judged by the caller passing "now" to [evictExpired]. At most
 * [maxPending] entries and at most [maxPerSender] per sender, keyed by `(sender, envelope CID)` so a pointer seen
 * twice - from two lookups or two DHT peers - is queued once. Lost on restart, like the gossip indexes; the
 * sender's next publication brings it back.
 *
 * Anti-displacement: the expiry of a pointer is attacker-chosen, so [evictExpired] also drops pointers claiming
 * a validity beyond `now + maxValiditySeconds`. When the queue is full, resolved entries go first; after that a
 * new pointer only displaces the oldest entry of the sender holding the most entries (and only if that sender
 * holds at least two more than the newcomer) - otherwise the newcomer is refused. A flood of throwaway identities therefore
 * cannot push out the entries of a legitimate sender.
 */
internal class InboxDhtPendingIndex(
    private val maxPending: Int = MAX_PENDING,
    private val maxPerSender: Int = MAX_PENDING_PER_SENDER,
) {
    class Entry(
        val sender: Secp256k1PublicKey,
        val senderPeerId: PeerId,
        val envelopeCid: Cid,
        val notValidAfterEpochSecond: Long,
    ) {
        @Volatile
        var resolved: Boolean = false
            internal set

        /** Network fetch attempts charged so far. */
        @Volatile
        var attempts: Int = 0
            internal set

        /** Earliest time (epoch seconds) of the next attempt (backoff). */
        @Volatile
        var nextAttemptEpochSecond: Long = 0
            internal set
    }

    init {
        require(maxPending > 0) { "maxPending must be positive" }
        require(maxPerSender > 0) { "maxPerSender must be positive" }
    }

    private val entries = LinkedHashMap<Pair<Secp256k1PublicKey, String>, Entry>()

    /** @return `true` if queued, `false` if already known or refused (per-sender cap, or queue full of others). */
    @Synchronized
    fun add(entry: Entry): Boolean {
        val key = entry.sender to entry.envelopeCid.toString()
        if (entries.containsKey(key)) return false
        if (entries.values.count { it.sender == entry.sender } >= maxPerSender) {
            val resolvedOwn = entries.entries.firstOrNull { it.value.sender == entry.sender && it.value.resolved }
            if (resolvedOwn == null) return false
            entries.remove(resolvedOwn.key)
        }
        while (entries.size >= maxPending) {
            val resolvedVictim = entries.entries.firstOrNull { it.value.resolved }
            if (resolvedVictim != null) {
                entries.remove(resolvedVictim.key)
                continue
            }
            val counts = entries.values.groupingBy { it.sender }.eachCount()
            val (heaviest, heaviestCount) = counts.maxByOrNull { it.value }!!
            val newcomerCount = counts.getOrDefault(entry.sender, 0)
            if (heaviest != entry.sender && heaviestCount <= newcomerCount + 1) return false
            val victim = entries.entries.first { it.value.sender == heaviest }
            entries.remove(victim.key)
        }
        entries[key] = entry
        return true
    }

    /** Entries not yet resolved, oldest first. */
    @Synchronized
    fun pending(): List<Entry> = entries.values.filter { !it.resolved }

    @Synchronized
    fun markResolved(entry: Entry) {
        entry.resolved = true
    }

    /**
     * Removes entries whose pointer has expired at [nowEpochSecond] or claims a validity beyond
     * `nowEpochSecond + maxValiditySeconds` (an honest sender never exceeds its own TTL); returns how many.
     */
    @Synchronized
    fun evictExpired(
        nowEpochSecond: Long,
        maxValiditySeconds: Long = MAX_POINTER_VALIDITY_SECONDS,
    ): Int {
        val before = entries.size
        val horizon = nowEpochSecond + maxValiditySeconds
        entries.values.removeIf {
            it.notValidAfterEpochSecond < nowEpochSecond || it.notValidAfterEpochSecond > horizon
        }
        return before - entries.size
    }

    /** Charges one network attempt to [entry] and schedules the next one with exponential backoff. */
    @Synchronized
    fun recordAttempt(
        entry: Entry,
        nowEpochSecond: Long,
    ) {
        entry.attempts++
        val shift = (entry.attempts - 1).coerceAtMost(BACKOFF_MAX_SHIFT)
        entry.nextAttemptEpochSecond =
            nowEpochSecond + (BACKOFF_BASE_SECONDS shl shift).coerceAtMost(BACKOFF_CAP_SECONDS)
    }

    @Synchronized
    fun size(): Int = entries.size

    companion object {
        const val MAX_PENDING: Int = 4096
        const val MAX_PENDING_PER_SENDER: Int = 64

        /** Sender TTL (7 days) plus one day of clock slack. */
        const val MAX_POINTER_VALIDITY_SECONDS: Long = 8 * 86_400L
        const val MAX_ATTEMPTS_PER_ENTRY: Int = 24
        const val BACKOFF_BASE_SECONDS: Long = 60L
        const val BACKOFF_CAP_SECONDS: Long = 6 * 3600L
        private const val BACKOFF_MAX_SHIFT: Int = 10
    }
}
