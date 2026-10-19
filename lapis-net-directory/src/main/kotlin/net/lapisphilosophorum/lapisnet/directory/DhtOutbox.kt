package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.util.Base64

/** What [DhtOutbox.selectForPublication] picked, and how many live entries did not fit. */
data class OutboxSelection(
    val entries: List<OutboxEntry>,
    val omitted: Int,
)

/**
 * The local, bounded store of this node's own outgoing [OutboxEntry]s (V0.9.14). Senders (`DmSessionManager`,
 * `MailSender`) only [offer] into it - a cheap in-memory operation with no I/O; the one and only writer of the
 * IPNS value remains [DirectoryDht.publishOwn], which asks for a [selectForPublication] each time it publishes.
 * Nothing here publishes by itself.
 *
 * Bounded by [maxTracked] entries (least recently offered is evicted) and deduplicated by
 * [OutboxEntry.contentId]. Held in memory only: after a restart of the sender the outbox is empty (documented
 * residual risk). Thread-safe.
 */
class DhtOutbox(
    private val maxTracked: Int = DirectoryDhtLimits().maxTrackedOutboxEntries,
) {
    init {
        require(maxTracked > 0) { "maxTracked must be positive" }
    }

    private val entries = LinkedHashMap<String, OutboxEntry>()

    private fun key(entry: OutboxEntry): String = Base64.getEncoder().encodeToString(entry.contentId())

    /** @return `true` if the entry was new, `false` if an identical one was already tracked (it is then refreshed). */
    @Synchronized
    fun offer(entry: OutboxEntry): Boolean {
        val k = key(entry)
        val existed = entries.remove(k) != null
        entries[k] = entry
        while (entries.size > maxTracked) {
            val eldest = entries.keys.iterator()
            eldest.next()
            eldest.remove()
        }
        return !existed
    }

    @Synchronized
    fun remove(entry: OutboxEntry) {
        entries.remove(key(entry))
    }

    @Synchronized
    fun size(): Int = entries.size

    /** The entries not expired at [nowEpochSecond], oldest first (diagnostics and tests of the senders). */
    @Synchronized
    fun snapshot(nowEpochSecond: Long): List<OutboxEntry> =
        entries.values.filter { it.notValidAfterEpochSecond >= nowEpochSecond }

    /**
     * Pure (no clock): drops entries expired at [nowEpochSecond], then takes entries round-robin over the
     * recipients - newest first within a recipient - so a burst to one recipient cannot push every other
     * recipient out. Stops at [maxEntries] or when [byteBudget] (sum of the encoded entry sizes) is used up; an
     * entry that does not fit is skipped and a smaller later one may still be taken.
     */
    @Synchronized
    internal fun selectForPublication(
        nowEpochSecond: Long,
        maxEntries: Int,
        byteBudget: Int,
    ): OutboxSelection {
        val live = entries.values.filter { it.notValidAfterEpochSecond >= nowEpochSecond }
        val byRecipient = LinkedHashMap<Secp256k1PublicKey, ArrayDeque<OutboxEntry>>()
        for (e in live.asReversed()) byRecipient.getOrPut(e.recipient) { ArrayDeque() }.addLast(e)
        val chosen = ArrayList<OutboxEntry>()
        var used = 0
        var progressed = true
        while (progressed && chosen.size < maxEntries) {
            progressed = false
            for (queue in byRecipient.values) {
                if (chosen.size >= maxEntries) break
                val head = queue.removeFirstOrNull() ?: continue
                progressed = true
                if (used + head.encodedSize() <= byteBudget) {
                    chosen.add(head)
                    used += head.encodedSize()
                }
            }
        }
        return OutboxSelection(chosen, live.size - chosen.size)
    }
}
