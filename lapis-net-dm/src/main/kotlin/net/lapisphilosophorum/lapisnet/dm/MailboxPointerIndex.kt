package net.lapisphilosophorum.lapisnet.dm

/** Wraps a [MailboxPointer.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - mirrors `net.lapisphilosophorum.lapisnet.directory.PeerRecordContentId`/
 * `net.lapisphilosophorum.lapisnet.mail.MailContentId` exactly, duplicated locally rather than
 * reused for the same module-boundary reason those classes document. Internal: [MailboxPointerIndex]
 * and [MailboxRedeliveryScheduler] (same package) need this. */
internal data class MailboxPointerContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is MailboxPointerContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Bounded, in-memory index of [MailboxPointer]s accepted by [MailboxGossip]'s validator, content-
 * id-keyed - unlike `net.lapisphilosophorum.lapisnet.directory.PeerRecordIndex`'s "latest wins per
 * identity" shape, a recipient can legitimately have MANY distinct pending offline messages at
 * once, so every distinct pointer is tracked, mirroring
 * `net.lapisphilosophorum.lapisnet.mail.InboxIndex`'s multiple-coexisting-entries shape instead.
 * Adds a resolved/pending flag `InboxIndex` does not need - see [markResolved].
 *
 * Mirrors the established two-cap eviction/persistence structure (an evicting in-memory tracking
 * cap, [entriesByContentId], plus a SEPARATE, non-evicting, hard-capped persistence-reservation cap,
 * [persistedContentIds]/[tryReservePersistence]) - see
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex`'s class doc comment for the full
 * reasoning this is copied from.
 *
 * **No per-sender lookup structure - V0.8.5 hardening pass finding, 2026-08-27.** An earlier
 * revision of this class kept a SECOND, parallel `pointersBySender` map alongside
 * [entriesByContentId] (a `Secp256k1PublicKey -> MutableList<MailboxPointer>` bucket, kept in sync
 * at both [add] and [evictExpired]) purely to serve a `pointersFrom(sender)` query. Removed here: a
 * repo-wide grep at the time of removal showed [MailboxGossip]'s own `pointersFrom` delegate had
 * exactly one caller anywhere in this codebase - `MailboxPointerIndexTest` itself - never any
 * production code path ([MailboxPoller] iterates [pending] only, never per-sender). Carrying a
 * second synchronized bucket that exists solely to make a test pass is the wrong trade: real
 * bookkeeping cost (a second map to keep consistent at every insertion AND eviction site) for a
 * capability nothing production-side uses. If a genuine near-term need for a per-sender pointer
 * query surfaces (e.g. a future "list pending mailbox deposits by sender" UI, or a per-sender
 * pointer cap enforced independently of [MailboxPoller.MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS]), it
 * should come back in whatever shape that consumer actually needs - not be spec-guessed back into
 * existence now. No such consumer is planned as of this note (V0.8.6 is an explicitly unplanned
 * reserved slot - see `docs/roadmap.adoc`'s own V0.8.6 entry).
 */
class MailboxPointerIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_POINTERS,
    private val maxPersisted: Int = MAX_PERSISTED_POINTERS,
) {
    /** Public entry point - always uses [MAX_TRACKED_POINTERS]/[MAX_PERSISTED_POINTERS]. The
     * internal constructor above exists purely as a test seam, mirroring `PeerRecordIndex`'s own
     * constructor pattern. */
    constructor() : this(MAX_TRACKED_POINTERS, MAX_PERSISTED_POINTERS)

    private class Entry(
        val pointer: MailboxPointer,
        var resolved: Boolean = false,
    )

    /** Backed by a [LinkedHashMap] with access-order tracking enabled, mirroring
     * `PeerRecordIndex.recordsByContentId`/`InboxIndex.messagesByContentId` exactly - see those
     * fields' doc comments for why this is FIFO-equivalent in practice, not true LRU. */
    private val entriesByContentId =
        object : LinkedHashMap<MailboxPointerContentId, Entry>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<MailboxPointerContentId, Entry>): Boolean =
                size > maxTracked
        }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * `PeerRecordIndex.persistedContentIds` exactly. */
    private val persistedContentIds = HashSet<MailboxPointerContentId>()

    /** Adds [pointer] to the index. Returns `true` iff it was newly added; `false` for an exact
     * content-id duplicate or a signature-invalid pointer - **never throws**, mirroring
     * `PeerRecordIndex.add`'s "last line of defense before untrusted gossip data reaches this
     * node's in-memory state" contract, including the defensive re-verification of
     * [MailboxPointer.verify]. */
    @Synchronized
    fun add(pointer: MailboxPointer): Boolean =
        runCatching {
            if (!MailboxPointer.verify(pointer)) return@runCatching false
            val id = MailboxPointerContentId(pointer.contentId())
            if (entriesByContentId.containsKey(id)) return@runCatching false
            entriesByContentId[id] = Entry(pointer)
            true
        }.getOrDefault(false)

    /** Cheap, non-mutating, no-I/O admission pre-check: `true` iff [pointer] is not already
     * tracked by content id. Mirrors `PeerRecordIndex.canAccept`'s dedup-only contract. */
    @Synchronized
    fun canAccept(pointer: MailboxPointer): Boolean =
        !entriesByContentId.containsKey(MailboxPointerContentId(pointer.contentId()))

    /** Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [entriesByContentId]'s evicting
     * cap. Mirrors `PeerRecordIndex.tryReservePersistence`'s contract exactly. */
    @Synchronized
    fun tryReservePersistence(pointer: MailboxPointer): Boolean {
        val id = MailboxPointerContentId(pointer.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** Releases a reservation [tryReservePersistence] granted, WITHOUT the corresponding
     * `storage.put` ever actually succeeding - security audit round 1 minor finding:
     * [tryReservePersistence] permanently inserts into the never-evicting [persistedContentIds] the
     * moment it is called, so a caller that reserves and then has the actual durable write fail
     * (e.g. `NabuStorageException`) previously burned one of [maxPersisted] slots forever, for a
     * pointer that ended up neither persisted NOR tracked - [MailboxGossip.onGossipMessage] is the
     * only caller. No-op if [pointer]'s content id was never reserved (or was already released) -
     * safe to call defensively. */
    @Synchronized
    fun releaseReservedPersistence(pointer: MailboxPointer) {
        persistedContentIds.remove(MailboxPointerContentId(pointer.contentId()))
    }

    /** Every tracked pointer NOT YET marked [resolved][markResolved] - what
     * [MailboxPoller.pollOnce] iterates. */
    @Synchronized
    fun pending(): List<MailboxPointer> = entriesByContentId.values.filterNot { it.resolved }.map { it.pointer }

    /** Marks [pointer] resolved - called after a successful fetch+decrypt+deliver, OR after a
     * DEFINITIVE failure (garbage/tampered blob, or an expired TTL - retrying never helps, the
     * bytes/expiry don't change). NOT called for "peer currently unreachable" (that stays pending
     * for the next poll pass - the sender may come back online). No-op if [pointer]'s content id
     * isn't currently tracked (already evicted by the LRU cap - same "bounded index, evicted
     * entries stop being served" tradeoff every sibling index in this codebase already accepts). */
    @Synchronized
    fun markResolved(pointer: MailboxPointer) {
        entriesByContentId[MailboxPointerContentId(pointer.contentId())]?.resolved = true
    }

    /** Number of currently content-id-tracked pointers (`<= maxTracked` always). */
    @Synchronized
    fun size(): Int = entriesByContentId.size

    /** Removes every tracked pointer whose [MailboxPointer.notValidAfterEpochSecond] is strictly
     * before [nowEpochSecond] - mirrors `PeerRecordIndex.evictExpired` exactly: a caller-supplied
     * clock (this class makes zero clock calls of its own), and NOT wired to any periodic scheduler
     * here - [MailboxPoller.pollOnce] calls this at the start of every pass. Returns the number of
     * pointers evicted. Never touches [persistedContentIds] (same "persistence reservations are a
     * separate, deliberately permanent resource" reasoning as `PeerRecordIndex.evictExpired`). */
    @Synchronized
    fun evictExpired(nowEpochSecond: Long): Int {
        var evictedCount = 0
        val iterator = entriesByContentId.entries.iterator()
        while (iterator.hasNext()) {
            val pointer = iterator.next().value.pointer
            if (pointer.notValidAfterEpochSecond < nowEpochSecond) {
                iterator.remove()
                evictedCount++
            }
        }
        return evictedCount
    }

    companion object {
        /** Mirrors `PeerRecordIndex.MAX_TRACKED_RECORDS` - pointer records are small (<= 274
         * bytes). Same provisional-magnitude caveat as every sibling cap: chosen for parity with
         * existing precedent, not derived from real pilot usage data. */
        const val MAX_TRACKED_POINTERS = 64_000

        /** Mirrors `PeerRecordIndex.MAX_PERSISTED_RECORDS`. */
        const val MAX_PERSISTED_POINTERS = 64_000
    }
}
