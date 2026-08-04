package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps a [MessageEnvelope.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.GrantContentId` /
 * `net.lapisphilosophorum.lapisnet.virtus.LtrContentId` exactly, duplicated locally rather than
 * reused: this module has no dependency edge to `lapis-net-trust`/`lapis-net-virtus` (see this
 * module's `build.gradle.kts` comment - mail is a separate subsystem, not a scoring dimension).
 * Internal: only [InboxIndex] (same package) needs this.
 */
internal data class MailContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is MailContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/** One accepted inbox message: the verified envelope plus the body blob it is CID-bound to. */
class InboxMessage(
    val envelope: MessageEnvelope,
    val body: MessageBody,
)

/**
 * Bounded, in-memory index of [InboxMessage]s accepted by [InboxGossip]'s validator, keyed by
 * envelope content id and by sender. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex`'s two-cap eviction/persistence
 * structure precisely (see that class's doc comment for the full round-2/round-3 reasoning this is
 * copied from: an evicting in-memory tracking cap for the live view, plus a SEPARATE, non-evicting
 * persistence-reservation cap, because tracking and durable persistence are different resources
 * with different correct policies).
 *
 * **Sizing note - smaller absolute numbers than the trust/virtus/madli modules' 64,000, not an
 * inconsistency.** A mail message's blob is up to ~48 KB
 * ([MessageBodyCodec.MAX_BODY_BLOB_SIZE]-ish) versus a Veritas grant's ~2 KB - an equal count
 * would be a roughly 25x larger disk/heap budget. [MAX_TRACKED_MESSAGES]/[MAX_PERSISTED_MESSAGES]
 * are provisional, chosen for a personal-node inbox scale, and should be revisited against real
 * usage - the same "provisional magnitude" caveat `LtrRecordIndex.MAX_TRACKED_RECORDS` documents.
 */
class InboxIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_MESSAGES,
    private val maxPersisted: Int = MAX_PERSISTED_MESSAGES,
) {
    /** Public entry point - always uses [MAX_TRACKED_MESSAGES]/[MAX_PERSISTED_MESSAGES]. The
     * internal constructor above exists purely as a test seam, mirroring
     * `VeritasGrantIndex`'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_MESSAGES, MAX_PERSISTED_MESSAGES)

    private val messagesBySender = HashMap<Secp256k1PublicKey, MutableList<InboxMessage>>()

    /** Backed by a [LinkedHashMap] with access-order tracking enabled, exactly mirroring
     * `VeritasGrantIndex.grantsByContentId` - see that field's doc comment for why this is
     * FIFO-equivalent in practice, not true LRU. */
    private val messagesByContentId =
        object : LinkedHashMap<MailContentId, InboxMessage>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<MailContentId, InboxMessage>): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                val sender = evicted.envelope.sender
                val bucket = messagesBySender[sender]
                bucket?.remove(evicted)
                if (bucket != null && bucket.isEmpty()) messagesBySender.remove(sender)
                return true
            }
        }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * `VeritasGrantIndex.persistedContentIds` exactly. */
    private val persistedContentIds = HashSet<MailContentId>()

    /**
     * Adds [message] to the index. Returns `true` iff it was newly added; `false` for a duplicate
     * (by envelope content id) or a signature-invalid envelope - **never throws**, mirroring
     * `VeritasGrantIndex.add`'s "last line of defense before untrusted gossip data reaches this
     * node's in-memory state" contract, including the defensive re-verification of the envelope's
     * signature.
     */
    @Synchronized
    fun add(message: InboxMessage): Boolean =
        runCatching {
            if (!MessageEnvelope.verify(message.envelope)) return@runCatching false
            val id = MailContentId(message.envelope.contentId())
            if (messagesByContentId.containsKey(id)) return@runCatching false
            messagesByContentId[id] = message
            messagesBySender.getOrPut(message.envelope.sender) { mutableListOf() }.add(message)
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [envelope] is not already
     * tracked by content id. Mirrors `VeritasGrantIndex.canAccept`'s dedup-only contract exactly -
     * see that method's doc comment for why this alone does not bound durable persistence
     * (post-eviction there is no "index is full" case for this to report; that is what
     * [tryReservePersistence] exists for, as a separate, non-evicting cap).
     */
    @Synchronized
    fun canAccept(envelope: MessageEnvelope): Boolean =
        !messagesByContentId.containsKey(MailContentId(envelope.contentId()))

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [messagesByContentId]'s evicting
     * cap. Mirrors `VeritasGrantIndex.tryReservePersistence`'s contract exactly, including atomic
     * reserve-before-put semantics (single `@Synchronized` check-and-commit) and idempotency per
     * content id. Not rolled back if the caller's subsequent `NabuStorage.put()` throws - same
     * deliberate, bounded-cost tradeoff as that method.
     */
    @Synchronized
    fun tryReservePersistence(envelope: MessageEnvelope): Boolean {
        val id = MailContentId(envelope.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** All tracked messages, oldest first (insertion order) - a defensive copy. */
    @Synchronized
    fun latest(): List<InboxMessage> = messagesByContentId.values.toList()

    /** All tracked messages from [sender], insertion order - a defensive copy. */
    @Synchronized
    internal fun messagesFrom(sender: Secp256k1PublicKey): List<InboxMessage> =
        messagesBySender[sender]?.toList() ?: emptyList()

    /** Every distinct sender with at least one tracked message. */
    @Synchronized
    internal fun senders(): Set<Secp256k1PublicKey> = messagesBySender.keys.toSet()

    /** Number of currently-tracked messages. */
    @Synchronized
    internal fun size(): Int = messagesByContentId.size

    companion object {
        /** See this class's doc comment for the sizing rationale (smaller than the trust/virtus/
         * madli modules' 64,000, because a mail blob is much larger than a grant/record/vote). */
        const val MAX_TRACKED_MESSAGES = 8_000

        /** See [tryReservePersistence] and this class's doc comment. Same provisional-magnitude
         * caveat as [MAX_TRACKED_MESSAGES] applies. */
        const val MAX_PERSISTED_MESSAGES = 8_000
    }
}
