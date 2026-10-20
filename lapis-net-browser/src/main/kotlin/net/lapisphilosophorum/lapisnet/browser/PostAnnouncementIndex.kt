package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid

/**
 * Wraps a [PostAnnouncement.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrContentId]/[net.lapisphilosophorum.lapisnet.trust.GrantContentId]
 * exactly, duplicated locally rather than reused for the same reason those two are duplicated
 * rather than shared: this module has no dependency edge that would make sharing one of them
 * natural. Internal: only [PostAnnouncementIndex] (same package) needs this.
 */
internal data class PostContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is PostContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * A tracked [PostAnnouncement] paired with the locally-derived [Cid] of its body bytes.
 * [PostAnnouncement] itself never carries a [Cid] field - see [PostAnnouncementGossip]'s doc
 * comment for why the [Cid] is always derived locally (by each node independently calling
 * `NabuStorage.put()` on the body bytes) rather than embedded in the signed structure.
 */
data class IndexedPost(
    val cid: Cid,
    val announcement: PostAnnouncement,
)

/**
 * Bounded, in-memory index of [PostAnnouncement]s received (locally created or via gossip), keyed
 * by content id. Mirrors [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]'s two-cap
 * eviction/persistence pattern exactly - see that class's doc comment for the full round-2/
 * round-3 reasoning this structure is copied from (an evicting in-memory tracking cap vs. a
 * separate, non-evicting, hard-capped persistence cap, and why those need to be two independent
 * resources).
 *
 * Simpler than [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex] in one respect: there is no
 * secondary reverse index by `(cid, viewId)` or similar - a browser timeline just wants every
 * tracked post, in insertion order (see [all]), so a single content-id-keyed structure is enough.
 */
class PostAnnouncementIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_ANNOUNCEMENTS,
    private val maxPersisted: Int = MAX_PERSISTED_ANNOUNCEMENTS,
    private val maxPersistedBodies: Int = MAX_PERSISTED_BODIES,
) {
    /** Public entry point - always uses [MAX_TRACKED_ANNOUNCEMENTS]/[MAX_PERSISTED_ANNOUNCEMENTS]/
     * [MAX_PERSISTED_BODIES]. The internal constructor above exists purely as a test seam,
     * mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]'s own constructor
     * pattern. */
    constructor() : this(MAX_TRACKED_ANNOUNCEMENTS, MAX_PERSISTED_ANNOUNCEMENTS, MAX_PERSISTED_BODIES)

    /** Backed by a [LinkedHashMap] constructed with access-order tracking enabled, exactly
     * mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.recordsByContentId] - see
     * that field's doc comment for why this is FIFO-equivalent in practice, not true LRU. */
    private val postsByContentId =
        object : LinkedHashMap<PostContentId, IndexedPost>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PostContentId, IndexedPost>): Boolean {
                if (size <= maxTracked) return false
                val author = eldest.value.announcement.author
                postsByAuthor[author]?.let { bucket ->
                    bucket.remove(eldest.key)
                    if (bucket.isEmpty()) postsByAuthor.remove(author)
                }
                return true
            }
        }

    /** Secondary index author -> that author's tracked posts, kept in lock-step with [postsByContentId] (including
     * eviction), so per-author lookups never scan the whole index. */
    private val postsByAuthor =
        HashMap<net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey, MutableMap<PostContentId, IndexedPost>>()

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.persistedContentIds] exactly. */
    private val persistedContentIds = HashSet<PostContentId>()

    /** Backing set for [tryReserveBodyPersistence] - a plain, never-evicting [HashSet], keyed by
     * [Cid] rather than by announcement content id (see that method's doc comment for why). Same
     * non-evicting, hard-capped policy as [persistedContentIds]/[tryReservePersistence], mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.persistedContentIds] exactly. */
    private val persistedBodyCids = HashSet<Cid>()

    /**
     * Adds [announcement] (with its locally-derived [cid]) to the index. Returns `true` iff it was
     * newly added; `false` for a duplicate (by content id) or a signature-invalid announcement -
     * **never throws**, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.add]'s "last line of defense before
     * untrusted gossip data reaches this node's in-memory state" contract exactly, including the
     * defensive re-verification of [announcement]'s signature.
     */
    @Synchronized
    fun add(
        announcement: PostAnnouncement,
        cid: Cid,
    ): Boolean =
        runCatching {
            if (!PostAnnouncement.verify(announcement)) return@runCatching false
            val id = PostContentId(announcement.contentId())
            if (postsByContentId.containsKey(id)) return@runCatching false
            val indexed = IndexedPost(cid, announcement)
            postsByContentId[id] = indexed
            postsByAuthor.getOrPut(announcement.author) { HashMap() }[id] = indexed
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [announcement] is not already
     * tracked by content id. Mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.canAccept]'s contract exactly.
     */
    @Synchronized
    fun canAccept(announcement: PostAnnouncement): Boolean =
        !postsByContentId.containsKey(PostContentId(announcement.contentId()))

    /**
     * Admission gate purely for **durable persistence of the announcement wrapper's own encoded
     * bytes** - a bounded, non-evicting, hard-reject-once-[maxPersisted] cap, entirely separate
     * from [postsByContentId]'s evicting cap. Mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.tryReservePersistence]'s contract
     * exactly, including atomic reserve-before-put semantics and idempotency per content id.
     *
     * **Does not gate persistence of the post body bytes themselves** - see
     * [tryReserveBodyPersistence] for that separate, [Cid]-keyed cap. This cap only bounds the
     * separate, optional durable copy of the signed announcement wrapper's own encoded bytes.
     */
    @Synchronized
    fun tryReservePersistence(announcement: PostAnnouncement): Boolean {
        val id = PostContentId(announcement.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /**
     * Admission gate purely for **durable persistence of a post's body bytes**, keyed by [Cid] -
     * a bounded, non-evicting, hard-reject-once-[maxPersistedBodies] cap, entirely separate from
     * [tryReservePersistence]'s wrapper-bytes cap. This closes the gap [tryReservePersistence]
     * deliberately leaves open (see that method's doc comment): body-bytes `storage.put()` calls
     * in [PostAnnouncementGossip.announce]/[PostAnnouncementGossip.onGossipMessage] were previously
     * unconditional, which meant a cheap attacker minting an unbounded stream of signed
     * announcements with trivially-varied bodies (each producing a fresh content id that always
     * passes [canAccept], since [PostAnnouncement.create] draws a fresh random nonce every call)
     * could force every relaying node in the mesh to independently and unconditionally grow its
     * local disk without bound - see `PostAnnouncementGossip`'s doc comment for the full attack
     * writeup. Keyed by [Cid], not by announcement content id like [tryReservePersistence]: body
     * bytes are content-addressed, so the same [Cid] re-announced (with a different nonce/
     * timestamp/signature wrapper) by a different or replaying party must not be double-counted
     * against the cap. Same non-evicting, hard-capped policy as [tryReservePersistence] - once
     * [maxPersistedBodies] distinct bodies have been durably stored, further distinct bodies are
     * declined for storage, but the announcement itself is still accepted/indexed/gossiped (see
     * call sites) - it will simply render as content-unavailable on nodes that never cached the
     * body locally, an already-established tradeoff in this codebase (mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s own "best-effort convergence"
     * precedent).
     */
    @Synchronized
    fun tryReserveBodyPersistence(cid: Cid): Boolean {
        if (persistedBodyCids.contains(cid)) return true
        if (persistedBodyCids.size >= maxPersistedBodies) return false
        persistedBodyCids.add(cid)
        return true
    }

    /** The tracked posts of one [author]; O(posts of that author), empty (and O(1)) for an unknown author. */
    @Synchronized
    fun postsBy(author: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey): List<IndexedPost> =
        postsByAuthor[author]?.values?.toList() ?: emptyList()

    /** Every tracked [IndexedPost], in insertion order. */
    @Synchronized
    fun all(): List<IndexedPost> = postsByContentId.values.toList()

    companion object {
        /**
         * Upper bound on distinct post announcements tracked from gossip. This number is
         * provisional, chosen for parity with existing precedent
         * ([net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.MAX_TRACKED_GRANTS]-style
         * reasoning) rather than derived from real pilot usage data - revisit once actual browser
         * pilot traffic volumes are observed.
         */
        const val MAX_TRACKED_ANNOUNCEMENTS = 8_000

        /**
         * Upper bound on distinct announcement-wrapper encodings this node will durably persist
         * via `NabuStorage.put()` from gossip - see [tryReservePersistence]. Same provisional-
         * magnitude caveat as [MAX_TRACKED_ANNOUNCEMENTS] applies.
         */
        const val MAX_PERSISTED_ANNOUNCEMENTS = 8_000

        /**
         * Upper bound on distinct post BODY byte blobs this node will durably persist via
         * `NabuStorage.put()`, keyed by [Cid] - see [tryReserveBodyPersistence]. Same provisional-
         * magnitude caveat as [MAX_TRACKED_ANNOUNCEMENTS] applies.
         */
        const val MAX_PERSISTED_BODIES = 8_000
    }
}
