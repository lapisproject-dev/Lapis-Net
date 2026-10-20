package net.lapisphilosophorum.lapisnet.trust

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps a [VeritasGrant.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality, which would make every
 * distinct array instance a distinct key even for identical content. Internal: only
 * [VeritasGrantIndex] and [VeritasGrantResolver] (same package) need this - it is not part of
 * either type's public surface.
 */
internal data class GrantContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is GrantContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    /** Read-only access to the wrapped bytes for [GrantContentIdBytesComparator] - not exposed as
     * a public property since callers outside this package have no legitimate use for the raw
     * content-id bytes (they should use [VeritasGrant.contentId] on the grant itself instead). */
    internal fun bytesForComparison(): ByteArray = bytes
}

/**
 * Bounded, in-memory index of [VeritasGrant]s received (locally created or via gossip), keyed by
 * content id and by (truster, target) pair. This IS the local cache [VeritasGossip.currentGrants]
 * resolves over - it does not itself persist anything (that is Nabu's job, see [VeritasGossip])
 * and is never rebuilt by scanning storage at startup (Nabu has no "enumerate local CIDs"
 * primitive - see the architecture doc's known-gap note).
 *
 * [GrantContentId] (SHA-256 over a grant's canonical bytes, [VeritasGrant.contentId]) is a
 * completely different byte layout from a Nabu [io.ipfs.cid.Cid], even when computed over the
 * same underlying bytes - this index and [VeritasGrantResolver] key exclusively off
 * [VeritasGrant.contentId], never off a Nabu-returned `Cid`.
 *
 * **Eviction, not rejection, once full (round-2 M2 fix).** [grantsByContentId] is backed by an
 * access-order-capable [LinkedHashMap] whose `removeEldestEntry` override evicts the oldest
 * tracked entry once [maxTracked] is exceeded - mirrors `lapis-net-storage`'s
 * `BoundedRecordStore` pattern exactly. A full index therefore no longer hard-rejects new grants
 * (the previous behavior): it displaces its oldest tracked grant to make room instead. This
 * matters because, per the domain model, "revocation is not a special case, just a new grant with
 * value 0" - a hard-reject-when-full policy would let a cheap attacker who fills the shared cap
 * permanently prevent victims from ever seeing anyone's future trust updates, including a
 * legitimate revocation of a compromised/malicious party. [grantsByPair] (the reverse index
 * [grantsFor]/[allPairs] read from) is kept in sync on every eviction - see the
 * `removeEldestEntry` override below.
 *
 * (On the "access-order-capable" phrasing above, and why this is currently FIFO-equivalent rather
 * than true LRU: see [grantsByContentId]'s own doc comment.)
 *
 * **A second, SEPARATE bounded structure, [persistedContentIds], with a deliberately DIFFERENT
 * (non-evicting) policy, gates durable persistence (round-3 fix).** [canAccept] only ever
 * predicts exact-content-id duplication against [grantsByContentId] - since round-2's M2 change,
 * a full in-memory index evicts rather than rejects, so there is no "index is full" case left for
 * [canAccept] to report, which means it cannot bound [NabuStorage.put] calls on its own (that was
 * round-3's finding: gating persistence on [canAccept] alone silently stopped bounding disk
 * writes the moment M2 made the index evict). [persistedContentIds] and [tryReservePersistence]
 * exist purely to give persistence its own, independent cap. Unlike [grantsByContentId], this
 * structure never evicts - it is a hard, reject-once-full cap. That asymmetry is intentional, not
 * an oversight: the in-memory index backs this node's *live trust view*
 * ([VeritasGossip.currentGrants], and transitively [TrustGraph]/[TrustPathFinder]), which must
 * stay responsive to new grants (including revocations) even once full, so eviction is the
 * correct policy there. Durable persistence is a different resource with a different correctness
 * requirement: nothing reads the live trust view from disk (see [VeritasGossip]'s class doc
 * comment - the index is never rebuilt from `NabuStorage` at startup), and this wave's own design
 * already publishes full grant bytes over gossip rather than a CID pointer specifically because a
 * peer cannot be relied on to fetch content from another node later. So once this node's own
 * persistence cap is reached, declining to write further gossip-received grants to disk costs it
 * only its own restart-durability and Bitswap-serving ability for that specific late-arriving
 * content - an acceptable, already-precedented tradeoff (see [VeritasGossip]'s "known gaps" list)
 * - while a hard reject (rather than evicting an *already-durably-committed* older grant to make
 * room for a newer one) avoids the much worse alternative of silently un-persisting something this
 * node already promised the network it had stored.
 */
class VeritasGrantIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_GRANTS,
    private val maxPersisted: Int = MAX_PERSISTED_GRANTS,
) {
    /** Public entry point - always uses [MAX_TRACKED_GRANTS]/[MAX_PERSISTED_GRANTS]. The internal
     * constructor above exists purely as a test seam (mirrors [TrustGraph.build]'s
     * `maxNodes`/`maxEdges` pattern), so tests can exercise cap enforcement with small caps rather
     * than constructing tens of thousands of real signed grants. */
    constructor() : this(MAX_TRACKED_GRANTS, MAX_PERSISTED_GRANTS)

    private val grantsByPair = HashMap<Pair<Secp256k1PublicKey, Secp256k1PublicKey>, MutableList<VeritasGrant>>()

    /** Backed by a [LinkedHashMap] constructed with access-order tracking enabled (`true` third
     * constructor arg to keep the door open for true LRU promotion-on-read later), so
     * `removeEldestEntry` evicts whatever `LinkedHashMap` currently considers its oldest entry.
     * **Under this class's actual current usage this is FIFO-equivalent, not true LRU**: the only
     * reads performed against this map are [add]'s and [canAccept]'s `containsKey` checks, and
     * `containsKey` does *not* count as an access for `LinkedHashMap`'s access-order bookkeeping
     * (only `get`/`put`-style operations do) - so no already-tracked entry is ever "promoted" to
     * more-recently-used by being looked up again. In practice the eviction order this produces is
     * therefore indistinguishable from plain insertion order. [grantsByPair] cleanup happens
     * directly off the evicted entry `removeEldestEntry` hands back - driving cleanup off that
     * value, rather than trying to recompute what was evicted after the fact, is why this is
     * correct even though [grantsByContentId] and [grantsByPair] are two separate structures
     * updated in two separate steps. */
    private val grantsByContentId =
        object : LinkedHashMap<GrantContentId, VeritasGrant>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<GrantContentId, VeritasGrant>): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                val pairKey = evicted.truster to evicted.target
                val bucket = grantsByPair[pairKey]
                bucket?.remove(evicted)
                if (bucket != null && bucket.isEmpty()) grantsByPair.remove(pairKey)
                return true
            }
        }

    /** Backing set for [tryReservePersistence] - deliberately a plain [HashSet], not a
     * [LinkedHashMap]: this structure never evicts, so it has no ordering to maintain. See the
     * class doc comment for why this is a separate, non-evicting cap rather than reusing
     * [grantsByContentId]'s eviction policy. */
    private val persistedContentIds = HashSet<GrantContentId>()

    /** Monotonic change counter, incremented on every successful [add] (which also covers evictions, since an
     * eviction only ever happens inside an add). Lets callers decide cheaply whether any derived snapshot is stale. */
    private var version: Long = 0

    /** Current change counter; O(1). Equal values on two reads mean the tracked grant set did not change between them. */
    @Synchronized
    fun version(): Long = version

    /**
     * Adds [grant] to the index. Returns `true` iff it was newly added; `false` for a duplicate
     * (by content id) or a signature-invalid grant - **never throws**, since this is the last line
     * of defense before untrusted gossip data reaches this node's in-memory state. Re-verifies
     * [grant]'s signature defensively via [VeritasGrant.verify] even though callers (the GossipSub
     * validator in `VeritasGossip`) should already have done so - mirrors
     * [VeritasGrantChain.validate]'s own precedent of re-verifying an "already trusted" list
     * rather than assuming.
     *
     * A full index is no longer a `false`-returning case (see the class doc comment on eviction) -
     * something else always gets displaced to make room, so `add` on a structurally-fine, not-yet-
     * tracked grant always succeeds.
     */
    @Synchronized
    fun add(grant: VeritasGrant): Boolean =
        runCatching {
            if (!VeritasGrant.verify(grant)) return@runCatching false
            val id = GrantContentId(grant.contentId())
            if (grantsByContentId.containsKey(id)) return@runCatching false
            grantsByContentId[id] = grant
            grantsByPair.getOrPut(grant.truster to grant.target) { mutableListOf() }.add(grant)
            version++
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [grant] is not already tracked
     * by content id. Intended to run **before** [add] gates whether a grant is tracked/propagated
     * at all - see [VeritasGossip.onGossipMessage], which declines a message outright (no persist
     * attempt, no indexing, no re-propagation) when this returns `false`.
     *
     * **This alone no longer bounds durable persistence (round-3 fix, correcting round-2's C2
     * fix).** Gating `NabuStorage.put()` on this check alone was sufficient back when a full index
     * hard-rejected new grants, but round-2's M2 change made the index evict instead - so this
     * predicts only exact-content-id duplication, never "no more room", and provides no cap on
     * `storage.put()` calls by itself. [VeritasGossip.onGossipMessage] additionally gates
     * persistence on [tryReservePersistence], a separate, non-evicting cap - see that method's and
     * the class doc comment's reasoning for why persistence needs its own, harder cap.
     *
     * Does **not** check signature validity (callers must already have called [VeritasGrant.verify]
     * before this, exactly as [VeritasGossip.onGossipMessage] does) and does **not** check
     * "is the index full" (see the class doc comment: a full index evicts, it never rejects) - the
     * only thing left that can make [add] decline a structurally-fine, signature-valid grant is an
     * exact content-id duplicate, so that is the only thing this pre-check needs to predict.
     * Calling this any number of times never itself mutates the index or fills the cap.
     */
    @Synchronized
    fun canAccept(grant: VeritasGrant): Boolean = !grantsByContentId.containsKey(GrantContentId(grant.contentId()))

    /**
     * Admission gate purely for **durable persistence** (round-3 fix) - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [grantsByContentId]'s
     * evicting cap. `true` means "go ahead and call `NabuStorage.put()` for this grant" (either
     * because a slot was just reserved, or because one was already reserved for this exact content
     * id earlier - see the idempotency note below); `false` means the persistence cap has been
     * reached and the caller should skip `NabuStorage.put()` for this grant.
     *
     * **Reserves the slot atomically, before the caller's `NabuStorage.put()` runs** - this is a
     * single `@Synchronized` check-and-commit, not a `canPersist()` + `markPersisted()` pair, so
     * there is no check-then-act race window between two concurrent callers both seeing spare
     * capacity and both committing to use the same last slot.
     *
     * **Idempotent per content id**: calling this again for a content id that already has a
     * reserved/persisted slot returns `true` without consuming a second slot - a caller does not
     * need to track "did I already reserve for this one" itself.
     *
     * **Not rolled back if the caller's subsequent `NabuStorage.put()` throws.** A reserved slot is
     * consumed the moment this returns `true`, regardless of what the caller does afterward. In the
     * rare case of a genuine storage error, this wastes one slot out of [maxPersisted] - deliberately
     * not worth the extra complexity of threading a rollback path through the caller for a rare
     * error case with a bounded, minor cost.
     */
    @Synchronized
    fun tryReservePersistence(grant: VeritasGrant): Boolean {
        val id = GrantContentId(grant.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** All grants currently tracked for the (truster, target) pair, in insertion order - the raw
     * candidate list [VeritasGrantResolver.resolveLatest] resolves down to a single winner. */
    @Synchronized
    internal fun grantsFor(
        truster: Secp256k1PublicKey,
        target: Secp256k1PublicKey,
    ): List<VeritasGrant> = grantsByPair[truster to target]?.toList() ?: emptyList()

    /** Every distinct (truster, target) pair with at least one tracked grant. */
    @Synchronized
    internal fun allPairs(): Set<Pair<Secp256k1PublicKey, Secp256k1PublicKey>> = grantsByPair.keys.toSet()

    companion object {
        /**
         * Upper bound on distinct grants tracked from gossip before they even reach
         * [TrustGraph]/[TrustPathFinder] - a separate cap from [TrustGraph.MAX_NODES]/
         * [TrustGraph.MAX_EDGES], because a single (truster, target) pair can accumulate an
         * unbounded number of superseding grants (a full version chain, not just one edge) before
         * [VeritasGrantResolver] ever collapses it down to one. 64,000 is generous headroom above
         * [TrustGraph.MAX_EDGES] (32,000) for exactly that reason - see this project's
         * personal/local web-of-trust scale target (Dunbar's-number reasoning documented on
         * [TrustGraph.MAX_NODES]). Since round-2, reaching this bound no longer stops new grants
         * from being tracked - it triggers eviction of the oldest tracked grant instead (currently
         * FIFO-equivalent in practice, not true LRU - see the class doc comment and
         * [grantsByContentId]'s doc comment for why).
         */
        const val MAX_TRACKED_GRANTS = 64_000

        /**
         * Upper bound on distinct grants this node will durably persist via `NabuStorage.put()`
         * from gossip (round-3 fix, see [tryReservePersistence] and the class doc comment). A
         * conceptually different resource from [MAX_TRACKED_GRANTS] - disk space rather than
         * in-memory trust-view slots - but sized identically and for the same underlying reason:
         * this project's stated personal/local web-of-trust scale target (Dunbar's-number
         * reasoning documented on [TrustGraph.MAX_NODES]). 64,000 durably-persisted grants is
         * generous headroom for that scale, and reusing the exact same number as
         * [MAX_TRACKED_GRANTS] is the simplest defensible choice here - there is no reason for a
         * personal node's disk budget for this data to be smaller than its in-memory tracking
         * budget, since a grant's encoded size is tiny (see [VeritasGossip]'s class doc comment on
         * [VeritasGrantCodec.MAX_BODY_SIZE] plus a 64-byte signature). Unlike [MAX_TRACKED_GRANTS],
         * reaching this bound does NOT evict anything already persisted - see
         * [tryReservePersistence].
         */
        const val MAX_PERSISTED_GRANTS = 64_000
    }
}
