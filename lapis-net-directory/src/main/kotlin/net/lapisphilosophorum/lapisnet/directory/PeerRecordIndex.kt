package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/** Wraps a [PeerRecord.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - mirrors `net.lapisphilosophorum.lapisnet.trust.GrantContentId`/
 * `net.lapisphilosophorum.lapisnet.mail.MailContentId` exactly, duplicated locally rather than
 * reused for the same module-boundary reason those classes document. Internal: only
 * [PeerRecordIndex] (same package) needs this. */
internal data class PeerRecordContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is PeerRecordContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/** Unsigned lexicographic byte-order comparator over content-id byte arrays - the deterministic
 * tie-break for two records sharing the same [PeerRecord.identity] and the same
 * [PeerRecord.sequenceNumber] (see [PeerRecordIndex]'s class doc comment). Mirrors
 * `net.lapisphilosophorum.lapisnet.madli.MadliContentIdBytesComparator`'s identical shape. */
private object PeerRecordContentIdBytesComparator : Comparator<ByteArray> {
    override fun compare(
        a: ByteArray,
        b: ByteArray,
    ): Int {
        val len = minOf(a.size, b.size)
        for (i in 0 until len) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }
}

/**
 * Bounded, in-memory index of [PeerRecord]s received (locally created or via gossip), latest-wins
 * per [PeerRecord.identity]. Mirrors `net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex`'s
 * two-cap eviction/persistence structure (an evicting in-memory tracking cap, [recordsByContentId],
 * plus a SEPARATE, non-evicting, hard-capped persistence-reservation cap, [persistedContentIds]/
 * [tryReservePersistence]) - see that class's doc comment for the full round-2/round-3 reasoning
 * this is copied from.
 *
 * **A genuinely new ordering rule, not copied from any sibling index - "at most one CURRENT record
 * per identity, decided by [PeerRecord.sequenceNumber], never by arrival order."**
 * `net.lapisphilosophorum.lapisnet.madli.MadliVectorIndex`'s "replace on conflict" invariant comes
 * closest, but Madli's tuple key (`observer, observedPeer, epochDay`) already encodes the ordering
 * dimension (day) IN the key, so a conflict there is always "same day, different content, most
 * recent arrival wins" - there is no attacker-supplied counter to compare. Here, [currentByIdentity]
 * holds the record with the HIGHEST [PeerRecord.sequenceNumber] seen for each identity so far,
 * ties broken deterministically (not by arrival order, so every honest node converges on the SAME
 * winner regardless of gossip delivery order) via [PeerRecordContentIdBytesComparator] over
 * [PeerRecord.contentId]. A record with a LOWER sequence number than the currently-tracked one for
 * the same identity is rejected outright by both [canAccept] and [add] - it is never even
 * considered for tracking, let alone persistence - this is the anti-rollback property
 * `PeerRecordSpoofingTest`'s case (b) tests.
 *
 * **Superseded records are actively DROPPED from [recordsByContentId], not merely un-linked from
 * [currentByIdentity].** When a strictly-newer (or tie-break-winning) record replaces the tracked
 * one for an identity, the OLD record's content id is removed from [recordsByContentId] in the
 * same step - mirrors `MadliVectorIndex.removeFromSecondaryIndices`'s "every secondary index MUST
 * be cleaned in lockstep" discipline, except here there is only one secondary index
 * ([currentByIdentity]) to keep in sync, and eviction is driven the other direction (superseding a
 * SPECIFIC known entry, not evicting the globally-oldest one).
 *
 * **[recordsByContentId]'s own LRU-style eviction (once [maxTracked] is exceeded) also keeps
 * [currentByIdentity] in sync** - `removeEldestEntry` below only clears an identity's
 * [currentByIdentity] entry if it STILL points at exactly the evicted record (a newer record for
 * that identity may already have superseded it via [add]'s own replacement path, in which case
 * [currentByIdentity] must NOT be clobbered) - mirrors `MadliVectorIndex.removeFromSecondaryIndices`'s
 * identical `if (map[key] == evicted) map.remove(key)` guard.
 *
 * **Invariant, relied on by [canAccept]/[add]/eviction alike: every value in [currentByIdentity] is
 * always also present in [recordsByContentId] at the same instant.** Consequently
 * `currentByIdentity.size <= recordsByContentId.size <= maxTracked` always holds - a flood of many
 * DISTINCT, freshly-generated identities (each publishing exactly one record, no per-identity
 * replacement happening) is bounded by [maxTracked] exactly like every sibling index's flood
 * defense, see `PeerRecordSpoofingTest`'s case (d).
 *
 * **The anti-rollback high-water mark, [highestSequenceByIdentity], deliberately uses a SEPARATE
 * eviction lifecycle from [currentByIdentity]'s, on a SEPARATE, larger cap - this is a V0.8.1
 * sub-wave security fix, not part of the original design (round 1), later hardened again (round
 * 2, see that field's own doc comment).** The doc-comment claim two paragraphs up ("a record with
 * a LOWER sequence number... is rejected outright") does NOT hold if it is checked only against
 * [currentByIdentity]: `removeEldestEntry` below clears an identity's [currentByIdentity] entry
 * the moment its record is evicted from [recordsByContentId] (e.g. a flood of freshly-fabricated
 * identities pushes it out past [maxTracked]), and once that happens [currentByIdentity] has no
 * high-water mark left to compare a replayed OLD record against - `canAccept`/`add` would then
 * accept ANY sequence number for that identity, including one already superseded, a genuine state
 * ROLLBACK of that identity's advertised addresses/capabilities/TTL to attacker-chosen (or merely
 * stale) older content. [highestSequenceByIdentity] fixes this by tracking the highest accepted
 * sequence number per identity in a structure sized and evicted independently of
 * [recordsByContentId]'s own churn - see [highestSequenceByIdentity]'s own doc comment for the
 * LRU-evicting shape and the accepted, bounded tradeoff once even ITS separate, larger cap is
 * reached.
 *
 * TTL ([PeerRecord.notValidAfterEpochSecond]) is NEVER consulted here - this index makes zero
 * clock calls anywhere, add/canAccept/current all included. Expiry is a pure READ-time filter, see
 * [PeerDirectoryGossip.lookup].
 */
class PeerRecordIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_RECORDS,
    private val maxPersisted: Int = MAX_PERSISTED_RECORDS,
    private val maxHighWaterMarks: Int = MAX_HIGH_WATER_MARKS,
) {
    /** Public entry point - always uses [MAX_TRACKED_RECORDS]/[MAX_PERSISTED_RECORDS]/
     * [MAX_HIGH_WATER_MARKS]. The internal constructor above exists purely as a test seam,
     * mirroring `VeritasGrantIndex`'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_RECORDS, MAX_PERSISTED_RECORDS, MAX_HIGH_WATER_MARKS)

    /** The current (highest-sequence-number, tie-broken deterministically) record per identity -
     * every value here is also a value in [recordsByContentId], see this class's doc comment. */
    private val currentByIdentity = HashMap<Secp256k1PublicKey, PeerRecord>()

    /** Backed by a [LinkedHashMap] with access-order tracking enabled, mirroring
     * `VeritasGrantIndex.grantsByContentId`/`InboxIndex.messagesByContentId` exactly - see those
     * fields' doc comments for why this is FIFO-equivalent in practice, not true LRU. */
    private val recordsByContentId =
        object : LinkedHashMap<PeerRecordContentId, PeerRecord>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerRecordContentId, PeerRecord>): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                if (currentByIdentity[evicted.identity] == evicted) currentByIdentity.remove(evicted.identity)
                return true
            }
        }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * `VeritasGrantIndex.persistedContentIds` exactly.
     *
     * **Permanent, one-shot, non-evicting cap - deliberately NOT converted to the same LRU-evicting
     * shape as [highestSequenceByIdentity] (V0.8.1 sub-wave audit round 2, minor finding 4,
     * evaluated and left as-is).** A single flood of [maxPersisted] legitimately signed,
     * binding-valid, possession-proven fabricated records permanently exhausts this reservation set
     * for the process lifetime, after which this node durably persists NO further peer record -
     * durability-only degradation, not a security-property break like finding 2's, which is why
     * this is accepted rather than blocking. Unlike [highestSequenceByIdentity] (where LRU eviction
     * restores a security PROPERTY - anti-rollback - without weakening any other guarantee this map
     * makes), evicting HERE would remove the one thing this set exists to bound: total
     * `NabuStorage.put()` calls over this node's lifetime. LRU-evicting an old reservation just to
     * admit a new one means the SAME already-evicted content id can be re-persisted later
     * (`storage.put` is idempotent, so no corruption results) - but a SUSTAINED flood could then
     * keep evicting and re-admitting forever, reintroducing unbounded total disk writes, which is
     * the exact risk this cap exists to prevent. The current hard, permanent cap is the safer
     * failure mode of the two: this node stops accepting NEW durable writes rather than accepting
     * unboundedly many over time. See [tryReservePersistence]'s doc comment for the mirrored
     * `VeritasGrantIndex` precedent this follows. */
    private val persistedContentIds = HashSet<PeerRecordContentId>()

    /** The highest [PeerRecord.sequenceNumber] ever ACCEPTED (via [add]) for each identity - the
     * anti-rollback high-water mark. A SEPARATE map from [currentByIdentity]: the latter is allowed
     * to lose an identity's entry the moment [recordsByContentId] evicts it (see this class's doc
     * comment on that eviction policy), but the anti-rollback PROPERTY this index claims must
     * survive that eviction - see this class's doc comment for the concrete replay this closes.
     *
     * **LRU-evicting, access-order [LinkedHashMap], capped at [maxHighWaterMarks] - deliberately
     * DECOUPLED from [maxTracked], and deliberately EVICTING rather than a permanent, non-evicting
     * lockout (V0.8.1 sub-wave audit round 2, major finding 2 fix; before this fix, this was a
     * plain, never-evicting [HashMap], gated at [maxTracked] instead of its own cap).** The
     * round-1 fix's non-evicting `HashMap` closed the ORIGINAL reported scenario (a flood evicting
     * an ALREADY-high-water-marked identity from [currentByIdentity]) but left an EQUIVALENT path
     * open: because that map never evicted and was admission-gated at a fixed size, once
     * [maxTracked] DISTINCT identities had EVER been observed (attacker-driven, or simply organic
     * growth on a long-running node), every identity arriving AFTER that point never got a
     * high-water mark AT ALL, for the remaining lifetime of the process - not a temporary
     * degradation but a PERMANENT one, and reachable with no attacker at all. The auditor's PROBE C
     * demonstrated this end to end through the real gossip validator: flood first to fill the
     * cap, THEN the genuine victim's record arrives and is accepted/indexed but never
     * high-water-marked, a later flood evicts it from [currentByIdentity] too, and a replayed OLD
     * record for that same identity is then accepted - `ROLLBACK SUCCEEDS`.
     *
     * Converting to an LRU-evicting map fixes the ADMISSION side of that finding directly: once
     * this map is full, a NEW identity's arrival evicts the LEAST-recently-touched existing entry
     * (typically a DORMANT, one-off flood identity that was never seen again) rather than being
     * refused a slot outright - so a victim arriving after a flood still gets high-water-mark
     * protection. [maxHighWaterMarks] is deliberately SIZED LARGER than [maxTracked] (rather than
     * sharing the same cap) precisely so that this map's own eviction lags behind
     * [recordsByContentId]'s churn - an identity that is STILL the one tracked in
     * [currentByIdentity] should, in the common case, also still have a live high-water mark here,
     * giving [add]'s `maxOf(existing, highWaterMark)` reference computation real redundancy instead
     * of both sides being evicted in lockstep by numerically-identical caps.
     *
     * **This does NOT make rollback protection unconditionally permanent for every identity ever
     * seen - an accepted, documented tradeoff, not a new gap.** A genuinely DORMANT identity
     * (high-water-marked once, never touched again) can still eventually be evicted by a
     * SUSTAINED-enough flood of subsequent distinct identities exceeding [maxHighWaterMarks] - but
     * this now requires ongoing flood volume rather than a ONE-TIME [maxHighWaterMarks]-sized flood
     * that then locks out EVERY future identity forever, and an identity that keeps receiving
     * fresh records (a normal [PeerPresenceAnnouncer] heartbeat, or even repeated replay attempts
     * targeting it) keeps refreshing its own recency via this map's access-order tracking and stays
     * protected far longer than a one-off entry would. See `PeerRecordSpoofingTest`'s case (h) and
     * `PeerRecordIndexTest`'s flood-before-victim regression for the concrete proof PROBE C's
     * scenario is closed. */
    private val highestSequenceByIdentity =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > maxHighWaterMarks
        }

    /**
     * Adds [record] to the index. Returns `true` iff it was newly added (including the
     * newer-sequence-number replacement case); `false` for an exact content-id duplicate, a
     * signature/binding-invalid record, or a stale-or-tie-break-losing sequence number for an
     * identity that already has a strictly-better-or-equal record tracked OR high-water-marked
     * (see [highestSequenceByIdentity]) - **never throws**, mirroring `VeritasGrantIndex.add`'s
     * "last line of defense before untrusted gossip data reaches this node's in-memory state"
     * contract, including the defensive re-verification of ALL THREE of [PeerRecord.verify],
     * [verifyBinding], AND [verifyPossession] (unlike every sibling index's single-signature
     * re-check - see [PeerRecord]'s class doc comment for why three checks are needed here).
     *
     * **All three checks are re-verified HERE, independently of whatever already ran in
     * [PeerDirectoryGossip.onGossipMessage] - V0.8.1 sub-wave audit round 3, major finding fix.**
     * Before this fix, [add] re-checked only [PeerRecord.verify] and [verifyBinding], leaving this
     * class's own doc-comment claim to be the "last line of defense" false: a record built exactly
     * like `PeerRecordSpoofingTest`'s case (h) (a FRESH, self-consistent [IdentityBinding] the
     * attacker mints over a victim's public Ed25519 key, genuinely self-signed) passed both
     * remaining checks and was tracked, becoming `current` for the victim's identity and resolving
     * `.peerId` to the victim's real, derivable `PeerId` - even though
     * [PeerDirectoryGossip.onGossipMessage] itself already blocks this shape with its own
     * [verifyPossession] call, because [add] is public API reached by other paths that never run
     * that validator: [PeerDirectoryGossip.announce] calls [add] with NO verification of its own at
     * all, and [PeerRecord.fromDecoded]/[PeerRecordCodec.decode] both explicitly produce unverified
     * records. See `PeerRecordIndexTest`'s possession-invalid regression for the direct proof.
     */
    @Synchronized
    fun add(record: PeerRecord): Boolean =
        runCatching {
            if (!PeerRecord.verify(record)) return@runCatching false
            if (!record.verifyBinding()) return@runCatching false
            if (!record.verifyPossession()) return@runCatching false

            val id = PeerRecordContentId(record.contentId())
            if (recordsByContentId.containsKey(id)) return@runCatching false

            val existing = currentByIdentity[record.identity]
            // The reference point for the rollback check is the HIGHER of the two: the live
            // tracked record's sequence number (may be absent if never seen) and the high-water
            // mark (may be absent only if this identity's first-ever record arrived after
            // [highestSequenceByIdentity]'s own cap was already full - see that field's doc
            // comment). In every other case the two are kept equal by this same function, so
            // `maxOf` is defense in depth, not load-bearing, EXCEPT precisely in that capped-out
            // case, where it correctly falls back to [existing] instead of silently accepting an
            // unbounded rollback for an identity this map failed to track.
            val highWaterMark = highestSequenceByIdentity[record.identity]
            val referenceSequence = maxOf(existing?.sequenceNumber ?: Long.MIN_VALUE, highWaterMark ?: Long.MIN_VALUE)
            if (referenceSequence > Long.MIN_VALUE) {
                val cmp = referenceSequence.compareTo(record.sequenceNumber)
                if (cmp > 0) return@runCatching false // strictly stale/rollback - reject outright
                if (cmp == 0) {
                    // A tie against the reference sequence number can only be broken
                    // deterministically if the actual winning record's content id is still known -
                    // i.e. [existing] is still tracked AND really is the record that set the
                    // reference. If the true winner was evicted from [currentByIdentity] (only the
                    // high-water mark survived), there is nothing left to compare content ids
                    // against, so a same-sequence-number record is conservatively rejected as
                    // not-strictly-newer rather than risking a rollback to different content the
                    // identity happened to sign under the same sequence number.
                    if (existing == null || existing.sequenceNumber != referenceSequence) return@runCatching false
                    // An exact content-id duplicate was already rejected above, so record's
                    // content id is guaranteed different from existing's here - this compare can
                    // never be a literal tie, only "wins" or "loses" the deterministic tie-break.
                    val tiebreak = PeerRecordContentIdBytesComparator.compare(record.contentId(), existing.contentId())
                    if (tiebreak <= 0) return@runCatching false
                }
            }

            // Strictly newer sequence number, or wins the deterministic tie-break: supersede.
            if (existing != null) {
                recordsByContentId.remove(PeerRecordContentId(existing.contentId()))
            }

            recordsByContentId[id] = record
            currentByIdentity[record.identity] = record
            // Always write - unlike the round-1 fix's admission-gated HashMap, this map now
            // self-manages its own bound via removeEldestEntry (see this field's doc comment), so
            // there is no longer a reason to skip tracking a brand-new identity just because the
            // map happens to be at capacity.
            highestSequenceByIdentity[record.identity] = record.sequenceNumber
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check. `true` iff [record] is (a) not already
     * tracked by content id AND (b) not stale/tie-break-losing against whatever is currently
     * tracked for [record].identity - see this class's doc comment for why (b) is a NEW predicate
     * this index's `canAccept` needs that no sibling index's `canAccept` does (their winner is
     * decided purely by arrival order, so their `canAccept` only ever needs to predict exact
     * content-id duplication). Gating [PeerDirectoryGossip.onGossipMessage]'s persistence attempt
     * on this means a stale/rollback record costs this node no `NabuStorage.put()` call, not just
     * no index slot - see `PeerRecordSpoofingTest`'s case (b).
     *
     * Narrow race, same shape and same acceptance as every sibling index: [canAccept] and [add] are
     * two separate `@Synchronized` lock acquisitions, so a concurrent gossip delivery of an even
     * newer record for the same identity between the two calls can make THIS record stale by the
     * time [add] runs, even though [canAccept] returned `true` moments earlier. [add] still handles
     * that correctly (returns `false`), and
     * [net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip.onGossipMessage] still returns
     * `Valid` in that case - the record was legitimately well-formed and correctly-ordered at the
     * moment it was checked, and propagating it is harmless (every other node applies the identical
     * ordering rule and converges the same way).
     */
    @Synchronized
    fun canAccept(record: PeerRecord): Boolean {
        val id = PeerRecordContentId(record.contentId())
        if (recordsByContentId.containsKey(id)) return false
        val existing = currentByIdentity[record.identity]
        // See [add]'s identical `referenceSequence` computation for why this must consult
        // [highestSequenceByIdentity] as well as [existing], not [existing] alone - this mirrors
        // [add]'s admission decision exactly, as its own doc comment promises.
        val highWaterMark = highestSequenceByIdentity[record.identity]
        val referenceSequence = maxOf(existing?.sequenceNumber ?: Long.MIN_VALUE, highWaterMark ?: Long.MIN_VALUE)
        if (referenceSequence == Long.MIN_VALUE) return true
        val cmp = referenceSequence.compareTo(record.sequenceNumber)
        if (cmp > 0) return false
        if (cmp == 0) {
            if (existing == null || existing.sequenceNumber != referenceSequence) return false
            return PeerRecordContentIdBytesComparator.compare(record.contentId(), existing.contentId()) > 0
        }
        return true
    }

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [recordsByContentId]'s evicting
     * cap. Mirrors `VeritasGrantIndex.tryReservePersistence`'s contract exactly, including atomic
     * reserve-before-put semantics and idempotency per content id.
     */
    @Synchronized
    fun tryReservePersistence(record: PeerRecord): Boolean {
        val id = PeerRecordContentId(record.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** The current (latest-by-sequence-number) record for [identity], regardless of whether it has
     * expired - TTL filtering happens ONLY in [PeerDirectoryGossip.lookup], never here. `internal`:
     * only [PeerDirectoryGossip] (same module) and this module's own tests need read access. */
    @Synchronized
    internal fun current(identity: Secp256k1PublicKey): PeerRecord? = currentByIdentity[identity]

    /** Every distinct identity with at least one tracked record. */
    @Synchronized
    internal fun allIdentities(): Set<Secp256k1PublicKey> = currentByIdentity.keys.toSet()

    /** Number of currently content-id-tracked records (`<= maxTracked` always) - a test-visibility
     * accessor, mirrors `net.lapisphilosophorum.lapisnet.mail.InboxIndex.size`. */
    @Synchronized
    internal fun size(): Int = recordsByContentId.size

    companion object {
        /** Upper bound on distinct records tracked from gossip. A [PeerRecord]'s encoded size is
         * comparable to a Veritas grant's (both small, well under 5 KB worst case) - reusing the
         * same Dunbar's-number-scale magnitude
         * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.MAX_TRACKED_GRANTS` documents,
         * not `net.lapisphilosophorum.lapisnet.mail.InboxIndex`'s smaller 8,000 (mail blobs are
         * ~25x larger). Same provisional-magnitude caveat as every sibling cap: chosen for parity
         * with existing precedent, not derived from real pilot usage data. */
        const val MAX_TRACKED_RECORDS = 64_000

        /** Upper bound on distinct records this node will durably persist via `NabuStorage.put()`
         * from gossip - see [tryReservePersistence] and `VeritasGrantIndex.MAX_PERSISTED_GRANTS`'s
         * doc comment for the full reasoning this mirrors. */
        const val MAX_PERSISTED_RECORDS = 64_000

        /** Upper bound on distinct identities [highestSequenceByIdentity] LRU-tracks - see that
         * field's doc comment for the round-2 audit fix this is part of. Deliberately DOUBLE
         * [MAX_TRACKED_RECORDS] rather than sharing the same value: giving the high-water map
         * genuine reserve capacity beyond [recordsByContentId]'s own churn means an identity that
         * is still the CURRENT tracked record for [currentByIdentity] also, in the common case,
         * still has a live entry here - the two caps are no longer numerically identical, so a
         * flood sized to overwhelm one does not automatically overwhelm the other in lockstep. */
        const val MAX_HIGH_WATER_MARKS = 128_000
    }
}
