package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey

/** Wraps a [PrekeyBundle.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - mirrors [PeerRecordContentId] exactly, duplicated locally for the same
 * module-boundary reason that class documents. Internal: only [PrekeyBundleIndex] needs this. */
internal data class PrekeyBundleContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is PrekeyBundleContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/** Unsigned lexicographic byte-order comparator over content-id byte arrays - the deterministic
 * tie-break for two bundles sharing the same [PrekeyBundle.identity] and the same
 * [PrekeyBundle.sequenceNumber]. Mirrors [PeerRecordContentIdBytesComparator]'s identical shape. */
private object PrekeyBundleContentIdBytesComparator : Comparator<ByteArray> {
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
 * Bounded, in-memory index of [PrekeyBundle]s received (locally created or via gossip), latest-wins
 * per [PrekeyBundle.identity] by [PrekeyBundle.sequenceNumber] - structurally the same ordering rule
 * [PeerRecordIndex] established for `PeerRecord` (V0.8.1), reapplied here verbatim rather than
 * reinvented: an evicting in-memory tracking cap ([bundlesByContentId]), a SEPARATE, non-evicting,
 * hard-capped persistence-reservation cap ([persistedContentIds]/[tryReservePersistence]), and a
 * THIRD, independently-sized, LRU-evicting anti-rollback high-water-mark cap
 * ([highestSequenceByIdentity]) - see [PeerRecordIndex]'s own class doc comment for the full
 * round-1/round-2 audit history this structure is copied from, already hardened.
 *
 * **[add] independently re-verifies all THREE of [PrekeyBundle.verify], [verifyEncryptionBinding],
 * and [verifySignedPrekey]** - regardless of whatever already ran in
 * [PrekeyBundleGossip.onGossipMessage] - for the exact reason [PeerRecordIndex.add]'s own doc
 * comment gives: `add` is public API reachable via [PrekeyBundleGossip.announce] (no verification of
 * its own) and via [PrekeyBundle.fromDecoded]/decode (explicitly unverified), so it must be the last
 * line of defense on its own.
 *
 * TTL ([PrekeyBundle.notValidAfterEpochSecond]) is NEVER consulted by [add]/[canAccept]/[current] -
 * admission and lookup decisions in this index make zero clock calls. Expiry is a pure READ-time
 * filter, see [PrekeyBundleGossip.lookup] and [evictExpired].
 */
class PrekeyBundleIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_BUNDLES,
    private val maxPersisted: Int = MAX_PERSISTED_BUNDLES,
    private val maxHighWaterMarks: Int = MAX_HIGH_WATER_MARKS,
) {
    /** Public entry point - always uses [MAX_TRACKED_BUNDLES]/[MAX_PERSISTED_BUNDLES]/
     * [MAX_HIGH_WATER_MARKS]. The internal constructor above exists purely as a test seam, mirroring
     * [PeerRecordIndex]'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_BUNDLES, MAX_PERSISTED_BUNDLES, MAX_HIGH_WATER_MARKS)

    /** The current (highest-sequence-number, tie-broken deterministically) bundle per identity -
     * every value here is also a value in [bundlesByContentId]. */
    private val currentByIdentity = HashMap<Secp256k1PublicKey, PrekeyBundle>()

    /** Backed by a [LinkedHashMap] with access-order tracking enabled - mirrors
     * [PeerRecordIndex]'s `recordsByContentId` exactly. */
    private val bundlesByContentId =
        object : LinkedHashMap<PrekeyBundleContentId, PrekeyBundle>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<PrekeyBundleContentId, PrekeyBundle>,
            ): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                if (currentByIdentity[evicted.identity] == evicted) currentByIdentity.remove(evicted.identity)
                return true
            }
        }

    /** Permanent, one-shot, non-evicting persistence-reservation cap - mirrors
     * [PeerRecordIndex]'s `persistedContentIds` exactly, including its accepted
     * durability-only-degradation tradeoff. */
    private val persistedContentIds = HashSet<PrekeyBundleContentId>()

    /** LRU-evicting, access-order anti-rollback high-water mark - mirrors [PeerRecordIndex]'s
     * `highestSequenceByIdentity` exactly, including its round-2-hardened admission-side fix. */
    private val highestSequenceByIdentity =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > maxHighWaterMarks
        }

    /**
     * Adds [bundle] to the index. Returns `true` iff newly added (including a newer-sequence-number
     * replacement); `false` for an exact content-id duplicate, a signature/binding/signed-prekey-
     * invalid bundle, or a stale-or-tie-break-losing sequence number - never throws. See this
     * class's doc comment for why all three cryptographic checks are re-verified here.
     */
    @Synchronized
    fun add(bundle: PrekeyBundle): Boolean =
        runCatching {
            if (!PrekeyBundle.verify(bundle)) return@runCatching false
            if (!bundle.verifyEncryptionBinding()) return@runCatching false
            if (!bundle.verifySignedPrekey()) return@runCatching false

            val id = PrekeyBundleContentId(bundle.contentId())
            if (bundlesByContentId.containsKey(id)) return@runCatching false

            val existing = currentByIdentity[bundle.identity]
            val highWaterMark = highestSequenceByIdentity[bundle.identity]
            val referenceSequence = maxOf(existing?.sequenceNumber ?: Long.MIN_VALUE, highWaterMark ?: Long.MIN_VALUE)
            if (referenceSequence > Long.MIN_VALUE) {
                val cmp = referenceSequence.compareTo(bundle.sequenceNumber)
                if (cmp > 0) return@runCatching false
                if (cmp == 0) {
                    if (existing == null || existing.sequenceNumber != referenceSequence) return@runCatching false
                    val tiebreak =
                        PrekeyBundleContentIdBytesComparator.compare(
                            bundle.contentId(),
                            existing.contentId(),
                        )
                    if (tiebreak <= 0) return@runCatching false
                }
            }

            if (existing != null) {
                bundlesByContentId.remove(PrekeyBundleContentId(existing.contentId()))
            }

            bundlesByContentId[id] = bundle
            currentByIdentity[bundle.identity] = bundle
            highestSequenceByIdentity[bundle.identity] = bundle.sequenceNumber
            true
        }.getOrDefault(false)

    /** Cheap, no-I/O admission pre-check - mirrors [PeerRecordIndex.canAccept]'s identical contract
     * and its documented not-fully-non-mutating access-order-map caveat. */
    @Synchronized
    fun canAccept(bundle: PrekeyBundle): Boolean {
        val id = PrekeyBundleContentId(bundle.contentId())
        if (bundlesByContentId.containsKey(id)) return false
        val existing = currentByIdentity[bundle.identity]
        val highWaterMark = highestSequenceByIdentity[bundle.identity]
        val referenceSequence = maxOf(existing?.sequenceNumber ?: Long.MIN_VALUE, highWaterMark ?: Long.MIN_VALUE)
        if (referenceSequence == Long.MIN_VALUE) return true
        val cmp = referenceSequence.compareTo(bundle.sequenceNumber)
        if (cmp > 0) return false
        if (cmp == 0) {
            if (existing == null || existing.sequenceNumber != referenceSequence) return false
            return PrekeyBundleContentIdBytesComparator.compare(bundle.contentId(), existing.contentId()) > 0
        }
        return true
    }

    /** Admission gate purely for durable persistence - mirrors [PeerRecordIndex.tryReservePersistence]
     * exactly, including atomic reserve-before-put semantics and idempotency per content id. */
    @Synchronized
    fun tryReservePersistence(bundle: PrekeyBundle): Boolean {
        val id = PrekeyBundleContentId(bundle.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** The current (latest-by-sequence-number) bundle for [identity], regardless of expiry - TTL
     * filtering happens ONLY in [PrekeyBundleGossip.lookup]. `internal`: only [PrekeyBundleGossip]
     * (same module) and this module's own tests need read access. */
    @Synchronized
    internal fun current(identity: Secp256k1PublicKey): PrekeyBundle? = currentByIdentity[identity]

    /** Every distinct identity with at least one tracked bundle. */
    @Synchronized
    internal fun allIdentities(): Set<Secp256k1PublicKey> = currentByIdentity.keys.toSet()

    /** Number of currently content-id-tracked bundles (`<= maxTracked` always). */
    @Synchronized
    internal fun size(): Int = bundlesByContentId.size

    /** Actively removes every tracked bundle whose [PrekeyBundle.notValidAfterEpochSecond] is
     * strictly before [nowEpochSecond] - mirrors [PeerRecordIndex.evictExpired]'s identical
     * memory-hygiene-only contract and its identical "does not touch the high-water mark or the
     * persistence reservations" invariants. Returns the number of bundles evicted. */
    @Synchronized
    fun evictExpired(nowEpochSecond: Long): Int {
        var evictedCount = 0
        val iterator = bundlesByContentId.entries.iterator()
        while (iterator.hasNext()) {
            val bundle = iterator.next().value
            if (bundle.notValidAfterEpochSecond < nowEpochSecond) {
                iterator.remove()
                if (currentByIdentity[bundle.identity] == bundle) currentByIdentity.remove(bundle.identity)
                evictedCount++
            }
        }
        return evictedCount
    }

    companion object {
        /** A [PrekeyBundle]'s worst-case encoded size (3,917 bytes) is the same order of magnitude
         * as a [PeerRecord]'s (4,346 bytes) - reusing [PeerRecordIndex.MAX_TRACKED_RECORDS]'s
         * identical Dunbar's-number-scale magnitude, same provisional-magnitude caveat. */
        const val MAX_TRACKED_BUNDLES = 64_000

        /** See [PeerRecordIndex.MAX_PERSISTED_RECORDS]'s doc comment for the identical reasoning
         * this mirrors. */
        const val MAX_PERSISTED_BUNDLES = 64_000

        /** Deliberately DOUBLE [MAX_TRACKED_BUNDLES], same reasoning as
         * [PeerRecordIndex.MAX_HIGH_WATER_MARKS]'s doc comment. */
        const val MAX_HIGH_WATER_MARKS = 128_000
    }
}
