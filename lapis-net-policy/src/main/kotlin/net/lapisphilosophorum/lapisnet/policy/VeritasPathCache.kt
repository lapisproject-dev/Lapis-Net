package net.lapisphilosophorum.lapisnet.policy

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder

/**
 * Memoizes [AcceptanceGateEvaluator.veritasPathCheck]'s verdict per `(localIdentity, candidate)`
 * pair - extracted verbatim from `lapis-net-mail`'s `MailAcceptanceCheck` (V0.9.4 hardening; see
 * that class's own history for the full "13.8-16.1 ms/call BFS on the gossip hot path" finding this
 * closes) so `lapis-net-dm`'s `DmAcceptanceCheck` gets the identical mitigation without duplicating
 * the cache logic.
 *
 * Safe to memoize indefinitely for THIS instance's lifetime, never invalidated in place: [trustGraph]
 * is an immutable, already-built snapshot. The documented way a caller reflects trust-graph evolution
 * is constructing a brand NEW owning object (`MailAcceptanceCheck`/`DmAcceptanceCheck`) - and
 * therefore a brand new [VeritasPathCache] - with a fresh [trustGraph], never mutating an existing
 * instance's graph in place.
 *
 * **Original V0.9.4 round-2 security-audit finding this class exists to close** (carried forward
 * verbatim from `MailAcceptanceCheck`'s pre-V0.8.6 `veritasPathCache` field, which this class
 * replaces): `TrustPathFinder.findPath`'s BFS was benchmarked at 13.8-16.1 ms/call on an
 * adversarial, near-cap trust graph. Paid on every single inbound gossip message with no cache at
 * all, that is enough to let a modest message flood pin a CPU core - hence memoizing the verdict
 * per `(localIdentity, candidate)` pair, since the graph itself is immutable for this instance's
 * lifetime and the BFS result for a given pair can never change without a new [trustGraph].
 *
 * **What this DOES mitigate**: repeated messages from the SAME already-seen candidate identity -
 * after the first BFS, every subsequent message from that candidate is an O(1) map lookup instead
 * of a fresh BFS.
 *
 * **What this does NOT mitigate: a flood of many DISTINCT candidate identities** (e.g. a fresh
 * throwaway keypair per message). Each distinct candidate still pays exactly one BFS the first time
 * it is seen - the memoization only helps once a candidate repeats. A node under sustained attack
 * from a stream of never-repeating throwaway identities gets no CPU relief from this cache alone; it
 * needs a gate that is cheap to evaluate for a NEVER-before-seen identity, such as `KarmaThreshold`
 * (a local score lookup, not a graph traversal) used ahead of `VeritasPath` in the gate ordering, or
 * some other admission control that does not require the graph walk at all.
 *
 * **Bounded, in addition to memoized (V0.8.6 hardening-pass finding)**: an unbounded map keyed on an
 * attacker-controlled `candidate` identity is itself a distinct, unbounded-heap-growth denial-of-
 * service vector, independent of the BFS-cost problem above - it is exactly the flood of distinct
 * throwaway identities described in "what this does NOT mitigate" above that also leaves one
 * permanent, never-evicted entry per identity if the map has no cap. [MAX_TRACKED_ENTRIES] plus
 * access-order LRU eviction (mirroring `DmAcceptedContacts`'s identical bound in `lapis-net-dm`,
 * whose own cache is keyed on an equally attacker-controlled peer identity) caps the memory this
 * cache can be made to consume, at the cost of a legitimate, still-relevant candidate's verdict
 * occasionally being evicted and recomputed - an acceptable trade given the alternative is
 * unbounded growth toward OOM.
 */
class VeritasPathCache(
    val trustGraph: TrustGraph,
    private val maxTrackedEntries: Int = MAX_TRACKED_ENTRIES,
) {
    private val cache =
        object : LinkedHashMap<CacheKey, Boolean>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<CacheKey, Boolean>): Boolean =
                size > maxTrackedEntries
        }

    /** A cached equivalent of `AcceptanceGateEvaluator.veritasPathCheck(trustGraph, localIdentity)` -
     * same verdict, backed by this cache instead of a fresh [TrustPathFinder] BFS on every
     * invocation. The backing [LinkedHashMap] is access-ordered for LRU eviction, which mutates it
     * on reads too, so every actual map access is `@Synchronized` (mirroring `DmAcceptedContacts`'s
     * identical choice) - but see [checkPair]'s own doc comment for why the expensive BFS itself
     * deliberately runs OUTSIDE that lock. */
    fun checkFor(localIdentity: Secp256k1PublicKey): (Secp256k1PublicKey) -> Boolean =
        { candidate -> checkPair(localIdentity, candidate) }

    /** **V0.8.6 hardening-pass finding: the BFS runs OUTSIDE the map lock, not inside it.** An
     * earlier version of this function held the single instance monitor (via a single
     * `@Synchronized` method body) for the ENTIRE cache-miss path, including
     * [TrustPathFinder.trustMicros]'s BFS - benchmarked at 13.8-16.1 ms/call on an adversarial,
     * near-cap trust graph (see this class's own class doc comment). Because this method is called
     * from multiple concurrent gossip-handling threads (and, per [DmAcceptanceCheck]'s wiring, from
     * both `MailboxGossip`'s validator thread AND `DmSessionManager`'s Netty event-loop thread), a
     * stream of never-repeating throwaway candidate identities - each one a guaranteed cache miss -
     * would serialize every caller on that BFS, turning an already-expensive-per-candidate cost
     * into a queue that blocks unrelated messages/connections behind it.
     *
     * The fix: look up the verdict under the lock (cheap), release the lock, run the BFS lock-free,
     * then take the lock again just to record the result. [TrustPathFinder.trustMicros] is a pure
     * function of an immutable [trustGraph] (see this class's own class doc comment), so if two
     * threads race on the same never-before-seen `(localIdentity, candidate)` pair, both simply
     * recompute the identical verdict and one of the two writes is redundant - never incorrect,
     * never lost, never inconsistent. That harmless double-computation is a strictly better trade
     * than serializing unrelated callers behind a 13-16 ms lock hold. */
    private fun checkPair(
        localIdentity: Secp256k1PublicKey,
        candidate: Secp256k1PublicKey,
    ): Boolean {
        val key = CacheKey(localIdentity, candidate)
        lookup(key)?.let { return it }
        val verdict = TrustPathFinder.trustMicros(trustGraph, localIdentity, candidate) > MIN_TRUST_MICROS
        record(key, verdict)
        return verdict
    }

    @Synchronized
    private fun lookup(key: CacheKey): Boolean? = cache[key]

    @Synchronized
    private fun record(
        key: CacheKey,
        verdict: Boolean,
    ) {
        cache[key] = verdict
    }

    /** Test-visibility passthrough to the current number of tracked `(localIdentity, candidate)`
     * entries - lets a test prove the [MAX_TRACKED_ENTRIES] bound holds without depending on
     * [LinkedHashMap] internals. */
    @Synchronized
    internal fun sizeForTest(): Int = cache.size

    /** Keyed on BOTH [localIdentity] and [candidate] - see `MailAcceptanceCheck`'s original
     * `VeritasPathCacheKey` doc comment for why this costs nothing and closes an entire class of
     * "cache poisoned by a second identity" bugs by construction. */
    private data class CacheKey(
        val localIdentity: Secp256k1PublicKey,
        val candidate: Secp256k1PublicKey,
    )

    companion object {
        /** Generous headroom, provisional magnitude - same "not derived from pilot data" framing as
         * `DmAcceptedContacts.MAX_TRACKED_ACCEPTED_CONTACTS`, whose value this mirrors: both cap a
         * cache keyed on an attacker-controlled identity. */
        const val MAX_TRACKED_ENTRIES = 4_096
    }
}
