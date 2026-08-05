package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder
import java.util.concurrent.ConcurrentHashMap

/**
 * Bundles everything [InboxGossip.onGossipMessage] needs to run [MailAcceptancePolicy.shouldAccept]
 * as an optional, pluggable check - see that validator's own doc comment for the insertion point
 * and ordering guarantee. `null` (the default in [InboxGossip.attach]) means no check runs at all,
 * preserving every prior V0.9.x wave's "accept everything addressed to me" behavior exactly -
 * functionally identical to passing a non-null instance configured with
 * [MailAcceptancePolicy.ACCEPT_ALL] (empty [gates]). **As of the V0.9.4 hardening pass, the two are
 * also equally CHEAP**: `InboxGossip.onGossipMessage` special-cases `acceptance.gates.isEmpty()`
 * before ever calling [depositLookup] or [MailAcceptancePolicy.shouldAccept] - see that function's
 * doc comment for the round-2 security audit finding this closes (an empty-gates, non-null
 * [MailAcceptanceCheck] used to still pay [depositLookup]'s cost on every message, because Kotlin
 * evaluates call arguments eagerly regardless of what the callee does with them).
 *
 * [trustGraph] is an already-built, already-locally-held [TrustGraph] snapshot - see
 * `net.lapisphilosophorum.lapisnet.trust.TrustGraph`'s own doc comment: building it is the
 * caller's job (typically from a `VeritasGrantIndex`'s resolved edges), never this validator's.
 * Re-supplying a fresh instance as the local node's trust state evolves is the caller's
 * responsibility - [InboxGossip.onGossipMessage] only ever reads whatever [trustGraph] the caller
 * handed it for that one gossip message, never fetches or refreshes it itself (the "zero
 * clock/network calls in the validator" rule this module's classes all share).
 *
 * [depositLookup] is a pure, local, no-I/O function from an already-decoded [MessageEnvelope] to
 * a [FirstContactDeposit] the caller already holds for it, or `null` if none is available. **The
 * deposit itself does NOT travel in-band over `MailFrameCodec`'s wire format this wave** - a
 * deliberate scope cut, consistent with this whole mechanism's "obtained out-of-band"/"manual,
 * application-layer decision" cuts (see [FirstContactDeposit]'s class doc comment): a real
 * deployment would populate a small local map (envelope content id -> deposit) once its
 * application layer observes an out-of-band Lightning payment settle, and this lambda is that
 * lookup. A future wave that extends `MailFrameCodec`/`MessageEnvelopeCodec` to carry a deposit
 * on the wire can supply this same lambda backed by the decoded frame instead, without
 * [MailAcceptancePolicy]/[InboxGossip] changing at all.
 *
 * [minDepositMsat] is the per-node floor [MailAcceptancePolicy.shouldAccept] enforces on top of
 * [FirstContactDepositVerifier.verify]'s structural self-consistency check - see
 * [MailAcceptancePolicy.DEFAULT_MIN_DEPOSIT_MSAT]'s doc comment for why a floor is needed at all
 * (round-2 security audit finding, V0.9.4 hardening).
 */
class MailAcceptanceCheck(
    val gates: List<MailAcceptanceGate>,
    val trustGraph: TrustGraph,
    val karmaScoreOf: KarmaScoreLookup,
    val minDepositMsat: Long = MailAcceptancePolicy.DEFAULT_MIN_DEPOSIT_MSAT,
    val depositLookup: (MessageEnvelope) -> FirstContactDeposit? = { null },
) {
    /**
     * Memoizes [MailAcceptancePolicy.veritasPathCheck]'s verdict per `(localIdentity, candidate)`
     * pair, backed by [ConcurrentHashMap] (this instance's single [trustGraph]/`veritasPathCache`
     * pair is shared across every concurrent GossipSub validator invocation `InboxGossip.attach`
     * wires it into - see `InboxGossip.onGossipMessage`'s own concurrency note).
     *
     * **Round-2 security audit finding, V0.9.4 hardening: `TrustPathFinder.findPath`'s BFS,
     * newly added to the gossip validator hot path this wave, benchmarked at 13.8-16.1 ms/call on
     * an adversarial near-cap trust graph (~100-150x the ~0.1 ms ECDSA verify that precedes it in
     * `InboxGossip.onGossipMessage`) - a real DoS-amplification/throughput concern, though not a
     * crash/OOM risk (the BFS is itself bounded and deterministic, per [TrustPathFinder]'s own doc
     * comment on [net.lapisphilosophorum.lapisnet.trust.TrustGraph.MAX_NODES]/
     * `TrustGraph.MAX_EDGES`/`TrustPathFinder.MAX_HOP_DEPTH`).**
     *
     * This cache is what makes REPEAT queries against the same candidate cheap: any sender who has
     * already been resolved once against [trustGraph] (whether the verdict was `true` or `false`)
     * costs this node one `ConcurrentHashMap` lookup on every subsequent gossip message, not
     * another full BFS - directly mitigating a single sender flooding the same inbox topic
     * repeatedly, which is the common case for gossip-level spam.
     *
     * **What this does NOT mitigate: a flood of many DISTINCT candidate identities** (e.g. a fresh
     * throwaway keypair per message) - each first-seen candidate still costs exactly one BFS,
     * identical to the pre-cache cost, because there is nothing to memoize on a first lookup. This
     * is an accepted, documented limitation, not an oversight: per the finding above, the BFS
     * itself is bounded and deterministic (never unbounded/OOM), so a distinct-identity flood
     * degrades throughput proportionally to flood size rather than causing an outage - and
     * [MailAcceptanceGate.KarmaThreshold] (which this cache does not apply to; `karmaScoreOf` is
     * already assumed cheap, a pure caller-supplied lookup) remains available as a
     * cache-immune-by-construction alternative/complementary gate for a node operator who expects
     * exactly this attack shape.
     *
     * **Safe to memoize indefinitely for THIS instance's lifetime, never invalidated in place**:
     * [trustGraph] is an immutable, already-built snapshot (see this class's own doc comment) - the
     * documented way a caller reflects trust-graph evolution is constructing a brand NEW
     * [MailAcceptanceCheck] (and therefore a brand new, empty `veritasPathCache`) with a fresh
     * [trustGraph], never mutating an existing instance's graph in place. A stale cache is
     * therefore structurally impossible: the cache and the graph it was computed from always share
     * the same object lifetime.
     */
    private val veritasPathCache = ConcurrentHashMap<VeritasPathCacheKey, Boolean>()

    /**
     * A cached equivalent of `MailAcceptancePolicy.veritasPathCheck(trustGraph, localIdentity)` -
     * same verdict, backed by [veritasPathCache] instead of a fresh [TrustPathFinder] BFS on every
     * invocation. `internal`, not `private`: `InboxGossip.onGossipMessage` (same module) is the
     * only intended caller.
     */
    internal fun cachedVeritasPathCheck(localIdentity: Secp256k1PublicKey): (Secp256k1PublicKey) -> Boolean =
        { candidate ->
            veritasPathCache.computeIfAbsent(VeritasPathCacheKey(localIdentity, candidate)) {
                TrustPathFinder.trustMicros(trustGraph, localIdentity, candidate) > MIN_TRUST_MICROS
            }
        }

    /** [veritasPathCache]'s key - keyed on BOTH [localIdentity] and [candidate], not [candidate]
     * alone, even though a single [MailAcceptanceCheck] instance is expected in practice to be used
     * for exactly one `localIdentity` (one `InboxGossip.attach` call) for its whole lifetime:
     * nothing in this class's public shape enforces that one-to-one relationship, so keying on the
     * pair costs nothing and closes off an entire class of "cache poisoned by a second identity"
     * bugs by construction rather than by convention. */
    private data class VeritasPathCacheKey(
        val localIdentity: Secp256k1PublicKey,
        val candidate: Secp256k1PublicKey,
    )
}
