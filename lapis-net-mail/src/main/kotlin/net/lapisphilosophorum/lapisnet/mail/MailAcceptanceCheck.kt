package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.policy.VeritasPathCache
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

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
     * pair - closes the round-2 security audit finding that `TrustPathFinder.findPath`'s BFS,
     * benchmarked at 13.8-16.1 ms/call on an adversarial near-cap trust graph, is otherwise paid on
     * every gossip message. **V0.8.6: delegates to lapis-net-policy's [VeritasPathCache], which now
     * carries this field's full original doc comment (memoization reasoning, what it does and does
     * NOT mitigate, and why it is safe to memoize for this instance's lifetime) verbatim** - see
     * that class's own class doc comment, and this module's `build.gradle.kts` header for why the
     * extraction happened (`lapis-net-dm`'s `DmAcceptanceCheck` needs the identical memoization
     * without a dependency on `lapis-net-mail`).
     */
    private val veritasPathCache = VeritasPathCache(trustGraph)

    /**
     * A cached equivalent of `MailAcceptancePolicy.veritasPathCheck(trustGraph, localIdentity)` -
     * same verdict, backed by [veritasPathCache] instead of a fresh BFS on every invocation.
     * `internal`, not `private`: `InboxGossip.onGossipMessage` (same module) is the only intended
     * caller.
     */
    internal fun cachedVeritasPathCheck(localIdentity: Secp256k1PublicKey): (Secp256k1PublicKey) -> Boolean =
        veritasPathCache.checkFor(localIdentity)
}
