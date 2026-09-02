package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGateEvaluator
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

/**
 * Pull-based Karma-score lookup for a candidate sender, mirroring
 * `net.lapisphilosophorum.lapisnet.madli.MadliRoutingPolicy.orderPeers`'s injected
 * `madliOf: (PeerId) -> AggregatedMadli?` lambda and
 * `net.lapisphilosophorum.lapisnet.madli.MadliAggregator.aggregate`'s injected
 * `observerWeight: (Secp256k1PublicKey) -> Double` - the same "trust-free core, thin caller-side
 * adapter" discipline that module's `build.gradle.kts` documents. `lapis-net-karma` has no
 * existing notion of a single per-IDENTITY Karma score (its `KarmaWeightCalculator`/
 * `KarmaScoring` compute Karma per-CONTENT, folding votes toward one target `Cid`) - deriving a
 * sender's aggregate score from that (e.g. summing the personalized Karma of every CID a node
 * believes that sender authored) is an application-layer composition this wave deliberately does
 * NOT prescribe, so [MailAcceptancePolicy] takes the resulting number as an injected lookup
 * instead of depending on `lapis-net-karma` at all. See this module's `build.gradle.kts` header
 * comment for the full reasoning.
 */
fun interface KarmaScoreLookup {
    fun karmaScoreOf(sender: Secp256k1PublicKey): Double
}

/** [MailAcceptancePolicy.shouldAccept]'s result. [Reject.reason] is a short, human-readable,
 * non-sensitive description (which gate(s) failed) - safe to log, never derived from any
 * attacker-controlled envelope content. */
sealed interface MailAcceptanceDecision {
    data object Accept : MailAcceptanceDecision

    data class Reject(
        val reason: String,
    ) : MailAcceptanceDecision
}

/**
 * One opt-in acceptance gate a node operator may configure. [MailAcceptancePolicy.shouldAccept]
 * accepts a sender who passes AT LEAST ONE configured gate (OR semantics across
 * [MailAcceptanceGate]s) - a node running both [VeritasPath] and [KarmaThreshold] is offering a
 * sender two independent ways past the filter, matching the anti-spam intent of "let a stranger
 * through if they clear ANY bar I've set", not "clear every bar I've set".
 */
sealed interface MailAcceptanceGate {
    /** Reject a sender with no positive Veritas trust path from the local identity. */
    data object VeritasPath : MailAcceptanceGate

    /** Reject a sender whose [KarmaScoreLookup]-derived score is below [minScore]. */
    data class KarmaThreshold(
        val minScore: Double,
    ) : MailAcceptanceGate
}

/**
 * A pure, local, no-I/O acceptance policy for `InboxGossip` - mirrors
 * `net.lapisphilosophorum.lapisnet.madli.MadliRoutingPolicy`/`MadliReplicationPolicy`'s shape
 * exactly (see those objects' class doc comments): a plain function of already-resolved local
 * state, unit-testable without any network/gossip machinery.
 *
 * **Unlike Madli's policy objects (built V0.5, left unwired that wave), this wave's policy IS
 * wired into [InboxGossip.onGossipMessage]** - see [MailAcceptanceCheck] and that validator's own
 * doc comment for the insertion point.
 *
 * **The protocol-mandated default is "accept all" - filters are opt-in node policy, never
 * protocol-enforced.** A node that configures [ACCEPT_ALL] (the empty gate list) sees every
 * sender, exactly like every prior V0.9.x wave's `InboxGossip` behavior, unchanged. This mirrors
 * `MadliReplicationPolicies.NEVER`'s "the protocol itself does not mandate X" precedent and this
 * codebase's Layering doc (`docs/architecture.adoc`): Veritas/Karma are tools a VIEW may apply to
 * its own inbox, never a protocol requirement every participant must obey - a spammer with no
 * Veritas path and no Karma is still a fully valid protocol participant whose messages every
 * OTHER node (running no filters, or different filters) is free to accept.
 */
object MailAcceptancePolicy {
    /** The protocol-mandated default: no gates configured, every sender accepted (subject only to
     * the signature/addressing/CID-binding checks `InboxGossip.onGossipMessage` already runs
     * before this policy is ever consulted). */
    val ACCEPT_ALL: List<MailAcceptanceGate> = emptyList()

    /**
     * The default floor for [shouldAccept]'s [minDepositMsat] parameter - **a policy-level minimum
     * on top of [FirstContactDepositVerifier.verify]'s purely structural self-consistency check**
     * (round-2 security audit finding, V0.9.4 hardening). Without this floor, [verify] only proves
     * the invoice amount matches [FirstContactDeposit.requiredAmountMsat] byte-for-byte - it says
     * nothing about whether that amount is economically meaningful as an anti-spam deterrent. A
     * self-consistent, genuinely-settled 1-msat deposit passes [verify] just as validly as a
     * 1_000_000-msat one, so without a floor a spammer can mint a first-contact bypass for a cost
     * indistinguishable from free.
     *
     * `1_000_000` msat (1000 sat) is comfortably above the Lightning Network's conventional ~546-sat
     * dust limit (the smallest amount most nodes will even forward/settle) while remaining a modest,
     * genuinely-affordable cost for a legitimate stranger's first contact - the same "cheap for a
     * real sender, real friction for automated spam at scale" tradeoff the whole first-contact-
     * deposit mechanism is built on (see [FirstContactDeposit]'s class doc comment). Provisional, a
     * node operator's own economic call: exposed as a normal parameter (and, per-node, via
     * [MailAcceptanceCheck.minDepositMsat]) specifically so it can be tuned without touching this
     * object's code, mirroring [MailAcceptanceGate.KarmaThreshold.minScore]'s "policy is
     * configuration, not a hardcoded constant" precedent.
     */
    const val DEFAULT_MIN_DEPOSIT_MSAT: Long = 1_000_000L

    /**
     * `true` iff [candidate] has a POSITIVE Veritas trust score from [localIdentity] - the one
     * place [TrustGraph]/[TrustPathFinder] are referenced directly, mirroring
     * `MadliAggregator.veritasObserverWeight`'s identical "thin adapter, trust-free core" split
     * (see that function's doc comment and this module's `build.gradle.kts` header for the
     * precedent). Self (`candidate == localIdentity`) always passes, via [TrustPathFinder]'s own
     * self-trust axiom (`trustMicros` returns `MAX_TRUST_MICROS` for `source == target` before any
     * graph lookup).
     *
     * **Deliberately [TrustPathFinder.trustMicros] `>` [MIN_TRUST_MICROS], NOT
     * [TrustPathFinder.findPath] `!= null`** (path EXISTENCE) - the two are NOT equivalent.
     * [MIN_TRUST_MICROS] (0) is documented on `VeritasGrant` as both "default / active distrust"
     * AND "the value used to revoke a prior grant", and [TrustGraph.build] admits zero-weight
     * edges (only self-edges are dropped). `findPath` happily returns a non-null, zero-score
     * [net.lapisphilosophorum.lapisnet.trust.TrustPath] for a revoked/zero-weight edge - and for
     * any Sybil identity reachable only through one such edge - so an existence check would make
     * revoking trust in a spammer a no-op for this gate, and would let an entire Sybil cluster
     * through behind a single zero-weight hop. Requiring a strictly positive score matches
     * `MadliAggregator.veritasObserverWeight`'s own precedent (`observerWeight > 0.0` at
     * `MadliAggregator.kt`, filtering on `trustMicros`, not on path existence).
     */
    fun veritasPathCheck(
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
    ): (Secp256k1PublicKey) -> Boolean = AcceptanceGateEvaluator.veritasPathCheck(graph, localIdentity)

    /**
     * The accept/reject decision for [envelope], addressed to [recipient] (the local identity
     * running this check - see [FirstContactDepositVerifier.verify]'s `recipient` binding). The
     * sender is always [envelope].[MessageEnvelope.sender] - **deliberately not a separate
     * parameter** (round-2 security audit finding, V0.9.4 hardening): every real call site already
     * has the sender only by way of an [envelope] (`InboxGossip.onGossipMessage` derives it from
     * the decoded envelope, never from anywhere else), so a second, independently-suppliable
     * `sender: Secp256k1PublicKey` parameter sitting next to the equally-typed [recipient] was pure
     * footgun surface - nothing in the type system stops a future caller from transposing the two,
     * and the compiler cannot catch `shouldAccept(recipient, sender, ...)` written where
     * `shouldAccept(sender, recipient, ...)` was meant, silently checking gates against the WRONG
     * identity. Deriving the sender from [envelope] instead removes the swap entirely by removing
     * one of the two swappable parameters.
     *
     * Evaluated in this exact order:
     *
     *  1. **Empty [gates] ([ACCEPT_ALL]) always accepts** - the protocol-mandated default, checked
     *     first so a node running no filters pays no cost at all (no deposit verification, no
     *     Veritas/Karma lookups) for messages it was always going to accept anyway.
     *  2. **A [deposit] whose [FirstContactDeposit.requiredAmountMsat] is at least [minDepositMsat]
     *     AND that verifies (see [FirstContactDepositVerifier.verify]) always accepts, bypassing
     *     every configured gate** - that is the whole point of the first-contact deposit mechanism:
     *     an unknown sender who paid ENOUGH gets through even with every gate configured and
     *     failing. The amount floor is checked first, before the (comparatively expensive) real
     *     BOLT-11 parse+signature verification - see [DEFAULT_MIN_DEPOSIT_MSAT]'s doc comment for
     *     why [verify]'s purely structural self-consistency check alone is not sufficient: a
     *     genuinely-settled, self-consistent 1-msat deposit passes [verify] exactly as validly as a
     *     economically-meaningful one, so without this floor a spammer could mint a bypass for a
     *     cost indistinguishable from free.
     *  3. Otherwise, accepted iff the sender passes AT LEAST ONE configured gate - see
     *     [MailAcceptanceGate]'s class doc comment for the OR-across-gates reasoning. Rejection
     *     reports every gate that failed.
     */
    fun shouldAccept(
        recipient: Secp256k1PublicKey,
        envelope: MessageEnvelope,
        hasVeritasPath: (Secp256k1PublicKey) -> Boolean,
        karmaScoreOf: KarmaScoreLookup,
        gates: List<MailAcceptanceGate> = ACCEPT_ALL,
        minDepositMsat: Long = DEFAULT_MIN_DEPOSIT_MSAT,
        deposit: FirstContactDeposit? = null,
    ): MailAcceptanceDecision {
        if (gates.isEmpty()) return MailAcceptanceDecision.Accept

        val sender = envelope.sender

        if (deposit != null &&
            deposit.requiredAmountMsat >= minDepositMsat &&
            FirstContactDepositVerifier.verify(envelope, recipient, deposit)
        ) {
            return MailAcceptanceDecision.Accept
        }

        // V0.8.6: delegates to lapis-net-policy's shared evaluator - see this module's
        // build.gradle.kts header comment for why the gate TYPES stay declared here
        // (MailAcceptanceGate, unchanged public signature) while the evaluation LOGIC now lives in
        // one place shared with lapis-net-dm's DmAcceptancePolicy.
        val reason =
            AcceptanceGateEvaluator.firstPassOrFailureReason(
                sender = sender,
                gates = gates.map { it.toPolicyGate() },
                hasVeritasPath = hasVeritasPath,
                karmaScoreOf =
                    net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup { candidate ->
                        karmaScoreOf.karmaScoreOf(candidate)
                    },
            )
        return if (reason == null) MailAcceptanceDecision.Accept else MailAcceptanceDecision.Reject(reason)
    }
}

/** Maps this module's own [MailAcceptanceGate] onto lapis-net-policy's shared [AcceptanceGate] -
 * see [MailAcceptancePolicy.shouldAccept]'s own doc comment for why a `typealias` cannot be used
 * here instead (Kotlin does not allow a type alias to qualify a nested classifier - KT-11968). */
private fun MailAcceptanceGate.toPolicyGate(): AcceptanceGate =
    when (this) {
        is MailAcceptanceGate.VeritasPath -> AcceptanceGate.VeritasPath
        is MailAcceptanceGate.KarmaThreshold -> AcceptanceGate.KarmaThreshold(minScore)
    }
