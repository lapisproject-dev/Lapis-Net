package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder

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
    ): (Secp256k1PublicKey) -> Boolean =
        { candidate -> TrustPathFinder.trustMicros(graph, localIdentity, candidate) > MIN_TRUST_MICROS }

    /**
     * The accept/reject decision for [envelope] from [sender], addressed to [recipient] (the
     * local identity running this check - see [FirstContactDepositVerifier.verify]'s `recipient`
     * binding). Evaluated in this exact order:
     *
     *  1. **Empty [gates] ([ACCEPT_ALL]) always accepts** - the protocol-mandated default, checked
     *     first so a node running no filters pays no cost at all (no deposit verification, no
     *     Veritas/Karma lookups) for messages it was always going to accept anyway.
     *  2. **A [deposit] that verifies (see [FirstContactDepositVerifier.verify]) always accepts,
     *     bypassing every configured gate** - that is the whole point of the first-contact deposit
     *     mechanism: an unknown sender who paid gets through even with every gate configured and
     *     failing.
     *  3. Otherwise, accepted iff [sender] passes AT LEAST ONE configured gate - see
     *     [MailAcceptanceGate]'s class doc comment for the OR-across-gates reasoning. Rejection
     *     reports every gate that failed.
     */
    fun shouldAccept(
        sender: Secp256k1PublicKey,
        recipient: Secp256k1PublicKey,
        envelope: MessageEnvelope,
        hasVeritasPath: (Secp256k1PublicKey) -> Boolean,
        karmaScoreOf: KarmaScoreLookup,
        gates: List<MailAcceptanceGate> = ACCEPT_ALL,
        deposit: FirstContactDeposit? = null,
    ): MailAcceptanceDecision {
        if (gates.isEmpty()) return MailAcceptanceDecision.Accept

        if (deposit != null && FirstContactDepositVerifier.verify(envelope, recipient, deposit)) {
            return MailAcceptanceDecision.Accept
        }

        val failedGates = mutableListOf<String>()
        for (gate in gates) {
            val passed =
                when (gate) {
                    is MailAcceptanceGate.VeritasPath -> hasVeritasPath(sender)
                    is MailAcceptanceGate.KarmaThreshold -> karmaScoreOf.karmaScoreOf(sender) >= gate.minScore
                }
            if (passed) return MailAcceptanceDecision.Accept
            failedGates +=
                when (gate) {
                    is MailAcceptanceGate.VeritasPath -> "no Veritas path from local identity to sender"
                    is MailAcceptanceGate.KarmaThreshold -> "karma below threshold ${gate.minScore}"
                }
        }
        return MailAcceptanceDecision.Reject(failedGates.joinToString("; "))
    }
}
