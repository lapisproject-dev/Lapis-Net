package net.lapisphilosophorum.lapisnet.policy

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * One opt-in acceptance gate a node operator may configure - the shared vocabulary
 * `lapis-net-mail`'s `MailAcceptanceGate` and `lapis-net-dm`'s `DmAcceptanceGate` (V0.8.6, see that
 * module's `DmAcceptancePolicy`) both delegate to. [AcceptanceGateEvaluator.firstPassOrFailureReason]
 * accepts a sender who passes AT LEAST ONE configured gate (OR semantics) - see that function's own
 * doc comment.
 */
sealed interface AcceptanceGate {
    /** Reject a sender with no positive Veritas trust path from the local identity. */
    data object VeritasPath : AcceptanceGate

    /** Reject a sender whose [KarmaScoreLookup]-derived score is below [minScore]. */
    data class KarmaThreshold(
        val minScore: Double,
    ) : AcceptanceGate
}

/**
 * Pull-based Karma-score lookup for a candidate sender - see `lapis-net-mail`'s original
 * `KarmaScoreLookup` (V0.9.4) for the full "trust-free core, thin caller-side adapter" reasoning
 * this shares. `lapis-net-karma` has no existing notion of a single per-IDENTITY Karma score, so
 * [AcceptanceGateEvaluator] takes the resulting number as an injected lookup instead of depending
 * on `lapis-net-karma` at all.
 */
fun interface KarmaScoreLookup {
    fun karmaScoreOf(sender: Secp256k1PublicKey): Double
}
