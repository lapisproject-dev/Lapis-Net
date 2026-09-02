package net.lapisphilosophorum.lapisnet.policy

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder

/**
 * The gate-evaluation core shared by `lapis-net-mail`'s `MailAcceptancePolicy` and
 * `lapis-net-dm`'s `DmAcceptancePolicy` (V0.8.6). Deliberately takes only a bare `sender`, not a
 * `MessageEnvelope`/`DmEnvelope` - each caller's own policy object is responsible for deriving the
 * sender from whatever authority IT trusts (a signed envelope for mail; the AEAD-authenticated
 * ratchet plaintext for DM) BEFORE calling in here. See both callers' own class doc comments for
 * where and why the sender becomes trustworthy in each case - this object has no opinion on that.
 */
object AcceptanceGateEvaluator {
    /** The protocol-mandated default: no gates configured, every sender accepted. */
    val ACCEPT_ALL: List<AcceptanceGate> = emptyList()

    /**
     * `true` iff [candidate] has a POSITIVE Veritas trust score from [localIdentity] - mirrors
     * `MailAcceptancePolicy.veritasPathCheck`'s exact reasoning (deliberately
     * [TrustPathFinder.trustMicros] `>` [MIN_TRUST_MICROS], NOT [TrustPathFinder.findPath] `!=
     * null` - path EXISTENCE is not equivalent to positive trust, see that function's own doc
     * comment history for the full argument this repeats verbatim).
     */
    fun veritasPathCheck(
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
    ): (Secp256k1PublicKey) -> Boolean =
        { candidate -> TrustPathFinder.trustMicros(graph, localIdentity, candidate) > MIN_TRUST_MICROS }

    /**
     * Evaluates [gates] against [sender] in order, OR semantics across gates (accepted if ANY gate
     * passes). Returns `null` if [sender] was accepted (passed at least one gate, or [gates] is
     * empty), or a short, human-readable, non-sensitive, log-safe composite reason (every failed
     * gate's own description, joined) if every configured gate failed.
     *
     * An empty [gates] list is NOT specially short-circuited here - the caller (`MailAcceptancePolicy.
     * shouldAccept`/`DmAcceptancePolicy`) already checks `gates.isEmpty()` before ever reaching a
     * deposit check or this function, exactly mirroring the original `MailAcceptancePolicy`'s own
     * "empty gates pays zero cost" ordering. This function still handles an empty list correctly on
     * its own (the for-loop simply never runs, `failedGates` stays empty, `null` returned via the
     * final `if (failedGates.isEmpty()) return null` path) so it is safe to call directly too.
     */
    fun firstPassOrFailureReason(
        sender: Secp256k1PublicKey,
        gates: List<AcceptanceGate>,
        hasVeritasPath: (Secp256k1PublicKey) -> Boolean,
        karmaScoreOf: KarmaScoreLookup,
    ): String? {
        val failedGates = mutableListOf<String>()
        for (gate in gates) {
            val passed =
                when (gate) {
                    is AcceptanceGate.VeritasPath -> hasVeritasPath(sender)
                    is AcceptanceGate.KarmaThreshold -> karmaScoreOf.karmaScoreOf(sender) >= gate.minScore
                }
            if (passed) return null
            failedGates +=
                when (gate) {
                    is AcceptanceGate.VeritasPath -> "no Veritas path from local identity to sender"
                    is AcceptanceGate.KarmaThreshold -> "karma below threshold ${gate.minScore}"
                }
        }
        if (failedGates.isEmpty()) return null
        return failedGates.joinToString("; ")
    }
}
