package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGateEvaluator
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup

/**
 * The outcome of a [DmAcceptancePolicy] evaluation. [Quarantine.reason]/[Reject.reason] are short,
 * human-readable, non-sensitive descriptions (which gate(s) failed) - safe to log, never derived
 * from any attacker-controlled content.
 *
 * **[shouldFetch] (the offline pre-check) can never return [Quarantine]; [classifyDelivered] (the
 * post-AEAD authoritative check) can never return [Reject]** - see `docs/architecture.adoc`'s "two
 * acceptance gates" section and this object's own doc comment for the full reasoning: the pre-check
 * runs on a signature-authenticated but not-yet-decrypted claim and can cheaply decline to spend a
 * Bitswap fetch on it; the post-AEAD check runs on an already-decrypted message whose sender is
 * cryptographically proven, at a point where the prekey/bandwidth cost is already spent - rejecting
 * it outright would destroy information for zero savings, so it is quarantined for the local user to
 * review instead.
 */
sealed interface DmAcceptanceDecision {
    data object Accept : DmAcceptanceDecision

    data class Quarantine(
        val reason: String,
    ) : DmAcceptanceDecision

    data class Reject(
        val reason: String,
    ) : DmAcceptanceDecision
}

/**
 * The DM analogue of `lapis-net-mail`'s `MailAcceptancePolicy` - V0.8.6. Shares the SAME gate
 * vocabulary ([AcceptanceGate]/[KarmaScoreLookup], `lapis-net-policy`) but is a DELIBERATELY
 * SEPARATE decision function, not a call-through, because DM has no signature-authenticated sender
 * claim available at the point mail's equivalent check runs - see the design note below.
 *
 * **Why two acceptance gates, not one shared mechanism with mail (the core V0.8.6 design decision -
 * "gates shared, decision not shared").** Mail checks in its GossipSub validator, on
 * `MessageEnvelope.sender` - a SIGNATURE-VERIFIED field - before anything costs anything. DM has no
 * equivalent trustworthy field at that point: [DmEnvelope.senderIdentity] is, by that class's own
 * doc comment, an UNTRUSTED CLAIM until [net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetSession.decrypt]
 * succeeds - and by then a one-time prekey has already been consumed. This yields two structurally
 * different checkpoints:
 *
 * | | Offline pre-check ([shouldFetch]) | Post-AEAD authoritative check ([classifyDelivered]) |
 * |---|---|---|
 * | Where | `MailboxGossip.onGossipMessage`, BEFORE the Bitswap fetch | `DmSessionManager.processInboundDmEnvelope`, AFTER AEAD succeeds |
 * | Authority | [MailboxPointer.senderIdentity] - signature-verified via [MailboxPointer.verify] | The AEAD-authenticated sender - the only authoritative source |
 * | Outcomes | Accept / Reject | Accept / Quarantine - never Reject |
 * | Savings | Real: skips the Bitswap fetch and a persistence-index reservation | None - the prekey is already spent, the plaintext already decrypted |
 *
 * **Honest, documented consequence: the deposit-unlock path is entirely UNAVAILABLE at [shouldFetch]
 * this wave, not merely inconvenient.** [DmFirstContactDepositVerifier.verify] requires a
 * [DmDepositBinding] bound to the X3DH ephemeral public key - a value that only exists inside the
 * `X3DH_INITIAL` header, unreadable until AFTER the very AEAD decrypt [shouldFetch] runs before. A
 * [DmSessionManager] caller can therefore never construct a real [DmDepositBinding] to pass
 * alongside [DmAcceptanceCheck.pointerDepositLookup]'s returned deposit at this checkpoint - the
 * parameter exists (mirroring `MailAcceptanceCheck.depositLookup`'s shape, and to keep [shouldFetch]/
 * [classifyDelivered] symmetric) but is structurally unusable here in V0.8.6. A stranger behind a
 * gated node's offline mailbox can therefore ONLY earn pre-check delivery by clearing a configured
 * [AcceptanceGate] - the in-band deposit only ever unlocks [classifyDelivered], post-decrypt, where
 * the real ephemeral key is finally available. A real, deliberate limitation for a node that has
 * gates configured - stated here so it is discovered by reading, not by surprise.
 */
object DmAcceptancePolicy {
    val ACCEPT_ALL: List<AcceptanceGate> = AcceptanceGateEvaluator.ACCEPT_ALL

    /** See [DmAcceptanceCheck.minDepositMsat]'s own doc comment - identical floor reasoning to
     * `MailAcceptancePolicy.DEFAULT_MIN_DEPOSIT_MSAT`. */
    const val DM_DEFAULT_MIN_DEPOSIT_MSAT: Long = 1_000_000L

    /** Evaluated in this exact order, identical for both [shouldFetch] and [classifyDelivered] -
     * only the terminal negative outcome differs (see this object's own class doc comment table):
     *
     *  1. Empty [gates] ([ACCEPT_ALL]) always accepts.
     *  2. [isAcceptedContact] always accepts - see [DmAcceptedContacts]'s own doc comment for how a
     *     peer gets there. **Deliberately NOT "an existing ratchet session" - see this function's
     *     own doc comment section below for why that would be a critical gap.**
     *  3. A [deposit]/[depositBinding] pair whose [DmFirstContactDeposit.requiredAmountMsat] is at
     *     least [minDepositMsat] AND that verifies ([DmFirstContactDepositVerifier.verify]) always
     *     accepts, bypassing every configured gate - the amount floor is checked first, before the
     *     comparatively expensive real BOLT-11 parse+signature verification.
     *  4. Otherwise, [AcceptanceGateEvaluator.firstPassOrFailureReason] against [gates].
     *
     * **Why NOT "an existing session counts as known" - the trap this function's design avoids.** A
     * session bootstrapped by the CLAIMED sender's own `X3DH_INITIAL` exists from message 1 of a
     * conversation the local node never approved. If bare session-existence counted as acceptance,
     * a spammer's SECOND message would sail through unquarantined the instant their first one
     * bootstrapped a session - the gate would only ever catch a spammer's very first message.
     * [isAcceptedContact] is deliberately the ONLY source of "known" here.
     */
    private fun decide(
        sender: Secp256k1PublicKey,
        localRecipient: Secp256k1PublicKey,
        gates: List<AcceptanceGate>,
        hasVeritasPath: (Secp256k1PublicKey) -> Boolean,
        karmaScoreOf: KarmaScoreLookup,
        isAcceptedContact: (Secp256k1PublicKey) -> Boolean,
        minDepositMsat: Long,
        deposit: DmFirstContactDeposit?,
        depositBinding: DmDepositBinding?,
    ): String? {
        if (gates.isEmpty()) return null
        if (isAcceptedContact(sender)) return null
        // V0.8.6 hardening-pass finding: [localRecipient] is now an explicit parameter, supplied by
        // the CALLER (which knows its own local identity independently of anything in
        // [depositBinding]), and checked here with a `require` BEFORE verification - mirroring
        // MailAcceptancePolicy.shouldAccept's separate, explicit `recipient` parameter. Previously
        // this function trusted `depositBinding.recipientIdentity` itself as "the local identity",
        // which is only true because every CURRENT caller happens to construct that binding from
        // its own local key - nothing in the type ever enforced it. A future caller building a
        // `DmDepositBinding` from wire data (e.g. from an X3DH header, as
        // `DmFirstContactDepositVerifier`'s own class doc comment describes) could otherwise let an
        // attacker set `recipientIdentity` to their OWN key and sign a self-issued invoice against
        // it, making this whole check tautological. Requiring the caller's own [localRecipient] to
        // match closes that by construction, the same way deriving the sender from `envelope`
        // (rather than accepting it as a second parameter) closes the swap risk in
        // `MailAcceptancePolicy.shouldAccept`'s own doc comment.
        if (deposit != null &&
            deposit.requiredAmountMsat >= minDepositMsat &&
            depositBinding != null &&
            depositBinding.initiatorIdentity == sender &&
            depositBinding.recipientIdentity == localRecipient &&
            DmFirstContactDepositVerifier.verify(depositBinding, localRecipient, deposit)
        ) {
            return null
        }
        return AcceptanceGateEvaluator.firstPassOrFailureReason(sender, gates, hasVeritasPath, karmaScoreOf)
    }

    /** The offline pre-check - NEVER returns [DmAcceptanceDecision.Quarantine]. [localRecipient] is
     * the local identity running this check - see [decide]'s own doc comment for why it is now a
     * required, explicit parameter rather than trusted implicitly off [depositBinding]. */
    fun shouldFetch(
        sender: Secp256k1PublicKey,
        localRecipient: Secp256k1PublicKey,
        gates: List<AcceptanceGate>,
        hasVeritasPath: (Secp256k1PublicKey) -> Boolean,
        karmaScoreOf: KarmaScoreLookup,
        isAcceptedContact: (Secp256k1PublicKey) -> Boolean = { false },
        minDepositMsat: Long = DM_DEFAULT_MIN_DEPOSIT_MSAT,
        deposit: DmFirstContactDeposit? = null,
        depositBinding: DmDepositBinding? = null,
    ): DmAcceptanceDecision {
        val reason =
            decide(
                sender,
                localRecipient,
                gates,
                hasVeritasPath,
                karmaScoreOf,
                isAcceptedContact,
                minDepositMsat,
                deposit,
                depositBinding,
            )
        return if (reason == null) DmAcceptanceDecision.Accept else DmAcceptanceDecision.Reject(reason)
    }

    /** The post-AEAD authoritative check - NEVER returns [DmAcceptanceDecision.Reject].
     * [localRecipient] is the local identity running this check - see [decide]'s own doc comment
     * for why it is now a required, explicit parameter rather than trusted implicitly off
     * [depositBinding]. */
    fun classifyDelivered(
        sender: Secp256k1PublicKey,
        localRecipient: Secp256k1PublicKey,
        gates: List<AcceptanceGate>,
        hasVeritasPath: (Secp256k1PublicKey) -> Boolean,
        karmaScoreOf: KarmaScoreLookup,
        isAcceptedContact: (Secp256k1PublicKey) -> Boolean = { false },
        minDepositMsat: Long = DM_DEFAULT_MIN_DEPOSIT_MSAT,
        deposit: DmFirstContactDeposit? = null,
        depositBinding: DmDepositBinding? = null,
    ): DmAcceptanceDecision {
        val reason =
            decide(
                sender,
                localRecipient,
                gates,
                hasVeritasPath,
                karmaScoreOf,
                isAcceptedContact,
                minDepositMsat,
                deposit,
                depositBinding,
            )
        return if (reason == null) DmAcceptanceDecision.Accept else DmAcceptanceDecision.Quarantine(reason)
    }
}
