package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.policy.VeritasPathCache
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

/**
 * Bundles everything [MailboxGossip.onGossipMessage]'s pre-check and [DmSessionManager]'s post-AEAD
 * classification need to run [DmAcceptancePolicy] as an optional, pluggable check - V0.8.6. `null`
 * (the default everywhere it is wired) means no check runs at all: every message is delivered
 * unquarantined, exactly like V0.8.5's behavior, functionally identical to a non-null instance
 * configured with [DmAcceptancePolicy.ACCEPT_ALL] (empty [gates]).
 *
 * [trustGraph] is an already-built, already-locally-held [TrustGraph] snapshot - building it is the
 * caller's job, mirroring `MailAcceptanceCheck`'s identical contract. [pointerDepositLookup] is a
 * pure, local, no-I/O function from an already-verified [MailboxPointer] to a
 * [DmFirstContactDeposit] the caller already holds for it, or `null` if none is available - the
 * OUT-OF-BAND deposit lookup [DmAcceptancePolicy.shouldFetch] needs, since the in-band deposit is
 * unreadable pre-decrypt (see that object's own class doc comment). Default `{ null }` mirrors
 * `MailAcceptanceCheck.depositLookup`'s identical default.
 *
 * **Wiring footgun to watch for**: the two call points this class doc comment names -
 * [MailboxGossip.onGossipMessage]'s pre-check and [DmSessionManager]'s post-AEAD classification -
 * are wired via two SEPARATE `attach(...)` calls (`MailboxGossip.attach` and
 * `DmSessionManager.attach` respectively), each taking its own independent `acceptance` parameter.
 * Passing the same instance to only one of them compiles, runs, and quarantines correctly at
 * whichever point IS wired - it just silently forfeits the other gate's savings. See
 * [DmSessionManager.attach]'s own `acceptance` parameter doc comment for the full explanation.
 */
class DmAcceptanceCheck(
    val gates: List<AcceptanceGate>,
    val trustGraph: TrustGraph,
    val karmaScoreOf: KarmaScoreLookup,
    val isAcceptedContact: (Secp256k1PublicKey) -> Boolean = { false },
    val minDepositMsat: Long = DmAcceptancePolicy.DM_DEFAULT_MIN_DEPOSIT_MSAT,
    val pointerDepositLookup: (MailboxPointer) -> DmFirstContactDeposit? = { null },
) {
    private val veritasPathCache = VeritasPathCache(trustGraph)

    /** A cached equivalent of `AcceptanceGateEvaluator.veritasPathCheck(trustGraph, localIdentity)` -
     * see [VeritasPathCache]'s own doc comment for the memoization this saves. `internal`, not
     * `private`: [MailboxGossip.onGossipMessage] and [DmSessionManager] (same module) are the only
     * intended callers. */
    internal fun cachedVeritasPathCheck(localIdentity: Secp256k1PublicKey): (Secp256k1PublicKey) -> Boolean =
        veritasPathCache.checkFor(localIdentity)
}
