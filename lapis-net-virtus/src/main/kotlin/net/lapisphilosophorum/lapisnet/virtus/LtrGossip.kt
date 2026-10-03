package net.lapisphilosophorum.lapisnet.virtus

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException

private val logger = KotlinLogging.logger {}

/**
 * Virtus-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates [LtrRecord]s
 * over a dedicated topic, persists every accepted record into [NabuStorage], and exposes both the
 * raw per-pair record set ([currentRecords]) and the decayed/accumulated sort-weight
 * ([currentWeight]) a view needs to rank content by. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s structure and persistence-lifecycle
 * ordering precisely - see that class's doc comment for the full reasoning; only the
 * pair-resolution semantics differ (see [LtrRecordIndex]'s doc comment: every record for a pair
 * is kept and summed, never resolved to one winner).
 *
 * **Publishes full record bytes, not a [Cid] pointer** - same reasoning as
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s own doc comment (an
 * [LtrRecordCodec.MAX_BODY_SIZE]-bounded record plus a 64-byte signature is tiny relative to any
 * reasonable gossip message-size ceiling, and `NabuStorage.findProviders()` did not reliably work
 * cross-node when this was written - repaired in V0.9.8).
 *
 * **Persistence lifecycle order is load-bearing, not stylistic** - identical to
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]:
 *  - Local creation ([announce]): for a genuinely NEW [LightningProof]-backed record, a
 *    payment-hash-reuse pre-check ([LtrRecordIndex.hasLightningPaymentBeenUsed] - the C1
 *    double-counting fix) gates everything FIRST; only then `put()` -> `index.add()` ->
 *    `publish()`, publish always last. See [announce]'s own doc comment for why this is NOT the
 *    same gate [onGossipMessage] uses.
 *  - Gossip receipt ([onGossipMessage]): [LtrRecordIndex.canAccept] (cheap, dedup-only) gates
 *    everything; [LtrRecordIndex.tryReservePersistence] (a separate, non-evicting cap)
 *    independently gates `put()`; reaching the persistence cap must NOT decline or invalidate the
 *    gossip message - this node's disk budget has no bearing on whether the record is valid or
 *    should keep propagating to the rest of the mesh.
 *
 * **Round-2 atomicity fix - the pre-checks above are cheap early-outs, not the real gate.**
 * [LtrRecordIndex.hasLightningPaymentBeenUsed]/[LtrRecordIndex.canAccept] and
 * [LtrRecordIndex.add]'s own mutation are still two separate `@Synchronized` acquisitions, so a
 * concurrent caller can race between a pre-check and [add] exactly as before. What changed is that
 * [add] itself now re-checks the payment-hash nullifier atomically, under its own lock, immediately
 * before committing - see [LtrRecordIndex.add]'s doc comment for the full "one payment, N records"
 * race this closes. Both call sites below ([announce] and [onGossipMessage]) still consult the
 * pre-checks first purely to skip an unnecessary `storage.put()` for a record that is obviously
 * going to be rejected, but [LtrRecordIndex.add]'s return value - never the pre-check's - is what
 * this class treats as authoritative for whether a record was actually credited.
 *
 * **[LightningProof] cryptographic verification runs in this hot path - a deliberate divergence
 * from [OnChainProof] (V0.6).** [OnChainProof]'s verification would require a live Bitcoin chain
 * lookup, which [onGossipMessage] correctly never performs (a liveness dependency on a third
 * party, cross-node non-determinism on reorgs, and DoS-amplification risk - see [OnChainProof]'s
 * and `KarmaGossip`'s doc comments for the full reasoning, repeated identically here).
 * [LightningProof] is different in kind, not just degree: [LightningProofVerifier.verify] is a
 * pure, bounded, local computation - hash a preimage, parse and verify a BOLT-11 signature,
 * compare a few already-size-capped fields - with **no** network I/O and **no** liveness
 * dependency on anything outside the message bytes themselves. Running it here makes a
 * [LightningProof] record strictly harder to forge over gossip than an [OnChainProof] record
 * (which is currently *not* cryptographically checked for real payment past its own signature)
 * - the correct asymmetry, since Lightning verification is the one real check available for free.
 */
class LtrGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: LtrRecordIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [record].
     * Returns `true` iff [record] was accepted; `false` iff it was declined BEFORE any
     * persist/index/publish step ran.
     *
     * **C1 fix - rejects a genuinely NEW record whose Lightning payment was already spent.** For a
     * [LightningProof]-backed [record] that is not already tracked by content id (see
     * [LtrRecordIndex.isTrackedByContentId]), [LtrRecordIndex.hasLightningPaymentBeenUsed] is
     * consulted: if [LightningProof.paymentHash] already backs another tracked record for the same
     * `(cid, viewId)` pair, this call is declined outright. Without this pre-check, repeatedly
     * POSTing the identical `(preimage, signedInvoice)` pair to `POST /api/ltr/lightning` would
     * mint a fresh-nonce [LtrRecord] every time (a different content id each call) and sum
     * unbounded weight from a single real payment.
     *
     * **Deliberately NOT gated on [LtrRecordIndex.canAccept] as a whole**, unlike
     * [onGossipMessage]'s step 1 - see [LtrRecordIndex.canAccept]'s doc comment for why: this
     * method is also used to RETRY publishing the SAME already-accepted [record] (gossip-mesh
     * warm-up delivery flakiness - see
     * [net.lapisphilosophorum.lapisnet.virtus.TwoNodeLtrGossipIntegrationTest]), and that harmless
     * re-send must still reach [pubsub.publish] even though its content id is already tracked -
     * behavior [LtrRecordIndex.canAccept]'s content-id half would incorrectly veto here.
     *
     * For an accepted [record], order matters (see class doc comment): `publish()` is the only
     * externally-visible step and always happens last.
     *
     * If [index.add] declines to track this node's own record, this method distinguishes WHY,
     * using [index.isTrackedByContentId] as the tell (see the two branches below):
     *  - **content id already tracked** - this call IS one of the legitimate retries described
     *    above (or a narrow content-id race with a concurrent [add] call for the exact same
     *    record), which is harmless: logged at `warn`, the record is still durably persisted and
     *    still gets published, mirroring
     *    [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.announce]'s exact contract.
     *  - **content id NOT tracked** - [record] is genuinely new, yet [index.add] still declined it.
     *    Since [index.add] only rejects a genuinely-new record for a spent payment hash (see that
     *    method's doc comment on the round-2 atomicity fix), this means a concurrent [announce]/
     *    gossip-receipt call raced this one and atomically won the same payment hash first - the
     *    pre-check above passed for both callers before either had committed. Unlike the
     *    content-id-retry branch, this record must NOT be credited: logged at `warn`, this method
     *    returns `false` even though `storage.put()` already ran for it (a wasted, but harmless,
     *    disk write - the same trade-off this class already accepts for the pre-check's own narrow
     *    race, see the class doc comment's "Round-2 atomicity fix" section).
     *
     * **No delivery guarantee** for an accepted record - see [GossipPubSub.publish]'s doc comment,
     * which this defers to.
     */
    fun announce(record: LtrRecord): Boolean {
        val proof = record.proof
        if (proof is LightningProof &&
            !index.isTrackedByContentId(record) &&
            index.hasLightningPaymentBeenUsed(record.cid, record.viewId, proof.paymentHash)
        ) {
            logger.warn {
                "declined to announce own Lightning-proof record (content id " +
                    "${record.contentId().fingerprintHex()}) - its payment hash was already used for this " +
                    "(cid, viewId) pair - see LtrRecordIndex.hasLightningPaymentBeenUsed"
            }
            return false
        }
        val bytes = LtrRecordCodec.encode(record)
        storage.put(bytes)
        if (!index.add(record)) {
            if (index.isTrackedByContentId(record)) {
                // Legitimate retry (or a harmless content-id race) - see this method's doc comment.
                logger.warn {
                    "own announced record (content id ${record.contentId().fingerprintHex()}) was not tracked " +
                        "locally - already durably persisted and will still be published"
                }
            } else {
                // Round-2 atomicity fix: index.add() atomically rejected this genuinely NEW record -
                // it lost a concurrent race for the same Lightning payment hash to another
                // announce()/gossip-receipt call that committed first (see LtrRecordIndex.add's doc
                // comment). Unlike the content-id-retry branch above, this must be reported as a
                // real rejection - the payment must not be credited twice.
                logger.warn {
                    "declined to announce own Lightning-proof record (content id " +
                        "${record.contentId().fingerprintHex()}) - lost an atomic payment-hash race in " +
                        "LtrRecordIndex.add to a concurrent record for this (cid, viewId) pair"
                }
                return false
            }
        }
        pubsub.publish(LTR_RECORD_GOSSIP_TOPIC, bytes)
        return true
    }

    /** Every tracked [LtrRecord] for the `(cid, viewId)` pair, in insertion order - see
     * [LtrRecordIndex.recordsFor]'s doc comment on why this is never resolved to one winner. */
    fun currentRecords(
        cid: Cid,
        viewId: Secp256k1PublicKey,
    ): List<LtrRecord> = index.recordsFor(cid, viewId)

    /** The decayed, accumulated sort-weight for the `(cid, viewId)` pair as of [atEpochSeconds] -
     * see [LtrWeightCalculator.accumulatedWeightMsat] for the underlying math. */
    fun currentWeight(
        cid: Cid,
        viewId: Secp256k1PublicKey,
        atEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): Double = LtrWeightCalculator.accumulatedWeightMsat(currentRecords(cid, viewId), atEpochSeconds)

    /** Unsubscribes from the gossip topic. No other sub-resources to release - mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.stop] exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for Virtus/LTR record propagation - deliberately a separate
         * string from [VIRTUS_LTR_RECORD_DOMAIN_TAG]-style signing domain-separation tags, same
         * reasoning as
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC]'s doc
         * comment. */
        const val LTR_RECORD_GOSSIP_TOPIC = "LapisNet:virtus-ltr-record-gossip:v1"

        /**
         * Attaches Virtus-specific GossipSub wiring on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage]. Subscribes to
         * [LTR_RECORD_GOSSIP_TOPIC] immediately - see [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): LtrGossip {
            val index = LtrRecordIndex()
            val subscription =
                pubsub.subscribe(LTR_RECORD_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return LtrGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: structural decode AND signature verification happen here in
         * one step, gating both this node's acceptance and mesh-wide re-propagation. Mirrors
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.onGossipMessage]'s three-way
         * structure exactly:
         *  1. [LtrRecordIndex.canAccept] - cheap, in-memory, dedup-only - declines an exact
         *     content-id duplicate immediately, with no persist attempt, no indexing, and no
         *     re-propagation. For a [LightningProof]-backed record, this step ALSO declines a
         *     reused [LightningProof.paymentHash] for the same `(cid, viewId)` pair (the C1
         *     payment-double-counting fix - see [LtrRecordIndex.hasLightningPaymentBeenUsed]'s doc
         *     comment) - this is what stops a peer that harvested a public preimage off the wire
         *     (preimage IS public once gossiped, see [LightningProof]'s doc comment) from
         *     re-minting records with fresh nonces/different payer keys to multiply one real
         *     payment's weight.
         *  2. For anything that clears step 1, [LtrRecordIndex.tryReservePersistence] - a
         *     separate, non-evicting cap - decides whether [storage].`put()` is even attempted.
         *  3. [LtrRecordIndex.add] always runs for a record that cleared step 1, and this function
         *     always returns `Valid` for it - regardless of whether step 2 actually persisted it.
         *     Only a genuine decode failure, signature failure, or `put()` throwing
         *     [NabuStorageException] returns `Invalid`.
         *
         * Visibility is `internal`, not `private`, purely as a test seam - mirrors
         * `VeritasGossip.onGossipMessage`'s own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: LtrRecordIndex,
        ): ValidationResult {
            val record =
                try {
                    LtrRecordCodec.decode(bytes)
                } catch (e: MalformedLtrRecordException) {
                    logger.debug(e) {
                        "rejected structurally malformed record from $from on $LTR_RECORD_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }
            if (!LtrRecord.verify(record)) {
                logger.debug { "rejected signature-invalid record from $from on $LTR_RECORD_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }
            val proof = record.proof
            if (proof is LightningProof && !LightningProofVerifier.verify(record, proof)) {
                logger.debug { "rejected crypto-invalid Lightning proof from $from on $LTR_RECORD_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }
            if (!index.canAccept(record)) {
                logger.debug {
                    "declining duplicate (already-tracked) record from $from on $LTR_RECORD_GOSSIP_TOPIC - " +
                        "not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }
            if (index.tryReservePersistence(record)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Couldn't durably persist - don't vouch for it either (never index/re-propagate
                    // something we failed to store). The reserved persistence slot is not rolled
                    // back here - see LtrRecordIndex.tryReservePersistence's doc comment.
                    logger.warn(e) { "failed to persist gossip-received record from $from - declining to accept it" }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached - NOT a reason to decline the message. This node's live
                // view and mesh-wide propagation don't depend on this node's own disk budget - see
                // this function's doc comment.
                logger.debug {
                    "persistence cap reached - not durably storing record from $from on $LTR_RECORD_GOSSIP_TOPIC " +
                        "(still tracking and propagating it)"
                }
            }
            if (!index.add(record)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery could win the index slot between the
                // two calls above, either by the identical content id (VeritasGossip.onGossipMessage's
                // original reasoning) or, since the round-2 atomicity fix, by the same Lightning
                // payment hash on a different content id (see LtrRecordIndex.add's doc comment).
                // Either way this is safe to still propagate: index.add() is the sole authority this
                // node's own weight computation (LtrGossip.currentWeight) relies on, so a record that
                // lost this race is never double-counted locally regardless of what this function
                // returns - and every other node enforces the identical atomic invariant
                // independently on its own index, so re-propagating a race loser cannot cause
                // double-counting anywhere else in the mesh either.
                logger.debug {
                    "record from $from on $LTR_RECORD_GOSSIP_TOPIC was persisted but lost a narrow index race - " +
                        "propagating anyway"
                }
            }
            return ValidationResult.Valid
        }
    }
}
