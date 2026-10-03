package net.lapisphilosophorum.lapisnet.trust

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException

private val logger = KotlinLogging.logger {}

/**
 * Veritas-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates
 * [VeritasGrant]s over a dedicated topic, persists every accepted grant into [NabuStorage], and
 * exposes the resolved "latest grant per (truster, target) pair" edge set ([currentGrants]) ready
 * to feed directly into [TrustGraph.fromGrants].
 *
 * **Publishes full grant bytes, not a [io.ipfs.cid.Cid] pointer.** A [VeritasGrant]'s encoded
 * size ([VeritasGrantCodec.MAX_BODY_SIZE] plus a 64-byte signature) is tiny relative to any
 * reasonable gossip message-size ceiling, and - decisively - `NabuStorage`'s documented known
 * limitation was that cross-node DHT provider discovery (`findProviders()`) did not
 * work (repaired in V0.9.8; see the architecture doc's V0.1.4 section): a node receiving only a bare CID over gossip
 * would have no reliable way to fetch the actual content. Publishing full bytes sidesteps that
 * broken discovery path entirely.
 *
 * **Persistence lifecycle order is load-bearing, not stylistic** - a crash mid-sequence must
 * never leave the network believing something this node never durably persisted:
 *  - Local creation ([announce]): `put()` -> `index.add()` -> `publish()`, publish always last.
 *  - Gossip receipt: [VeritasGrantIndex.canAccept] (cheap, in-memory, dedup-only) gates whether a
 *    grant is considered at all; [VeritasGrantIndex.tryReservePersistence] (a SEPARATE, harder,
 *    non-evicting cap - round-3 fix) then independently gates `put()` (expensive, durable). Via
 *    the returned [ValidationResult], [canAccept] is what gates mesh-wide re-propagation - a
 *    persistence-capped-out grant still propagates, it just isn't durably stored by *this* node
 *    (see [onGossipMessage]'s doc comment for why that split is correct, not a compromise).
 *    `put()`, when attempted, happens inside the GossipSub validator, before `Valid` is returned -
 *    see [onGossipMessage].
 *
 * **Known gaps (matching this project's established practice of documenting limitations - see
 * `NabuStorage`'s V0.1.4 DHT-discovery gap):**
 *  - The in-memory [VeritasGrantIndex] is never rebuilt by scanning Nabu's local blockstore at
 *    startup - `NabuStorage` has no "enumerate local CIDs" primitive. A restarted node starts with
 *    an empty index regardless of what it durably persisted in a previous run.
 *  - A node joining after a grant's gossip window has passed has no backfill path - gossip
 *    carries full bytes but only propagates live, never historically. This is best-effort
 *    convergence, not always-eventually-consistent.
 *  - Unbounded message *rate* from a single peer is not defended against at this layer - deferred
 *    to jvm-libp2p's own GossipSub mesh-control-message rate limiting (see [GossipPubSub]).
 */
class VeritasGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: VeritasGrantIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [grant]. Order
     * matters (see class doc comment): `publish()` is the only externally-visible step and always
     * happens last, so a crash before it leaves no trace on the network of something this node
     * hasn't durably committed to.
     *
     * If [index.add] declines to track this node's own grant (an exact content-id duplicate - see
     * [VeritasGrantIndex.add]; the index no longer rejects for "full", it evicts, so that is not a
     * possible cause here), that is logged at `warn`: the grant is still durably persisted and
     * still gets published either way, so there is no correctness problem with the *message* -
     * this is purely local bookkeeping visibility for the caller, who would otherwise have no way
     * to notice their own grant silently didn't end up in the local index.
     *
     * **No delivery guarantee.** Like [GossipPubSub.publish] (whose doc comment this defers to for
     * the mechanism), this call can return normally even if the grant never reaches a single peer -
     * e.g. immediately after connecting, before GossipSub's mesh has formed. A caller that needs
     * to know whether a grant actually propagated must observe that independently (e.g. by polling
     * a peer's [currentGrants]), not by this call's return.
     */
    fun announce(grant: VeritasGrant) {
        val bytes = VeritasGrantCodec.encode(grant)
        storage.put(bytes)
        if (!index.add(grant)) {
            logger.warn {
                "own announced grant (content id ${grant.contentId().fingerprintHex()}) was not tracked locally - " +
                    "already durably persisted and will still be published"
            }
        }
        pubsub.publish(VERITAS_GRANT_GOSSIP_TOPIC, bytes)
    }

    /**
     * The resolved latest-per-pair edge set, ready for [TrustGraph.fromGrants]. Resolved on
     * demand over the whole index on every call - incremental caching is deferred, since an index
     * scan is cheap at this project's stated personal/local web-of-trust scale (see
     * [TrustGraph.MAX_NODES]'s Dunbar's-number reasoning).
     */
    fun currentGrants(): Collection<VeritasGrant> =
        index.allPairs().mapNotNull { (truster, target) ->
            VeritasGrantResolver.resolveLatest(index.grantsFor(truster, target))
        }

    /** Unsubscribes from the gossip topic. No other sub-resources to release - [GossipPubSub]/
     * [NabuStorage] are owned and stopped by their own callers, not by this class. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /**
         * Dedicated GossipSub topic for Veritas grant propagation. Deliberately a SEPARATE string
         * from the `"LapisNet:veritas-trust-edge:v1"` signing domain-separation tag
         * ([VeritasGrant]) even though it follows the same versioned-tag convention: a signing
         * domain-separation tag and a pubsub topic name are different kinds of thing, and reusing
         * the identical string for both would be confusing in logs/debugging even though it is
         * not a cryptographic risk. Single network-wide topic - topic naming is a Veritas concern,
         * so it lives here rather than in `lapis-net-networking`.
         */
        const val VERITAS_GRANT_GOSSIP_TOPIC = "LapisNet:veritas-trust-edge-gossip:v1"

        /**
         * Attaches Veritas-specific GossipSub wiring on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage] (both, in turn, on an
         * already-`start()`-ed [net.lapisphilosophorum.lapisnet.networking.LapisNode]). Subscribes
         * to [VERITAS_GRANT_GOSSIP_TOPIC] immediately - see [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): VeritasGossip {
            val index = VeritasGrantIndex()
            val subscription =
                pubsub.subscribe(VERITAS_GRANT_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return VeritasGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: BOTH structural decode AND signature verification happen here,
         * in one step, not split across two - GossipSub's re-propagation to the mesh is gated
         * purely by this function's returned [ValidationResult], so deferring signature
         * verification to a later step would mean every relaying node re-gossips signature-invalid
         * garbage before individually declining to act on it. Side effects (persist, index) only
         * happen after both checks pass.
         *
         * **Three-way structure (round-3 fix, superseding round-2's C2 fix): a dedup gate, an
         * independent persistence gate, and unconditional indexing/propagation for everything that
         * clears the first.**
         *  1. [VeritasGrantIndex.canAccept] - cheap, in-memory, dedup-only - gates everything: an
         *     exact content-id duplicate is declined immediately, with no persist attempt, no
         *     indexing, and no re-propagation (`ValidationResult.Invalid`).
         *  2. For anything that clears step 1, [VeritasGrantIndex.tryReservePersistence] - a
         *     SEPARATE, harder, non-evicting cap - decides whether [storage].`put()` is even
         *     attempted. If the persistence cap has been reached, `put()` is skipped entirely (a
         *     `debug` log notes this) and the grant proceeds straight to indexing.
         *  3. [VeritasGrantIndex.add] always runs for a grant that cleared step 1, and this
         *     function always returns `Valid` for it - regardless of whether step 2 actually
         *     persisted it. Only a genuine decode failure, signature failure, or `put()` throwing
         *     [NabuStorageException] returns `Invalid`.
         *
         * **Why persistence capping out must not also decline the message.** This node's live
         * trust view ([VeritasGrantIndex], [VeritasGossip.currentGrants], and transitively
         * [TrustGraph]/[TrustPathFinder]) is read exclusively from the in-memory index, never from
         * `NabuStorage` - so *this* node's own disk budget has no bearing on whether tracking this
         * grant, or continuing to relay it to the rest of the mesh (the property that actually
         * matters for network-wide convergence), is correct. Declining the message outright once
         * local disk capacity is reached would incorrectly conflate "my disk is full" with "this
         * grant is invalid", stalling propagation for every peer downstream of this node for a
         * reason that has nothing to do with the grant's validity.
         *
         * **CORRECTION to this doc comment's round-2 claim:** round-2 stated that gating `put()` on
         * [VeritasGrantIndex.canAccept] alone was sufficient to bound persistence. That was true
         * only as long as a full index hard-rejected new grants. Round-2's own M2 fix (LRU-style
         * eviction instead of rejection once [VeritasGrantIndex.MAX_TRACKED_GRANTS] is reached)
         * silently invalidated that claim: an evicting index has no "full" case left for
         * [VeritasGrantIndex.canAccept] to report, so it stopped bounding `put()` calls at all -
         * this is exactly the round-3 finding this three-way structure fixes. The lesson generalizes:
         * [VeritasGrantIndex.canAccept] bounds *tracking*, not *persistence* - the two need their
         * own independent caps precisely because they are different resources with different
         * correct policies (see [VeritasGrantIndex]'s class doc comment).
         *
         * Visibility is `internal`, not `private`, purely as a test seam: it takes [index]/
         * [storage] as parameters already, so a test can exercise this three-way structure directly
         * against small-cap [VeritasGrantIndex]s and a real (single-node, unconnected) [NabuStorage],
         * without needing a full two-node GossipSub mesh just to prove it.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: VeritasGrantIndex,
        ): ValidationResult {
            val grant =
                try {
                    VeritasGrantCodec.decode(bytes)
                } catch (e: MalformedVeritasGrantException) {
                    logger.debug(e) {
                        "rejected structurally malformed grant from $from on $VERITAS_GRANT_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }
            if (!VeritasGrant.verify(grant)) {
                logger.debug { "rejected signature-invalid grant from $from on $VERITAS_GRANT_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }
            if (!index.canAccept(grant)) {
                logger.debug {
                    "declining duplicate (already-tracked) grant from $from on $VERITAS_GRANT_GOSSIP_TOPIC - " +
                        "not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }
            if (index.tryReservePersistence(grant)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Couldn't durably persist - don't vouch for it either (D7's persist-before-index
                    // ordering: never index/re-propagate something we failed to store). The reserved
                    // persistence slot is not rolled back here - see [VeritasGrantIndex.tryReservePersistence]'s
                    // doc comment on why that is an acceptable, minor inefficiency rather than a bug.
                    logger.warn(e) { "failed to persist gossip-received grant from $from - declining to accept it" }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached (round-3 fix) - this is NOT a reason to decline the
                // message. This node's live trust view and mesh-wide propagation don't depend on
                // this node's own disk budget - see this function's doc comment. The grant still
                // gets indexed and still returns Valid below; it just won't have a durable local
                // copy on this node.
                logger.debug {
                    "persistence cap reached - not durably storing grant from $from on $VERITAS_GRANT_GOSSIP_TOPIC " +
                        "(still tracking and propagating it)"
                }
            }
            if (!index.add(grant)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions, not one atomic check-and-commit, so a concurrent gossip delivery of
                // the identical content id could win the index slot between the two calls above.
                // The grant is still cryptographically valid, and was durably persisted just above
                // unless the persistence cap had already been reached - either way that's
                // legitimate, useful data for the rest of the mesh, so it still propagates. This
                // node simply didn't end up tracking it a second time in its own local index, which
                // is a purely local bookkeeping shortfall, not a correctness problem with the
                // message itself.
                logger.debug {
                    "grant from $from on $VERITAS_GRANT_GOSSIP_TOPIC was persisted but lost a narrow index race - " +
                        "propagating anyway"
                }
            }
            return ValidationResult.Valid
        }
    }
}
