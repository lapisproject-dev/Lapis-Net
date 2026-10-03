package net.lapisphilosophorum.lapisnet.madli

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
 * Madli-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates
 * [MadliDailyVector]s over a dedicated topic, persists every accepted vector into [NabuStorage],
 * and exposes the tracked vector set ([currentVectorsForObservedPeer]) [MadliAggregator] needs to
 * compute an aggregated view of one observed peer. Mirrors `KarmaGossip`/`LtrGossip`'s structure
 * and persistence-lifecycle ordering precisely - see those classes' doc comments for the general
 * pattern this follows.
 *
 * **No network/clock call anywhere in [onGossipMessage] - the same central design decision
 * `KarmaGossip`/`LtrGossip` already establish.** The validator checks ONLY structure
 * ([MadliDailyVectorCodec.decode]) and the [MadliDailyVector] signature
 * ([MadliDailyVector.verify]) - it never inspects `epochDay` against wall-clock time. Deliberately
 * NOT rejecting a future-dated or old `epochDay` here would otherwise make this node's mesh
 * behavior depend on wall-clock skew between peers, breaking the "same structural+signature rules
 * applied to the same bytes always yield the same accept/reject decision on every honest node"
 * invariant this codebase relies on for safe re-propagation. Backdating/future-dating is instead
 * defused at READ time ([MadliDecayCalculator]/[MadliAggregator]'s future-clamp) and bounded by
 * [MadliVectorIndex]'s per-pair distinct-day cap (invariant B).
 *
 * **Publishes full vector bytes, not a `Cid` pointer** - same reasoning as
 * `KarmaGossip`/`LtrGossip`'s own doc comments (a [MadliDailyVectorCodec.MAX_BODY_SIZE]-bounded
 * vector plus a 64-byte signature is tiny relative to any reasonable gossip message-size ceiling,
 * and `NabuStorage.findProviders()` did not work end-to-end when this was written (repaired in
 * V0.9.8, see `docs/architecture.adoc`'s Storage section) - so a bare-CID gossip message would
 * have been unfetchable).
 *
 * **Persistence lifecycle order is load-bearing, not stylistic** - identical to
 * `KarmaGossip`/`LtrGossip`:
 *  - Local creation ([announce]): `put()` -> `index.add()` -> `publish()`, publish always last.
 *  - Gossip receipt ([onGossipMessage]): [MadliVectorIndex.canAccept] (cheap, dedup-only) gates
 *    everything; [MadliVectorIndex.tryReservePersistence] (a separate, non-evicting cap)
 *    independently gates `put()`; reaching the persistence cap must NOT decline or invalidate the
 *    gossip message - this node's disk budget has no bearing on whether the message is valid or
 *    should keep propagating to the rest of the mesh.
 */
class MadliGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: MadliVectorIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [vector]. Order
     * matters (see class doc comment): `publish()` is the only externally-visible step and always
     * happens last.
     *
     * If [index.add] declines to track this node's own vector (an exact content-id duplicate),
     * that is logged at `warn` - the vector is still durably persisted and still gets published
     * either way, mirroring `KarmaGossip.announce`'s exact contract.
     *
     * **No delivery guarantee** - see [GossipPubSub.publish]'s doc comment, which this defers to.
     */
    fun announce(vector: MadliDailyVector) {
        val bytes = MadliDailyVectorCodec.encode(vector)
        storage.put(bytes)
        if (!index.add(vector)) {
            logger.warn {
                "own announced vector (content id ${vector.contentId().fingerprintHex()}) was not tracked " +
                    "locally - already durably persisted and will still be published"
            }
        }
        pubsub.publish(MADLI_DAILY_VECTOR_GOSSIP_TOPIC, bytes)
    }

    /** Every tracked [MadliDailyVector] about [peer], in insertion order - the raw input
     * [MadliAggregator.aggregate] folds over. */
    fun currentVectorsForObservedPeer(peer: PeerId): List<MadliDailyVector> = index.vectorsForObservedPeer(peer)

    /** Unsubscribes from the gossip topic. No other sub-resources to release - mirrors
     * `KarmaGossip.stop`/`LtrGossip.stop` exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for Madli daily-vector propagation - deliberately a separate
         * string from [MadliDailyVector]'s own signing domain-separation tag, same reasoning as
         * `KarmaGossip.KARMA_VOTE_GOSSIP_TOPIC`'s doc comment. */
        const val MADLI_DAILY_VECTOR_GOSSIP_TOPIC = "LapisNet:madli-daily-vector-gossip:v1"

        /**
         * Attaches Madli-specific GossipSub wiring on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage]. Subscribes to
         * [MADLI_DAILY_VECTOR_GOSSIP_TOPIC] immediately - see [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): MadliGossip {
            val index = MadliVectorIndex()
            val subscription =
                pubsub.subscribe(MADLI_DAILY_VECTOR_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return MadliGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: structural decode AND signature verification happen here in
         * one step, gating both this node's acceptance and mesh-wide re-propagation. **No network
         * or clock call of any kind happens in this function** - see this class's doc comment for
         * the full reasoning. Mirrors `KarmaGossip.onGossipMessage`/`LtrGossip.onGossipMessage`'s
         * three-way structure exactly:
         *  1. [MadliVectorIndex.canAccept] - cheap, in-memory, dedup-only - declines an exact
         *     content-id duplicate immediately, with no persist attempt, no indexing, and no
         *     re-propagation.
         *  2. For anything that clears step 1, [MadliVectorIndex.tryReservePersistence] - a
         *     separate, non-evicting cap - decides whether [storage].`put()` is even attempted.
         *  3. [MadliVectorIndex.add] always runs for a vector that cleared step 1, and this
         *     function always returns `Valid` for it - regardless of whether step 2 actually
         *     persisted it. Only a genuine decode failure, signature failure, or `put()` throwing
         *     [NabuStorageException] returns `Invalid`.
         *
         * Visibility is `internal`, not `private`, purely as a test seam - mirrors
         * `KarmaGossip.onGossipMessage`'s own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: MadliVectorIndex,
        ): ValidationResult {
            val vector =
                try {
                    MadliDailyVectorCodec.decode(bytes)
                } catch (e: MalformedMadliDailyVectorException) {
                    logger.debug(e) {
                        "rejected structurally malformed vector from $from on $MADLI_DAILY_VECTOR_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }
            if (!MadliDailyVector.verify(vector)) {
                logger.debug { "rejected signature-invalid vector from $from on $MADLI_DAILY_VECTOR_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }
            if (!index.canAccept(vector)) {
                logger.debug {
                    "declining duplicate (already-tracked) vector from $from on " +
                        "$MADLI_DAILY_VECTOR_GOSSIP_TOPIC - not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }
            if (index.tryReservePersistence(vector)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Couldn't durably persist - don't vouch for it either (never index/re-propagate
                    // something we failed to store). The reserved persistence slot is not rolled
                    // back here - see MadliVectorIndex.tryReservePersistence's doc comment.
                    logger.warn(e) {
                        "failed to persist gossip-received vector from $from - declining to accept it"
                    }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached - NOT a reason to decline the message. This node's live
                // view and mesh-wide propagation don't depend on this node's own disk budget - see
                // this function's doc comment.
                logger.debug {
                    "persistence cap reached - not durably storing vector from $from on " +
                        "$MADLI_DAILY_VECTOR_GOSSIP_TOPIC (still tracking and propagating it)"
                }
            }
            if (!index.add(vector)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates - see
                // LtrGossip.onGossipMessage's identical reasoning.
                logger.debug {
                    "vector from $from on $MADLI_DAILY_VECTOR_GOSSIP_TOPIC was persisted but lost a narrow " +
                        "index race - propagating anyway"
                }
            }
            return ValidationResult.Valid
        }
    }
}
