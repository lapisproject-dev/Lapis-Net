package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.security.MessageDigest

private val logger = KotlinLogging.logger {}

/**
 * Locally derives the [Cid] that `NabuStorage.put(bytes)` would produce for [bytes], with zero
 * storage I/O - a pure, sha256-based content hash. Mirrors Nabu's own `FileBlockstore.put` [Cid]
 * derivation exactly bit-for-bit (Cid v1, [Cid.Codec.Raw], `Multihash.Type.sha2_256` over a plain
 * SHA-256 digest of the bytes - `org.peergos.Hash.sha256` is itself just
 * `MessageDigest.getInstance("SHA-256").digest(bytes)`, verified by decompiling Nabu v0.8.0's
 * `FileBlockstore` before writing this), so callers can know a body's [Cid] BEFORE deciding
 * whether to actually persist it.
 *
 * Needed by [PostAnnouncementIndex.tryReserveBodyPersistence]'s cap (see that method's doc
 * comment for the attack it closes): to gate the `storage.put()` call itself - not merely bookkeep
 * after the write already happened - the [Cid] a write WOULD produce must be known first. Using
 * the JDK's own `MessageDigest` here (rather than reaching into `org.peergos.Hash`, an internal
 * Nabu implementation class this module has no other dependency on) keeps this a self-contained,
 * standard-library-only computation; [Cid.buildCidV1] itself is already an established, public
 * pattern in this module's own test code and elsewhere in this project. If Nabu's blockstore ever
 * changes its hashing/codec scheme, this would silently drift out of sync - the existing
 * [PostAnnouncementGossipTest] round-trip assertions (fetching a body back from real [NabuStorage]
 * via its locally-derived [Cid]) would catch that immediately.
 */
internal fun deriveBodyCid(bytes: ByteArray): Cid {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, digest)
}

/**
 * Browser-MVP-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates
 * [PostAnnouncement]s over a dedicated topic, persists every accepted post into [NabuStorage], and
 * exposes the tracked post set ([currentPosts]) a browser timeline reads from. Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]'s structure and persistence-lifecycle
 * ordering precisely - see that class's doc comment for the general pattern this follows.
 *
 * **Critical design point: [PostAnnouncement] never carries a [Cid].** Unlike a hypothetical
 * design where the sender computes a [Cid] once and gossips a bare pointer, both the sender (in
 * [announce]) and every receiver (in [onGossipMessage]) independently call
 * `storage.put(announcement.bodyBytes)` to derive their OWN local [Cid] from the content bytes.
 * This is deliberate, not an oversight:
 *
 * Content-addressing guarantees that identical bytes hash to the identical [Cid] on every node -
 * `sha256`-derived (via Nabu's blockstore) content addressing is a pure function of the bytes
 * alone, with no dependency on which node computed it or when. So a node that receives the full
 * [PostAnnouncement.bodyBytes] over gossip and calls `storage.put()` on them locally always
 * arrives at exactly the same [Cid] the original author got. This design was chosen to sidestep
 * [net.lapisphilosophorum.lapisnet.storage.NabuStorage]'s then-documented cross-node-discovery
 * gap: until the V0.9.8 repair (see `NabuStorage.provide()`'s doc comment) DHT provider
 * announcement/discovery did not work at all, so a bare [Cid] pointer gossiped without the
 * underlying bytes would have been undiscoverable by any other node - there was no reliable way
 * for a peer to ask "who has this Cid" and get a real answer. That gap is now closed at the
 * storage layer, but this module deliberately keeps its self-contained gossip design: migrating
 * it onto DHT-backed publication is a separate wave, and the property below holds either way.
 * Embedding the actual bytes in the gossiped announcement and having each node independently
 * re-derive the [Cid] closes that gap entirely - nothing here ever depends on DHT provider
 * discovery working. This mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]'s/[net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s
 * own "publish full bytes, not a pointer" design for exactly the same reason - the only difference
 * here is that the [Cid] derivation is an explicit, first-class step of this module's design
 * (those two never mint a Nabu [Cid] over their payload at all), because a browser timeline needs
 * a [Cid] to key content by.
 *
 * **Persistence lifecycle order is load-bearing, not stylistic** - identical in spirit to
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]:
 *  - Local creation ([announce]): derive the [Cid] of the body bytes (zero I/O, [deriveBodyCid]) ->
 *    `storage.put(bodyBytes)` iff [PostAnnouncementIndex.tryReserveBodyPersistence] admits it ->
 *    `index.add()` -> persist the announcement wrapper's own encoded bytes -> `publish()`, publish
 *    always last.
 *  - Gossip receipt ([onGossipMessage]): [PostAnnouncementIndex.canAccept] (cheap, dedup-only)
 *    gates everything; the body-bytes `storage.put()` that derives the [Cid] is gated by
 *    [PostAnnouncementIndex.tryReserveBodyPersistence], a dedicated, [Cid]-keyed, non-evicting cap
 *    (see that method's doc comment for the network-amplified-disk-growth attack it closes -
 *    without it, a cheap attacker minting an unbounded stream of signed announcements with
 *    trivially-varied bodies, each with a fresh random nonce and therefore a fresh content id that
 *    always passes [PostAnnouncementIndex.canAccept], could force every relaying node in the mesh
 *    to independently and unboundedly grow its local disk). [PostAnnouncementIndex.tryReservePersistence]
 *    (a separate, non-evicting cap, keyed by announcement content id rather than [Cid])
 *    independently gates only the announcement WRAPPER's own separate durable-encoded-bytes
 *    persistence, exactly like [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]'s persistence
 *    cap gates its record bytes. Declining either cap never declines the announcement itself - it
 *    is still accepted/indexed/gossiped, just without one or both durable copies (see call sites).
 */
class PostAnnouncementGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: PostAnnouncementIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Derives the post body's [Cid] and persists it iff [PostAnnouncementIndex.tryReserveBodyPersistence]
     * admits it (see that method's doc comment - a locally-authored post is subject to the exact
     * same body-persistence cap as a gossip-received one, for consistency and because a single
     * identity composing many distinct-content posts is otherwise indistinguishable from the
     * attack that cap defends against), indexes, persists the announcement wrapper's own encoded
     * bytes, then publishes an already-locally-verified (self-signed) [announcement]. Order matters
     * (see class doc comment): `publish()` is the only externally-visible step and always happens
     * last. Returns the locally-derived [Cid] of [announcement]'s body bytes regardless of whether
     * the body-persistence cap admitted the actual `storage.put()` call.
     */
    fun announce(announcement: PostAnnouncement): Cid {
        val cid = deriveBodyCid(announcement.bodyBytes)
        if (index.tryReserveBodyPersistence(cid)) {
            storage.put(announcement.bodyBytes)
        } else {
            logger.debug {
                "body persistence cap reached - not durably storing own post body bytes (cid $cid, " +
                    "content id ${announcement.contentId().fingerprintHex()})"
            }
        }
        if (!index.add(announcement, cid)) {
            logger.warn {
                "own announced post (content id ${announcement.contentId().fingerprintHex()}) was not tracked " +
                    "locally - already durably persisted and will still be published"
            }
        }
        val bytes = PostAnnouncementCodec.encode(announcement)
        storage.put(bytes)
        pubsub.publish(POST_ANNOUNCEMENT_GOSSIP_TOPIC, bytes)
        return cid
    }

    /** Every tracked [IndexedPost], in insertion order - see [PostAnnouncementIndex.all]. */
    fun currentPosts(): List<IndexedPost> = index.all()

    /** Unsubscribes from the gossip topic. No other sub-resources to release - mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.stop] exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for browser post-announcement propagation - deliberately a
         * separate string from [BROWSER_POST_ANNOUNCEMENT_DOMAIN_TAG]-style signing
         * domain-separation tags, same reasoning as
         * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.LTR_RECORD_GOSSIP_TOPIC]'s doc
         * comment. */
        const val POST_ANNOUNCEMENT_GOSSIP_TOPIC = "LapisNet:browser-post-announcement-gossip:v1"

        /**
         * Attaches browser-MVP-specific GossipSub wiring on top of an already-
         * [GossipPubSub.attach]-ed [pubsub] and an already-[NabuStorage.attach]-ed [storage].
         * Subscribes to [POST_ANNOUNCEMENT_GOSSIP_TOPIC] immediately - see [onGossipMessage] for
         * the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): PostAnnouncementGossip {
            val index = PostAnnouncementIndex()
            val subscription =
                pubsub.subscribe(POST_ANNOUNCEMENT_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return PostAnnouncementGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: structural decode AND signature verification happen here in one
         * step, gating both this node's acceptance and mesh-wide re-propagation. Mirrors
         * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.onGossipMessage]'s structure, with one
         * addition specific to this module: a body-bytes `storage.put()` call that derives (via
         * [deriveBodyCid], with zero I/O) and, if [PostAnnouncementIndex.tryReserveBodyPersistence]
         * admits it, durably stores this node's own local [Cid] copy of the body - see this class's
         * doc comment and [PostAnnouncementIndex.tryReserveBodyPersistence]'s doc comment for why
         * that cap exists (a network-amplified disk-growth attack) and why declining it still lets
         * the announcement itself through.
         *
         * Visibility is `internal`, not `private`, purely as a test seam - mirrors
         * `LtrGossip.onGossipMessage`'s own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: PostAnnouncementIndex,
        ): ValidationResult {
            val announcement =
                try {
                    PostAnnouncementCodec.decode(bytes)
                } catch (e: MalformedPostAnnouncementException) {
                    logger.debug(e) {
                        "rejected structurally malformed announcement from $from on $POST_ANNOUNCEMENT_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }
            if (!PostAnnouncement.verify(announcement)) {
                logger.debug {
                    "rejected signature-invalid announcement from $from on $POST_ANNOUNCEMENT_GOSSIP_TOPIC"
                }
                return ValidationResult.Invalid
            }
            if (!index.canAccept(announcement)) {
                logger.debug {
                    "declining duplicate (already-tracked) announcement from $from on " +
                        "$POST_ANNOUNCEMENT_GOSSIP_TOPIC - not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }

            // Cid derivation itself (zero I/O, see deriveBodyCid's doc comment) is unconditional -
            // deriving this node's own local Cid from the content bytes is the entire point of
            // this module's design (see class doc comment). Whether the body bytes are actually
            // WRITTEN to storage is a separate decision, gated by tryReserveBodyPersistence - see
            // that method's doc comment for the network-amplified disk-growth attack this closes.
            val cid = deriveBodyCid(announcement.bodyBytes)
            if (index.tryReserveBodyPersistence(cid)) {
                try {
                    storage.put(announcement.bodyBytes)
                } catch (e: NabuStorageException) {
                    logger.warn(e) {
                        "failed to persist post body bytes from $from on $POST_ANNOUNCEMENT_GOSSIP_TOPIC - " +
                            "declining to accept it"
                    }
                    return ValidationResult.Invalid
                }
            } else {
                // Body-persistence cap reached - NOT a reason to decline the message, mirroring
                // the wrapper-bytes cap's identical reasoning just below. The post is still
                // tracked and re-propagated; it will render as content-unavailable on this node
                // (and any node that also missed the cap window) since the body was never durably
                // stored here.
                logger.debug {
                    "body persistence cap reached - not durably storing post body bytes from $from on " +
                        "$POST_ANNOUNCEMENT_GOSSIP_TOPIC (cid $cid, still tracking and propagating it)"
                }
            }

            if (index.tryReservePersistence(announcement)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Mirrors LtrGossip.onGossipMessage's identical reasoning: don't vouch for an
                    // announcement whose own wrapper bytes we failed to durably persist.
                    logger.warn(e) {
                        "failed to persist announcement wrapper bytes from $from on " +
                            "$POST_ANNOUNCEMENT_GOSSIP_TOPIC - declining to accept it"
                    }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached for the wrapper bytes - NOT a reason to decline the
                // message; this is an independent cap from the body-bytes one handled above.
                // Mirrors LtrGossip.onGossipMessage's identical reasoning.
                logger.debug {
                    "persistence cap reached - not durably storing announcement wrapper bytes from $from on " +
                        "$POST_ANNOUNCEMENT_GOSSIP_TOPIC (still tracking and propagating it)"
                }
            }

            if (!index.add(announcement, cid)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - mirrors LtrGossip.onGossipMessage's identical reasoning.
                logger.debug {
                    "announcement from $from on $POST_ANNOUNCEMENT_GOSSIP_TOPIC was persisted but lost a narrow " +
                        "index race - propagating anyway"
                }
            }
            return ValidationResult.Valid
        }
    }
}
