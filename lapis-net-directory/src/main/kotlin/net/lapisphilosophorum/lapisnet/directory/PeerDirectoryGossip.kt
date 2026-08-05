package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.time.Instant

private val logger = KotlinLogging.logger {}

/**
 * Directory-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates
 * [PeerRecord]s over a dedicated topic, persists every accepted record into [NabuStorage], and
 * exposes read access ([lookup]) to the resolved "current record per identity" view. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGossip`'s shape (publishes full record bytes, not
 * a bare CID pointer - same `Kademlia.dialPeer`-broken reasoning, see this module's
 * `build.gradle.kts` comment) refined with `net.lapisphilosophorum.lapisnet.mail.InboxGossip`'s
 * more recently established `onGossipMessage` step ordering.
 *
 * **Publish-last ordering is load-bearing, mirroring every sibling `Gossip` class exactly**:
 * `announce()` is `storage.put()` -> `index.add()` -> `pubsub.publish()`, publish always last, so a
 * crash mid-sequence never leaves the network believing this node durably committed to something it
 * did not.
 *
 * **Deliberately NOT rate-limited here** - see [PeerPresenceAnnouncer]'s class doc comment for why
 * the minimum-republish-interval this record type's own "known, accepted metadata-exposure tension"
 * demands (see [PeerRecord]'s class doc comment) lives one layer up, wrapping this class, rather
 * than inside [announce] itself.
 */
class PeerDirectoryGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: PeerRecordIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [record]. Order
     * matters (see class doc comment): `pubsub.publish()` is the only externally-visible step and
     * always happens last.
     *
     * If [PeerRecordIndex.add] declines to track this node's own record (e.g. an exact content-id
     * duplicate from a retried announce, or - unusually - a sequence number this node itself
     * regressed on), that is logged at `warn`: the record is still durably persisted and still gets
     * published either way, mirroring `VeritasGossip.announce`'s identical reasoning.
     *
     * **Safe to call repeatedly with the SAME [record]** - `storage.put` is idempotent/
     * deterministic for identical content, and a repeat `index.add()` call harmlessly hits the
     * exact-content-id-duplicate branch and returns `false`. This is what
     * `TwoNodePeerDirectoryGossipIntegrationTest`'s bounded-polling-against-one-deadline loop relies
     * on, mirroring `TwoNodeVeritasGossipIntegrationTest`'s identical retry-the-whole-announce-call
     * pattern - unlike [PeerPresenceAnnouncer.announceIfDue], THIS method never suppresses a call
     * based on timing.
     *
     * **No delivery guarantee** - see [GossipPubSub.publish]'s doc comment.
     */
    fun announce(record: PeerRecord) {
        val bytes = PeerRecordCodec.encode(record)
        storage.put(bytes)
        if (!index.add(record)) {
            logger.warn {
                "own announced peer record for identity ${record.identity.fingerprint()} was not tracked " +
                    "locally - already durably persisted and will still be published"
            }
        }
        pubsub.publish(PEER_RECORD_GOSSIP_TOPIC, bytes)
    }

    /**
     * The latest (highest-sequence-number) still-valid record for [identity], or `null` if none is
     * tracked, or the tracked one has expired (`record.notValidAfterEpochSecond < [nowEpochSecond]`).
     *
     * **TTL is checked ONLY here, at read time - never inside [onGossipMessage]'s accept/reject
     * decision**, which makes zero clock calls (see that function's doc comment). An expired record
     * is NOT actively evicted from the underlying index by expiry - it stays stored, and would still
     * be returned by a call with an earlier [nowEpochSecond] - only this read-time filter hides it
     * from a caller using the real current time. See `PeerRecordSpoofingTest`'s case (c).
     *
     * [nowEpochSecond] is caller-injectable purely for deterministic testing.
     */
    fun lookup(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long = Instant.now().epochSecond,
    ): PeerRecord? {
        val record = index.current(identity) ?: return null
        return if (record.notValidAfterEpochSecond < nowEpochSecond) null else record
    }

    /** Unsubscribes from the gossip topic. No other sub-resources to release - mirrors
     * `VeritasGossip.stop` exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for peer/presence directory record propagation. Deliberately a
         * SEPARATE string from [PeerRecord]'s `"LapisNet:peer-record:v1"` signing domain-separation
         * tag, mirroring `VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC`'s identical "topic name and
         * signing tag are different kinds of thing" precedent. */
        const val PEER_RECORD_GOSSIP_TOPIC = "LapisNet:peer-record-gossip:v1"

        /** Attaches directory-specific GossipSub wiring on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage]. Subscribes to
         * [PEER_RECORD_GOSSIP_TOPIC] immediately - see [onGossipMessage] for the validator. */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): PeerDirectoryGossip {
            val index = PeerRecordIndex()
            val subscription =
                pubsub.subscribe(PEER_RECORD_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return PeerDirectoryGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: decode -> verify signature -> verify identity/peerId binding ->
         * verify possession proof -> dedup/staleness check -> persist -> index, in exactly this
         * order - cheapest and most-selective checks first, mirroring `InboxGossip.onGossipMessage`'s
         * established ordering discipline.
         *
         * **ALL THREE of [PeerRecord.verify], [verifyBinding], AND [verifyPossession] run here, as
         * INDEPENDENT checks - no pair alone is sufficient.** See [PeerRecord]'s class doc comment:
         * an attacker can produce a genuinely [PeerRecord.verify]-passing record (self-signed with
         * their OWN key) while embedding a FRESH [PeerRecord.binding] they minted themselves over a
         * VICTIM's public Ed25519 key (`IdentityBinding.create(attackerKeyPair,
         * victimEd25519PublicKey)`) - this passes [verifyBinding] too (it is genuinely
         * self-consistent), claiming the victim's real network addresses/peerId under the attacker's
         * own record (V0.8.1 sub-wave audit round 2, major finding 1 - the gap `verify` +
         * `verifyBinding` alone left open). [verifyPossession] is what catches THIS - it fails unless
         * the caller genuinely holds the Ed25519 PRIVATE key, which an attacker who only ever saw the
         * victim's PUBLIC key does not - `PeerRecordSpoofingTest`'s case (h) is the concrete
         * end-to-end adversarial proof; case (a) remains the original (already-closed) shape this
         * wave started with, reusing a victim's OWN binding object verbatim rather than re-signing a
         * fresh one.
         *
         * **`from` (the transport-authenticated GossipSub sender) is deliberately NOT consulted for
         * any accept/reject decision here, logging only** - this project's `GossipPubSub.attach`
         * wires `GossipRouterBuilder` with its DEFAULT `messageValidator`
         * (`io.libp2p.pubsub.PubsubRouterKt.NOP_ROUTER_VALIDATOR`, verified directly against the
         * real jvm-libp2p jar), not the library's own `SIGNATURE_ROUTER_VALIDATOR` - so `from` is
         * NOT cryptographically authenticated at the transport layer in this codebase today, and
         * comparing `record.peerId == from` here would be a false sense of security, not a real
         * proof-of-possession check (V0.8.1 sub-wave audit round 2, minor finding 5 - the reasoning
         * this doc comment records so a future change to `from`'s trustworthiness does not silently
         * invalidate it). [verifyPossession] instead proves possession INSIDE the record itself,
         * independent of whatever pubsub transport or relay chain carried it - a strictly stronger
         * property that does not depend on this or any other module's GossipSub wiring.
         *
         * **Zero clock and zero network calls in this function - absolute, not an optimization.**
         * [PeerRecord.notValidAfterEpochSecond] is attacker-controlled and is NEVER consulted for an
         * accept/reject decision here - TTL is a pure [lookup]-time filter. There is also no
         * `storage.get`/`storage.findProviders` call - the record travels as full bytes, not a CID
         * pointer, for the same `Kademlia.dialPeer`-broken reasoning as every sibling `Gossip` class.
         *
         * **[PeerRecordIndex.canAccept] here predicts BOTH exact-content-id duplication AND
         * stale/rollback sequence numbers** - unlike every sibling index's purely-dedup `canAccept`,
         * see [PeerRecordIndex]'s class doc comment. A stale record costs this node no
         * `NabuStorage.put()` attempt, not just no index slot.
         *
         * Visibility is `internal`, purely as a test seam, mirroring `VeritasGossip.onGossipMessage`'s
         * own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: PeerRecordIndex,
        ): ValidationResult {
            val record =
                try {
                    PeerRecordCodec.decode(bytes)
                } catch (e: MalformedPeerRecordException) {
                    logger.debug(e) {
                        "rejected structurally malformed peer record from $from on $PEER_RECORD_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }

            if (!PeerRecord.verify(record)) {
                logger.debug { "rejected signature-invalid peer record from $from on $PEER_RECORD_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }

            if (!record.verifyBinding()) {
                logger.debug {
                    "rejected peer record from $from on $PEER_RECORD_GOSSIP_TOPIC whose identity binding does " +
                        "not verify - identity ${record.identity.fingerprint()} does not actually vouch for the " +
                        "claimed transport peerId ${record.peerId}"
                }
                return ValidationResult.Invalid
            }

            if (!record.verifyPossession()) {
                logger.debug {
                    "rejected peer record from $from on $PEER_RECORD_GOSSIP_TOPIC whose possession proof does " +
                        "not verify - identity ${record.identity.fingerprint()} does not actually hold the " +
                        "Ed25519 private key behind claimed transport peerId ${record.peerId}"
                }
                return ValidationResult.Invalid
            }

            if (!index.canAccept(record)) {
                logger.debug {
                    "declining duplicate or stale (sequence-number-superseded) peer record from $from on " +
                        "$PEER_RECORD_GOSSIP_TOPIC - not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }

            if (index.tryReservePersistence(record)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    logger.warn(e) {
                        "failed to persist gossip-received peer record from $from - declining to accept it"
                    }
                    return ValidationResult.Invalid
                }
            } else {
                logger.debug {
                    "persistence cap reached - not durably storing peer record from $from on " +
                        "$PEER_RECORD_GOSSIP_TOPIC (still tracking and propagating it)"
                }
            }

            if (!index.add(record)) {
                // Wider than the "narrow race" every sibling index documents: PeerRecordIndex.add
                // can also decline a record that WAS acceptable at canAccept()-time but has since
                // been superseded by an even-newer concurrently-processed record for the same
                // identity, not just an exact duplicate - see PeerRecordIndex.canAccept's doc
                // comment. Still propagates: the record was legitimately well-formed and
                // correctly-ordered at the moment it was checked.
                logger.debug {
                    "peer record from $from on $PEER_RECORD_GOSSIP_TOPIC was persisted but lost a race (duplicate " +
                        "or since-superseded) before add() ran - propagating anyway"
                }
            }

            return ValidationResult.Valid
        }
    }
}
