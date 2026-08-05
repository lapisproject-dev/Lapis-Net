package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.ratchet.MalformedPrekeyBundleException
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.time.Instant

private val logger = KotlinLogging.logger {}

/**
 * Publication and resolution of [PrekeyBundle]s over a dedicated GossipSub topic - the V0.8.2
 * addition to this module, reusing [PeerDirectoryGossip]'s established codec + gossip + cap-index
 * machinery rather than duplicating it inside `lapis-net-ratchet` (which is deliberately network-
 * free - see that module's `build.gradle.kts`). Structurally identical to [PeerDirectoryGossip]:
 * `announce()` is `storage.put()` -> `index.add()` -> `pubsub.publish()`, publish always last, and
 * `onGossipMessage`'s validator makes zero clock/network calls and never consults `from` for an
 * accept/reject decision - see [PeerDirectoryGossip]'s class doc comment for the full reasoning
 * this mirrors line for line.
 */
class PrekeyBundleGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: PrekeyBundleIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [bundle]. Order
     * matters, mirroring [PeerDirectoryGossip.announce]'s identical publish-last invariant.
     * Safe to call repeatedly with the SAME [bundle] - `storage.put` is idempotent and a repeat
     * `index.add()` call harmlessly hits the exact-content-id-duplicate branch.
     */
    fun announce(bundle: PrekeyBundle) {
        val bytes = PrekeyBundleCodec.encode(bundle)
        storage.put(bytes)
        if (!index.add(bundle)) {
            logger.warn {
                "own announced prekey bundle for identity ${bundle.identity.fingerprint()} was not tracked " +
                    "locally - already durably persisted and will still be published"
            }
        }
        pubsub.publish(PREKEY_BUNDLE_GOSSIP_TOPIC, bytes)
    }

    /**
     * The latest (highest-sequence-number) still-valid bundle for [identity], or `null` if none is
     * tracked or the tracked one has expired. TTL is checked ONLY here, at read time - mirrors
     * [PeerDirectoryGossip.lookup]'s identical contract.
     */
    fun lookup(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long = Instant.now().epochSecond,
    ): PrekeyBundle? {
        val bundle = index.current(identity) ?: return null
        return if (bundle.notValidAfterEpochSecond < nowEpochSecond) null else bundle
    }

    /** Unsubscribes from the gossip topic - mirrors [PeerDirectoryGossip.stop] exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for prekey-bundle propagation - deliberately a SEPARATE string
         * from any of [PrekeyBundle]'s own signing domain-separation tags, mirroring
         * [PeerDirectoryGossip.PEER_RECORD_GOSSIP_TOPIC]'s identical "topic name and signing tag are
         * different kinds of thing" precedent. */
        const val PREKEY_BUNDLE_GOSSIP_TOPIC = "LapisNet:prekey-bundle-gossip:v1"

        /** Attaches prekey-bundle-specific GossipSub wiring on top of an already-attached [pubsub]
         * and [storage]. Subscribes to [PREKEY_BUNDLE_GOSSIP_TOPIC] immediately. */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): PrekeyBundleGossip {
            val index = PrekeyBundleIndex()
            val subscription =
                pubsub.subscribe(PREKEY_BUNDLE_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return PrekeyBundleGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: decode -> [PrekeyBundle.verify] -> [verifyEncryptionBinding] ->
         * [verifySignedPrekey] -> dedup/staleness check ([PrekeyBundleIndex.canAccept]) -> persist
         * (behind [PrekeyBundleIndex.tryReservePersistence]) -> index, cheapest and most-selective
         * checks first - mirrors [PeerDirectoryGossip.onGossipMessage]'s established ordering
         * discipline exactly, with three cryptographic checks instead of that function's three
         * (verify/verifyBinding/verifyPossession) - the analogous set for this record type, see
         * [PrekeyBundle]'s class doc comment for why these three, and no possession-proof field,
         * are the correct set here.
         *
         * **`from` is deliberately NOT consulted for any accept/reject decision, logging only** -
         * identical reasoning to [PeerDirectoryGossip.onGossipMessage]'s own doc comment
         * (`GossipPubSub.attach` wires the default `NOP_ROUTER_VALIDATOR`, so `from` carries no
         * cryptographic guarantee here).
         *
         * **Zero clock and zero network calls in this function - absolute, not an optimization.**
         * [PrekeyBundle.notValidAfterEpochSecond] is attacker-controlled and never consulted for an
         * accept/reject decision here; TTL is a pure [lookup]-time filter.
         *
         * Visibility is `internal`, purely as a test seam, mirroring
         * [PeerDirectoryGossip.onGossipMessage]'s own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: PrekeyBundleIndex,
        ): ValidationResult {
            val bundle =
                try {
                    PrekeyBundleCodec.decode(bytes)
                } catch (e: MalformedPrekeyBundleException) {
                    logger.debug(e) {
                        "rejected structurally malformed prekey bundle from $from on $PREKEY_BUNDLE_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }

            if (!PrekeyBundle.verify(bundle)) {
                logger.debug { "rejected signature-invalid prekey bundle from $from on $PREKEY_BUNDLE_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }

            if (!bundle.verifyEncryptionBinding()) {
                logger.debug {
                    "rejected prekey bundle from $from on $PREKEY_BUNDLE_GOSSIP_TOPIC whose encryption key " +
                        "binding does not verify against the bundle's own claimed identity " +
                        bundle.identity.fingerprint()
                }
                return ValidationResult.Invalid
            }

            if (!bundle.verifySignedPrekey()) {
                logger.debug {
                    "rejected prekey bundle from $from on $PREKEY_BUNDLE_GOSSIP_TOPIC whose signed prekey " +
                        "signature does not verify - identity ${bundle.identity.fingerprint()}"
                }
                return ValidationResult.Invalid
            }

            if (!index.canAccept(bundle)) {
                logger.debug {
                    "declining duplicate or stale (sequence-number-superseded) prekey bundle from $from on " +
                        "$PREKEY_BUNDLE_GOSSIP_TOPIC - not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }

            if (index.tryReservePersistence(bundle)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    logger.warn(e) {
                        "failed to persist gossip-received prekey bundle from $from - declining to accept it"
                    }
                    return ValidationResult.Invalid
                }
            } else {
                logger.debug {
                    "persistence cap reached - not durably storing prekey bundle from $from on " +
                        "$PREKEY_BUNDLE_GOSSIP_TOPIC (still tracking and propagating it)"
                }
            }

            if (!index.add(bundle)) {
                logger.debug {
                    "prekey bundle from $from on $PREKEY_BUNDLE_GOSSIP_TOPIC was persisted but lost a race " +
                        "(duplicate or since-superseded) before add() ran - propagating anyway"
                }
            }

            return ValidationResult.Valid
        }
    }
}
