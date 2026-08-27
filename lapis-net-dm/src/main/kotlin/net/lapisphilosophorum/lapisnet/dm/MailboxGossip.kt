package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException

private val logger = KotlinLogging.logger {}

/**
 * Subscribes the local identity's own mailbox topic ([MailboxTopics.forRecipient]) and runs the
 * GossipSub validator that turns raw wire bytes into durably-persisted, indexed [MailboxPointer]s.
 * Mirrors `net.lapisphilosophorum.lapisnet.mail.InboxGossip`'s shape exactly.
 *
 * **Subscribe-only, no `announce()` method here - deliberately.** Publishing a pointer onto a
 * DIFFERENT identity's mailbox topic is the SENDER's job
 * ([DmSessionManager.sendOffline]/[MailboxRedeliveryScheduler]), not this class's - mirrors the
 * `net.lapisphilosophorum.lapisnet.mail.MailSender`/`InboxGossip` split, not the self-publishing
 * `net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip.announce` shape.
 */
class MailboxGossip private constructor(
    private val index: MailboxPointerIndex,
    private val subscription: PubsubSubscription,
) {
    /** Every tracked pointer not yet marked resolved - see [MailboxPointerIndex.pending]. */
    fun pending(): List<MailboxPointer> = index.pending()

    /** See [MailboxPointerIndex.markResolved]. */
    fun markResolved(pointer: MailboxPointer) = index.markResolved(pointer)

    /** See [MailboxPointerIndex.evictExpired]. */
    fun evictExpired(nowEpochSecond: Long): Int = index.evictExpired(nowEpochSecond)

    /** Unsubscribes from the mailbox topic. No other sub-resources to release - mirrors
     * `InboxGossip.stop`/`net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip.stop`
     * exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /**
         * Subscribes [localIdentity]'s own mailbox topic on top of an already-
         * [GossipPubSub.attach]-ed [pubsub] and an already-[NabuStorage.attach]-ed [storage].
         * Subscribes immediately - see [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
            localIdentity: Secp256k1PublicKey,
        ): MailboxGossip {
            val index = MailboxPointerIndex()
            val topic = MailboxTopics.forRecipient(localIdentity)
            val subscription =
                pubsub.subscribe(topic) { bytes, from -> onGossipMessage(bytes, from, storage, index, localIdentity) }
            return MailboxGossip(index, subscription)
        }

        /**
         * The GossipSub validator: decode -> addressed-to-local check -> signature -> dedup ->
         * persist -> index, in exactly this order - cheapest and most-selective checks first,
         * mirroring `InboxGossip.onGossipMessage`'s established ordering discipline.
         *
         * **Pointers not addressed to [localIdentity] are dropped WITHOUT being persisted, indexed,
         * or re-propagated** - mirrors `InboxGossip.onGossipMessage`'s identical divergence from
         * `VeritasGossip`'s "keep relaying even what we can't use": a mailbox topic is
         * identity-scoped, so nothing legitimately subscribed to this topic could be the intended
         * recipient of a pointer that omits this identity.
         *
         * **Zero clock and zero network calls in this function - a hard invariant, not an
         * optimization.** [MailboxPointer.notValidAfterEpochSecond] is attacker-controlled and is
         * NEVER consulted for an accept/reject decision here - TTL is checked only at read/poll
         * time (see [MailboxPoller.pollOnce]). There is also no `storage.get`/`storage.get` with
         * peers/`storage.findProviders` call anywhere in this function - the pointer bytes ARE the
         * full record; ONLY the referenced blob is fetched later, out-of-band, by [MailboxPoller].
         *
         * Visibility is `internal`, purely as a test seam, mirroring `InboxGossip.onGossipMessage`'s
         * own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: MailboxPointerIndex,
            localIdentity: Secp256k1PublicKey,
        ): ValidationResult {
            val pointer =
                try {
                    MailboxPointerCodec.decode(bytes)
                } catch (e: MalformedMailboxPointerException) {
                    logger.debug(e) { "rejected structurally malformed mailbox pointer from $from" }
                    return ValidationResult.Invalid
                }

            if (pointer.recipientIdentity != localIdentity) {
                logger.debug {
                    "dropping mailbox pointer from $from on ${MailboxTopics.forRecipient(localIdentity)} that is " +
                        "not addressed to this identity - not persisting, not indexing, not re-propagating"
                }
                return ValidationResult.Invalid
            }

            if (!MailboxPointer.verify(pointer)) {
                logger.debug { "rejected signature-invalid mailbox pointer from $from" }
                return ValidationResult.Invalid
            }

            if (!index.canAccept(pointer)) {
                logger.debug {
                    "declining duplicate (already-tracked) mailbox pointer from $from - not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }

            if (index.tryReservePersistence(pointer)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Security audit round 1 minor finding: release the reservation on failure -
                    // tryReservePersistence already inserted the content id into the never-evicting
                    // persistedContentIds set, so leaving it in place here would permanently burn a
                    // slot for a pointer that ends up neither persisted nor tracked. See
                    // MailboxPointerIndex.releaseReservedPersistence's own doc comment.
                    index.releaseReservedPersistence(pointer)
                    logger.warn(
                        e,
                    ) { "failed to persist gossip-received mailbox pointer from $from - declining to accept it" }
                    return ValidationResult.Invalid
                }
            } else {
                logger.debug {
                    "persistence cap reached - not durably storing mailbox pointer from $from " +
                        "(still tracking and propagating it)"
                }
            }

            if (!index.add(pointer)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates: the pointer was
                // legitimately well-formed at the moment it was checked.
                logger.debug {
                    "mailbox pointer from $from was persisted but lost a narrow index race - propagating anyway"
                }
            }

            return ValidationResult.Valid
        }
    }
}
