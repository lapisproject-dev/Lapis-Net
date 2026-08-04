package net.lapisphilosophorum.lapisnet.mail

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
 * Subscribes the local identity's own inbox topic ([InboxTopics.forRecipient]) and runs the
 * GossipSub validator that turns raw wire bytes into durably-persisted, indexed [InboxMessage]s.
 *
 * **Scope cuts for V0.9.1 (stated here, this module's center of gravity, and referenced from
 * [MessageEnvelope]/[MailSender]):**
 *  - **No DHT inbox record.** Gossip-only, because `Kademlia.dialPeer` is documented broken since
 *    V0.1.4 (see `NabuStorage.provide`'s doc comment). A node offline during the gossip window has
 *    no catch-up path - a known, accepted limitation carried from
 *    `net.lapisphilosophorum.lapisnet.trust.VeritasGossip`'s best-effort-convergence precedent.
 *  - **No relay population.** GossipSub only forwards on topics a peer subscribes to, and an inbox
 *    topic is identity-scoped - so delivery effectively requires a live sender-to-recipient
 *    connection at send time, strictly weaker than `VeritasGossip`'s network-wide topic.
 *  - **No topic sharding.**
 *  - **No newsletter/subscription model.**
 *  - **No address book, no pubkey-to-name mapping.** Recipients are raw compressed secp256k1 keys.
 *  - **No thread assembly.** `replyTo`/`threadRoot` are carried and signed but nothing walks them
 *    into a thread - V0.9.3.
 *  - **No browser HTTP routes.** `lapis-net-browser` is untouched by this wave - V0.9.3.
 *  - **No encryption.** `HYBRID_ECIES`/`MLS_ARCHIVE` are wire-representable but rejected outright -
 *    V0.9.2.
 *  - **No attachment fetching, verification, or encryption.** [AttachmentRef.size] is declared,
 *    never checked; no key field - V0.9.3.
 *  - **No self-delivery.** GossipSub never delivers a node's own [GossipPubSub.publish] calls to
 *    its own [GossipPubSub.subscribe] handler (see that method's doc comment) - a sender that lists
 *    themself among recipients never sees the message in their own inbox. A local "sent" view is
 *    V0.9.3.
 *
 * **The gossip frame carries the body, not just a CID pointer** - see [MailFrameCodec]'s class doc
 * comment for the full reasoning (`NabuStorage.get()` falls through to a live DHT lookup on a
 * local miss, forbidden inside a validator; and provider discovery is documented broken anyway).
 */
class InboxGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val localIdentity: Secp256k1PublicKey,
    private val index: InboxIndex,
    private val subscription: PubsubSubscription,
) {
    /** The GossipSub topic this instance is subscribed to - [InboxTopics.forRecipient] applied to
     * the identity this instance was [attach]ed for. */
    val topic: String = InboxTopics.forRecipient(localIdentity)

    /** All tracked inbox messages, oldest first. */
    fun messages(): List<InboxMessage> = index.latest()

    /** All tracked inbox messages from [sender], oldest first. */
    fun messagesFrom(sender: Secp256k1PublicKey): List<InboxMessage> = index.messagesFrom(sender)

    /** Unsubscribes from the inbox topic. No other sub-resources to release - mirrors
     * `net.lapisphilosophorum.lapisnet.trust.VeritasGossip.stop` exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /**
         * Subscribes [localIdentity]'s own inbox topic on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage]. Subscribes immediately - see
         * [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
            localIdentity: Secp256k1PublicKey,
        ): InboxGossip {
            val index = InboxIndex()
            val topic = InboxTopics.forRecipient(localIdentity)
            val subscription =
                pubsub.subscribe(topic) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index, localIdentity)
                }
            return InboxGossip(pubsub, storage, localIdentity, index, subscription)
        }

        /**
         * The GossipSub validator: decode -> addressing check -> signature -> CID binding -> dedup
         * -> persist -> index, all in one step, in exactly this order. The order is deliberate, not
         * arbitrary: cheapest and most-selective checks run first, so an attacker spamming our
         * inbox topic with envelopes not addressed to us costs this node one decode and no ECDSA
         * verification.
         *
         * **Envelopes not addressed to [localIdentity] are dropped WITHOUT being persisted, indexed,
         * or re-propagated** - a deliberate divergence from
         * `net.lapisphilosophorum.lapisnet.trust.VeritasGossip`'s "keep relaying even what we can't
         * use": an inbox topic is identity-scoped, so nothing legitimately subscribed to this topic
         * could be the intended recipient of an envelope that omits this identity, and there is no
         * mesh-wide convergence property to preserve here (unlike a network-wide Veritas topic).
         *
         * **Zero clock and zero network calls in this function - a hard invariant, not an
         * optimization.** [MessageEnvelope.sentAtEpochSecond] is attacker-controlled and is NEVER
         * consulted for an accept/reject decision here, mirroring
         * `net.lapisphilosophorum.lapisnet.karma.KarmaGossip`/
         * `net.lapisphilosophorum.lapisnet.madli.MadliGossip`/
         * `net.lapisphilosophorum.lapisnet.virtus.LtrGossip`'s identical "no clock/network in the
         * validator" rule. There is also no `storage.get`/`storage.findProviders` call anywhere in
         * this function - see [MailFrameCodec]'s class doc comment for why the frame carries the
         * body instead.
         *
         * Visibility is `internal`, not `private`, purely as a test seam - mirrors
         * `VeritasGossip.onGossipMessage`'s own documented reasoning: it already takes [storage]/
         * [index] as plain parameters, so a test can exercise this function directly against a real
         * (single-node, unconnected) [NabuStorage] and small-cap [InboxIndex]s.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: InboxIndex,
            localIdentity: Secp256k1PublicKey,
        ): ValidationResult {
            val frame =
                try {
                    MailFrameCodec.decode(bytes)
                } catch (e: MalformedMailFrameException) {
                    logger.debug(e) { "rejected structurally malformed mail frame from $from" }
                    return ValidationResult.Invalid
                }

            val envelope =
                try {
                    MessageEnvelopeCodec.decode(frame.envelopeBytes)
                } catch (e: MalformedMessageEnvelopeException) {
                    logger.debug(e) { "rejected structurally malformed envelope from $from" }
                    return ValidationResult.Invalid
                }

            // Belt-and-braces: unreachable via the decode() path above today (decode() already
            // rejects a reserved encryption mode), kept so a future codec change can never silently
            // let a reserved mode through this validator without this function also changing.
            if (envelope.encryption != EncryptionMode.NONE) {
                logger.debug { "rejected envelope from $from with reserved encryption mode ${envelope.encryption}" }
                return ValidationResult.Invalid
            }

            if (!envelope.isAddressedTo(localIdentity)) {
                logger.debug {
                    "dropping envelope from $from on ${InboxTopics.forRecipient(localIdentity)} that is not " +
                        "addressed to this identity - not persisting, not indexing, not re-propagating"
                }
                return ValidationResult.Invalid
            }

            if (!MessageEnvelope.verify(envelope)) {
                logger.debug { "rejected signature-invalid envelope from $from" }
                return ValidationResult.Invalid
            }

            if (MessageBodyCodec.cidFor(frame.bodyBytes) != envelope.contentCid) {
                logger.debug { "rejected envelope from $from whose contentCid does not match the frame's body" }
                return ValidationResult.Invalid
            }

            val body =
                try {
                    MessageBodyCodec.decode(frame.bodyBytes)
                } catch (e: MalformedMessageBodyException) {
                    logger.debug(e) { "rejected structurally malformed body from $from" }
                    return ValidationResult.Invalid
                }

            if (!index.canAccept(envelope)) {
                logger.debug {
                    "declining duplicate (already-tracked) envelope from $from - not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }

            if (index.tryReservePersistence(envelope)) {
                try {
                    // Body first, then envelope: a crash between the two never leaves a persisted
                    // envelope pointing at a body this node does not have.
                    storage.put(frame.bodyBytes)
                    storage.put(frame.envelopeBytes)
                } catch (e: NabuStorageException) {
                    logger.warn(e) { "failed to persist gossip-received mail from $from - declining to accept it" }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached - NOT a reason to decline the message, mirroring
                // VeritasGossip/KarmaGossip/LtrGossip/MadliGossip's identical reasoning.
                logger.debug {
                    "persistence cap reached - not durably storing mail from $from (still tracking and propagating it)"
                }
            }

            if (!index.add(InboxMessage(envelope, body))) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates.
                logger.debug { "envelope from $from was persisted but lost a narrow index race - propagating anyway" }
            }

            return ValidationResult.Valid
        }
    }
}
