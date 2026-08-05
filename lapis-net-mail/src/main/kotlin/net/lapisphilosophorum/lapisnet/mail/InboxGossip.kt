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
 *  - **No newsletter/subscription model.** Still cut in V0.9.3 - stated explicitly, not an
 *    oversight.
 *  - **No address book, no pubkey-to-name mapping.** Recipients are raw compressed secp256k1 keys.
 *    Still cut in V0.9.3, despite an earlier roadmap draft mentioning it for this sub-wave - see
 *    `docs/roadmap.adoc`'s V0.9.3 section for the explicit carve-out.
 *  - **V0.9.3: thread assembly exists** ([ThreadBuilder]), built from `replyTo` alone -
 *    `threadRoot` is still carried and signed but structurally unused (see [ThreadBuilder]'s class
 *    doc comment for why, and for the non-recursive, cycle-safe traversal it uses).
 *  - **V0.9.3: browser HTTP routes exist** (`lapis-net-browser`'s `GET /api/mail`,
 *    `GET /api/mail/sent`, `GET /api/mail/thread/{cid}`, `POST /api/mail`,
 *    `GET /api/mail/attachment/{cid}`).
 *  - **V0.9.2: `HYBRID_ECIES` is functional; `MLS_ARCHIVE` remains reserved and rejected outright**
 *    - no implementation plan exists for it in this arc. **This validator never decrypts and never
 *    holds a private key** - a positive property, not a limitation: it is only ever given a
 *    [Secp256k1PublicKey] (see [attach]'s `localIdentity` parameter), so private key material
 *    never enters the GossipSub validator, by construction. An accepted `HYBRID_ECIES` message is
 *    indexed as [InboxPayload.Sealed] - decryption is an explicit, later, caller-driven
 *    [HybridEcies.open] call.
 *  - **V0.9.3: attachment encryption exists** ([MailAttachmentCipher], [EncryptedAttachmentBlobCodec])
 *    - but attachment **fetching** over the network is still limited by the same
 *    `NabuStorage.get()`/`Kademlia.dialPeer` gap documented below: a node can only decrypt an
 *    attachment blob it already has locally. [AttachmentRef.size] remains declared, never checked
 *    against the real blob.
 *  - **V0.9.3: no self-delivery, but a local "sent" view now exists** ([SentFolder]). GossipSub
 *    still never delivers a node's own [GossipPubSub.publish] calls to its own
 *    [GossipPubSub.subscribe] handler (see that method's doc comment) - a sender that lists
 *    themself among recipients still never sees the message via gossip in their own inbox; what
 *    changed is that [SentFolder] now gives the sender's own UI a local record of what it sent,
 *    populated by the caller from [MailSender.send]'s own return value, not by gossip.
 *  - **No encrypted full-text search.** Still cut in V0.9.3.
 *  - **No SMTP import gateway.** Still cut in V0.9.3.
 *  - **V0.9.4: spam protection exists** ([MailAcceptancePolicy]) and IS wired into
 *    [onGossipMessage] as an optional, pluggable check ([MailAcceptanceCheck] - `null` by default,
 *    preserving every prior wave's "accept everything addressed to me" behavior exactly). Unlike
 *    Madli's policy objects (V0.5, built but left unwired that wave), this policy actually runs in
 *    the hot path when a caller opts in - see [MailAcceptanceCheck]'s doc comment for the deposit
 *    mechanism's own "not yet on the wire" scope cut.
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
         * [onGossipMessage] for the validator. [acceptance] is `null` by default - see
         * [MailAcceptanceCheck]'s doc comment for what a non-null value opts into.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
            localIdentity: Secp256k1PublicKey,
            acceptance: MailAcceptanceCheck? = null,
        ): InboxGossip {
            val index = InboxIndex()
            val topic = InboxTopics.forRecipient(localIdentity)
            val subscription =
                pubsub.subscribe(topic) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index, localIdentity, acceptance)
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
         *
         * **V0.9.4: [acceptance], when non-null AND [MailAcceptanceCheck.gates] is non-empty, runs
         * [MailAcceptancePolicy.shouldAccept] AFTER the signature/addressing/CID-binding checks
         * below (those are cheap and must reject first) and BEFORE payload decode/dedup/
         * persistence** - a rejected sender costs this node no payload allocation and no
         * index/storage work. The check itself makes zero network calls and zero clock calls, same
         * as every other check in this function: [MailAcceptanceCheck.trustGraph] is an
         * already-built local snapshot (queried through [MailAcceptanceCheck.cachedVeritasPathCheck]
         * - see that method's doc comment for the round-2 audit's BFS-cost finding and the
         * per-`(localIdentity, candidate)` memoization this wave added to address it),
         * [MailAcceptanceCheck.karmaScoreOf] is a pure local lookup the caller supplies, and
         * [MailAcceptanceCheck.depositLookup] is a pure local lookup too (see that class's doc
         * comment on why the deposit itself is not yet carried on the wire this wave).
         *
         * **`acceptance.gates.isEmpty()` (a non-null [MailAcceptanceCheck] configured with
         * [MailAcceptancePolicy.ACCEPT_ALL]) is checked HERE, not left to
         * [MailAcceptancePolicy.shouldAccept]'s own internal short-circuit** - round-2 security
         * audit finding, V0.9.4 hardening: `shouldAccept`'s short-circuit runs too late to keep
         * this branch's documented "zero cost for accept-all" property, because
         * [MailAcceptanceCheck.depositLookup] is evaluated as a plain Kotlin call argument BEFORE
         * `shouldAccept` is even entered, regardless of what `shouldAccept` does with it. See the
         * guard below for the fix.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: InboxIndex,
            localIdentity: Secp256k1PublicKey,
            acceptance: MailAcceptanceCheck? = null,
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
            // rejects MLS_ARCHIVE), kept so a future codec change can never silently let a
            // reserved mode through this validator without this function also changing.
            if (envelope.encryption == EncryptionMode.MLS_ARCHIVE) {
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

            // cidFor is a pure function of raw bytes - this check is unchanged and correct for
            // BOTH EncryptionMode.NONE (frame.bodyBytes is a plaintext MessageBody blob) and
            // EncryptionMode.HYBRID_ECIES (frame.bodyBytes is a SealedBody blob). The name reads
            // slightly misleadingly for the sealed case, but the binding it enforces is identical.
            if (MessageBodyCodec.cidFor(frame.bodyBytes) != envelope.contentCid) {
                logger.debug { "rejected envelope from $from whose contentCid does not match the frame's body" }
                return ValidationResult.Invalid
            }

            // acceptance.gates.isEmpty() is checked HERE, before calling shouldAccept, not just
            // inside it - see MailAcceptanceCheck's doc comment and the round-2 security audit
            // finding it documents: shouldAccept(...)'s own internal gates.isEmpty() short-circuit
            // is too late to keep this branch's "zero cost for accept-all" property, because Kotlin
            // evaluates every call argument (in particular acceptance.depositLookup(envelope),
            // which a real deployment's application layer may back with actual lookup work) BEFORE
            // the call happens - an empty-gates node running a non-null MailAcceptanceCheck used to
            // pay depositLookup's cost on every single message despite never being able to reject
            // one. Guarding here means an empty-gates check now costs exactly what a `null`
            // acceptance costs: one boolean check, no depositLookup call, no cache lookup.
            if (acceptance != null && acceptance.gates.isNotEmpty()) {
                val decision =
                    MailAcceptancePolicy.shouldAccept(
                        recipient = localIdentity,
                        envelope = envelope,
                        hasVeritasPath = acceptance.cachedVeritasPathCheck(localIdentity),
                        karmaScoreOf = acceptance.karmaScoreOf,
                        gates = acceptance.gates,
                        minDepositMsat = acceptance.minDepositMsat,
                        deposit = acceptance.depositLookup(envelope),
                    )
                if (decision is MailAcceptanceDecision.Reject) {
                    logger.debug { "rejected envelope from $from by mail acceptance policy: ${decision.reason}" }
                    return ValidationResult.Invalid
                }
            }

            val payload =
                try {
                    when (envelope.encryption) {
                        EncryptionMode.NONE -> InboxPayload.Plaintext(MessageBodyCodec.decode(frame.bodyBytes))
                        EncryptionMode.HYBRID_ECIES -> InboxPayload.Sealed(SealedBodyCodec.decode(frame.bodyBytes))
                        EncryptionMode.MLS_ARCHIVE -> return ValidationResult.Invalid // unreachable, checked above
                    }
                } catch (e: MalformedMessageBodyException) {
                    logger.debug(e) { "rejected structurally malformed body from $from" }
                    return ValidationResult.Invalid
                } catch (e: MalformedSealedBodyException) {
                    logger.debug(e) { "rejected structurally malformed sealed body from $from" }
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

            if (!index.add(InboxMessage(envelope, payload))) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates.
                logger.debug { "envelope from $from was persisted but lost a narrow index race - propagating anyway" }
            }

            return ValidationResult.Valid
        }
    }
}
