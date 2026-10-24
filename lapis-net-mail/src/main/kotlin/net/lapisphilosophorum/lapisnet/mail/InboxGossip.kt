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
 *  - **No DHT inbox record - but since V0.9.14 a DHT fallback for the POINTER.** This validator and the
 *    frame stay gossip-only (the frame carries the body; see below). A node offline during the gossip window
 *    can learn of a mail through the DHT outbox of the sender (`InboxDhtFetcher`), which fetches envelope and
 *    body and ingests them through [checkEnvelope]/[ingestChecked] - the two halves of this validator, shared.
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
 *    `NabuStorage.get()`/`Kademlia.dialPeer` gap (repaired in V0.9.8) documented below: a node can
 *    only decrypt an attachment blob it already has locally. [AttachmentRef.size] remains declared, never checked
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
 * local miss, forbidden inside a validator; and provider discovery was documented broken until V0.9.8).
 */
class InboxGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val localIdentity: Secp256k1PublicKey,
    private val index: InboxIndex,
    private val subscription: PubsubSubscription?,
    private val acceptanceRef: AcceptanceRef,
) {
    /** The GossipSub topic this instance is subscribed to - [InboxTopics.forRecipient] applied to
     * the identity this instance was [attach]ed for. */
    val topic: String = InboxTopics.forRecipient(localIdentity)

    /**
     * `false` for an instance built by [attachAnonymous]: it holds the same acceptance policy and index but never
     * subscribed to the per-recipient inbox topic, so nothing about it is visible on the gossip network.
     */
    val subscribed: Boolean get() = subscription != null

    /** All tracked inbox messages, oldest first. */
    fun messages(): List<InboxMessage> = index.latest()

    /** All tracked inbox messages from [sender], oldest first. */
    fun messagesFrom(sender: Secp256k1PublicKey): List<InboxMessage> = index.messagesFrom(sender)

    /**
     * V0.9.14: the envelope-only checks of this instance, with its own acceptance policy - used by the DHT
     * fetcher so the policy cannot be wired differently for that path. See [checkEnvelope].
     */
    internal fun dhtCheckEnvelope(envelopeBytes: ByteArray): EnvelopeCheck =
        checkEnvelope(envelopeBytes, localIdentity, acceptanceRef.value, null, "the DHT")

    /**
     * Replaces the acceptance policy of BOTH entry paths (gossip validator and DHT fetcher) atomically; takes
     * effect from the next message. `null` disables filtering. Mirrors `MailboxGossip.updateAcceptanceCheck`.
     */
    fun updateAcceptanceCheck(check: MailAcceptanceCheck?) {
        acceptanceRef.value = check
    }

    /** The currently installed acceptance policy, or `null`. */
    fun currentAcceptanceCheck(): MailAcceptanceCheck? = acceptanceRef.value

    /** V0.9.14: [ingestChecked] with this instance's storage and index. */
    internal fun dhtIngest(
        envelope: MessageEnvelope,
        envelopeBytes: ByteArray,
        bodyBytes: ByteArray,
    ): InboxIngestOutcome = ingestChecked(envelope, envelopeBytes, bodyBytes, storage, index, "the DHT")

    /** Whether this inbox already tracks [envelope] (e.g. it arrived by gossip). */
    internal fun alreadyHas(envelope: MessageEnvelope): Boolean = !index.canAccept(envelope)

    /** Unsubscribes from the inbox topic. No other sub-resources to release - mirrors
     * `net.lapisphilosophorum.lapisnet.trust.VeritasGossip.stop` exactly. */
    fun stop() {
        subscription?.unsubscribe()
    }

    /**
     * V0.10.0-F2: the single entrance of mail that arrived over circuits (rendezvous stream or sealed item). It runs
     * exactly the stages of the gossip validator: frame decode (the caller bounds the size), [checkEnvelope] with the
     * live acceptance policy (read per message) and [ingestChecked], with the same contact bypass and the same
     * [InboxIndex] duplicate suppression. Never throws; the outcome is for the caller's counters only and must not be
     * reported to the sender.
     */
    internal fun anonymousIngest(frameBytes: ByteArray): InboxIngestOutcome = anonymousIngestMessage(frameBytes).first

    /** [anonymousIngest] that also returns the indexed message when the mail was accepted. */
    internal fun anonymousIngestMessage(frameBytes: ByteArray): Pair<InboxIngestOutcome, InboxMessage?> {
        val frame =
            try {
                MailFrameCodec.decode(frameBytes)
            } catch (e: MalformedMailFrameException) {
                logger.debug { "rejected structurally malformed mail frame from a circuit" }
                return InboxIngestOutcome.INVALID to null
            }
        val check = checkEnvelope(frame.envelopeBytes, localIdentity, acceptanceRef.value, frame.bodyBytes, "a circuit")
        val envelope =
            when (check) {
                is EnvelopeCheck.Passed -> check.envelope
                is EnvelopeCheck.Failed -> return InboxIngestOutcome.INVALID to null
            }
        val outcome =
            ingestChecked(
                envelope,
                frame.envelopeBytes,
                frame.bodyBytes,
                storage,
                index,
                "a circuit",
                true,
                serveable = false,
            )
        val message =
            if (outcome == InboxIngestOutcome.ACCEPTED) index.latest().lastOrNull { it.envelope == envelope } else null
        return outcome to message
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
            // Read on every message (never captured as a value): see updateAcceptanceCheck.
            val acceptanceRef = AcceptanceRef(acceptance)
            val subscription =
                pubsub.subscribe(topic) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index, localIdentity, acceptanceRef.value)
                }
            return InboxGossip(pubsub, storage, localIdentity, index, subscription, acceptanceRef)
        }

        /**
         * V0.10.0-F2: anonymity mode. Same instance shape as [attach] (same index, same live acceptance policy, same
         * [checkEnvelope]/[ingestChecked]) but it does NOT subscribe to the per-recipient inbox topic: a topic named
         * after the recipient's key would tie the node's network position to its mail identity. Mail arrives only via
         * [anonymousIngest].
         */
        fun attachAnonymous(
            pubsub: GossipPubSub,
            storage: NabuStorage,
            localIdentity: Secp256k1PublicKey,
            acceptance: MailAcceptanceCheck? = null,
        ): InboxGossip = InboxGossip(pubsub, storage, localIdentity, InboxIndex(), null, AcceptanceRef(acceptance))

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

            // cidFor is a pure function of raw bytes - the content-CID binding is checked inside checkEnvelope
            // (given the body) at the same position in the order as ever: after the signature, before the policy.
            val check =
                checkEnvelope(frame.envelopeBytes, localIdentity, acceptance, frame.bodyBytes, "peer $from")
            val envelope =
                when (check) {
                    is EnvelopeCheck.Passed -> check.envelope
                    is EnvelopeCheck.Failed -> return ValidationResult.Invalid
                }
            return when (
                ingestChecked(envelope, frame.envelopeBytes, frame.bodyBytes, storage, index, "peer $from", true)
            ) {
                InboxIngestOutcome.ACCEPTED -> ValidationResult.Valid
                InboxIngestOutcome.DUPLICATE, InboxIngestOutcome.INVALID, InboxIngestOutcome.PERSIST_FAILED ->
                    ValidationResult.Invalid
            }
        }

        /**
         * Everything that can be decided from the envelope alone (V0.9.14: shared by the gossip validator and
         * the DHT fetcher): decode -> reserved mode -> addressed to [localIdentity] -> signature -> (only when
         * [bodyBytes] is given) content-CID binding -> acceptance policy. The DHT path calls it without the
         * body: the policy then runs BEFORE the body is ever fetched. No clock, no network.
         */
        internal fun checkEnvelope(
            envelopeBytes: ByteArray,
            localIdentity: Secp256k1PublicKey,
            acceptance: MailAcceptanceCheck?,
            bodyBytes: ByteArray? = null,
            source: String = "unknown",
        ): EnvelopeCheck {
            val envelope =
                try {
                    MessageEnvelopeCodec.decode(envelopeBytes)
                } catch (e: MalformedMessageEnvelopeException) {
                    logger.debug(e) { "rejected structurally malformed envelope from $source" }
                    return EnvelopeCheck.Failed("malformed envelope")
                }

            // Belt-and-braces: unreachable via the decode() path above today (decode() already
            // rejects MLS_ARCHIVE), kept so a future codec change can never silently let a
            // reserved mode through this validator without this function also changing.
            if (envelope.encryption == EncryptionMode.MLS_ARCHIVE) {
                logger.debug { "rejected envelope from $source with reserved encryption mode ${envelope.encryption}" }
                return EnvelopeCheck.Failed("reserved encryption mode")
            }

            if (!envelope.isAddressedTo(localIdentity)) {
                logger.debug {
                    "dropping envelope from $source on ${InboxTopics.forRecipient(localIdentity)} that is not " +
                        "addressed to this identity - not persisting, not indexing, not re-propagating"
                }
                return EnvelopeCheck.Failed("not addressed to this identity")
            }

            if (!MessageEnvelope.verify(envelope)) {
                logger.debug { "rejected signature-invalid envelope from $source" }
                return EnvelopeCheck.Failed("signature invalid")
            }

            // Valid for BOTH EncryptionMode.NONE (a plaintext MessageBody blob) and
            // EncryptionMode.HYBRID_ECIES (a SealedBody blob): the binding it enforces is identical.
            if (bodyBytes != null && MessageBodyCodec.cidFor(bodyBytes) != envelope.contentCid) {
                logger.debug { "rejected envelope from $source whose contentCid does not match the frame's body" }
                return EnvelopeCheck.Failed("content cid mismatch")
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
                        isAcceptedContact = acceptance.isAcceptedContact,
                    )
                if (decision is MailAcceptanceDecision.Reject) {
                    // The one place a policy reject is counted, so gossip and DHT behave identically.
                    // reason only names gates (never keys or content).
                    acceptance.notifyRejected(decision)
                    logger.debug { "rejected envelope from $source by mail acceptance policy: ${decision.reason}" }
                    return EnvelopeCheck.Failed("acceptance policy: ${decision.reason}")
                }
            }
            return EnvelopeCheck.Passed(envelope)
        }

        /**
         * The second half (V0.9.14: shared by gossip and the DHT fetcher), for an envelope that passed
         * [checkEnvelope]: content-CID binding (skipped when [cidChecked]) -> payload decode -> dedup -> persist
         * (body first, then envelope) -> index.
         */
        internal fun ingestChecked(
            envelope: MessageEnvelope,
            envelopeBytes: ByteArray,
            bodyBytes: ByteArray,
            storage: NabuStorage,
            index: InboxIndex,
            source: String,
            cidChecked: Boolean = false,
            serveable: Boolean = true,
        ): InboxIngestOutcome {
            if (!cidChecked && MessageBodyCodec.cidFor(bodyBytes) != envelope.contentCid) {
                logger.debug { "rejected envelope from $source whose contentCid does not match the body" }
                return InboxIngestOutcome.INVALID
            }

            val payload =
                try {
                    when (envelope.encryption) {
                        EncryptionMode.NONE -> InboxPayload.Plaintext(MessageBodyCodec.decode(bodyBytes))
                        EncryptionMode.HYBRID_ECIES -> InboxPayload.Sealed(SealedBodyCodec.decode(bodyBytes))
                        EncryptionMode.MLS_ARCHIVE -> return InboxIngestOutcome.INVALID // unreachable
                    }
                } catch (e: MalformedMessageBodyException) {
                    logger.debug(e) { "rejected structurally malformed body from $source" }
                    return InboxIngestOutcome.INVALID
                } catch (e: MalformedSealedBodyException) {
                    logger.debug(e) { "rejected structurally malformed sealed body from $source" }
                    return InboxIngestOutcome.INVALID
                }

            if (!index.canAccept(envelope)) {
                logger.debug {
                    "declining duplicate (already-tracked) envelope from $source - not persisting or re-propagating"
                }
                return InboxIngestOutcome.DUPLICATE
            }

            if (index.tryReservePersistence(envelope)) {
                try {
                    // Body first, then envelope: a crash between the two never leaves a persisted
                    // envelope pointing at a body this node does not have.
                    // mail received over a circuit is kept in the unserved store: Bitswap must not reveal acceptance
                    if (serveable) {
                        storage.put(bodyBytes)
                        storage.put(envelopeBytes)
                    } else {
                        storage.putUnserved(bodyBytes)
                        storage.putUnserved(envelopeBytes)
                    }
                } catch (e: NabuStorageException) {
                    // Backported from MailboxGossip's identical fix (V0.8.5 security audit
                    // finding): release the reservation on failure - tryReservePersistence already
                    // inserted the content id into the never-evicting persistedContentIds set, so
                    // leaving it in place here would permanently burn a slot for an envelope that
                    // ends up neither persisted nor tracked. See
                    // InboxIndex.releaseReservedPersistence's own doc comment.
                    //
                    // Partial-failure case, thought through explicitly: if storage.put(bodyBytes)
                    // above already succeeded and ONLY storage.put(envelopeBytes) throws, the body
                    // blob is now durably stored even though this envelope is being rejected here -
                    // an orphaned blob with no envelope ever pointing at it. This is accepted,
                    // deliberately not fixed by this backport: Nabu has no pin/GC in this project
                    // (see NabuStorage's own scope), so an orphaned blob is not a NEW class of
                    // problem this change introduces - it is exactly as inert as any other
                    // unreferenced blob this node may already hold. The bug this backport actually
                    // fixes - the never-evicting persistence-reservation slot leak - is fully closed
                    // by releasing the reservation below regardless of which of the two put() calls
                    // failed.
                    index.releaseReservedPersistence(envelope)
                    logger.warn(e) { "failed to persist received mail from $source - declining to accept it" }
                    return InboxIngestOutcome.PERSIST_FAILED
                }
            } else {
                // Persistence cap reached - NOT a reason to decline the message, mirroring
                // VeritasGossip/KarmaGossip/LtrGossip/MadliGossip's identical reasoning.
                logger.debug {
                    "persistence cap reached - not durably storing mail from $source (still tracking and propagating it)"
                }
            }

            if (!index.add(InboxMessage(envelope, payload))) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates.
                logger.debug { "envelope from $source was persisted but lost a narrow index race - propagating anyway" }
            }

            return InboxIngestOutcome.ACCEPTED
        }
    }
}

/** Holder for the live acceptance policy; read once per message. */
internal class AcceptanceRef(
    @Volatile var value: MailAcceptanceCheck?,
)

/** Result of [InboxGossip.checkEnvelope]. */
internal sealed interface EnvelopeCheck {
    data class Passed(
        val envelope: MessageEnvelope,
    ) : EnvelopeCheck

    data class Failed(
        val reason: String,
    ) : EnvelopeCheck
}

/** Result of [InboxGossip.ingestChecked]. */
internal enum class InboxIngestOutcome { ACCEPTED, DUPLICATE, INVALID, PERSIST_FAILED }
