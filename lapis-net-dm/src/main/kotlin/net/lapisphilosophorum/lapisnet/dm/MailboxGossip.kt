package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.directory.OutboxEntry
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryConsumer
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.OutboxIngestOutcome
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
    private val storage: NabuStorage,
    private val localIdentity: Secp256k1PublicKey,
    private val acceptanceRef: AcceptanceRef,
) {
    /**
     * V0.9.15 - replaces the acceptance policy of **both** entry paths (the GossipSub validator and
     * [dhtConsumer]) at once, because both read this one reference on every call instead of capturing a value at
     * [attach] time. Pairs with [DmSessionManager.updateAcceptanceCheck]: a caller that rebuilds its policy
     * (e.g. after the trust graph changed) hands the same new instance to both.
     */
    fun updateAcceptanceCheck(check: DmAcceptanceCheck?) {
        acceptanceRef.value = check
    }

    /** The check currently in effect for both entry paths (diagnostics and wiring tests). */
    fun currentAcceptanceCheck(): DmAcceptanceCheck? = acceptanceRef.value

    /**
     * The consumer of DHT outbox entries of kind [OutboxEntryKind.DM_MAILBOX_POINTER] (V0.9.14): register it with
     * `DirectoryDht.registerOutboxConsumer`. It shares this instance's index, storage and **the same
     * [DmAcceptanceCheck] as the gossip validator**, so the acceptance policy cannot be wired differently for
     * the DHT path. It only fills the index - the unchanged [MailboxPoller] does the fetching.
     */
    fun dhtConsumer(): OutboxEntryConsumer =
        OutboxEntryConsumer { sender, _, entry ->
            onDhtEntry(sender, entry, storage, index, localIdentity, acceptanceRef.value)
        }

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
            /** V0.8.6 - see [DmAcceptanceCheck]'s own doc comment. `null` (the default) preserves
             * V0.8.5's behavior exactly: every pointer addressed to this identity is accepted. */
            acceptance: DmAcceptanceCheck? = null,
        ): MailboxGossip {
            val index = MailboxPointerIndex()
            val topic = MailboxTopics.forRecipient(localIdentity)
            // Read on every message (never captured as a value): see updateAcceptanceCheck.
            val acceptanceRef = AcceptanceRef(acceptance)
            val subscription =
                pubsub.subscribe(topic) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index, localIdentity, acceptanceRef.value)
                }
            return MailboxGossip(index, subscription, storage, localIdentity, acceptanceRef)
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
            acceptance: DmAcceptanceCheck? = null,
        ): ValidationResult {
            val pointer =
                try {
                    MailboxPointerCodec.decode(bytes)
                } catch (e: MalformedMailboxPointerException) {
                    logger.debug(e) { "rejected structurally malformed mailbox pointer from $from" }
                    return ValidationResult.Invalid
                }
            return when (ingestPointer(pointer, bytes, storage, index, localIdentity, acceptance, "peer $from")) {
                PointerIngestOutcome.ACCEPTED -> ValidationResult.Valid
                PointerIngestOutcome.DUPLICATE, PointerIngestOutcome.REJECTED, PointerIngestOutcome.PERSIST_FAILED ->
                    ValidationResult.Invalid
            }
        }

        /**
         * The DHT entry point (V0.9.14). The header of the outbox entry is only a transport wrapper: the
         * payload is a full signed [MailboxPointer] and goes through exactly the checks of the gossip path
         * ([ingestPointer]), after these additional ones that bind the pointer to the value it came in:
         * the entry has the right kind, [sender] (the identity of the signed directory value) is the pointer's
         * sender (so nobody can re-publish somebody else's pointer under their own value), the pointer and the
         * entry agree on recipient and expiry.
         *
         * Same invariant as the gossip validator: no clock, no network, nothing published or forwarded.
         */
        internal fun onDhtEntry(
            sender: Secp256k1PublicKey,
            entry: OutboxEntry,
            storage: NabuStorage,
            index: MailboxPointerIndex,
            localIdentity: Secp256k1PublicKey,
            acceptance: DmAcceptanceCheck? = null,
        ): OutboxIngestOutcome {
            if (entry.kind != OutboxEntryKind.DM_MAILBOX_POINTER) return OutboxIngestOutcome.REJECTED
            val payload = entry.payload
            val pointer =
                try {
                    MailboxPointerCodec.decode(payload)
                } catch (e: MalformedMailboxPointerException) {
                    logger.debug(e) { "rejected structurally malformed DHT mailbox pointer" }
                    return OutboxIngestOutcome.REJECTED
                }
            if (pointer.senderIdentity != sender ||
                pointer.recipientIdentity != entry.recipient ||
                entry.recipient != localIdentity ||
                pointer.notValidAfterEpochSecond != entry.notValidAfterEpochSecond
            ) {
                logger.debug { "rejected a DHT mailbox pointer that does not match its outbox entry" }
                return OutboxIngestOutcome.REJECTED
            }
            return when (ingestPointer(pointer, payload, storage, index, localIdentity, acceptance, "the DHT")) {
                PointerIngestOutcome.ACCEPTED -> OutboxIngestOutcome.ACCEPTED
                PointerIngestOutcome.DUPLICATE -> OutboxIngestOutcome.DUPLICATE
                PointerIngestOutcome.REJECTED -> OutboxIngestOutcome.REJECTED
                PointerIngestOutcome.PERSIST_FAILED -> OutboxIngestOutcome.DEFERRED
            }
        }

        /** The mutable holder both entry paths read the current [DmAcceptanceCheck] from. */
        internal class AcceptanceRef(
            @Volatile var value: DmAcceptanceCheck?,
        )

        private enum class PointerIngestOutcome { ACCEPTED, DUPLICATE, REJECTED, PERSIST_FAILED }

        /**
         * The checks both paths share, in the order that was established for gossip: addressed to the local
         * identity -> signature -> acceptance policy -> dedup -> persist -> index (cheapest and most selective
         * first). [source] is for log messages only.
         */
        private fun ingestPointer(
            pointer: MailboxPointer,
            bytes: ByteArray,
            storage: NabuStorage,
            index: MailboxPointerIndex,
            localIdentity: Secp256k1PublicKey,
            acceptance: DmAcceptanceCheck?,
            source: String,
        ): PointerIngestOutcome {
            if (pointer.recipientIdentity != localIdentity) {
                logger.debug {
                    "dropping mailbox pointer from $source on ${MailboxTopics.forRecipient(localIdentity)} that is " +
                        "not addressed to this identity - not persisting, not indexing, not re-propagating"
                }
                return PointerIngestOutcome.REJECTED
            }

            if (!MailboxPointer.verify(pointer)) {
                logger.debug { "rejected signature-invalid mailbox pointer from $source" }
                return PointerIngestOutcome.REJECTED
            }

            // V0.8.6 offline pre-check - see DmAcceptancePolicy's own class doc comment for why this
            // sits HERE (after signature verification, before canAccept/tryReservePersistence: no
            // slot, no persistence cost for a pointer this check would reject). The `gates.isEmpty()`
            // short-circuit is load-bearing, not an optimization: without it, a node running NO
            // filters would still pay pointerDepositLookup's cost on every single pointer - the exact
            // V0.9.4 security-audit-round-2 finding MailAcceptanceCheck's own doc comment documents,
            // reproduced here deliberately rather than re-discovered.
            if (acceptance != null && acceptance.gates.isNotEmpty()) {
                val decision =
                    DmAcceptancePolicy.shouldFetch(
                        sender = pointer.senderIdentity,
                        localRecipient = localIdentity,
                        gates = acceptance.gates,
                        hasVeritasPath = acceptance.cachedVeritasPathCheck(localIdentity),
                        karmaScoreOf = acceptance.karmaScoreOf,
                        isAcceptedContact = acceptance.isAcceptedContact,
                        minDepositMsat = acceptance.minDepositMsat,
                        deposit = acceptance.pointerDepositLookup(pointer),
                        depositBinding = null,
                    )
                if (decision is DmAcceptanceDecision.Reject) {
                    logger.debug {
                        "declining to fetch mailbox pointer from $source claiming sender " +
                            "${pointer.senderIdentity.fingerprint()} - acceptance policy rejected: ${decision.reason}"
                    }
                    return PointerIngestOutcome.REJECTED
                }
            }

            if (!index.canAccept(pointer)) {
                logger.debug {
                    "declining duplicate (already-tracked) mailbox pointer from $source - not persisting or re-propagating"
                }
                return PointerIngestOutcome.DUPLICATE
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
                    ) { "failed to persist received mailbox pointer from $source - declining to accept it" }
                    return PointerIngestOutcome.PERSIST_FAILED
                }
            } else {
                logger.debug {
                    "persistence cap reached - not durably storing mailbox pointer from $source " +
                        "(still tracking and propagating it)"
                }
            }

            if (!index.add(pointer)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates: the pointer was
                // legitimately well-formed at the moment it was checked.
                logger.debug {
                    "mailbox pointer from $source was persisted but lost a narrow index race - propagating anyway"
                }
            }

            return PointerIngestOutcome.ACCEPTED
        }
    }
}
