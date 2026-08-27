package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps a [MessageEnvelope.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.GrantContentId` /
 * `net.lapisphilosophorum.lapisnet.virtus.LtrContentId` exactly, duplicated locally rather than
 * reused: even though this module gained a dependency edge to `lapis-net-trust` in V0.9.4 (see
 * this module's `build.gradle.kts` comment), `GrantContentId` itself is `internal` to that module
 * and not exposed for reuse - the duplication reasoning stands independent of the dependency edge.
 * Internal: only [InboxIndex] (same package) needs this.
 */
internal data class MailContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is MailContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/** What an accepted inbox message actually carries. V0.9.2: encrypted mail stays SEALED in the
 * index - [InboxGossip]'s validator holds only a public key and deliberately never decrypts (see
 * that class's doc comment). Call [HybridEcies.open] explicitly, with a keypair, to read a
 * [Sealed] payload. */
sealed interface InboxPayload {
    class Plaintext(
        val body: MessageBody,
    ) : InboxPayload

    class Sealed(
        val sealedBody: SealedBody,
    ) : InboxPayload
}

/** One accepted inbox message: the verified envelope plus its [InboxPayload] - either the
 * plaintext [MessageBody] ([EncryptionMode.NONE]) or a still-[SealedBody]
 * ([EncryptionMode.HYBRID_ECIES]). See [InboxPayload]'s doc comment for why encrypted mail is
 * never decrypted at this layer. */
class InboxMessage(
    val envelope: MessageEnvelope,
    val payload: InboxPayload,
) {
    /** Source-compatibility convenience for [EncryptionMode.NONE] messages - `null` when the
     * payload is still [InboxPayload.Sealed]. */
    val body: MessageBody? get() = (payload as? InboxPayload.Plaintext)?.body

    constructor(envelope: MessageEnvelope, body: MessageBody) : this(envelope, InboxPayload.Plaintext(body))

    constructor(envelope: MessageEnvelope, sealedBody: SealedBody) : this(envelope, InboxPayload.Sealed(sealedBody))
}

/**
 * Bounded, in-memory index of [InboxMessage]s accepted by [InboxGossip]'s validator, keyed by
 * envelope content id and by sender. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex`'s two-cap eviction/persistence
 * structure precisely (see that class's doc comment for the full round-2/round-3 reasoning this is
 * copied from: an evicting in-memory tracking cap for the live view, plus a SEPARATE, non-evicting
 * persistence-reservation cap, because tracking and durable persistence are different resources
 * with different correct policies).
 *
 * **Sizing note - smaller absolute numbers than the trust/virtus/madli modules' 64,000, not an
 * inconsistency.** A mail message's blob is up to ~48 KB
 * ([MessageBodyCodec.MAX_BODY_BLOB_SIZE]-ish) versus a Veritas grant's ~2 KB - an equal count
 * would be a roughly 25x larger disk/heap budget. [MAX_TRACKED_MESSAGES]/[MAX_PERSISTED_MESSAGES]
 * are provisional, chosen for a personal-node inbox scale, and should be revisited against real
 * usage - the same "provisional magnitude" caveat `LtrRecordIndex.MAX_TRACKED_RECORDS` documents.
 *
 * **Informational, round-2 security audit finding (V0.9.4 hardening) - post-eviction
 * re-admission of a verbatim-replayed identical message is possible and accepted.**
 * [messagesByContentId] evicts its oldest entry once [maxTracked] ([MAX_TRACKED_MESSAGES]) is
 * exceeded (see that field's doc comment). Once a message's entry has been evicted, an exact,
 * byte-for-byte replay of the SAME already-delivered envelope (identical signature, identical
 * `contentId`, gossiped again verbatim - not a forgery, not a different message from the same
 * sender) passes [canAccept] again (the content id is no longer tracked) and is re-admitted:
 * re-persisted via [tryReservePersistence] (idempotent - a no-op if [persistedContentIds] still
 * has it) and re-added to the live index. **Confirmed correct characterization: this is
 * RE-DELIVERY of a message this node already legitimately accepted once, not admission of a NEW
 * or DIFFERENT message** - the sender did nothing to earn a second acceptance, the same signature
 * that was valid the first time is simply valid again, and any spam-acceptance gate
 * ([MailAcceptancePolicy]/[MailAcceptanceCheck]) that would have accepted this sender once
 * continues to hold. This applies uniformly to every already-trusted sender (Veritas-gated,
 * Karma-gated, or deposit-admitted) - it is not a way to bypass any gate, only a way to see one
 * already-accepted message a second time after the tracking cap has rotated it out. No functional
 * fix is planned for this item: it is an accepted consequence of [messagesByContentId] being a
 * BOUNDED, evicting index rather than a permanent record of every content id ever seen, the same
 * tradeoff `VeritasGrantIndex.grantsByContentId` already accepts (see this class's own doc comment
 * on why the eviction/persistence split mirrors that class precisely).
 */
class InboxIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_MESSAGES,
    private val maxPersisted: Int = MAX_PERSISTED_MESSAGES,
) {
    /** Public entry point - always uses [MAX_TRACKED_MESSAGES]/[MAX_PERSISTED_MESSAGES]. The
     * internal constructor above exists purely as a test seam, mirroring
     * `VeritasGrantIndex`'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_MESSAGES, MAX_PERSISTED_MESSAGES)

    private val messagesBySender = HashMap<Secp256k1PublicKey, MutableList<InboxMessage>>()

    /** Backed by a [LinkedHashMap] with access-order tracking enabled, exactly mirroring
     * `VeritasGrantIndex.grantsByContentId` - see that field's doc comment for why this is
     * FIFO-equivalent in practice, not true LRU. */
    private val messagesByContentId =
        object : LinkedHashMap<MailContentId, InboxMessage>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<MailContentId, InboxMessage>): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                val sender = evicted.envelope.sender
                val bucket = messagesBySender[sender]
                bucket?.remove(evicted)
                if (bucket != null && bucket.isEmpty()) messagesBySender.remove(sender)
                return true
            }
        }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * `VeritasGrantIndex.persistedContentIds` exactly. */
    private val persistedContentIds = HashSet<MailContentId>()

    /**
     * Adds [message] to the index. Returns `true` iff it was newly added; `false` for a duplicate
     * (by envelope content id) or a signature-invalid envelope - **never throws**, mirroring
     * `VeritasGrantIndex.add`'s "last line of defense before untrusted gossip data reaches this
     * node's in-memory state" contract, including the defensive re-verification of the envelope's
     * signature.
     */
    @Synchronized
    fun add(message: InboxMessage): Boolean =
        runCatching {
            if (!MessageEnvelope.verify(message.envelope)) return@runCatching false
            val id = MailContentId(message.envelope.contentId())
            if (messagesByContentId.containsKey(id)) return@runCatching false
            messagesByContentId[id] = message
            messagesBySender.getOrPut(message.envelope.sender) { mutableListOf() }.add(message)
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [envelope] is not already
     * tracked by content id. Mirrors `VeritasGrantIndex.canAccept`'s dedup-only contract exactly -
     * see that method's doc comment for why this alone does not bound durable persistence
     * (post-eviction there is no "index is full" case for this to report; that is what
     * [tryReservePersistence] exists for, as a separate, non-evicting cap).
     */
    @Synchronized
    fun canAccept(envelope: MessageEnvelope): Boolean =
        !messagesByContentId.containsKey(MailContentId(envelope.contentId()))

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [messagesByContentId]'s evicting
     * cap. Mirrors `VeritasGrantIndex.tryReservePersistence`'s contract exactly, including atomic
     * reserve-before-put semantics (single `@Synchronized` check-and-commit) and idempotency per
     * content id. Not rolled back if the caller's subsequent `NabuStorage.put()` throws - same
     * deliberate, bounded-cost tradeoff as that method.
     */
    @Synchronized
    fun tryReservePersistence(envelope: MessageEnvelope): Boolean {
        val id = MailContentId(envelope.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** Releases a reservation [tryReservePersistence] granted, WITHOUT the corresponding
     * `storage.put` ever actually succeeding - backported from
     * `net.lapisphilosophorum.lapisnet.dm.MailboxPointerIndex.releaseReservedPersistence`
     * (V0.8.5 security audit finding): [tryReservePersistence] permanently inserts into the
     * never-evicting [persistedContentIds] the moment it is called, so a caller that reserves and
     * then has the actual durable write fail (e.g. `NabuStorageException`) previously burned one
     * of [maxPersisted] slots forever, for an envelope that ended up neither persisted NOR
     * tracked - [InboxGossip.onGossipMessage] is the only caller. No-op if [envelope]'s content id
     * was never reserved (or was already released) - safe to call defensively. */
    @Synchronized
    fun releaseReservedPersistence(envelope: MessageEnvelope) {
        persistedContentIds.remove(MailContentId(envelope.contentId()))
    }

    /** All tracked messages, oldest first (insertion order) - a defensive copy. */
    @Synchronized
    fun latest(): List<InboxMessage> = messagesByContentId.values.toList()

    /** All tracked messages from [sender], insertion order - a defensive copy. */
    @Synchronized
    internal fun messagesFrom(sender: Secp256k1PublicKey): List<InboxMessage> =
        messagesBySender[sender]?.toList() ?: emptyList()

    /** Every distinct sender with at least one tracked message. */
    @Synchronized
    internal fun senders(): Set<Secp256k1PublicKey> = messagesBySender.keys.toSet()

    /** Number of currently-tracked messages. */
    @Synchronized
    internal fun size(): Int = messagesByContentId.size

    companion object {
        /** See this class's doc comment for the sizing rationale (smaller than the trust/virtus/
         * madli modules' 64,000, because a mail blob is much larger than a grant/record/vote). */
        const val MAX_TRACKED_MESSAGES = 8_000

        /** See [tryReservePersistence] and this class's doc comment. Same provisional-magnitude
         * caveat as [MAX_TRACKED_MESSAGES] applies. */
        const val MAX_PERSISTED_MESSAGES = 8_000
    }
}
