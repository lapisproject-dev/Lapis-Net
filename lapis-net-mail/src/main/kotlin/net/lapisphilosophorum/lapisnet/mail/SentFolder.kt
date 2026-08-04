package net.lapisphilosophorum.lapisnet.mail

/**
 * Local-only bookkeeping of [SentMessage]s this identity has authored via [MailSender.send] -
 * never gossiped, never networked. Closes V0.9.1's documented gap ("no self-delivery... a local
 * 'sent' view is V0.9.3", see [InboxGossip]/[MailSender]'s class doc comments).
 *
 * **Population is the CALLER's responsibility.** [MailSender.send] has no reference to this class
 * and never populates one implicitly - a caller (e.g. `POST /api/mail`'s route handler in
 * `lapis-net-browser`) must explicitly [add] the [SentMessage] [MailSender.send] returns. This
 * mirrors [MailSender]'s existing, deliberate decoupling from any particular index.
 *
 * **Deliberately ONE cap, not [InboxIndex]'s two** - a documented divergence from a literal reading
 * of this class's own spec, mirroring [MailFrameCodec]'s own precedent for stating such a
 * departure explicitly rather than silently deviating. [InboxIndex]'s SEPARATE persistence-
 * reservation cap exists to GATE `NabuStorage.put()` against an ATTACKER's unbounded gossip flood.
 * [add] is only ever called AFTER [MailSender.send] has already unconditionally, successfully
 * persisted the body and envelope - by the time [add] runs there is nothing left to gate; a second
 * cap here would bound only this class's own bookkeeping of which content ids it considers
 * "reserved", with zero actual gating effect on any storage call. A single evicting tracking cap,
 * mirroring [InboxIndex]'s `messagesByContentId` LRU-ish eviction shape, is the honest mechanism
 * for what this class actually needs to bound: its own in-memory footprint.
 */
class SentFolder internal constructor(
    private val maxTracked: Int = MAX_TRACKED_SENT_MESSAGES,
) {
    /** Public entry point - always uses [MAX_TRACKED_SENT_MESSAGES]. The internal constructor
     * above exists purely as a test seam, mirroring [InboxIndex]'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_SENT_MESSAGES)

    /** Backed by a [LinkedHashMap] with access-order tracking enabled, exactly mirroring
     * [InboxIndex]'s `messagesByContentId` - see that field's doc comment for why this is
     * FIFO-equivalent in practice, not true LRU. Keyed by [MailContentId] (`envelope.contentId()`),
     * reusing that package-internal type directly rather than duplicating it. */
    private val sentByContentId =
        object : LinkedHashMap<MailContentId, SentMessage>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<MailContentId, SentMessage>): Boolean =
                size > maxTracked
        }

    /** Adds [sent] to this folder. Returns `true` iff it was newly added; `false` for a duplicate
     * (by envelope content id) - never throws. */
    @Synchronized
    fun add(sent: SentMessage): Boolean {
        val id = MailContentId(sent.envelope.contentId())
        if (sentByContentId.containsKey(id)) return false
        sentByContentId[id] = sent
        return true
    }

    /** All tracked sent messages, oldest first (insertion order) - a defensive copy. */
    @Synchronized
    fun latest(): List<SentMessage> = sentByContentId.values.toList()

    /** Number of currently-tracked sent messages. */
    @Synchronized
    fun size(): Int = sentByContentId.size

    companion object {
        /** Mirrors [InboxIndex.MAX_TRACKED_MESSAGES]'s sizing rationale unchanged. */
        const val MAX_TRACKED_SENT_MESSAGES = 8_000
    }
}

/** A [SentMessage]'s body is always the local sender's own already-plaintext [MessageBody], even
 * for a [EncryptionMode.HYBRID_ECIES] send (see [SentMessage]'s own doc comment) - so this adapter
 * needs no decryption. Lets [ThreadBuilder] and the browser routes treat inbox and sent items
 * uniformly as [InboxMessage]s. */
fun SentMessage.toInboxMessage(): InboxMessage = InboxMessage(envelope, body)
