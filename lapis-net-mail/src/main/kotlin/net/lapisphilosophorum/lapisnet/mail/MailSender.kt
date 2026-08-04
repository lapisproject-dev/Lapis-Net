package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage

/** The result of a [MailSender.send] call: the signed envelope, the decoded body, the body's CID,
 * and the exact frame bytes that were published - kept around so [MailSender.republish] can
 * re-send the identical frame without re-signing or re-storing anything. */
class SentMessage(
    val envelope: MessageEnvelope,
    val body: MessageBody,
    val bodyCid: Cid,
    frameBytes: ByteArray,
) {
    private val storedFrameBytes: ByteArray = frameBytes.copyOf()

    /** Returns a fresh copy on every access. */
    val frameBytes: ByteArray get() = storedFrameBytes.copyOf()
}

/**
 * Builds, signs, persists, and publishes a [MessageEnvelope]/[MessageBody] pair.
 *
 * **No delivery guarantee, and no self-delivery** - see [MailSender.send]'s doc comment.
 */
class MailSender(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
) {
    /**
     * Builds a [MessageBody] from [subject]/[body]/[attachments]/[headers], stores it in
     * [storage], signs a [MessageEnvelope] bound to that blob's CID with [localIdentity], stores
     * the envelope too, then publishes the combined [MailFrameCodec] frame to every recipient's
     * inbox topic ([InboxTopics.forRecipient]).
     *
     * **Load-bearing order** (mirrors `net.lapisphilosophorum.lapisnet.trust.VeritasGossip.announce`'s
     * put-then-index-then-publish ordering, where publish-last is a documented invariant, not an
     * accident): body `put()`, then envelope `put()`, then one `publish()` per recipient, strictly
     * after both puts succeed. A crash mid-sequence therefore never leaves the network believing
     * something this node never durably persisted.
     *
     * **No delivery guarantee.** Like [GossipPubSub.publish] (whose doc comment this defers to for
     * the mechanism), this call can return normally even if the message never reaches a single
     * peer - e.g. immediately after connecting, before GossipSub's mesh has formed. A caller that
     * needs to know whether the message actually propagated must observe that independently (e.g.
     * by polling a recipient's [InboxGossip.messages]), not by this call's return - see
     * [republish].
     *
     * **No self-delivery.** If [recipients] includes [localIdentity]'s own public key, this node
     * will never see the message in its own [InboxGossip]: GossipSub never delivers a node's own
     * [GossipPubSub.publish] calls to its own [GossipPubSub.subscribe] handler (see that method's
     * doc comment). A local "sent" view is V0.9.3.
     *
     * One publish per recipient - an N-recipient message is N publishes of the identical frame.
     */
    fun send(
        localIdentity: Secp256k1KeyPair,
        recipients: List<Secp256k1PublicKey>,
        subject: String,
        body: String,
        attachments: List<AttachmentRef> = emptyList(),
        headers: Map<String, String> = emptyMap(),
        replyTo: Cid? = null,
        threadRoot: Cid? = null,
        sentAtEpochSecond: Long = System.currentTimeMillis() / 1000,
    ): SentMessage {
        val messageBody = MessageBody(subject, body, attachments, headers)
        val bodyBytes = MessageBodyCodec.encode(messageBody)
        val bodyCid = storage.put(bodyBytes)

        val envelope =
            MessageEnvelope.create(
                sender = localIdentity,
                recipients = recipients,
                contentCid = bodyCid,
                sentAtEpochSecond = sentAtEpochSecond,
                encryption = EncryptionMode.NONE,
                replyTo = replyTo,
                threadRoot = threadRoot,
            )
        val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
        storage.put(envelopeBytes)

        val frame = MailFrameCodec.encode(envelopeBytes, bodyBytes)
        recipients.forEach { recipient -> pubsub.publish(InboxTopics.forRecipient(recipient), frame) }

        return SentMessage(envelope, messageBody, bodyCid, frame)
    }

    /**
     * Re-publishes an already-[send]-built [sent] message's frame to every recipient's inbox
     * topic, without re-signing or re-storing anything. Exists because GossipSub mesh formation
     * (GRAFT) is asynchronous and a publish issued before the mesh has formed has no delivery
     * guarantee at all - callers retry through this, exactly as
     * `net.lapisphilosophorum.lapisnet.trust.TwoNodeVeritasGossipIntegrationTest` retries
     * `VeritasGossip.announce`. Idempotent: re-sending the same frame is harmless (the receiving
     * [InboxGossip]'s [InboxIndex] dedups by content id).
     */
    fun republish(sent: SentMessage) {
        sent.envelope.recipients.forEach { recipient ->
            pubsub.publish(InboxTopics.forRecipient(recipient), sent.frameBytes)
        }
    }
}
