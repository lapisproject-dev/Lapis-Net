package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage

/** The result of a [MailSender.send] call: the signed envelope, the decoded body, the body's CID,
 * and the exact frame bytes that were published - kept around so [MailSender.republish] can
 * re-send the identical frame without re-signing or re-storing anything.
 *
 * [sealedBody] is non-null only for [EncryptionMode.HYBRID_ECIES] sends - it lets a caller (or a
 * test) prove the sender's own self-wrap opens their own sent mail without touching the network,
 * e.g. `HybridEcies.open(sent.envelope, sent.sealedBody!!, localIdentity)`. */
class SentMessage(
    val envelope: MessageEnvelope,
    val body: MessageBody,
    val bodyCid: Cid,
    val sealedBody: SealedBody?,
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
     * Builds a [MessageBody] from [subject]/[body]/[attachments]/[headers]. For
     * [EncryptionMode.NONE] (the default), stores the plaintext body blob in [storage], signs a
     * [MessageEnvelope] bound to that blob's CID with [localIdentity], stores the envelope too,
     * then publishes the combined [MailFrameCodec] frame to every recipient's inbox topic
     * ([InboxTopics.forRecipient]). For [EncryptionMode.HYBRID_ECIES], the body is
     * [HybridEcies.seal]ed first and the SEALED blob (never the plaintext) is what gets stored and
     * published - see [HybridEcies]'s class doc comment for the encryption scheme.
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
     * doc comment). For [EncryptionMode.HYBRID_ECIES], the sender's own self-wrap (see
     * [HybridEcies]'s class doc comment) still lets them open their OWN [SentMessage.sealedBody]
     * locally via [HybridEcies.open] - that is a local decrypt of what this call already returned,
     * not network self-delivery. **A local "sent" view exists as of V0.9.3** ([SentFolder]) - this
     * function itself does not populate one (it has no reference to any particular [SentFolder]
     * instance); a caller (e.g. `POST /api/mail`'s route handler in `lapis-net-browser`) must
     * explicitly call `SentFolder.add` with this call's returned [SentMessage].
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
        encryption: EncryptionMode = EncryptionMode.NONE,
        sentAtEpochSecond: Long = System.currentTimeMillis() / 1000,
    ): SentMessage {
        val messageBody = MessageBody(subject, body, attachments, headers)

        return when (encryption) {
            EncryptionMode.NONE ->
                sendPlaintext(localIdentity, recipients, messageBody, replyTo, threadRoot, sentAtEpochSecond)
            EncryptionMode.HYBRID_ECIES ->
                sendHybridEcies(localIdentity, recipients, messageBody, replyTo, threadRoot, sentAtEpochSecond)
            EncryptionMode.MLS_ARCHIVE ->
                throw IllegalArgumentException("encryption mode MLS_ARCHIVE is reserved and not implemented")
        }
    }

    private fun sendPlaintext(
        localIdentity: Secp256k1KeyPair,
        recipients: List<Secp256k1PublicKey>,
        messageBody: MessageBody,
        replyTo: Cid?,
        threadRoot: Cid?,
        sentAtEpochSecond: Long,
    ): SentMessage {
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

        return SentMessage(envelope, messageBody, bodyCid, sealedBody = null, frameBytes = frame)
    }

    private fun sendHybridEcies(
        localIdentity: Secp256k1KeyPair,
        recipients: List<Secp256k1PublicKey>,
        messageBody: MessageBody,
        replyTo: Cid?,
        threadRoot: Cid?,
        sentAtEpochSecond: Long,
    ): SentMessage {
        // MailAadContext.forNewMessage and MessageEnvelope.create must be built from the IDENTICAL
        // sentAtEpochSecond value - reading System.currentTimeMillis() twice (once for the AAD
        // context, once for the envelope) would seal the content key against one timestamp and
        // sign the envelope with another, producing mail that nobody - including the sender -
        // could ever decrypt. sentAtEpochSecond is already materialized exactly once, as this
        // function's own parameter (defaulted in send(), never re-read here) - this comment exists
        // so a future edit does not reintroduce a second System.currentTimeMillis() call.
        val context =
            MailAadContext.forNewMessage(
                sender = localIdentity.publicKey,
                recipients = recipients,
                sentAtEpochSecond = sentAtEpochSecond,
                replyTo = replyTo,
                threadRoot = threadRoot,
            )
        val sealed = HybridEcies.seal(messageBody, localIdentity, context)
        // Body put FIRST - same load-bearing invariant as the plaintext path, applied to the
        // sealed blob instead of the plaintext one.
        storage.put(sealed.sealedBodyBytes)

        val envelope =
            MessageEnvelope.create(
                sender = localIdentity,
                recipients = recipients,
                contentCid = sealed.contentCid,
                sentAtEpochSecond = sentAtEpochSecond,
                encryption = EncryptionMode.HYBRID_ECIES,
                replyTo = replyTo,
                threadRoot = threadRoot,
                wraps = sealed.wraps,
            )
        val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
        storage.put(envelopeBytes)

        val frame = MailFrameCodec.encode(envelopeBytes, sealed.sealedBodyBytes)
        recipients.forEach { recipient -> pubsub.publish(InboxTopics.forRecipient(recipient), frame) }

        return SentMessage(envelope, messageBody, sealed.contentCid, sealedBody = sealed.sealedBody, frameBytes = frame)
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
