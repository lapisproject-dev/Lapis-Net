package net.lapisphilosophorum.lapisnet.mail

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * The inbound end of mail over circuits (wave V0.10.0-F2): the ONE place both anonymous paths (the rendezvous stream
 * bundle and the sealed mailbox item) enter the inbox. It forwards the frame to [InboxGossip.anonymousIngest], which
 * applies the same envelope checks, acceptance policy, contact bypass and duplicate suppression as the direct path.
 *
 * Attachment blobs are only ever looked at AFTER the mail was accepted: a refused mail stores nothing, so storage is no
 * side channel. A blob is kept only if its own CID (computed here, never taken from the sender) is referenced by the
 * mail's body; everything else is discarded and counted. Storing is local ([NabuStorage.put] touches the blockstore
 * only).
 *
 * [referencedAttachmentCids] decrypts a sealed body and returns the CIDs of its attachments (the caller holds the
 * identity key, this class never does); for a plaintext body the references are read directly.
 */
class InboxAnonymousSink(
    private val inbox: InboxGossip,
    private val storage: NabuStorage,
    private val referencedAttachmentCids: (InboxMessage) -> Set<Cid>?,
) : AnonymousMailInboundSink {
    private val unreferencedBlobs = AtomicLong(0)
    private val accepted = AtomicLong(0)

    /** Blobs discarded because the accepted mail does not reference them (tests, diagnostics). */
    fun discardedBlobCount(): Long = unreferencedBlobs.get()

    /** Mails accepted through this sink (tests, diagnostics). */
    fun acceptedCount(): Long = accepted.get()

    override fun acceptAnonymousMail(
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
    ) {
        try {
            if (frameBytes.isEmpty() || frameBytes.size > AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES) return
            val (outcome, message) = inbox.anonymousIngestMessage(frameBytes)
            if (outcome != InboxIngestOutcome.ACCEPTED || message == null) return
            accepted.incrementAndGet()
            if (attachmentBlobs.isEmpty()) return
            val referenced =
                when (val payload = message.payload) {
                    is InboxPayload.Plaintext ->
                        payload.body.attachments
                            .map { it.cid }
                            .toSet()
                    is InboxPayload.Sealed -> referencedAttachmentCids(message)
                } ?: return
            for (blob in attachmentBlobs.take(AnonymousMailSizing.MAX_ATTACHMENTS)) {
                if (MessageBodyCodec.cidFor(blob) in referenced) {
                    storage.putUnserved(blob)
                } else {
                    unreferencedBlobs.incrementAndGet()
                }
            }
        } catch (e: RuntimeException) {
            logger.debug { "anonymous mail handling failed (${e.javaClass.simpleName})" }
        }
    }

    override fun toString(): String = "InboxAnonymousSink(REDACTED)"
}
