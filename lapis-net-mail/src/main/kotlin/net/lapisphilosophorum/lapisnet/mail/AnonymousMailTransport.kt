package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Stable, content-free reasons for a refused anonymous mail send (wave V0.10.0-F2). The wire form is what the
 * browser API reports; it never names a recipient, a peer or an address.
 */
enum class MailAnonymousFailure(
    val wire: String,
) {
    /** The anonymity runtime is not up (yet); there is no fallback to the direct path. */
    ANONYMITY_NOT_READY("anonymity-not-ready"),

    /**
     * ONE answer for every way a recipient can be unreachable anonymously (unknown, direct mode, revoked, no MAIL
     * capability, no prekey bundle), so the refusal is no oracle.
     */
    RECIPIENT_NOT_REACHABLE_ANONYMOUSLY("recipient-not-reachable-anonymously"),

    /** The bundle exceeds [AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES] or [AnonymousMailSizing.MAX_ATTACHMENTS]. */
    MAIL_TOO_LARGE_ANONYMOUS("mail-too-large-anonymous"),

    /** An attachment blob is not held locally; anonymity mode never fetches blobs from the network. */
    ATTACHMENTS_UNAVAILABLE_ANONYMOUS("attachments-unavailable-anonymous"),
}

/** Thrown by anonymous mail sending; the message is the stable wire code, never a peer, address or key. */
class MailAnonymousDeliveryException(
    val failure: MailAnonymousFailure,
) : RuntimeException(failure.wire)

/** How a mail travels over circuits. */
enum class AnonymousMailSizeClass {
    /** The signed frame fits one sealed mailbox item and there are no attachments: online stream or offline item. */
    INLINE,

    /** Frame plus attachment blobs travel as one bundle over a rendezvous stream; online only, retried for 48 h. */
    CIRCUIT,
}

/** The size rules of anonymous mail; checked before any network step. */
object AnonymousMailSizing {
    /** Largest transport bundle as encoded on the wire (header, frame and attachment blobs): 1 MiB. */
    const val MAX_CIRCUIT_BUNDLE_BYTES: Int = 1 shl 20

    /** Largest number of attachment blobs in one bundle. */
    const val MAX_ATTACHMENTS: Int = 16

    /** Largest frame that still fits one sealed mailbox item (`SealedMailboxBox.MAX_PAYLOAD_BYTES`, asserted by a test). */
    const val MAX_INLINE_FRAME_BYTES: Int = 5_668

    /** @throws MailAnonymousDeliveryException [MailAnonymousFailure.MAIL_TOO_LARGE_ANONYMOUS] when nothing fits. */
    fun classify(
        frameBytes: Int,
        attachmentBlobSizes: List<Int>,
    ): AnonymousMailSizeClass {
        val tooLarge = MailAnonymousDeliveryException(MailAnonymousFailure.MAIL_TOO_LARGE_ANONYMOUS)
        if (frameBytes < 1 || attachmentBlobSizes.size > MAX_ATTACHMENTS || attachmentBlobSizes.any { it < 0 }) {
            throw tooLarge
        }
        // exact encoded size of MailCircuitBundleCodec: version(1) + frameLen(4) + frame + count(1) + (blobLen(4) + blob)*
        var total = 1L + 4 + frameBytes + 1
        for (s in attachmentBlobSizes) total += 4L + s
        if (total > MAX_CIRCUIT_BUNDLE_BYTES) throw tooLarge
        return if (attachmentBlobSizes.isEmpty() && frameBytes <= MAX_INLINE_FRAME_BYTES) {
            AnonymousMailSizeClass.INLINE
        } else {
            AnonymousMailSizeClass.CIRCUIT
        }
    }
}

/**
 * Mail over onion circuits, as seen by [MailSender] (the seam; lapis-net-mail knows nothing about circuits, the
 * adapter module `lapis-net-mail-onion` implements it). The browser installs it after the anonymity runtime is up;
 * until then every anonymous send fails with [MailAnonymousFailure.ANONYMITY_NOT_READY], never with a fallback.
 */
interface AnonymousMailTransport : AutoCloseable {
    /**
     * All-or-nothing check before anything is stored or sent: every recipient (the sender itself excepted) must be
     * reachable anonymously and the size rules must hold. No network I/O besides the local directory.
     *
     * @throws MailAnonymousDeliveryException
     */
    fun preflight(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: Int,
        attachmentBlobSizes: List<Int>,
    ): AnonymousMailSizeClass

    /**
     * Hands the already built frame (and blobs) to circuits. Never blocks the caller for longer than queueing; the
     * outcome (delivered now or retried later) is deliberately not reported, so the API answer is the same either way.
     */
    fun deliver(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
        sizeClass: AnonymousMailSizeClass,
    )
}

/**
 * The single entrance for mail that arrives over circuits, on both anonymous paths (rendezvous stream and sealed
 * item). It must apply the same acceptance pipeline as the direct path and must reveal nothing to the sender.
 */
interface AnonymousMailInboundSink {
    /**
     * Never throws and never reports why a mail was refused. The arrays belong to the caller, which may wipe them as
     * soon as this returns: an implementation that keeps them must copy.
     */
    fun acceptAnonymousMail(
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
    )
}
