package net.lapisphilosophorum.lapisnet.mailonion

import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.dmonion.DmFrameReader
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizing
import java.nio.ByteBuffer

/** A malformed mail bundle; carries no content. */
class MalformedMailBundleException(
    message: String,
) : IllegalArgumentException(message)

/** A decoded bundle: the signed mail frame and the attachment blobs that travel with it. */
class MailCircuitBundle(
    val frame: ByteArray,
    val blobs: List<ByteArray>,
) {
    override fun toString(): String = "MailCircuitBundle(REDACTED)"
}

/**
 * The transport bundle of mail over a rendezvous stream (wave V0.10.0-F2):
 *
 * ```
 * version(1)=1 | frameLen(4) | mailFrame | count(1) | { blobLen(4) | blob }*
 * ```
 *
 * Every length is checked against the remaining bytes and the bundle limits BEFORE anything is allocated. CIDs are not
 * transmitted: the receiver computes them from the blob bytes, so a blob can only ever match what the mail references.
 */
object MailCircuitBundleCodec {
    private const val VERSION: Byte = 1

    fun encode(
        frame: ByteArray,
        blobs: List<ByteArray>,
    ): ByteArray {
        require(frame.isNotEmpty()) { "empty mail frame" }
        require(blobs.size <= AnonymousMailSizing.MAX_ATTACHMENTS) { "too many attachments" }
        val total = 1L + 4 + frame.size + 1 + blobs.sumOf { 4L + it.size }
        require(total <= AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES) { "bundle too large" }
        val buffer = ByteBuffer.allocate(total.toInt())
        buffer
            .put(VERSION)
            .putInt(frame.size)
            .put(frame)
            .put(blobs.size.toByte())
        for (b in blobs) buffer.putInt(b.size).put(b)
        return buffer.array()
    }

    fun decode(bytes: ByteArray): MailCircuitBundle {
        if (bytes.size > AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES) throw MalformedMailBundleException("too large")
        val buffer = ByteBuffer.wrap(bytes)
        if (buffer.remaining() < 1 + 4 || buffer.get() != VERSION) throw MalformedMailBundleException("bad header")
        val frameLen = buffer.getInt()
        if (frameLen < 1 || frameLen > buffer.remaining() - 1) throw MalformedMailBundleException("bad frame length")
        val frame = ByteArray(frameLen)
        buffer.get(frame)
        val count = buffer.get().toInt() and 0xFF
        if (count > AnonymousMailSizing.MAX_ATTACHMENTS) throw MalformedMailBundleException("too many blobs")
        val blobs = ArrayList<ByteArray>(count)
        repeat(count) {
            if (buffer.remaining() < 4) throw MalformedMailBundleException("truncated")
            val len = buffer.getInt()
            if (len < 0 || len > buffer.remaining()) throw MalformedMailBundleException("bad blob length")
            val blob = ByteArray(len)
            buffer.get(blob)
            blobs += blob
        }
        if (buffer.hasRemaining()) throw MalformedMailBundleException("trailing bytes")
        return MailCircuitBundle(frame, blobs)
    }
}

/**
 * Stream framing of mail: the direct-message framing ([DmCircuitFraming]) with one more frame type. The receiver accepts
 * only [TYPE_MAIL_BUNDLE], the sender only [TYPE_ACK] (the same constant acknowledgement byte as for DM, sent as soon as
 * the frame is complete and queued, before anything is checked).
 */
object MailCircuitFraming {
    const val TYPE_MAIL_BUNDLE = 3

    /** A bundle frame padded with zero bytes to a size class (wave V0.10.0-H); reported to handlers as [TYPE_MAIL_BUNDLE]. */
    const val TYPE_MAIL_BUNDLE_PADDED = 5
    const val TYPE_ACK = DmCircuitFraming.TYPE_ACK

    /** Largest declared frame length a receiver accepts (the bundle limit plus the framing's own slack). */
    const val MAX_FRAME_BYTES = AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES + 16

    fun bundleFrame(bundle: ByteArray): ByteArray = DmCircuitFraming.frame(TYPE_MAIL_BUNDLE, bundle)

    /** A bundle frame padded to its size class: an exact multiple of [maxPayload] ([FrameSizeClasses]). */
    fun paddedBundleFrame(
        bundle: ByteArray,
        maxPayload: Int,
    ): ByteArray = DmCircuitFraming.paddedFrame(TYPE_MAIL_BUNDLE_PADDED, bundle, maxPayload, MAX_FRAME_BYTES)

    fun ackFrame(): ByteArray = DmCircuitFraming.ackFrame()

    fun chunks(
        frame: ByteArray,
        maxPayload: Int,
    ): List<ByteArray> = DmCircuitFraming.chunks(frame, maxPayload)

    /** A receiver-side reader; [admit] sees the declared length before the body buffer is allocated. */
    fun bundleReader(
        clockMillis: () -> Long,
        maxPayload: Int = DmCircuitFraming.DEFAULT_MAX_PAYLOAD,
        admit: (Int) -> Boolean,
    ): DmFrameReader =
        DmFrameReader(
            setOf(TYPE_MAIL_BUNDLE, TYPE_MAIL_BUNDLE_PADDED),
            clockMillis,
            MAX_FRAME_BYTES,
            admit,
            maxPayload,
            mapOf(TYPE_MAIL_BUNDLE_PADDED to TYPE_MAIL_BUNDLE),
        )

    /** A sender-side reader that accepts only the acknowledgement. */
    fun ackReader(clockMillis: () -> Long): DmFrameReader = DmFrameReader(TYPE_ACK, clockMillis)
}
