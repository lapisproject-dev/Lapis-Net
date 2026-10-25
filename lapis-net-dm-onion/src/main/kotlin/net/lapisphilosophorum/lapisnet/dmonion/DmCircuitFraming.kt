package net.lapisphilosophorum.lapisnet.dmonion

import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec
import java.nio.ByteBuffer

/** A protocol violation on a DM rendezvous stream; the stream is closed, the cause carries no content. */
class DmFramingException(
    message: String,
) : RuntimeException(message)

/**
 * The framing of direct messages on a rendezvous stream (wave V0.10.0-F1): `type(1) | len(4, big endian) | bytes`,
 * spread over as many stream messages of at most `maxPayload` bytes (910) as needed. Two frame types exist:
 * [TYPE_ENVELOPE] (receiver accepts only this) and [TYPE_ACK] (sender accepts only this). The acknowledgement is one
 * constant byte and is sent as soon as an envelope frame has been read completely and its length was valid, BEFORE the
 * envelope is looked at, so its timing says nothing about decryption, policy or duplicates.
 */
object DmCircuitFraming {
    const val TYPE_ENVELOPE = 1
    const val TYPE_ACK = 2

    /** An envelope frame padded with zero bytes to a size class (wave V0.10.0-H); reported to handlers as [TYPE_ENVELOPE]. */
    const val TYPE_ENVELOPE_PADDED = 4
    const val HEADER_SIZE = 5

    /** The payload of one rendezvous stream message (one relay cell). */
    const val DEFAULT_MAX_PAYLOAD = 910
    const val ACK_BYTE: Byte = 1

    fun frame(
        type: Int,
        payload: ByteArray,
    ): ByteArray =
        ByteBuffer
            .allocate(HEADER_SIZE + payload.size)
            .put(type.toByte())
            .putInt(payload.size)
            .put(payload)
            .array()

    fun envelopeFrame(envelopeBytes: ByteArray): ByteArray = frame(TYPE_ENVELOPE, envelopeBytes)

    /**
     * An envelope frame extended with zero bytes to its size class ([FrameSizeClasses]); the result is an exact multiple
     * of [maxPayload]. The zeros travel inside the end-to-end encrypted stream; a receiver counts and discards them.
     */
    fun paddedEnvelopeFrame(
        envelopeBytes: ByteArray,
        maxPayload: Int,
    ): ByteArray = paddedFrame(TYPE_ENVELOPE_PADDED, envelopeBytes, maxPayload, DmEnvelopeCodec.MAX_ENVELOPE_BYTES)

    /** Builds `type | len | payload | zero padding` up to the size class; shared with the mail framing. */
    fun paddedFrame(
        type: Int,
        payload: ByteArray,
        maxPayload: Int,
        maxPayloadLength: Int,
    ): ByteArray {
        val total = FrameSizeClasses.paddedFrameBytes(payload.size, maxPayload, maxPayloadLength)
        require(total <= Int.MAX_VALUE) { "frame too large" }
        val out = ByteArray(total.toInt())
        ByteBuffer
            .wrap(out)
            .put(type.toByte())
            .putInt(payload.size)
            .put(payload)
        return out
    }

    fun ackFrame(): ByteArray = frame(TYPE_ACK, byteArrayOf(ACK_BYTE))

    /** Splits [frame] into stream messages of at most [maxPayload] bytes. */
    fun chunks(
        frame: ByteArray,
        maxPayload: Int,
    ): List<ByteArray> {
        require(maxPayload > 0) { "maxPayload must be positive" }
        return (frame.indices step maxPayload).map { frame.copyOfRange(it, minOf(it + maxPayload, frame.size)) }
    }
}

/**
 * Incremental parser of [DmCircuitFraming] frames. The length is validated against the allowed types' bound BEFORE any
 * buffer is allocated. Not thread-safe: one reader per stream, fed from the stream's single delivery thread.
 *
 * Padded frame types ([paddedTypes], padded type to base type) carry zero padding up to their size class after the
 * payload. The padding length follows deterministically from the declared length and [maxPayload], so a peer cannot
 * choose it; the padding bytes are counted and discarded, never inspected (no oracle), and [onFrame] is called only
 * after the last padding byte, with the base type, so that the acknowledgement of a frame is sent only after the whole
 * size class has arrived.
 */
class DmFrameReader(
    private val allowedTypes: Set<Int>,
    private val clockMillis: () -> Long,
    private val maxEnvelopeBytes: Int = DmEnvelopeCodec.MAX_ENVELOPE_BYTES,
    /** Asked with the declared length BEFORE the body buffer is allocated; `false` ends the stream. */
    private val admit: (length: Int) -> Boolean = { true },
    private val maxPayload: Int = DmCircuitFraming.DEFAULT_MAX_PAYLOAD,
    private val paddedTypes: Map<Int, Int> = emptyMap(),
) {
    constructor(
        allowedType: Int,
        clockMillis: () -> Long,
        maxEnvelopeBytes: Int = DmEnvelopeCodec.MAX_ENVELOPE_BYTES,
        admit: (length: Int) -> Boolean = { true },
    ) : this(setOf(allowedType), clockMillis, maxEnvelopeBytes, admit)

    private val header = ByteArray(DmCircuitFraming.HEADER_SIZE)
    private var headerFill = 0
    private var body: ByteArray? = null
    private var bodyFill = 0

    /** Padding bytes still to be discarded before the completed [body] is reported; 0 outside the padding phase. */
    private var padLeft = 0L
    private var completed: ByteArray? = null

    /** Time of the last byte that advanced an incomplete frame; meaningless while [inFrame] is false. */
    @Volatile var lastProgressMillis: Long = clockMillis()
        private set

    /** `true` while a frame has been started but not completed. */
    @Volatile var inFrame: Boolean = false
        private set

    /** `true` once the header of the current frame has been read completely (its length is known). */
    @Volatile var headerComplete: Boolean = false
        private set

    /** Time the body of the current frame started (header complete); meaningless while [headerComplete] is false. */
    @Volatile var bodyStartMillis: Long = 0L
        private set

    /** Body (and padding) bytes of the current frame received so far. */
    @Volatile var bodyReceived: Int = 0
        private set

    /** Declared body length plus padding of the current frame; meaningless while [headerComplete] is false. */
    @Volatile var bodyLength: Int = 0
        private set

    /**
     * `true` if the body of the current frame is arriving slower than [minBytesPerSecond] on average, measured from the end of
     * the header after a grace period of [graceMillis]. A trickle of single bytes inside the idle limit cannot hold a stream.
     * With a [deadlineMillis] (absolute time) it is also `true` if, at the average rate so far, the body cannot complete before
     * the deadline: a stream that holds its slot until the deadline must therefore finish its frame. The padding counts as
     * part of the body.
     */
    fun bodyTooSlow(
        nowMillis: Long,
        graceMillis: Long,
        minBytesPerSecond: Long,
        deadlineMillis: Long = Long.MAX_VALUE,
    ): Boolean {
        if (!headerComplete) return false
        val elapsed = nowMillis - bodyStartMillis
        if (elapsed < graceMillis || elapsed <= 0L) return false
        val received = bodyReceived.toLong()
        if (received * 1000L < (elapsed - graceMillis) * minBytesPerSecond) return true
        if (deadlineMillis == Long.MAX_VALUE) return false
        val timeLeft = deadlineMillis - nowMillis
        if (timeLeft <= 0L) return false
        return received + received * timeLeft / elapsed < bodyLength.toLong()
    }

    /** Feeds one stream message; calls [onFrame] for every frame that completes. @throws DmFramingException */
    fun feed(
        chunk: ByteArray,
        onFrame: (type: Int, payload: ByteArray) -> Unit,
    ) {
        var offset = 0
        while (offset < chunk.size) {
            val current = body
            if (padLeft > 0L) {
                // padding phase: counted and discarded, never compared
                val take = minOf(padLeft, (chunk.size - offset).toLong()).toInt()
                padLeft -= take
                offset += take
                bodyReceived += take
                lastProgressMillis = clockMillis()
                if (padLeft == 0L) finish(onFrame)
            } else if (current == null) {
                val take = minOf(header.size - headerFill, chunk.size - offset)
                chunk.copyInto(header, headerFill, offset, offset + take)
                headerFill += take
                offset += take
                inFrame = true
                lastProgressMillis = clockMillis()
                if (headerFill < header.size) continue
                val type = header[0].toInt() and 0xFF
                val length = ByteBuffer.wrap(header, 1, 4).getInt()
                if (type !in allowedTypes) throw DmFramingException("unexpected frame type")
                val valid =
                    if (type == DmCircuitFraming.TYPE_ACK) length == 1 else length in 1..maxEnvelopeBytes
                if (!valid) throw DmFramingException("frame length out of range")
                if (!admit(length)) throw DmFramingException("frame not admitted")
                val pad =
                    if (type in paddedTypes) {
                        FrameSizeClasses.paddingBytes(length, maxPayload, maxEnvelopeBytes)
                    } else {
                        0L
                    }
                body = ByteArray(length)
                bodyFill = 0
                bodyReceived = 0
                bodyLength = Math.toIntExact(length + pad)
                bodyStartMillis = clockMillis()
                headerComplete = true
            } else {
                val take = minOf(current.size - bodyFill, chunk.size - offset)
                chunk.copyInto(current, bodyFill, offset, offset + take)
                bodyFill += take
                bodyReceived = bodyFill
                offset += take
                lastProgressMillis = clockMillis()
                if (bodyFill == current.size) {
                    val type = header[0].toInt() and 0xFF
                    completed = current
                    body = null
                    bodyFill = 0
                    padLeft =
                        if (type in paddedTypes) {
                            FrameSizeClasses.paddingBytes(current.size, maxPayload, maxEnvelopeBytes)
                        } else {
                            0L
                        }
                    if (padLeft == 0L) finish(onFrame)
                }
            }
        }
    }

    private fun finish(onFrame: (type: Int, payload: ByteArray) -> Unit) {
        val type = header[0].toInt() and 0xFF
        val payload = completed!!
        completed = null
        headerFill = 0
        onFrame(paddedTypes[type] ?: type, payload)
        // reset only after the callback, so a sweeper never sees a completed frame as a silent stream
        inFrame = false
        headerComplete = false
        bodyReceived = 0
    }
}
