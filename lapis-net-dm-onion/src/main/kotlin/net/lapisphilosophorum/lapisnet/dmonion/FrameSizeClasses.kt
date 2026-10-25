package net.lapisphilosophorum.lapisnet.dmonion

/**
 * Size classes of padded stream frames (wave V0.10.0-H), counted in stream messages ("chunks") of `maxPayload` bytes.
 *
 * On a rendezvous stream every message is one fixed-size cell, so the only thing that reveals the length of a direct
 * message, call signal or mail bundle to an observer of the guard link is the NUMBER of cells. A padded frame is
 * therefore extended with zero bytes (inside the end-to-end encrypted stream) to the next class: the smallest power of
 * two of chunks that holds it, capped at the chunk count of the largest legal frame.
 */
object FrameSizeClasses {
    /** Smallest power of two >= [realChunks], capped at [maxChunks] (the class of the largest legal frame). */
    fun classChunks(
        realChunks: Int,
        maxChunks: Int,
    ): Int {
        require(realChunks >= 1) { "realChunks must be positive" }
        require(maxChunks >= 1) { "maxChunks must be positive" }
        require(realChunks <= maxChunks) { "frame exceeds the largest class" }
        var c = 1L
        while (c < realChunks) c = c shl 1
        return minOf(c, maxChunks.toLong()).toInt()
    }

    /** Chunks of a frame with header [DmCircuitFraming.HEADER_SIZE] and [payloadLength] bytes (no overflow). */
    fun realChunks(
        payloadLength: Int,
        maxPayload: Int,
    ): Int {
        require(payloadLength >= 0) { "payloadLength must not be negative" }
        require(maxPayload > 0) { "maxPayload must be positive" }
        val total = DmCircuitFraming.HEADER_SIZE.toLong() + payloadLength.toLong()
        val chunks = (total + maxPayload - 1) / maxPayload
        require(chunks <= Int.MAX_VALUE) { "frame too large" }
        return chunks.toInt()
    }

    /** Chunks of the largest legal frame of a kind. */
    fun maxChunks(
        maxPayloadLength: Int,
        maxPayload: Int,
    ): Int = realChunks(maxPayloadLength, maxPayload)

    /** Total padded frame bytes = classChunks * maxPayload. Throws if [payloadLength] exceeds [maxPayloadLength]. */
    fun paddedFrameBytes(
        payloadLength: Int,
        maxPayload: Int,
        maxPayloadLength: Int,
    ): Long {
        require(payloadLength <= maxPayloadLength) { "payload exceeds the maximum" }
        val real = realChunks(payloadLength, maxPayload)
        return classChunks(real, maxChunks(maxPayloadLength, maxPayload)).toLong() * maxPayload
    }

    /** Zero bytes appended after the payload. Derived from the (authenticated) length only, never chosen by a peer. */
    fun paddingBytes(
        payloadLength: Int,
        maxPayload: Int,
        maxPayloadLength: Int,
    ): Long =
        paddedFrameBytes(payloadLength, maxPayload, maxPayloadLength) -
            DmCircuitFraming.HEADER_SIZE.toLong() - payloadLength.toLong()

    /** All classes of a kind, ascending (documentation and tests). */
    fun classes(
        maxPayloadLength: Int,
        maxPayload: Int,
    ): List<Int> {
        val max = maxChunks(maxPayloadLength, maxPayload)
        val result = mutableListOf<Int>()
        var c = 1
        while (c < max) {
            result += c
            c = c shl 1
        }
        result += max
        return result
    }
}
