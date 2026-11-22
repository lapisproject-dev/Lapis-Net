package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.onion.LookupSizeClass
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Bounds of attachment fetches over circuits (wave Q21, unreleased; the values are provisional, not measured in a
 * pilot; the design Q21-A to Q21-I is confirmed by the user (2026-11-22)).
 */
object AnonymousAttachmentLimits {
    /** `status(1) | classIndex(1) | chunkIndex(2) | chunkCount(2) | totalLength(4)`. */
    const val FRAME_HEADER = 10

    /** Data bytes one chunk of the largest lookup class (128 KiB) carries. */
    const val MAX_CHUNK_DATA = 131_072 - FRAME_HEADER // 131,062

    const val MAX_CHUNKS = 32

    /** The largest blob a fetch can carry: 32 chunks of 131,062 bytes = 4,193,984 bytes (about 4 MiB). */
    const val MAX_BLOB_BYTES: Int = MAX_CHUNKS * MAX_CHUNK_DATA

    /** A fetch request body is always exactly this long (like a LOOKUP request). */
    const val REQUEST_SIZE = 720
}

/** The status byte of an answer chunk. Only [FOUND] carries data; every other status is one class-0 chunk. */
enum class AttachmentFetchStatus(
    val code: Byte,
) {
    FOUND(0),
    NOT_FOUND(1),
    RATE_LIMITED(2),
    MALFORMED(3),
    TOO_LARGE(6),
    ;

    companion object {
        fun fromCode(code: Byte): AttachmentFetchStatus? = entries.firstOrNull { it.code == code }
    }
}

/**
 * Transfer classes of an answer: the observable size of a transfer (its cell count) is only one of 2K, 8K, 32K, 128K,
 * 256K, 512K, 1M, 2M and 4M. A blob up to 131,062 bytes travels as one chunk of the smallest lookup class that holds it;
 * a larger one as a power of two of 128 KiB chunks (2 to 32), the chunks past the data carrying padding only.
 */
object AttachmentTransferClass {
    private const val LARGEST_CLASS = LookupSizeClass.COUNT - 1

    /** `(classIndex, chunkCount)` for a FOUND answer of [totalLength] bytes, or `null` (empty, or above the maximum). */
    fun forLength(totalLength: Int): Pair<Int, Int>? {
        if (totalLength < 1 || totalLength > AnonymousAttachmentLimits.MAX_BLOB_BYTES) return null
        for (i in 0 until LookupSizeClass.COUNT) {
            if (totalLength + AnonymousAttachmentLimits.FRAME_HEADER <= LookupSizeClass.size(i)) return i to 1
        }
        val needed =
            (totalLength + AnonymousAttachmentLimits.MAX_CHUNK_DATA - 1) / AnonymousAttachmentLimits.MAX_CHUNK_DATA
        var count = 1
        while (count < needed) count = count shl 1
        return LARGEST_CLASS to count
    }

    /** `true` iff a FOUND answer of [totalLength] bytes uses exactly [classIndex] and [chunkCount]. */
    fun isConsistent(
        classIndex: Int,
        chunkCount: Int,
        totalLength: Int,
    ): Boolean = forLength(totalLength) == (classIndex to chunkCount)

    /** Bytes of padded chunk payload a FOUND answer of [totalLength] bytes puts on the stream, or `null`. */
    fun transferBytes(totalLength: Int): Long? {
        val (classIndex, count) = forLength(totalLength) ?: return null
        return LookupSizeClass.size(classIndex).toLong() * count
    }

    /** Data bytes chunk [chunkIndex] of a FOUND answer carries. */
    fun dataLength(
        totalLength: Int,
        chunkCount: Int,
        chunkIndex: Int,
    ): Int =
        if (chunkCount == 1) {
            totalLength
        } else {
            (totalLength - chunkIndex * AnonymousAttachmentLimits.MAX_CHUNK_DATA)
                .coerceIn(0, AnonymousAttachmentLimits.MAX_CHUNK_DATA)
        }
}

/**
 * The fetch authorisation (wave Q21, decision Q21-D, confirmed by the user (2026-11-22), not externally reviewed): a
 * token key `K_t = HKDF-SHA256(ikm = attachment key, salt = empty, info = "LapisNet:attachment-fetch-token-key:v1" ||
 * cid bytes)`, then `HMAC-SHA256(K_t, "LapisNet:attachment-fetch:v1" || cid bytes)`. The attachment key itself is used
 * only for AES-GCM and as HKDF input, never directly as an HMAC key (wave Q21-Token). Only someone who holds the
 * attachment's encryption key (from the message that carried the reference) can compute the token; the sender
 * recomputes and compares in constant time. New [HKDFBytesGenerator]/[HMac] per call; the derived key is zeroed after
 * use. A new construction from existing primitives.
 */
object AttachmentFetchToken {
    const val SIZE = 32
    private val LABEL = "LapisNet:attachment-fetch:v1".toByteArray(Charsets.US_ASCII)
    private val KEY_INFO_LABEL = "LapisNet:attachment-fetch-token-key:v1".toByteArray(Charsets.US_ASCII)
    private const val TOKEN_KEY_SIZE = 32

    /** @throws IllegalArgumentException for a CID that is not CIDv1/raw/SHA-256 or an empty key. */
    fun compute(
        attachmentKey: ByteArray,
        cid: Cid,
    ): ByteArray {
        require(attachmentKey.isNotEmpty()) { "attachment key must not be empty" }
        val cidBytes = requireNotNull(RemoteContentVerifier.rawSha256CidBytes(cid)) { "unsupported CID shape" }
        val tokenKey = deriveTokenKey(attachmentKey, cidBytes)
        try {
            val mac = HMac(SHA256Digest())
            mac.init(KeyParameter(tokenKey))
            mac.update(LABEL, 0, LABEL.size)
            mac.update(cidBytes, 0, cidBytes.size)
            val out = ByteArray(mac.macSize)
            mac.doFinal(out, 0)
            return out
        } finally {
            tokenKey.fill(0)
        }
    }

    /**
     * The token key `K_t` for [attachmentKey] and the CID's raw bytes [cidBytes] (visible for the reference-vector
     * test). A caller outside [compute] zeroes the result itself.
     *
     * Salt `null`: BouncyCastle then uses HashLen (32) zero bytes, which RFC 5869 defines as the value for "salt not
     * provided"; an empty array would give the same PRK (HMAC pads a short key with zeros). `null` states the intent;
     * the reference vector in the test pins the result.
     */
    internal fun deriveTokenKey(
        attachmentKey: ByteArray,
        cidBytes: ByteArray,
    ): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(attachmentKey, null, KEY_INFO_LABEL + cidBytes))
        val out = ByteArray(TOKEN_KEY_SIZE)
        hkdf.generateBytes(out, 0, TOKEN_KEY_SIZE)
        return out
    }

    /** Constant-time comparison; `false` for any length other than [SIZE]. */
    fun matches(
        expected: ByteArray,
        presented: ByteArray,
    ): Boolean {
        if (expected.size != SIZE || presented.size != SIZE) return false
        return MessageDigest.isEqual(expected, presented)
    }
}

/** A fetch request that is not exactly the version-1 shape; carries no content. */
open class MalformedAttachmentFetchException(
    message: String,
) : RuntimeException(message)

/**
 * Wire format of attachment fetches over a rendezvous stream (wave Q21), carried in [DmCircuitFraming] frames:
 *
 * - Request ([TYPE_FETCH_REQUEST]), always [AnonymousAttachmentLimits.REQUEST_SIZE] (720) bytes:
 *   `version(1) = 1 | flags(1) = 0 | cidLen(2) = 36 | cid(36, CIDv1 raw SHA-256) | token(32) | random padding`.
 * - Answer: one or more [TYPE_ATTACHMENT_CHUNK] frames whose payload is exactly the size of its lookup class:
 *   `status(1) | classIndex(1) | chunkIndex(2) | chunkCount(2) | totalLength(4) | data | zero padding`.
 *   The zeros travel inside the end-to-end encrypted stream (same reasoning as `FrameSizeClasses`).
 */
object AttachmentFetchCodec {
    const val VERSION: Int = 1

    /** Free frame types (1 to 5 are taken by the DM and mail framings). */
    const val TYPE_FETCH_REQUEST: Int = 6
    const val TYPE_ATTACHMENT_CHUNK: Int = 7

    private const val CID_LENGTH = 36
    private const val REQUEST_HEADER = 4

    /** A decoded request. Defensive copies; [toString] never shows the CID or the token. */
    class FetchRequest(
        val cid: Cid,
        token: ByteArray,
    ) {
        private val storedToken = token.copyOf()
        val token: ByteArray get() = storedToken.copyOf()

        override fun toString(): String = "FetchRequest(REDACTED)"
    }

    /** One answer chunk's header. */
    class ChunkHeader(
        val status: AttachmentFetchStatus,
        val classIndex: Int,
        val chunkIndex: Int,
        val chunkCount: Int,
        val totalLength: Int,
    )

    /** The 720-byte request body. @throws IllegalArgumentException for a token of the wrong length or a foreign CID. */
    fun encodeRequest(
        cid: Cid,
        token: ByteArray,
        random: SecureRandom,
    ): ByteArray {
        require(token.size == AttachmentFetchToken.SIZE) { "token must be ${AttachmentFetchToken.SIZE} bytes" }
        val cidBytes = requireNotNull(RemoteContentVerifier.rawSha256CidBytes(cid)) { "unsupported CID shape" }
        val out = ByteArray(AnonymousAttachmentLimits.REQUEST_SIZE)
        random.nextBytes(out)
        ByteBuffer
            .wrap(out)
            .put(VERSION.toByte())
            .put(0)
            .putShort(CID_LENGTH.toShort())
            .put(cidBytes)
            .put(token)
        return out
    }

    /**
     * Decodes a request body. The CID bytes are checked by hand (length 36, CIDv1, raw, SHA-256, 32-byte digest) BEFORE
     * `Cid.cast` runs: that one allocates from a declared length before any bound check (same reason as LOOKUP).
     * @throws MalformedAttachmentFetchException
     */
    fun decodeRequest(body: ByteArray): FetchRequest {
        if (body.size != AnonymousAttachmentLimits.REQUEST_SIZE) throw MalformedAttachmentFetchException("bad length")
        val buf = ByteBuffer.wrap(body)
        if (buf.get().toInt() != VERSION) throw MalformedAttachmentFetchException("unsupported version")
        if (buf.get().toInt() != 0) throw MalformedAttachmentFetchException("reserved flags set")
        if (buf.getShort().toInt() != CID_LENGTH) throw MalformedAttachmentFetchException("bad cid length")
        val cidBytes = ByteArray(CID_LENGTH).also { buf.get(it) }
        val cid =
            RemoteContentVerifier.parseRawSha256Cid(cidBytes) ?: throw MalformedAttachmentFetchException("bad cid")
        val token = ByteArray(AttachmentFetchToken.SIZE).also { buf.get(it) }
        return FetchRequest(cid, token)
    }

    /** The request as one stream frame (`type | len | body`). */
    fun requestFrame(body: ByteArray): ByteArray = DmCircuitFraming.frame(TYPE_FETCH_REQUEST, body)

    /** Bytes of a request frame on the stream. */
    const val REQUEST_FRAME_SIZE: Int = DmCircuitFraming.HEADER_SIZE + AnonymousAttachmentLimits.REQUEST_SIZE

    /** Number of answer chunks (frames) for [status] and a FOUND blob of [blobLength] bytes. */
    fun chunkCount(
        status: AttachmentFetchStatus,
        blobLength: Int,
    ): Int =
        if (status == AttachmentFetchStatus.FOUND) {
            requireNotNull(AttachmentTransferClass.forLength(blobLength)) { "blob length out of range" }.second
        } else {
            1
        }

    /**
     * The payload of answer chunk [chunkIndex] (exactly the class size). [blob] is required for FOUND and ignored for
     * every other status (always one class-0 chunk with `totalLength = 0`).
     */
    fun encodeChunk(
        status: AttachmentFetchStatus,
        blob: ByteArray?,
        chunkIndex: Int,
    ): ByteArray {
        if (status != AttachmentFetchStatus.FOUND) {
            require(chunkIndex == 0) { "error answers have one chunk" }
            val out = ByteArray(LookupSizeClass.size(0))
            ByteBuffer
                .wrap(out)
                .put(status.code)
                .put(0)
                .putShort(0)
                .putShort(1)
                .putInt(0)
            return out
        }
        val data = requireNotNull(blob) { "FOUND needs a blob" }
        val (classIndex, count) =
            requireNotNull(AttachmentTransferClass.forLength(data.size)) { "blob length out of range" }
        require(chunkIndex in 0 until count) { "chunk index out of range" }
        val out = ByteArray(LookupSizeClass.size(classIndex))
        val length = AttachmentTransferClass.dataLength(data.size, count, chunkIndex)
        val buf =
            ByteBuffer
                .wrap(out)
                .put(status.code)
                .put(classIndex.toByte())
                .putShort(chunkIndex.toShort())
                .putShort(count.toShort())
                .putInt(data.size)
        // a padding chunk (past the data) carries no data at all
        if (length > 0) buf.put(data, chunkIndex * AnonymousAttachmentLimits.MAX_CHUNK_DATA, length)
        return out
    }

    /** All chunk payloads of an answer (tests and small answers; the server builds them one at a time). */
    fun encodeAnswer(
        status: AttachmentFetchStatus,
        blob: ByteArray?,
    ): List<ByteArray> =
        List(chunkCount(status, blob?.size ?: 0)) { index ->
            encodeChunk(status, blob, index)
        }

    /** One chunk payload as a stream frame (`type | len | payload`). */
    fun chunkFrame(payload: ByteArray): ByteArray = DmCircuitFraming.frame(TYPE_ATTACHMENT_CHUNK, payload)

    /**
     * Parses the 10-byte header at the start of a chunk payload; [payloadLength] is the frame's declared length, which
     * must be exactly the size of the header's class. Checks the structure only; the sequence is the reader's job.
     * @throws MalformedAttachmentFetchException
     */
    fun decodeChunkHeader(
        header: ByteArray,
        payloadLength: Int,
    ): ChunkHeader {
        if (header.size <
            AnonymousAttachmentLimits.FRAME_HEADER
        ) {
            throw MalformedAttachmentFetchException("short header")
        }
        val buf = ByteBuffer.wrap(header, 0, AnonymousAttachmentLimits.FRAME_HEADER)
        val status = AttachmentFetchStatus.fromCode(buf.get()) ?: throw MalformedAttachmentFetchException("bad status")
        val classIndex = buf.get().toInt() and 0xFF
        val chunkIndex = buf.getShort().toInt() and 0xFFFF
        val chunkCount = buf.getShort().toInt() and 0xFFFF
        val totalLength = buf.getInt()
        if (classIndex >= LookupSizeClass.COUNT) throw MalformedAttachmentFetchException("bad class")
        if (payloadLength != LookupSizeClass.size(classIndex)) throw MalformedAttachmentFetchException("bad frame size")
        if (status == AttachmentFetchStatus.FOUND) {
            if (!AttachmentTransferClass.isConsistent(classIndex, chunkCount, totalLength)) {
                throw MalformedAttachmentFetchException("inconsistent transfer class")
            }
            if (chunkIndex >= chunkCount) throw MalformedAttachmentFetchException("bad chunk index")
        } else if (classIndex != 0 || chunkIndex != 0 || chunkCount != 1 || totalLength != 0) {
            throw MalformedAttachmentFetchException("bad error answer")
        }
        return ChunkHeader(status, classIndex, chunkIndex, chunkCount, totalLength)
    }

    /** `true` iff [length] is the payload length of some chunk class. */
    fun isChunkPayloadLength(length: Int): Boolean =
        (0 until LookupSizeClass.COUNT).any {
            LookupSizeClass.size(it) ==
                length
        }
}
