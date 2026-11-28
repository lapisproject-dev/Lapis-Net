package net.lapisphilosophorum.lapisnet.onion

import java.security.SecureRandom

/** What a LOOKUP_REQUEST asks the last hop for (wave V0.10.0-J2). */
enum class LookupOperation(
    val code: Int,
) {
    /** A raw block named by a CIDv1 (raw codec, SHA-256); the key is the CID's bytes. */
    GET_BLOCK(1),

    /** The signed IPNS record of an Ed25519 name; the key is the routing key `/ipns/<multihash>`. */
    GET_IPNS_RECORD(2),
    ;

    companion object {
        fun fromCode(code: Int): LookupOperation? = entries.firstOrNull { it.code == code }
    }
}

/** First byte of a lookup answer payload. Every status except [FOUND] travels in the smallest size class. */
object LookupStatus {
    const val FOUND: Byte = 0

    /** Also: negative cache hit, attempt limit, content that failed validation at the relay. */
    const val NOT_FOUND: Byte = 1

    /** Per-link, global, byte budget or in-flight limit of the relay. */
    const val RATE_LIMITED: Byte = 2

    /** The key does not parse (a CID that is not raw/SHA-256, an IPNS key that is not an Ed25519 `/ipns/` name). */
    const val MALFORMED: Byte = 3
    const val UNSUPPORTED_OPERATION: Byte = 4
    const val UNSUPPORTED_VERSION: Byte = 5

    /** The content is larger than the largest size class can carry. */
    const val TOO_LARGE: Byte = 6

    /** The relay runs with `--onion-relay-lookup=false`. */
    const val DISABLED: Byte = 7

    /** The relay's own lookup did not finish within its deadline. */
    const val TIMEOUT: Byte = 8

    fun isKnown(status: Byte): Boolean = status in FOUND..TIMEOUT
}

/**
 * Size classes of a lookup answer (wave V0.10.0-J2, Q8). The answer payload is `status(1) | classIndex(1) |
 * length(4) | content | random padding`, padded to the full fragments of the SMALLEST class that holds it, so the
 * number of cells reveals only the class. The class sizes are the padded payload including the 6-byte header: the
 * largest content is [MAX_CONTENT] (131,066) bytes. Cells per class: 3, 12, 46, 184.
 */
object LookupSizeClass {
    private val CLASS_SIZES = intArrayOf(2048, 8192, 32768, 131072)

    /** A copy of the class sizes (bytes of padded payload, header included). */
    val CLASSES: IntArray get() = CLASS_SIZES.copyOf()

    const val COUNT = 4
    const val ANSWER_HEADER = 6
    const val MAX_CONTENT = 131072 - ANSWER_HEADER

    fun size(classIndex: Int): Int = CLASS_SIZES[classIndex]

    /** The smallest class index that carries [contentLength] bytes of content, or `null` (too large). */
    fun classFor(contentLength: Int): Int? {
        if (contentLength < 0) return null
        for (i in CLASS_SIZES.indices) if (contentLength + ANSWER_HEADER <= CLASS_SIZES[i]) return i
        return null
    }

    /** Number of LOOKUP_RESPONSE fragments of class [classIndex]: 3, 12, 46 or 184. */
    fun fragmentCount(classIndex: Int): Int =
        (CLASS_SIZES[classIndex] + LookupResponseBody.FRAGMENT_DATA - 1) / LookupResponseBody.FRAGMENT_DATA

    /** The class whose fragment count is [fragCount], or `null`. */
    fun classForFragmentCount(fragCount: Int): Int? = (0 until COUNT).firstOrNull { fragmentCount(it) == fragCount }
}

/**
 * LOOKUP_REQUEST body (wave V0.10.0-J2), always exactly [BODY_SIZE] (720) bytes, which fits the relay-message capacity
 * of a circuit with the maximum number of hops: `version(1) = 1 | requestId(1) | op(1) | flags(1) = 0 |
 * keyLength(2) | key(<= 256) | random padding`.
 */
object LookupRequestBody {
    const val BODY_SIZE = 720
    const val VERSION: Int = 1
    const val MAX_KEY = 256
    private const val HEADER = 6

    sealed interface Decoded {
        val requestId: Int

        class Request(
            override val requestId: Int,
            val op: LookupOperation,
            key: ByteArray,
        ) : Decoded {
            private val storedKey = key.copyOf()
            val key: ByteArray get() = storedKey.copyOf()

            override fun toString(): String = "Request(op=$op)"
        }

        /** A well-formed request of an unknown version or operation: answered with [status], not a violation. */
        class Unsupported(
            override val requestId: Int,
            val status: Byte,
        ) : Decoded
    }

    fun encode(
        requestId: Int,
        op: LookupOperation,
        key: ByteArray,
        random: SecureRandom,
    ): ByteArray {
        require(requestId in 0..255) { "request id out of range" }
        require(key.isNotEmpty() && key.size <= MAX_KEY) { "key length out of range" }
        val out = ByteArray(BODY_SIZE)
        out[0] = VERSION.toByte()
        out[1] = requestId.toByte()
        out[2] = op.code.toByte()
        out[3] = 0
        out[4] = (key.size ushr 8).toByte()
        out[5] = key.size.toByte()
        key.copyInto(out, HEADER)
        fillRandom(out, HEADER + key.size, random)
        return out
    }

    /**
     * Checks the exact length first, then `flags` and `keyLength`; an unknown version or operation is returned as
     * [Decoded.Unsupported] (the relay answers it with a status instead of destroying the circuit).
     *
     * @throws CellFormatException on a wrong length, flags other than 0 or a key length of 0, above [MAX_KEY] or
     * beyond the body.
     */
    fun decode(data: ByteArray): Decoded {
        if (data.size != BODY_SIZE) throw CellFormatException("lookup request has the wrong length")
        val requestId = data[1].toInt() and 0xFF
        if (data[3].toInt() != 0) throw CellFormatException("lookup request flags must be zero")
        val keyLength = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (keyLength == 0 || keyLength > MAX_KEY || keyLength > BODY_SIZE - HEADER) {
            throw CellFormatException("lookup request key length out of range")
        }
        if ((data[0].toInt() and 0xFF) !=
            VERSION
        ) {
            return Decoded.Unsupported(requestId, LookupStatus.UNSUPPORTED_VERSION)
        }
        val op =
            LookupOperation.fromCode(data[2].toInt() and 0xFF)
                ?: return Decoded.Unsupported(requestId, LookupStatus.UNSUPPORTED_OPERATION)
        return Decoded.Request(requestId, op, data.copyOfRange(HEADER, HEADER + keyLength))
    }
}

/**
 * LOOKUP_RESPONSE fragment (wave V0.10.0-J2), always exactly [BODY_SIZE] (720) bytes: `version(1) | requestId(1) |
 * fragIndex(2) | fragCount(2) | data(714)`. The concatenated data of all fragments is the answer payload of
 * [LookupSizeClass].
 */
object LookupResponseBody {
    const val BODY_SIZE = 720
    const val HEADER = 6
    const val FRAGMENT_DATA = BODY_SIZE - HEADER
    const val VERSION: Int = 1

    class FragmentHeader(
        val requestId: Int,
        val fragIndex: Int,
        val fragCount: Int,
    )

    /** The decoded answer header inside the payload (first fragment). */
    class AnswerHeader(
        val status: Byte,
        val classIndex: Int,
        val length: Int,
    )

    /**
     * The fragments of one answer: [content] (only with [LookupStatus.FOUND]; empty otherwise) padded with random bytes
     * to the smallest class that holds it. Every status other than FOUND uses class 0.
     */
    fun encodeAnswer(
        requestId: Int,
        status: Byte,
        content: ByteArray,
        random: SecureRandom,
    ): List<ByteArray> {
        require(requestId in 0..255) { "request id out of range" }
        require(LookupStatus.isKnown(status)) { "unknown status" }
        require(status == LookupStatus.FOUND || content.isEmpty()) { "only a found answer carries content" }
        val classIndex = LookupSizeClass.classFor(content.size) ?: throw IllegalArgumentException("content too large")
        val count = LookupSizeClass.fragmentCount(classIndex)
        val payload = ByteArray(count * FRAGMENT_DATA)
        payload[0] = status
        payload[1] = classIndex.toByte()
        payload[2] = (content.size ushr 24).toByte()
        payload[3] = (content.size ushr 16).toByte()
        payload[4] = (content.size ushr 8).toByte()
        payload[5] = content.size.toByte()
        content.copyInto(payload, LookupSizeClass.ANSWER_HEADER)
        fillRandom(payload, LookupSizeClass.ANSWER_HEADER + content.size, random)
        return (0 until count).map { i ->
            val out = ByteArray(BODY_SIZE)
            out[0] = VERSION.toByte()
            out[1] = requestId.toByte()
            out[2] = (i ushr 8).toByte()
            out[3] = i.toByte()
            out[4] = (count ushr 8).toByte()
            out[5] = count.toByte()
            payload.copyInto(out, HEADER, i * FRAGMENT_DATA, (i + 1) * FRAGMENT_DATA)
            out
        }
    }

    /**
     * Checks the exact length, the version, that `fragCount` is one of the class fragment counts and that
     * `fragIndex < fragCount`.
     *
     * @throws CellFormatException on any deviation.
     */
    fun decodeFragmentHeader(data: ByteArray): FragmentHeader {
        if (data.size != BODY_SIZE) throw CellFormatException("lookup response has the wrong length")
        if ((data[0].toInt() and 0xFF) != VERSION) throw CellFormatException("lookup response version unknown")
        val fragIndex = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val fragCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (LookupSizeClass.classForFragmentCount(fragCount) == null || fragIndex >= fragCount) {
            throw CellFormatException("lookup response fragment header malformed")
        }
        return FragmentHeader(data[1].toInt() and 0xFF, fragIndex, fragCount)
    }

    /**
     * Decodes the answer header from the data of the FIRST fragment and checks it against [fragCount]: known status,
     * class index matching the fragment count, `length <= class - 6`, and class 0 for every status other than FOUND.
     *
     * @throws CellFormatException on any deviation.
     */
    fun decodeAnswerHeader(
        firstFragment: ByteArray,
        fragCount: Int,
    ): AnswerHeader {
        if (firstFragment.size != BODY_SIZE) throw CellFormatException("lookup response has the wrong length")
        val status = firstFragment[HEADER]
        val classIndex = firstFragment[HEADER + 1].toInt() and 0xFF
        val length =
            ((firstFragment[HEADER + 2].toInt() and 0xFF) shl 24) or
                ((firstFragment[HEADER + 3].toInt() and 0xFF) shl 16) or
                ((firstFragment[HEADER + 4].toInt() and 0xFF) shl 8) or
                (firstFragment[HEADER + 5].toInt() and 0xFF)
        if (!LookupStatus.isKnown(status)) throw CellFormatException("lookup response status unknown")
        if (classIndex >= LookupSizeClass.COUNT || LookupSizeClass.fragmentCount(classIndex) != fragCount) {
            throw CellFormatException("lookup response class does not match the fragment count")
        }
        if (length < 0 || length > LookupSizeClass.size(classIndex) - LookupSizeClass.ANSWER_HEADER) {
            throw CellFormatException("lookup response length exceeds its class")
        }
        if (status != LookupStatus.FOUND && (classIndex != 0 || length != 0)) {
            throw CellFormatException("lookup response error status with content")
        }
        return AnswerHeader(status, classIndex, length)
    }

    fun fragmentData(data: ByteArray): ByteArray = data.copyOfRange(HEADER, BODY_SIZE)
}

/** The version byte of a lookup request body (the first byte), or 0 when [data] is empty. */
fun lookupRequestVersion(data: ByteArray): Int = if (data.isEmpty()) 0 else data[0].toInt() and 0xFF

/**
 * LOOKUP_REQUEST body version 2 (wave Q16): a batch of up to [MAX_ITEMS] keys of ONE operation, always exactly
 * [BODY_SIZE] (720) bytes: `version(1) = 2 | requestId(1) | op(1) | flags(1) = 0 | itemCount(2) | items:
 * [keyLength(1) | key(<= 64)] x itemCount | random padding`.
 *
 * Compatibility: bytes 3..5 are laid out so that the UNCHANGED version-1 decoder of a 0.13 relay accepts the frame
 * (length 720, flags 0, a "key length" in 1..256 = the item count) and answers UNSUPPORTED_VERSION instead of
 * destroying the circuit. Do not move them.
 */
object LookupBatchRequestBody {
    const val BODY_SIZE = 720
    const val VERSION: Int = 2
    const val MAX_ITEMS = 8
    const val MAX_ITEM_KEY = 64
    private const val HEADER = 6

    sealed interface Decoded {
        val requestId: Int

        class Batch(
            override val requestId: Int,
            val op: LookupOperation,
            keys: List<ByteArray>,
        ) : Decoded {
            private val storedKeys = keys.map { it.copyOf() }
            val keys: List<ByteArray> get() = storedKeys.map { it.copyOf() }
            val itemCount: Int get() = storedKeys.size

            override fun toString(): String = "Batch(op=$op, items=${storedKeys.size})"
        }

        /** A well-formed batch of an unknown operation: answered with [status] for each of [itemCount] items. */
        class Unsupported(
            override val requestId: Int,
            val status: Byte,
            val itemCount: Int,
        ) : Decoded
    }

    fun encode(
        requestId: Int,
        op: LookupOperation,
        keys: List<ByteArray>,
        random: SecureRandom,
    ): ByteArray {
        require(requestId in 0..255) { "request id out of range" }
        require(keys.size in 1..MAX_ITEMS) { "item count out of range" }
        require(keys.all { it.size in 1..MAX_ITEM_KEY }) { "key length out of range" }
        val out = ByteArray(BODY_SIZE)
        out[0] = VERSION.toByte()
        out[1] = requestId.toByte()
        out[2] = op.code.toByte()
        out[3] = 0
        out[4] = (keys.size ushr 8).toByte()
        out[5] = keys.size.toByte()
        var pos = HEADER
        for (k in keys) {
            out[pos++] = k.size.toByte()
            k.copyInto(out, pos)
            pos += k.size
        }
        fillRandom(out, pos, random)
        return out
    }

    /** The item count of a version-2 body (bytes 4..5) if it is in range, else `null`. Does not validate more. */
    fun peekItemCount(data: ByteArray): Int? {
        if (data.size != BODY_SIZE) return null
        val n = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        return if (n in 1..MAX_ITEMS) n else null
    }

    /**
     * @throws CellFormatException on a wrong length or version, flags other than 0, an item count outside 1..[MAX_ITEMS],
     * an item key length outside 1..[MAX_ITEM_KEY], an item beyond the body or a duplicate key.
     */
    fun decode(data: ByteArray): Decoded {
        if (data.size != BODY_SIZE) throw CellFormatException("lookup batch request has the wrong length")
        if ((data[0].toInt() and 0xFF) != VERSION) throw CellFormatException("lookup batch request version unknown")
        if (data[3].toInt() != 0) throw CellFormatException("lookup batch request flags must be zero")
        val requestId = data[1].toInt() and 0xFF
        val n = peekItemCount(data) ?: throw CellFormatException("lookup batch item count out of range")
        var pos = HEADER
        val keys = ArrayList<ByteArray>(n)
        repeat(n) {
            if (pos >= BODY_SIZE) throw CellFormatException("lookup batch item beyond the body")
            val len = data[pos].toInt() and 0xFF
            pos++
            if (len < 1 || len > MAX_ITEM_KEY || pos + len > BODY_SIZE) {
                throw CellFormatException("lookup batch key length out of range")
            }
            val key = data.copyOfRange(pos, pos + len)
            pos += len
            if (keys.any { it.contentEquals(key) }) throw CellFormatException("lookup batch has a duplicate key")
            keys += key
        }
        val op =
            LookupOperation.fromCode(data[2].toInt() and 0xFF)
                ?: return Decoded.Unsupported(requestId, LookupStatus.UNSUPPORTED_OPERATION, n)
        return Decoded.Batch(requestId, op, keys)
    }
}

/**
 * LOOKUP_RESPONSE fragments for a version-2 batch (wave Q16), each exactly [BODY_SIZE] (720) bytes: `version(1) = 2 |
 * requestId(1) | itemIndex(1) | fragIndex(2) | fragCount(2) | data(713)`. Per item the payload is the unchanged
 * `status | classIndex | length | content | padding` of [LookupSizeClass], padded to the smallest class; the fragment
 * counts per class stay 3, 12, 46, 184. Items are answered strictly in request order, the fragments of an item
 * contiguously.
 */
object LookupBatchResponseBody {
    const val BODY_SIZE = 720
    const val HEADER = 7
    const val FRAGMENT_DATA = BODY_SIZE - HEADER
    const val VERSION: Int = 2

    class FragmentHeader(
        val requestId: Int,
        val itemIndex: Int,
        val fragIndex: Int,
        val fragCount: Int,
    )

    fun fragmentCount(classIndex: Int): Int = (LookupSizeClass.size(classIndex) + FRAGMENT_DATA - 1) / FRAGMENT_DATA

    private fun classForFragmentCount(fragCount: Int): Int? =
        (0 until LookupSizeClass.COUNT).firstOrNull { fragmentCount(it) == fragCount }

    fun encodeItemAnswer(
        requestId: Int,
        itemIndex: Int,
        status: Byte,
        content: ByteArray,
        random: SecureRandom,
    ): List<ByteArray> {
        require(requestId in 0..255) { "request id out of range" }
        require(itemIndex in 0 until LookupBatchRequestBody.MAX_ITEMS) { "item index out of range" }
        require(LookupStatus.isKnown(status)) { "unknown status" }
        require(status == LookupStatus.FOUND || content.isEmpty()) { "only a found answer carries content" }
        val classIndex = LookupSizeClass.classFor(content.size) ?: throw IllegalArgumentException("content too large")
        val count = fragmentCount(classIndex)
        val payload = ByteArray(count * FRAGMENT_DATA)
        payload[0] = status
        payload[1] = classIndex.toByte()
        payload[2] = (content.size ushr 24).toByte()
        payload[3] = (content.size ushr 16).toByte()
        payload[4] = (content.size ushr 8).toByte()
        payload[5] = content.size.toByte()
        content.copyInto(payload, LookupSizeClass.ANSWER_HEADER)
        fillRandom(payload, LookupSizeClass.ANSWER_HEADER + content.size, random)
        return (0 until count).map { i ->
            val out = ByteArray(BODY_SIZE)
            out[0] = VERSION.toByte()
            out[1] = requestId.toByte()
            out[2] = itemIndex.toByte()
            out[3] = (i ushr 8).toByte()
            out[4] = i.toByte()
            out[5] = (count ushr 8).toByte()
            out[6] = count.toByte()
            payload.copyInto(out, HEADER, i * FRAGMENT_DATA, (i + 1) * FRAGMENT_DATA)
            out
        }
    }

    /** All fragments of a batch in request order; [answers] are `(status, content)` per item. */
    fun encodeBatch(
        requestId: Int,
        answers: List<Pair<Byte, ByteArray>>,
        random: SecureRandom,
    ): List<ByteArray> =
        answers.flatMapIndexed { i, (status, content) -> encodeItemAnswer(requestId, i, status, content, random) }

    /**
     * @throws CellFormatException on a wrong length or version, an item index at or above [itemCount], a fragment
     * count that is not a class count or a fragment index at or above the count.
     */
    fun decodeFragmentHeader(
        data: ByteArray,
        itemCount: Int,
    ): FragmentHeader {
        if (data.size != BODY_SIZE) throw CellFormatException("lookup batch response has the wrong length")
        if ((data[0].toInt() and 0xFF) != VERSION) throw CellFormatException("lookup batch response version unknown")
        val itemIndex = data[2].toInt() and 0xFF
        val fragIndex = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        val fragCount = ((data[5].toInt() and 0xFF) shl 8) or (data[6].toInt() and 0xFF)
        if (itemIndex >= itemCount || classForFragmentCount(fragCount) == null || fragIndex >= fragCount) {
            throw CellFormatException("lookup batch response fragment header malformed")
        }
        return FragmentHeader(data[1].toInt() and 0xFF, itemIndex, fragIndex, fragCount)
    }

    /** Same rules as [LookupResponseBody.decodeAnswerHeader], at offset [HEADER]. */
    fun decodeAnswerHeader(
        firstFragment: ByteArray,
        fragCount: Int,
    ): LookupResponseBody.AnswerHeader {
        if (firstFragment.size != BODY_SIZE) throw CellFormatException("lookup batch response has the wrong length")
        val status = firstFragment[HEADER]
        val classIndex = firstFragment[HEADER + 1].toInt() and 0xFF
        val length =
            ((firstFragment[HEADER + 2].toInt() and 0xFF) shl 24) or
                ((firstFragment[HEADER + 3].toInt() and 0xFF) shl 16) or
                ((firstFragment[HEADER + 4].toInt() and 0xFF) shl 8) or
                (firstFragment[HEADER + 5].toInt() and 0xFF)
        if (!LookupStatus.isKnown(status)) throw CellFormatException("lookup response status unknown")
        if (classIndex >= LookupSizeClass.COUNT || fragmentCount(classIndex) != fragCount) {
            throw CellFormatException("lookup response class does not match the fragment count")
        }
        if (length < 0 || length > LookupSizeClass.size(classIndex) - LookupSizeClass.ANSWER_HEADER) {
            throw CellFormatException("lookup response length exceeds its class")
        }
        if (status != LookupStatus.FOUND && (classIndex != 0 || length != 0)) {
            throw CellFormatException("lookup response error status with content")
        }
        return LookupResponseBody.AnswerHeader(status, classIndex, length)
    }

    fun fragmentData(data: ByteArray): ByteArray = data.copyOfRange(HEADER, BODY_SIZE)
}
