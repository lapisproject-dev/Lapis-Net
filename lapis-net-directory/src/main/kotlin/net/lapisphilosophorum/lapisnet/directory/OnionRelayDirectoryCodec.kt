package net.lapisphilosophorum.lapisnet.directory

/** Protocol id of the relay directory snapshot (wave V0.10.0-J1b). */
const val ONION_RELAY_DIRECTORY_PROTOCOL_ID = "/lapis/onion-relay-directory/1.0.0"

/** Thrown for any structurally invalid snapshot bytes. The message never contains byte contents. */
class MalformedRelayDirectorySnapshotException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * One snapshot entry: a structurally decoded (NOT yet verified) relay descriptor and, if the serving node had a usable
 * one, the encoded peer record of the same relay (also not verified). [RelayDirectorySnapshotIngest] verifies both.
 */
class RelayDirectorySnapshotEntry(
    val descriptor: OnionRelayDescriptor,
    recordBytes: ByteArray?,
) {
    private val storedRecord = recordBytes?.copyOf()

    val recordBytes: ByteArray? get() = storedRecord?.copyOf()
}

/** A decoded snapshot (at most [OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES] entries). */
class RelayDirectorySnapshot(
    val entries: List<RelayDirectorySnapshotEntry>,
)

/**
 * Wire format of `/lapis/onion-relay-directory/1.0.0` (wave V0.10.0-J1b).
 *
 * Request: exactly [REQUEST_SIZE] bytes, `"LNRD" | version(1)`. It carries no parameter on purpose: the request does not
 * tell the serving node what the asking node already knows (no "since" field that could become a fingerprint).
 *
 * Response: `"LNRS" | version(1) | count(u16) | count x ( descriptor[379] | recordLen(u16) | record[recordLen] )`;
 * `recordLen = 0` means no record. Limits ([MAX_SNAPSHOT_ENTRIES], [MAX_SNAPSHOT_RECORD_BYTES],
 * [MAX_SNAPSHOT_RESPONSE_BYTES]) are checked from the header fields BEFORE anything is allocated; trailing bytes are
 * rejected. Any structural fault rejects the whole response.
 */
object OnionRelayDirectoryCodec {
    const val VERSION = 1
    const val REQUEST_SIZE = 5
    const val HEADER_SIZE = 7
    const val MAX_SNAPSHOT_ENTRIES = 256
    const val MAX_SNAPSHOT_RECORD_BYTES = 1024
    const val MAX_SNAPSHOT_RESPONSE_BYTES = 512 * 1024
    private val REQUEST_MAGIC = byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'R'.code.toByte(), 'D'.code.toByte())
    private val RESPONSE_MAGIC = byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'R'.code.toByte(), 'S'.code.toByte())
    private const val DESCRIPTOR_SIZE = OnionRelayDescriptorCodec.ENCODED_SIZE

    fun encodeRequest(): ByteArray = REQUEST_MAGIC + VERSION.toByte()

    /** `true` for exactly the [REQUEST_SIZE] bytes of [encodeRequest]. */
    fun isValidRequest(bytes: ByteArray): Boolean = bytes.contentEquals(encodeRequest())

    /** Encodes a response; [entries] pairs a descriptor with its encoded peer record (or `null`). */
    fun encodeResponse(entries: List<Pair<OnionRelayDescriptor, ByteArray?>>): ByteArray {
        require(entries.size <= MAX_SNAPSHOT_ENTRIES) { "too many snapshot entries" }
        var size = HEADER_SIZE
        for ((_, record) in entries) {
            require(record == null || record.size in 1..MAX_SNAPSHOT_RECORD_BYTES) { "snapshot record too large" }
            size += DESCRIPTOR_SIZE + 2 + (record?.size ?: 0)
        }
        require(size <= MAX_SNAPSHOT_RESPONSE_BYTES) { "snapshot response too large" }
        val out = java.nio.ByteBuffer.allocate(size)
        out.put(RESPONSE_MAGIC)
        out.put(VERSION.toByte())
        out.putShort(entries.size.toShort())
        for ((descriptor, record) in entries) {
            out.put(OnionRelayDescriptorCodec.encode(descriptor))
            out.putShort((record?.size ?: 0).toShort())
            record?.let { out.put(it) }
        }
        return out.array()
    }

    /**
     * The total length of the response whose first [length] bytes are in [buffer], or `null` while that can not be known
     * yet. Only header and length fields are read; violations throw [MalformedRelayDirectorySnapshotException]. Lets a
     * reader decide completion without depending on stream close semantics.
     */
    fun expectedResponseLength(
        buffer: ByteArray,
        length: Int,
    ): Int? {
        if (length < HEADER_SIZE) {
            checkMagicPrefix(buffer, length)
            return null
        }
        checkMagicPrefix(buffer, HEADER_SIZE)
        val count = u16(buffer, 5)
        if (count > MAX_SNAPSHOT_ENTRIES) throw MalformedRelayDirectorySnapshotException("too many snapshot entries")
        var offset = HEADER_SIZE
        repeat(count) {
            offset += DESCRIPTOR_SIZE
            if (length < offset + 2) return null
            val recordLen = u16(buffer, offset)
            if (recordLen > MAX_SNAPSHOT_RECORD_BYTES) {
                throw MalformedRelayDirectorySnapshotException("snapshot record too large")
            }
            offset += 2 + recordLen
            if (offset > MAX_SNAPSHOT_RESPONSE_BYTES) {
                throw MalformedRelayDirectorySnapshotException("snapshot response too large")
            }
        }
        return offset
    }

    fun decodeResponse(bytes: ByteArray): RelayDirectorySnapshot {
        if (bytes.size > MAX_SNAPSHOT_RESPONSE_BYTES) {
            throw MalformedRelayDirectorySnapshotException("snapshot response too large")
        }
        val expected =
            expectedResponseLength(bytes, bytes.size)
                ?: throw MalformedRelayDirectorySnapshotException("truncated snapshot response")
        if (bytes.size < expected) throw MalformedRelayDirectorySnapshotException("truncated snapshot response")
        if (bytes.size > expected) throw MalformedRelayDirectorySnapshotException("trailing bytes after snapshot")
        val count = u16(bytes, 5)
        val entries = ArrayList<RelayDirectorySnapshotEntry>(count)
        var offset = HEADER_SIZE
        repeat(count) {
            val descriptor =
                try {
                    OnionRelayDescriptorCodec.decode(bytes.copyOfRange(offset, offset + DESCRIPTOR_SIZE))
                } catch (e: MalformedOnionRelayDescriptorException) {
                    throw MalformedRelayDirectorySnapshotException("malformed descriptor in snapshot", e)
                }
            offset += DESCRIPTOR_SIZE
            val recordLen = u16(bytes, offset)
            offset += 2
            val record = if (recordLen == 0) null else bytes.copyOfRange(offset, offset + recordLen)
            offset += recordLen
            entries += RelayDirectorySnapshotEntry(descriptor, record)
        }
        return RelayDirectorySnapshot(entries)
    }

    private fun checkMagicPrefix(
        buffer: ByteArray,
        length: Int,
    ) {
        for (i in 0 until minOf(length, 4)) {
            if (buffer[i] != RESPONSE_MAGIC[i]) throw MalformedRelayDirectorySnapshotException("wrong snapshot magic")
        }
        if (length >= 5 && buffer[4].toInt() != VERSION) {
            throw MalformedRelayDirectorySnapshotException("unsupported snapshot version")
        }
    }

    private fun u16(
        b: ByteArray,
        at: Int,
    ): Int = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)
}
