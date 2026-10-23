package net.lapisphilosophorum.lapisnet.onion

import java.security.SecureRandom

/** The kind of directory object carried by a DIRECTORY_PUBLISH message (wave V0.10.0-D). */
enum class DirectoryObjectType(
    val code: Int,
) {
    ANONYMOUS_PEER_RECORD(1),
    ONION_SERVICE_DESCRIPTOR(2),
    PREKEY_BUNDLE(3),
    ;

    companion object {
        fun fromCode(code: Int): DirectoryObjectType? = entries.firstOrNull { it.code == code }
    }
}

/** Status byte of DIRECTORY_PUBLISHED. The same value (0) is returned for a new and for an already known object. */
object DirectoryPublishStatus {
    const val ACCEPTED: Byte = 0
    const val INVALID: Byte = 1
    const val RATE_LIMITED: Byte = 2
    const val MALFORMED: Byte = 3
    const val UNKNOWN_TYPE: Byte = 4
}

/** A decoded DIRECTORY_PUBLISH request. `toString` never prints the object. */
class DirectoryPublishRequest(
    val type: DirectoryObjectType,
    objectBytes: ByteArray,
) {
    private val stored = objectBytes.copyOf()
    val objectBytes: ByteArray get() = stored.copyOf()

    override fun toString(): String = "DirectoryPublishRequest(type=$type, length=${stored.size})"
}

/**
 * DIRECTORY_PUBLISH body, always exactly [BODY_SIZE] (720) bytes so that the three object kinds are
 * indistinguishable by length: `type(1) | length(2) | object(<= 717) | random padding`. The padding is random and
 * never interpreted. 720 fits the relay-message capacity of a circuit with the maximum number of hops (929 bytes).
 */
object DirectoryPublishBody {
    const val BODY_SIZE = 720
    const val MAX_OBJECT_SIZE = BODY_SIZE - 3

    fun encode(
        type: DirectoryObjectType,
        objectBytes: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        require(objectBytes.isNotEmpty() && objectBytes.size <= MAX_OBJECT_SIZE) { "directory object does not fit" }
        val out = ByteArray(BODY_SIZE)
        out[0] = type.code.toByte()
        out[1] = (objectBytes.size ushr 8).toByte()
        out[2] = objectBytes.size.toByte()
        objectBytes.copyInto(out, 3)
        val padding = ByteArray(BODY_SIZE - 3 - objectBytes.size)
        random.nextBytes(padding)
        padding.copyInto(out, 3 + objectBytes.size)
        return out
    }

    /**
     * The exact length is checked first.
     *
     * @throws CellFormatException on a wrong length, an unknown type or a `length` field that overflows the body.
     */
    fun decode(data: ByteArray): DirectoryPublishRequest {
        if (data.size != BODY_SIZE) throw CellFormatException("directory publish body has the wrong length")
        val type =
            DirectoryObjectType.fromCode(data[0].toInt() and 0xFF) ?: throw CellFormatException("unknown object type")
        val length = ((data[1].toInt() and 0xFF) shl 8) or (data[2].toInt() and 0xFF)
        if (length == 0 || length > MAX_OBJECT_SIZE) throw CellFormatException("directory object length out of range")
        return DirectoryPublishRequest(type, data.copyOfRange(3, 3 + length))
    }

    /** `true` iff the first byte names a known object type (the body length must have been checked by the caller). */
    fun knownType(data: ByteArray): Boolean =
        data.isNotEmpty() && DirectoryObjectType.fromCode(data[0].toInt() and 0xFF) != null
}
