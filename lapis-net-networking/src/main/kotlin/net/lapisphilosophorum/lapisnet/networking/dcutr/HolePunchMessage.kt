package net.lapisphilosophorum.lapisnet.networking.dcutr

import com.google.protobuf.CodedInputStream
import com.google.protobuf.CodedOutputStream
import com.google.protobuf.InvalidProtocolBufferException
import com.google.protobuf.WireFormat
import java.io.ByteArrayOutputStream

/** `holepunch.proto` of the libp2p DCUtR specification: `CONNECT = 100`, `SYNC = 300`. */
enum class HolePunchType(
    val wire: Int,
) {
    CONNECT(100),
    SYNC(300),
    ;

    companion object {
        fun fromWire(value: Int): HolePunchType? = entries.firstOrNull { it.wire == value }
    }
}

data class HolePunchMessage(
    val type: HolePunchType,
    val observedAddresses: List<ByteArray> = emptyList(),
) {
    override fun equals(other: Any?): Boolean =
        other is HolePunchMessage &&
            other.type == type &&
            other.observedAddresses.size == observedAddresses.size &&
            other.observedAddresses.indices.all { other.observedAddresses[it].contentEquals(observedAddresses[it]) }

    override fun hashCode(): Int = type.hashCode() * 31 + observedAddresses.sumOf { it.contentHashCode() }
}

/** The peer sent something that is not a valid hole-punch message. */
class HolePunchProtocolException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Hand-written wire codec for [HolePunchMessage] (field 1 = type varint, field 2 = repeated bytes),
 * so the project needs no protobuf code generator. Strict: every limit violation, an unknown type, a
 * missing type, a group wire type and any malformed byte sequence throws [HolePunchProtocolException].
 */
internal object HolePunchCodec {
    const val MAX_MESSAGE_BYTES = 4096
    const val MAX_OBSERVED_ADDRESSES = 8
    const val MAX_ADDRESS_BYTES = 64

    private const val TYPE_TAG = (1 shl 3) or WireFormat.WIRETYPE_VARINT
    private const val ADDRESS_TAG = (2 shl 3) or WireFormat.WIRETYPE_LENGTH_DELIMITED

    fun encode(message: HolePunchMessage): ByteArray {
        require(message.observedAddresses.size <= MAX_OBSERVED_ADDRESSES) { "too many observed addresses" }
        require(message.observedAddresses.all { it.size <= MAX_ADDRESS_BYTES }) { "observed address too long" }
        val out = ByteArrayOutputStream()
        val coded = CodedOutputStream.newInstance(out)
        coded.writeEnum(1, message.type.wire)
        message.observedAddresses.forEach { coded.writeByteArray(2, it) }
        coded.flush()
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): HolePunchMessage {
        if (bytes.size >
            MAX_MESSAGE_BYTES
        ) {
            throw HolePunchProtocolException("message larger than $MAX_MESSAGE_BYTES bytes")
        }
        try {
            val input = CodedInputStream.newInstance(bytes)
            var type: HolePunchType? = null
            val addresses = ArrayList<ByteArray>()
            while (true) {
                val tag = input.readTag()
                if (tag == 0) break
                when (tag) {
                    TYPE_TAG -> {
                        if (type != null) throw HolePunchProtocolException("duplicate type field")
                        val raw = input.readEnum()
                        type =
                            HolePunchType.fromWire(raw) ?: throw HolePunchProtocolException("unknown message type $raw")
                    }
                    ADDRESS_TAG -> {
                        if (addresses.size >=
                            MAX_OBSERVED_ADDRESSES
                        ) {
                            throw HolePunchProtocolException("too many addresses")
                        }
                        val address = input.readByteArray()
                        if (address.size > MAX_ADDRESS_BYTES) throw HolePunchProtocolException("address too long")
                        addresses += address
                    }
                    else -> {
                        val wireType = WireFormat.getTagWireType(tag)
                        if (wireType == WireFormat.WIRETYPE_START_GROUP || wireType == WireFormat.WIRETYPE_END_GROUP) {
                            throw HolePunchProtocolException("unsupported wire type $wireType")
                        }
                        if (!input.skipField(tag)) break
                    }
                }
            }
            return HolePunchMessage(type ?: throw HolePunchProtocolException("missing message type"), addresses)
        } catch (e: InvalidProtocolBufferException) {
            throw HolePunchProtocolException("malformed message", e)
        }
    }
}
