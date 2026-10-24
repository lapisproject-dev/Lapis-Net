package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.BODY_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.DIGEST_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.LAYER_OVERHEAD
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_HOPS
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_LINK_SPECIFIER
import java.security.SecureRandom

enum class RelayCommand(
    val code: Byte,
) {
    DATA(1),
    EXTEND(2),
    EXTENDED(3),
    END(4),
    DROP(5),

    // Hidden-service (rendezvous) commands, wave V0.10.0-C. Direction in docs/anonymity.adoc.
    ESTABLISH_INTRO(6),
    INTRO_ESTABLISHED(7),
    INTRODUCE1(8),
    INTRODUCE2(9),
    INTRODUCE_ACK(10),
    ESTABLISH_RENDEZVOUS(11),
    RENDEZVOUS_ESTABLISHED(12),
    RENDEZVOUS1(13),
    RENDEZVOUS2(14),
    RENDEZVOUS_DATA(15),

    // Directory publication through a circuit (wave V0.10.0-D): client to last hop, and its acknowledgement.
    DIRECTORY_PUBLISH(16),
    DIRECTORY_PUBLISHED(17),

    // Sealed mailbox item publication through a circuit (wave V0.10.0-F1): client to last hop, and its acknowledgement.
    MAILBOX_PUBLISH(18),
    MAILBOX_PUBLISHED(19),
    ;

    companion object {
        fun fromCode(b: Byte): RelayCommand? = entries.firstOrNull { it.code == b }
    }
}

/** The plaintext seen by the addressed hop. */
class RelayMessage(
    val command: RelayCommand,
    val streamId: Short,
    data: ByteArray,
) {
    private val storedData = data.copyOf()
    val data: ByteArray get() = storedData.copyOf()

    override fun toString(): String = "RelayMessage(command=$command, streamId=$streamId, length=${storedData.size})"
}

/**
 * Relay-message codec: `command(1) | streamId(2) | length(2) | data | padding`. The plaintext is
 * padded to the exact capacity of the addressed layer with random bytes (they are authenticated
 * inside the sealed layer, so padding content is not a covert channel).
 */
object RelayMessageCodec {
    const val HEADER = 1 + 2 + 2

    /** Payload capacity for a message addressed to hop [hops] (1-based). */
    fun maxData(hops: Int): Int {
        require(hops in 1..MAX_HOPS) { "hops out of range" }
        return capacity(hops) - HEADER
    }

    /** Plaintext length addressed to hop [hops]: the cell body minus one overhead per layer. */
    fun capacity(hops: Int): Int = BODY_SIZE - hops * LAYER_OVERHEAD

    fun encode(
        msg: RelayMessage,
        capacity: Int,
        random: SecureRandom,
    ): ByteArray {
        val data = msg.data
        require(capacity >= HEADER && data.size <= capacity - HEADER) { "relay message does not fit" }
        val out = ByteArray(capacity)
        out[0] = msg.command.code
        out[1] = (msg.streamId.toInt() ushr 8).toByte()
        out[2] = msg.streamId.toByte()
        out[3] = (data.size ushr 8).toByte()
        out[4] = data.size.toByte()
        data.copyInto(out, HEADER)
        fillRandom(out, HEADER + data.size, random)
        return out
    }

    fun decode(plaintext: ByteArray): RelayMessage {
        if (plaintext.size < HEADER) throw CellFormatException("relay message too short")
        val command = RelayCommand.fromCode(plaintext[0]) ?: throw CellFormatException("unknown relay command")
        val stream = (((plaintext[1].toInt() and 0xFF) shl 8) or (plaintext[2].toInt() and 0xFF)).toShort()
        val length = ((plaintext[3].toInt() and 0xFF) shl 8) or (plaintext[4].toInt() and 0xFF)
        // The length is checked against the buffer BEFORE copyOfRange: no input-dependent allocation.
        if (length > plaintext.size - HEADER) throw CellFormatException("relay message length exceeds capacity")
        return RelayMessage(command, stream, plaintext.copyOfRange(HEADER, HEADER + length))
    }
}

/**
 * EXTEND payload: `hopIndex(1) | targetRelayIdDigest(32) | onionKeyFingerprint(32) |
 * clientEphemeral X(32) | linkSpecifierLength(1) | linkSpecifier(<=128)`. The link specifier is
 * opaque in this wave (how to reach the target is a wire-integration matter, wave B).
 */
class ExtendPayload(
    val hopIndex: Int,
    targetRelayIdDigest: ByteArray,
    onionKeyFingerprint: ByteArray,
    val clientEphemeral: X25519PublicKey,
    linkSpecifier: ByteArray,
) {
    private val storedTarget = targetRelayIdDigest.copyOf()
    private val storedFingerprint = onionKeyFingerprint.copyOf()
    private val storedSpecifier = linkSpecifier.copyOf()
    val targetRelayIdDigest: ByteArray get() = storedTarget.copyOf()
    val onionKeyFingerprint: ByteArray get() = storedFingerprint.copyOf()
    val linkSpecifier: ByteArray get() = storedSpecifier.copyOf()

    init {
        require(hopIndex in 1..MAX_HOPS) { "hop index out of range" }
        require(storedTarget.size == DIGEST_SIZE && storedFingerprint.size == DIGEST_SIZE) { "digest size" }
        require(storedSpecifier.size <= MAX_LINK_SPECIFIER) { "link specifier too long" }
    }

    override fun toString(): String = "ExtendPayload(hopIndex=$hopIndex)"
}

object ExtendPayloadCodec {
    private const val FIXED = 1 + 3 * DIGEST_SIZE + 1

    fun encode(p: ExtendPayload): ByteArray {
        val spec = p.linkSpecifier
        val out = ByteArray(FIXED + spec.size)
        out[0] = p.hopIndex.toByte()
        p.targetRelayIdDigest.copyInto(out, 1)
        p.onionKeyFingerprint.copyInto(out, 1 + DIGEST_SIZE)
        p.clientEphemeral.bytes.copyInto(out, 1 + 2 * DIGEST_SIZE)
        out[1 + 3 * DIGEST_SIZE] = spec.size.toByte()
        spec.copyInto(out, FIXED)
        return out
    }

    fun decode(data: ByteArray): ExtendPayload {
        if (data.size < FIXED) throw CellFormatException("extend payload too short")
        val hop = data[0].toInt() and 0xFF
        if (hop !in 1..MAX_HOPS) throw CellFormatException("hop index out of range")
        val specLen = data[1 + 3 * DIGEST_SIZE].toInt() and 0xFF
        if (specLen > MAX_LINK_SPECIFIER) throw CellFormatException("link specifier too long")
        if (specLen != data.size - FIXED) throw CellFormatException("extend payload length mismatch")
        val x =
            try {
                X25519PublicKey(data.copyOfRange(1 + 2 * DIGEST_SIZE, 1 + 3 * DIGEST_SIZE))
            } catch (e: IllegalArgumentException) {
                throw CellFormatException("invalid client ephemeral")
            }
        return ExtendPayload(
            hop,
            data.copyOfRange(1, 1 + DIGEST_SIZE),
            data.copyOfRange(1 + DIGEST_SIZE, 1 + 2 * DIGEST_SIZE),
            x,
            data.copyOfRange(FIXED, data.size),
        )
    }
}
