package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.BODY_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.DIGEST_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_HOPS
import java.security.SecureRandom

private const val KEY_SIZE = 32

/** Fills [from] until the end of [body] with CSPRNG bytes. Unused body space is random, not zero,
 * so that empty fields reveal nothing; parsers ignore it. */
internal fun fillRandom(
    body: ByteArray,
    from: Int,
    random: SecureRandom,
) {
    val rest = ByteArray(body.size - from)
    random.nextBytes(rest)
    rest.copyInto(body, from)
}

/**
 * CREATE body: `handshakeType(2) | hopIndex(1) | relayIdDigest(32) | onionKeyFingerprint(32) |
 * clientEphemeral X(32) | random`.
 *
 * [hopIndex] (1-based position of the addressed relay in the circuit) is set by the client and
 * tells the relay which layer size to use; it is also bound into every AEAD's associated data, so a
 * wrong value merely makes the client's own circuit fail. It reveals the relay's position to that
 * relay (see docs/anonymity.adoc, known leaks).
 */
class CreateBody(
    val hopIndex: Int,
    relayIdDigest: ByteArray,
    onionKeyFingerprint: ByteArray,
    val clientEphemeral: X25519PublicKey,
    val handshakeType: Int = OnionConstants.HANDSHAKE_NTOR,
) {
    private val storedRelayId = relayIdDigest.copyOf()
    private val storedFingerprint = onionKeyFingerprint.copyOf()

    val relayIdDigest: ByteArray get() = storedRelayId.copyOf()
    val onionKeyFingerprint: ByteArray get() = storedFingerprint.copyOf()

    init {
        require(hopIndex in 1..MAX_HOPS) { "hop index out of range" }
        require(storedRelayId.size == DIGEST_SIZE && storedFingerprint.size == DIGEST_SIZE) { "digest size" }
    }

    fun encode(random: SecureRandom = SecureRandom()): ByteArray {
        val b = ByteArray(BODY_SIZE)
        b[0] = (handshakeType ushr 8).toByte()
        b[1] = handshakeType.toByte()
        b[2] = hopIndex.toByte()
        storedRelayId.copyInto(b, 3)
        storedFingerprint.copyInto(b, 3 + DIGEST_SIZE)
        clientEphemeral.bytes.copyInto(b, 3 + 2 * DIGEST_SIZE)
        fillRandom(b, USED, random)
        return b
    }

    override fun toString(): String = "CreateBody(hopIndex=$hopIndex)"

    companion object {
        private const val USED = 3 + 2 * DIGEST_SIZE + KEY_SIZE

        fun decode(body: ByteArray): CreateBody {
            if (body.size != BODY_SIZE) throw CellFormatException("create body has wrong size")
            val type = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
            if (type != OnionConstants.HANDSHAKE_NTOR) throw CellFormatException("unsupported handshake type")
            val hop = body[2].toInt() and 0xFF
            if (hop !in 1..MAX_HOPS) throw CellFormatException("hop index out of range")
            val x =
                try {
                    X25519PublicKey(body.copyOfRange(3 + 2 * DIGEST_SIZE, USED))
                } catch (e: IllegalArgumentException) {
                    throw CellFormatException("invalid client ephemeral")
                }
            return CreateBody(
                hop,
                body.copyOfRange(3, 3 + DIGEST_SIZE),
                body.copyOfRange(3 + DIGEST_SIZE, 3 + 2 * DIGEST_SIZE),
                x,
                type,
            )
        }
    }
}

/** CREATED body: `Y(32) | AUTH(32) | random`. */
class CreatedBody(
    val serverEphemeral: X25519PublicKey,
    auth: ByteArray,
) {
    private val storedAuth = auth.copyOf()
    val auth: ByteArray get() = storedAuth.copyOf()

    init {
        require(storedAuth.size == DIGEST_SIZE) { "auth size" }
    }

    fun encode(random: SecureRandom = SecureRandom()): ByteArray {
        val b = ByteArray(BODY_SIZE)
        serverEphemeral.bytes.copyInto(b, 0)
        storedAuth.copyInto(b, KEY_SIZE)
        fillRandom(b, KEY_SIZE + DIGEST_SIZE, random)
        return b
    }

    /** The 64-byte `Y | AUTH` form carried inside an EXTENDED relay message. */
    fun toExtendedPayload(): ByteArray = serverEphemeral.bytes + storedAuth

    override fun toString(): String = "CreatedBody(REDACTED)"

    companion object {
        fun decode(body: ByteArray): CreatedBody {
            if (body.size != BODY_SIZE) throw CellFormatException("created body has wrong size")
            return fromExtendedPayload(body.copyOfRange(0, KEY_SIZE + DIGEST_SIZE))
        }

        fun fromExtendedPayload(data: ByteArray): CreatedBody {
            if (data.size != KEY_SIZE + DIGEST_SIZE) throw CellFormatException("created payload has wrong size")
            val y =
                try {
                    X25519PublicKey(data.copyOfRange(0, KEY_SIZE))
                } catch (e: IllegalArgumentException) {
                    throw CellFormatException("invalid server ephemeral")
                }
            return CreatedBody(y, data.copyOfRange(KEY_SIZE, KEY_SIZE + DIGEST_SIZE))
        }
    }
}

enum class DestroyReason(
    val code: Byte,
) {
    NONE(0),
    PROTOCOL(1),
    INTERNAL(2),
    RESOURCE_LIMIT(3),
    FINISHED(4),
    AUTH_FAILED(5),
}

/** DESTROY body: `reason(1) | random`. An unknown reason code decodes as PROTOCOL: a DESTROY is
 * always honoured. */
object DestroyBody {
    fun encode(
        reason: DestroyReason,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        val b = ByteArray(BODY_SIZE)
        b[0] = reason.code
        fillRandom(b, 1, random)
        return b
    }

    fun decode(body: ByteArray): DestroyReason {
        if (body.size != BODY_SIZE) throw CellFormatException("destroy body has wrong size")
        return DestroyReason.entries.firstOrNull { it.code == body[0] } ?: DestroyReason.PROTOCOL
    }
}
