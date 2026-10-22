package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.security.SecureRandom

/** Application-level type inside an end-to-end blob. */
enum class E2eType(
    val code: Byte,
) {
    DATA(1),
    END(2),
    DROP(3),
    ;

    companion object {
        fun fromCode(b: Byte): E2eType? = entries.firstOrNull { it.code == b }
    }
}

private const val E2E_AAD_LABEL = "LapisNet:hs-e2e:v1"
private const val E2E_HEADER = 1 + 2

/**
 * The end-to-end layer between the two ends of a rendezvous, independent of the hops on either side. Every
 * blob is exactly [HsConstants.E2E_BLOB_SIZE] bytes (plaintext `type | length | data | random padding`
 * sealed with ChaCha20-Poly1305, implicit counter nonce, no replay window: a replayed, dropped, duplicated
 * or reordered blob fails the tag and poisons the session).
 */
class RendezvousEndToEnd internal constructor(
    keys: CircuitHopKeys,
    role: Role,
) : AutoCloseable {
    enum class Role { SENDER, RECEIVER }

    private val sealCipher: HopCipher
    private val openCipher: HopCipher

    init {
        // sender: seals with Kf (FORWARD), opens with Kb (BACKWARD); receiver the other way round.
        val f = keys.forwardKeyCopy()
        val b = keys.backwardKeyCopy()
        keys.close()
        if (role == Role.SENDER) {
            sealCipher = HopCipher(f, Direction.FORWARD, 1, aadLabel = E2E_AAD_LABEL)
            openCipher = HopCipher(b, Direction.BACKWARD, 1, aadLabel = E2E_AAD_LABEL)
        } else {
            sealCipher = HopCipher(b, Direction.BACKWARD, 1, aadLabel = E2E_AAD_LABEL)
            openCipher = HopCipher(f, Direction.FORWARD, 1, aadLabel = E2E_AAD_LABEL)
        }
    }

    /** Largest application payload per blob. */
    val maxPayload: Int get() = HsConstants.E2E_BLOB_SIZE - PLAIN_OVERHEAD - E2E_HEADER

    @Synchronized
    fun seal(
        type: E2eType,
        data: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        require(data.size <= maxPayload) { "payload too large" }
        val plain = ByteArray(HsConstants.E2E_BLOB_SIZE - PLAIN_OVERHEAD)
        plain[0] = type.code
        plain[1] = (data.size ushr 8).toByte()
        plain[2] = data.size.toByte()
        data.copyInto(plain, E2E_HEADER)
        fillRandom(plain, E2E_HEADER + data.size, random)
        try {
            return sealCipher.seal(plain)
        } finally {
            plain.fill(0)
        }
    }

    /** Throws [OnionIntegrityException] on any failure; the session is poisoned afterwards. */
    @Synchronized
    fun open(blob: ByteArray): Pair<E2eType, ByteArray> {
        if (blob.size != HsConstants.E2E_BLOB_SIZE) throw OnionIntegrityException()
        val plain = openCipher.open(blob)
        try {
            val type = E2eType.fromCode(plain[0]) ?: throw OnionIntegrityException()
            val len = ((plain[1].toInt() and 0xFF) shl 8) or (plain[2].toInt() and 0xFF)
            if (len > plain.size - E2E_HEADER) throw OnionIntegrityException()
            return type to plain.copyOfRange(E2E_HEADER, E2E_HEADER + len)
        } finally {
            plain.fill(0)
        }
    }

    @Synchronized
    override fun close() {
        sealCipher.close()
        openCipher.close()
    }

    internal fun zeroizedForTest(): Boolean =
        sealCipher.keyRaw.all { it == 0.toByte() } && openCipher.keyRaw.all { it == 0.toByte() }

    override fun toString(): String = "RendezvousEndToEnd(REDACTED)"

    private companion object {
        const val PLAIN_OVERHEAD = OnionConstants.TAG_SIZE
    }
}

/** Sender-side end-to-end handshake state (holds the ephemeral scalar until [RendezvousHandshake.senderFinish]). */
class RendezvousSenderState internal constructor(
    internal val ntor: NtorClientState,
    val clientEphemeral: X25519PublicKey,
) : AutoCloseable {
    override fun close() = ntor.close()

    override fun toString(): String = "RendezvousSenderState(REDACTED)"
}

/** The receiver's reply: `Y | AUTH`, to be sent with the cookie in RENDEZVOUS1. */
class RendezvousReply internal constructor(
    val serverEphemeral: ByteArray,
    val auth: ByteArray,
) {
    override fun toString(): String = "RendezvousReply(REDACTED)"
}

/**
 * End-to-end handshake of a rendezvous: the existing ntor construction with its own protocol id, the
 * service id as identity and the service's encryption key as the "onion key". AUTH proves to the sender that
 * the party that read the INTRODUCE holds the encryption key listed in the (service-key-signed) descriptor.
 */
object RendezvousHandshake {
    fun senderStart(
        address: OnionServiceAddress,
        encKey: X25519PublicKey,
        random: SecureRandom = SecureRandom(),
    ): RendezvousSenderState {
        val (state, x) = NtorHandshake.clientStartRaw(address.serviceIdDigest(), encKey, random)
        return RendezvousSenderState(state, x)
    }

    fun receiverRespond(
        serviceIdDigest: ByteArray,
        encPrivate: X25519PrivateKey,
        encPublic: X25519PublicKey,
        clientEphemeral: X25519PublicKey,
        random: SecureRandom = SecureRandom(),
    ): Pair<RendezvousReply, RendezvousEndToEnd> {
        val result =
            NtorHandshake.serverRespondRaw(
                serviceIdDigest,
                encPublic,
                encPrivate,
                clientEphemeral,
                NtorLabels.HS,
                random,
            )
        return RendezvousReply(result.created.serverEphemeral.bytes, result.created.auth) to
            RendezvousEndToEnd(result.keys, RendezvousEndToEnd.Role.RECEIVER)
    }

    /** Zeroises [state] on every path. Throws [OnionHandshakeException] if AUTH does not verify. */
    fun senderFinish(
        state: RendezvousSenderState,
        rendezvous2Payload: ByteArray,
    ): RendezvousEndToEnd {
        val created =
            try {
                CreatedBody.fromExtendedPayload(rendezvous2Payload)
            } catch (e: CellFormatException) {
                state.close()
                throw OnionHandshakeException()
            }
        val keys = NtorHandshake.clientFinishRaw(state.ntor, created, NtorLabels.HS)
        return RendezvousEndToEnd(keys, RendezvousEndToEnd.Role.SENDER)
    }
}
