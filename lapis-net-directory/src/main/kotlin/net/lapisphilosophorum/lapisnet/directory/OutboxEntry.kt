package net.lapisphilosophorum.lapisnet.directory

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

/**
 * What an [OutboxEntry] points at (V0.9.14). The directory module deliberately knows no mail or DM types: a
 * kind only fixes the wire id and the largest opaque payload; the module that owns the kind (lapis-net-dm,
 * lapis-net-mail) encodes and fully verifies the payload itself.
 *
 * [maxPayloadBytes] mirrors the maximum of the owning codec (`MailboxPointerCodec.MAX_POINTER_BYTES`,
 * `MailDhtPointerCodec.MAX_BYTES`); tests in those modules pin the equality, because this module cannot depend
 * on them.
 */
enum class OutboxEntryKind(
    val wireId: Int,
    val maxPayloadBytes: Int,
) {
    /** A signed `MailboxPointer` (offline direct message). */
    DM_MAILBOX_POINTER(1, 274),

    /** A pointer to a mail envelope blob (see `MailDhtPointerCodec`). */
    MAIL_POINTER(2, 130),
    ;

    companion object {
        fun fromWireId(id: Int): OutboxEntryKind? = entries.firstOrNull { it.wireId == id }
    }
}

/**
 * One entry of the "outbox" part of a [DirectoryDhtValue]: a typed, opaque [payload] (always only a pointer,
 * never the message itself) addressed to [recipient] and valid until [notValidAfterEpochSecond]. The header
 * (kind, recipient, expiry) is NOT signed by itself; it travels inside the signed IPNS record of the sender,
 * and the consumer re-verifies the payload and checks that the header agrees with it.
 */
class OutboxEntry(
    val kind: OutboxEntryKind,
    val recipient: Secp256k1PublicKey,
    val notValidAfterEpochSecond: Long,
    payload: ByteArray,
) {
    private val storedPayload: ByteArray = payload.copyOf()

    /** A fresh copy on every access. */
    val payload: ByteArray get() = storedPayload.copyOf()

    init {
        require(storedPayload.isNotEmpty()) { "outbox payload must not be empty" }
        require(storedPayload.size <= kind.maxPayloadBytes) {
            "outbox payload for $kind is at most ${kind.maxPayloadBytes} bytes, was ${storedPayload.size}"
        }
    }

    /** Size of this entry in the encoded value: `kind(1) | recipient(33) | notValidAfter(8) | len(2) | payload`. */
    internal fun encodedSize(): Int = HEADER_SIZE + storedPayload.size

    /** SHA-256 over `kind | recipient | notValidAfter | payload`: identical entries share an id. */
    fun contentId(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(kind.wireId.toByte())
        digest.update(recipient.bytes)
        val nva = notValidAfterEpochSecond
        for (shift in 56 downTo 0 step 8) digest.update((nva ushr shift).toByte())
        digest.update(storedPayload)
        return digest.digest()
    }

    override fun equals(other: Any?): Boolean =
        other is OutboxEntry &&
            kind == other.kind &&
            recipient == other.recipient &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            storedPayload.contentEquals(other.storedPayload)

    override fun hashCode(): Int {
        var result = kind.hashCode()
        result = 31 * result + recipient.hashCode()
        result = 31 * result + notValidAfterEpochSecond.hashCode()
        result = 31 * result + storedPayload.contentHashCode()
        return result
    }

    override fun toString(): String =
        "OutboxEntry(kind=$kind, recipient=${recipient.fingerprint()}, " +
            "notValidAfter=$notValidAfterEpochSecond, payloadBytes=${storedPayload.size})"

    internal companion object {
        const val HEADER_SIZE: Int = 1 + 33 + 8 + 2
    }
}

/** What an [OutboxEntryConsumer] did with an entry. */
enum class OutboxIngestOutcome { ACCEPTED, DUPLICATE, REJECTED, DEFERRED }

/**
 * The seam through which the module that owns an [OutboxEntryKind] receives entries addressed to the local
 * identity (see [DirectoryDht.registerOutboxConsumer]).
 */
fun interface OutboxEntryConsumer {
    /**
     * Called outside every [DirectoryDht] lock, on the thread of the resolve caller. [sender] is the identity
     * of the value's publisher (checked by [DirectoryDhtValidator]); [senderPeerId] is the Ed25519 peer ID
     * that signed the IPNS record. Must not block on network I/O and must not call back into [DirectoryDht].
     */
    fun onDhtOutboxEntry(
        sender: Secp256k1PublicKey,
        senderPeerId: PeerId,
        entry: OutboxEntry,
    ): OutboxIngestOutcome
}
