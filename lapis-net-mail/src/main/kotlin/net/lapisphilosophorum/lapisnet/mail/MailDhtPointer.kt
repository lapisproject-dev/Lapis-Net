package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation

/** Thrown when a [MailDhtPointer]'s encoding is structurally invalid. */
class MalformedMailDhtPointerException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * What a mail leaves in the DHT outbox (V0.9.14): only the CID of its signed envelope blob. Recipient and expiry
 * are in the generic outbox entry header; the envelope itself (sender, recipients, signature, content CID) is
 * fetched from the sender and verified in full by [InboxDhtFetcher] - this pointer is not trusted for anything.
 */
class MailDhtPointer(
    val envelopeCid: Cid,
)

/**
 * `version(1) | envelopeCidLen(1, 1..MessageEnvelopeCodec.MAX_CID_BYTES) | envelopeCid`, at most [MAX_BYTES].
 * Every length is checked against the bytes actually present before anything is allocated; no trailing bytes;
 * the CID's own declared multihash length is checked ([CidBytesValidation]) before `Cid.cast` sees it.
 */
object MailDhtPointerCodec {
    const val VERSION: Int = 1

    /** `1 + 1 + 128`; pinned against the directory module's mirrored constant by a test. */
    const val MAX_BYTES: Int = 2 + MessageBodyCodec.MAX_CID_BYTES

    fun encode(pointer: MailDhtPointer): ByteArray {
        val cid = pointer.envelopeCid.toBytes()
        require(cid.size in 1..MessageBodyCodec.MAX_CID_BYTES) { "envelope cid is ${cid.size} bytes" }
        return byteArrayOf(VERSION.toByte(), cid.size.toByte()) + cid
    }

    /** @throws MalformedMailDhtPointerException */
    fun decode(bytes: ByteArray): MailDhtPointer {
        if (bytes.size < 3 || bytes.size > MAX_BYTES) throw MalformedMailDhtPointerException("bad size: ${bytes.size}")
        val version = bytes[0].toInt() and 0xFF
        if (version != VERSION) throw MalformedMailDhtPointerException("unsupported version $version")
        val length = bytes[1].toInt() and 0xFF
        if (length !in 1..MessageBodyCodec.MAX_CID_BYTES) {
            throw MalformedMailDhtPointerException("invalid cid length: $length")
        }
        if (bytes.size != 2 + length) throw MalformedMailDhtPointerException("length mismatch or trailing bytes")
        val cidBytes = bytes.copyOfRange(2, bytes.size)
        if (!CidBytesValidation.isSafeToCast(cidBytes)) {
            throw MalformedMailDhtPointerException("cid declares an unsafe multihash length")
        }
        return try {
            MailDhtPointer(Cid.cast(cidBytes))
        } catch (e: RuntimeException) {
            throw MalformedMailDhtPointerException("invalid cid", e)
        }
    }
}
