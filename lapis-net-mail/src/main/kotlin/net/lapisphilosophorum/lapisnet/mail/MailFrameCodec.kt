package net.lapisphilosophorum.lapisnet.mail

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/** Thrown when decoding a [MailFrame]'s canonical byte encoding fails structurally. */
class MalformedMailFrameException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** The decoded wire frame: the two byte blobs, still completely unverified - neither the envelope
 * signature nor the CID binding to the body has been checked yet. See [MailFrameCodec]'s class doc
 * comment for why both blobs travel together on the wire. */
class MailFrame internal constructor(
    envelopeBytes: ByteArray,
    bodyBytes: ByteArray,
) {
    private val storedEnvelopeBytes: ByteArray = envelopeBytes.copyOf()
    private val storedBodyBytes: ByteArray = bodyBytes.copyOf()

    /** Returns a fresh copy on every access. */
    val envelopeBytes: ByteArray get() = storedEnvelopeBytes.copyOf()

    /** Returns a fresh copy on every access. */
    val bodyBytes: ByteArray get() = storedBodyBytes.copyOf()
}

/**
 * Wire framing for GossipSub delivery: a single frame carries BOTH a [MessageEnvelopeCodec]-encoded
 * envelope and its referenced [MessageBodyCodec]-encoded body, not a bare envelope plus a CID
 * pointer.
 *
 * **Why the body rides along instead of being fetched by CID.**
 * `net.lapisphilosophorum.lapisnet.storage.NabuStorage.get()` falls through to a live Kademlia DHT
 * provider lookup on a local cache miss - a network call, which [InboxGossip]'s GossipSub
 * validator must never make (see that class's doc comment for the full "zero clock, zero network"
 * rule it shares with `KarmaGossip`/`MadliGossip`/`LtrGossip`). And even if that were allowed,
 * cross-node DHT provider discovery is documented broken since V0.1.4
 * (`net.lapisphilosophorum.lapisnet.storage.NabuStorage.provide`'s doc comment references the
 * architecture doc's investigation) - a receiving node could never reliably fetch a body it only
 * knows by CID. This is the exact same reasoning, and the exact same resolution, as
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGossip` publishing full grant bytes rather than a
 * CID pointer (see that class's doc comment).
 *
 * Layout: `magic(4) | version(1) | flags(1, reserved, must be zero) | envelopeLen(2) |
 * envelope(envelopeLen) | bodyLen(2) | body(bodyLen)`, both lengths validated BEFORE the
 * corresponding allocation. All integers are big-endian.
 */
object MailFrameCodec {
    private val MAGIC = "LNMF".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1

    /** Cap on the envelope section's declared length. A `writeShort`/`readUnsignedShort` length
     * field can only ever represent `0..0xFFFF` - deliberately NOT
     * `MessageEnvelopeCodec.MAX_BODY_SIZE + 64` (the signed body cap plus a 64-byte signature),
     * because that sum (65599) overflows an unsigned 16-bit field and would silently wrap on
     * encode. In practice a real envelope is always far smaller (worst case ~2.6 KB for 64
     * recipients, see [MessageEnvelopeCodec.MAX_BODY_SIZE]'s doc comment) - this cap is the wire
     * field's own hard ceiling, not a tight fit to that estimate. */
    const val MAX_ENVELOPE_SECTION_BYTES = 0xFFFF

    fun encode(
        envelopeBytes: ByteArray,
        bodyBytes: ByteArray,
    ): ByteArray {
        require(envelopeBytes.size in 1..MAX_ENVELOPE_SECTION_BYTES) {
            "envelope bytes must be 1..$MAX_ENVELOPE_SECTION_BYTES, was ${envelopeBytes.size}"
        }
        require(bodyBytes.size <= MessageBodyCodec.MAX_BODY_BLOB_SIZE) {
            "body bytes must be at most ${MessageBodyCodec.MAX_BODY_BLOB_SIZE}, was ${bodyBytes.size}"
        }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: all bits reserved, must be zero
            writeShort(envelopeBytes.size)
            write(envelopeBytes)
            writeShort(bodyBytes.size)
            write(bodyBytes)
        }
        return out.toByteArray()
    }

    /** @throws MalformedMailFrameException if the bytes are structurally invalid. Both lengths are
     * validated before the corresponding allocation - see this object's class doc comment. */
    fun decode(bytes: ByteArray): MailFrame {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedMailFrameException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedMailFrameException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedMailFrameException("reserved flag bits must be zero: $flags")

            val envelopeLen = input.readUnsignedShort()
            if (envelopeLen !in 1..MAX_ENVELOPE_SECTION_BYTES) {
                throw MalformedMailFrameException("invalid envelope length: $envelopeLen")
            }
            val envelopeBytes = ByteArray(envelopeLen).also { input.readFully(it) }

            val bodyLen = input.readUnsignedShort()
            if (bodyLen > MessageBodyCodec.MAX_BODY_BLOB_SIZE) {
                throw MalformedMailFrameException("invalid body length: $bodyLen")
            }
            val bodyBytes = ByteArray(bodyLen).also { input.readFully(it) }

            if (input.available() > 0) throw MalformedMailFrameException("trailing bytes after frame")

            return MailFrame(envelopeBytes, bodyBytes)
        } catch (e: EOFException) {
            throw MalformedMailFrameException("truncated frame bytes", e)
        } catch (e: IOException) {
            throw MalformedMailFrameException("failed to decode frame", e)
        } catch (e: MalformedMailFrameException) {
            throw e
        } catch (e: RuntimeException) {
            throw MalformedMailFrameException("invalid frame field", e)
        }
    }
}
