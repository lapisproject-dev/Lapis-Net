package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/** Thrown when a [DirectoryDhtValue]'s encoding is structurally invalid (never for failed verification). */
class MalformedDirectoryDhtValueException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical byte encoding of a [DirectoryDhtValue], in the layout discipline of [PeerRecordCodec]:
 * magic, version, flag byte with reserved bits that must be zero, fixed-size fields, length-prefixed
 * variable parts with every length checked against the bytes actually left BEFORE it allocates, no
 * trailing bytes. All integers big-endian.
 *
 * Layout: `magic "LNDV"(4) | version(1) | flags(1: bit0 peer record, bit1 prekey bundle, bit2 outbox) |
 * identity(33) | edPublicKey(32) | bindingSignature(64) | [peerRecordLen(2) | peerRecord] |
 * [prekeyBundleLen(2) | prekeyBundle] | [outboxCount(1, 1..MAX_OUTBOX_ENTRIES_PER_VALUE) | outboxCount x
 * (kind(1) | recipient(33) | notValidAfter(8, signed) | payloadLen(2) | payload)]`. The outbox part (V0.9.14)
 * was added to version 1 in place: no value of the earlier layout was ever published to a network. The domain tag `LapisNet:dht-directory-value:v1` of the design is
 * the magic plus version: this value is not signed by itself, it travels inside a signed IPNS record, so
 * no separate signing domain is needed.
 *
 * [MAX_VALUE_BYTES] is sized from the IPNS side: an IPNS v2 record carries its value twice (protobuf
 * `value` and the signed CBOR `data`), and no DHT peer accepts a record above 10 KiB. A test builds the
 * largest value and checks the signed record is still within that limit.
 */
object DirectoryDhtValueCodec {
    const val VERSION: Int = 1

    /** The domain-separation tag naming this format. */
    const val DOMAIN_TAG: String = "LapisNet:dht-directory-value:v1"

    /** Largest encoded value; see the class comment. */
    const val MAX_VALUE_BYTES: Int = 4_800

    /** Most outbox entries one value carries. */
    const val MAX_OUTBOX_ENTRIES_PER_VALUE: Int = 64

    /** Largest encoded outbox part (count byte included). */
    const val MAX_OUTBOX_BYTES: Int = 2_048

    private val MAGIC = "LNDV".toByteArray(Charsets.US_ASCII)
    private const val FLAG_PEER_RECORD = 0x01
    private const val FLAG_PREKEY_BUNDLE = 0x02
    private const val FLAG_OUTBOX = 0x04
    private const val KNOWN_FLAGS = FLAG_PEER_RECORD or FLAG_PREKEY_BUNDLE or FLAG_OUTBOX
    private const val PUBLIC_KEY_SIZE = 33
    private const val ED25519_PUBLIC_KEY_SIZE = 32
    private const val SIGNATURE_SIZE = 64
    internal const val FIXED_SIZE = 4 + 1 + 1 + PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE + SIGNATURE_SIZE

    /** @throws IllegalArgumentException if the value would exceed [MAX_VALUE_BYTES]. */
    fun encode(value: DirectoryDhtValue): ByteArray {
        val peerRecord = value.peerRecordBytes
        val bundle = value.prekeyBundleBytes
        val outbox = value.outboxEntries
        val flags =
            (if (peerRecord != null) FLAG_PEER_RECORD else 0) or
                (if (bundle != null) FLAG_PREKEY_BUNDLE else 0) or
                (if (outbox.isNotEmpty()) FLAG_OUTBOX else 0)
        require(outbox.size <= MAX_OUTBOX_ENTRIES_PER_VALUE) { "too many outbox entries: ${outbox.size}" }
        require(outbox.isEmpty() || 1 + outbox.sumOf { it.encodedSize() } <= MAX_OUTBOX_BYTES) {
            "outbox part exceeds $MAX_OUTBOX_BYTES bytes"
        }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION)
            writeByte(flags)
            write(value.identity.bytes)
            write(value.binding.ed25519PublicKey.bytes)
            write(value.binding.signature)
            if (peerRecord != null) {
                require(peerRecord.size <= 0xFFFF) { "peer record is too large" }
                writeShort(peerRecord.size)
                write(peerRecord)
            }
            if (bundle != null) {
                require(bundle.size <= 0xFFFF) { "prekey bundle is too large" }
                writeShort(bundle.size)
                write(bundle)
            }
            if (outbox.isNotEmpty()) {
                writeByte(outbox.size)
                for (entry in outbox) {
                    writeByte(entry.kind.wireId)
                    write(entry.recipient.bytes)
                    writeLong(entry.notValidAfterEpochSecond)
                    val payload = entry.payload
                    writeShort(payload.size)
                    write(payload)
                }
            }
        }
        val bytes = out.toByteArray()
        require(bytes.size <= MAX_VALUE_BYTES) {
            "encoded directory value is ${bytes.size} bytes, the limit is $MAX_VALUE_BYTES"
        }
        return bytes
    }

    private fun outboxEntries(input: DataInputStream): List<OutboxEntry> {
        val availableAtStart = input.available()
        val count = input.readUnsignedByte()
        if (count !in 1..MAX_OUTBOX_ENTRIES_PER_VALUE) {
            throw MalformedDirectoryDhtValueException("invalid outbox entry count: $count")
        }
        val entries = ArrayList<OutboxEntry>(count)
        repeat(count) {
            val kindId = input.readUnsignedByte()
            val kind =
                OutboxEntryKind.fromWireId(kindId)
                    ?: throw MalformedDirectoryDhtValueException("unknown outbox entry kind: $kindId")
            val recipient = Secp256k1PublicKey(ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) })
            val notValidAfter = input.readLong()
            val length = input.readUnsignedShort()
            if (length !in 1..kind.maxPayloadBytes || length > input.available()) {
                throw MalformedDirectoryDhtValueException("invalid outbox payload length: $length")
            }
            entries.add(OutboxEntry(kind, recipient, notValidAfter, ByteArray(length).also { input.readFully(it) }))
        }
        if (availableAtStart - input.available() > MAX_OUTBOX_BYTES) {
            throw MalformedDirectoryDhtValueException("outbox part exceeds $MAX_OUTBOX_BYTES bytes")
        }
        return entries
    }

    /** Structural decode only - verifies no signature. @throws MalformedDirectoryDhtValueException */
    fun decode(bytes: ByteArray): DirectoryDhtValue {
        if (bytes.size > MAX_VALUE_BYTES) throw MalformedDirectoryDhtValueException("value too large: ${bytes.size}")
        if (bytes.size < FIXED_SIZE) throw MalformedDirectoryDhtValueException("truncated directory value")
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))
            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedDirectoryDhtValueException("bad magic")
            val version = input.readUnsignedByte()
            if (version != VERSION) throw MalformedDirectoryDhtValueException("unsupported version $version")
            val flags = input.readUnsignedByte()
            if (flags and KNOWN_FLAGS.inv() != 0) {
                throw MalformedDirectoryDhtValueException("reserved flag bits must be zero: $flags")
            }
            if (flags == 0) throw MalformedDirectoryDhtValueException("a value carries at least one part")
            val identity = Secp256k1PublicKey(ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) })
            val edKey = Ed25519PublicKey(ByteArray(ED25519_PUBLIC_KEY_SIZE).also { input.readFully(it) })
            val bindingSignature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }

            fun part(): ByteArray {
                val length = input.readUnsignedShort()
                if (length == 0 || length > input.available()) {
                    throw MalformedDirectoryDhtValueException("invalid part length: $length")
                }
                return ByteArray(length).also { input.readFully(it) }
            }
            val peerRecord = if (flags and FLAG_PEER_RECORD != 0) part() else null
            val bundle = if (flags and FLAG_PREKEY_BUNDLE != 0) part() else null
            val outbox = if (flags and FLAG_OUTBOX != 0) outboxEntries(input) else emptyList()
            if (input.available() > 0) throw MalformedDirectoryDhtValueException("trailing bytes")
            return DirectoryDhtValue(identity, IdentityBinding(edKey, bindingSignature), peerRecord, bundle, outbox)
        } catch (e: EOFException) {
            throw MalformedDirectoryDhtValueException("truncated directory value", e)
        } catch (e: IOException) {
            throw MalformedDirectoryDhtValueException("failed to decode directory value", e)
        } catch (e: MalformedDirectoryDhtValueException) {
            throw e
        } catch (e: RuntimeException) {
            // an off-curve key, a wrong-size signature: anything a field constructor refuses
            throw MalformedDirectoryDhtValueException("invalid directory value field", e)
        }
    }
}
