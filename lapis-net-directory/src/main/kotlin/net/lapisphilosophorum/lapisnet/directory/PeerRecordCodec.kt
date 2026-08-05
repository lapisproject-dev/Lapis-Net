package net.lapisphilosophorum.lapisnet.directory

import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/** Thrown when decoding a [PeerRecord]'s canonical byte encoding fails structurally. Never thrown
 * for signature/binding verification failures - [PeerRecordCodec.decode] does not verify either,
 * see its doc comment. */
class MalformedPeerRecordException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [PeerRecord]. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec`/
 * `net.lapisphilosophorum.lapisnet.mail.MessageEnvelopeCodec`'s layout discipline exactly: magic,
 * version, reserved-flag-bits-must-be-zero, sequential length-prefixed variable fields, every
 * length validated BEFORE the corresponding allocation. All integers are big-endian.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4) | version(1) | flags(1, reserved, must be
 * zero) | identity(33) | edPublicKey(32) | bindingSignature(64) | possessionProof(64) |
 * addressCount(2) | ( addrLen(2) | addr(addrLen) ) * addressCount | capabilityBits(1) |
 * sequenceNumber(8) | notValidAfterEpochSecond(8)`. [encode] appends the record's own 64-byte
 * outer signature after that - a THIRD, DIFFERENT 64 bytes from both `bindingSignature` and
 * `possessionProof` above, see [PeerRecord]'s class doc comment on why three independent
 * signatures exist (V0.8.1 sub-wave audit round 2, major finding 1: `possessionProof` is the new
 * field, added right after `bindingSignature` so every 64-byte signature-shaped field sits
 * together at the front of the layout).
 *
 * **No `io.ipfs.cid.Cid` field anywhere in this layout - deliberately.** Unlike
 * `VeritasGrantCodec`/`MessageEnvelopeCodec`, this codec never calls `Cid.cast`, so
 * `net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation` is never invoked here - there is
 * nothing for it to guard.
 *
 * **No `CidBytesValidation`-equivalent guard for the Multiaddr address section either -
 * deliberately, verified against the real `jvm-libp2p` sources, not assumed safe.**
 * `Multiaddr.deserialize(bytes)` parses via a Netty `ByteBuf` wrapping the already
 * length-capped-at-[MAX_MULTIADDR_BYTES] `addrBytes` array; every `ByteBuf.readBytes(length)` call
 * inside `Protocol.readAddressBytes` bounds-checks against the buffer's remaining readable bytes
 * BEFORE allocating (Netty's `checkReadableBytes`), unlike `io.ipfs.multihash.Multihash`'s raw
 * `new byte[len]`-before-bounds-check pattern `CidBytesValidation` exists to guard against - so
 * there is no equivalent oversized-allocation-before-bounds-check class here. Every exception a
 * malformed multiaddr can throw (`Protocol.getOrThrow`'s `IllegalArgumentException`, Netty's
 * `IndexOutOfBoundsException` on buffer underflow) is a plain `RuntimeException`, caught by
 * [decode]'s existing blanket `catch (e: RuntimeException)` below.
 */
object PeerRecordCodec {
    private val MAGIC = "LNPR".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val ED25519_PUBLIC_KEY_SIZE = 32
    private const val BINDING_SIGNATURE_SIZE = 64
    private const val POSSESSION_PROOF_SIZE = 64
    private const val SIGNATURE_SIZE = 64

    /** Hard cap on the number of addresses a single record may advertise - generous headroom for
     * a personal node's realistic address surface (LAN IPv4/IPv6, external IPv4/IPv6, a couple of
     * relay/circuit addresses), not derived from any protocol requirement. */
    const val MAX_ADDRESSES = 16

    /** Cap on a single encoded `Multiaddr`'s byte length - generous headroom above a realistic
     * worst case (an `/ip6/.../tcp/.../p2p/<peerid>/p2p-circuit/p2p/<peerid>` relayed address is
     * comfortably under 200 bytes). */
    const val MAX_MULTIADDR_BYTES = 256

    /** [net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest] treats the whole signed
     * body as a single part, capped at this size. Worst case (16 addresses at the 256-byte cap):
     * `4+1+1+33+32+64+64+2+16*(2+256)+1+8+8 = 4,346` bytes (64 bytes larger than before round 2's
     * `possessionProof` field was added) - comfortably under this limit, capped at the same round
     * `0xFFFF` every sibling codec uses for consistency even though real usage is far smaller. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [PeerRecord.create]. */
    fun encodeSignedBody(
        identity: Secp256k1PublicKey,
        binding: IdentityBinding,
        possessionProof: ByteArray,
        addresses: List<Multiaddr>,
        capabilities: Set<PeerCapability>,
        sequenceNumber: Long,
        notValidAfterEpochSecond: Long,
    ): ByteArray {
        require(addresses.size <= MAX_ADDRESSES) { "at most $MAX_ADDRESSES addresses allowed, was ${addresses.size}" }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0, was $sequenceNumber" }
        require(possessionProof.size == POSSESSION_PROOF_SIZE) {
            "possessionProof must be a compact $POSSESSION_PROOF_SIZE-byte Ed25519 signature, was ${possessionProof.size}"
        }
        val addressBytesList =
            addresses.map { addr ->
                val bytes = addr.serialize()
                require(bytes.size in 1..MAX_MULTIADDR_BYTES) {
                    "multiaddr must be 1..$MAX_MULTIADDR_BYTES bytes, was ${bytes.size}"
                }
                bytes
            }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: all bits reserved, must be zero
            write(identity.bytes)
            write(binding.ed25519PublicKey.bytes)
            write(binding.signature)
            write(possessionProof)
            writeShort(addressBytesList.size)
            addressBytesList.forEach { addrBytes ->
                writeShort(addrBytes.size)
                write(addrBytes)
            }
            writeByte(PeerCapability.bitsFrom(capabilities))
            writeLong(sequenceNumber)
            writeLong(notValidAfterEpochSecond)
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded peer record body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [record]. */
    fun encodeSignedBody(record: PeerRecord): ByteArray =
        encodeSignedBody(
            identity = record.identity,
            binding = record.binding,
            possessionProof = record.possessionProof,
            addresses = record.addresses,
            capabilities = record.capabilities,
            sequenceNumber = record.sequenceNumber,
            notValidAfterEpochSecond = record.notValidAfterEpochSecond,
        )

    /** The full canonical artifact: signed body followed by the record's own 64-byte outer
     * signature (NOT `binding.signature`, which already sits inside the signed body itself). */
    fun encode(record: PeerRecord): ByteArray = encodeSignedBody(record) + record.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - a content identifier/index key, not
     * itself a signed value. A fresh [MessageDigest] instance per call. */
    fun contentId(record: PeerRecord): ByteArray = sha256(encode(record))

    /**
     * Structural decode only - does **not** verify any signature, mirroring
     * `VeritasGrantCodec.decode`'s contract exactly. Callers must explicitly call
     * [PeerRecord.verify], [verifyBinding], AND [verifyPossession] before trusting the result - see
     * [PeerRecord]'s class doc comment for why all three are independently required.
     *
     * @throws MalformedPeerRecordException if the bytes are structurally invalid.
     */
    fun decode(bytes: ByteArray): PeerRecord {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedPeerRecordException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedPeerRecordException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedPeerRecordException("reserved flag bits must be zero: $flags")

            val identityBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val edPublicKeyBytes = ByteArray(ED25519_PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val bindingSignatureBytes = ByteArray(BINDING_SIGNATURE_SIZE).also { input.readFully(it) }
            val possessionProofBytes = ByteArray(POSSESSION_PROOF_SIZE).also { input.readFully(it) }

            val addressCount = input.readUnsignedShort()
            if (addressCount > MAX_ADDRESSES) throw MalformedPeerRecordException("too many addresses: $addressCount")
            val addresses =
                (0 until addressCount).map {
                    val addrLen = input.readUnsignedShort()
                    if (addrLen !in 1..MAX_MULTIADDR_BYTES) {
                        throw MalformedPeerRecordException("invalid multiaddr length: $addrLen")
                    }
                    val addrBytes = ByteArray(addrLen).also { buf -> input.readFully(buf) }
                    Multiaddr.deserialize(addrBytes)
                }

            val capBits = input.readUnsignedByte()
            if (capBits and PeerCapability.KNOWN_BITS_MASK.inv() != 0) {
                throw MalformedPeerRecordException("reserved capability bits must be zero: $capBits")
            }
            val capabilities = PeerCapability.setFromBits(capBits)

            val sequenceNumber = input.readLong()
            if (sequenceNumber < 0) throw MalformedPeerRecordException("sequenceNumber must be >= 0: $sequenceNumber")

            val notValidAfterEpochSecond = input.readLong()
            // Deliberately no range check - see PeerRecord's init block doc comment.

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedPeerRecordException("trailing bytes after signature")

            return PeerRecord.fromDecoded(
                identity = Secp256k1PublicKey(identityBytes),
                binding = IdentityBinding(Ed25519PublicKey(edPublicKeyBytes), bindingSignatureBytes),
                addresses = addresses,
                capabilities = capabilities,
                sequenceNumber = sequenceNumber,
                notValidAfterEpochSecond = notValidAfterEpochSecond,
                signature = signature,
                possessionProof = possessionProofBytes,
            )
        } catch (e: EOFException) {
            throw MalformedPeerRecordException("truncated peer record bytes", e)
        } catch (e: IOException) {
            throw MalformedPeerRecordException("failed to decode peer record", e)
        } catch (e: MalformedPeerRecordException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, kept for structural consistency with every sibling codec, even
            // though every allocation in this function is already bounded by an explicit cap
            // checked BEFORE allocation (PUBLIC_KEY_SIZE/ED25519_PUBLIC_KEY_SIZE/
            // BINDING_SIGNATURE_SIZE/MAX_ADDRESSES*MAX_MULTIADDR_BYTES/SIGNATURE_SIZE) - unlike
            // VeritasGrantCodec/MessageEnvelopeCodec, no specific unbounded-allocation path was
            // found here (see this object's class doc comment on why the CID OOM-DoS class does
            // not apply to Multiaddr bytes). Never thrown by a known path today; kept so a future
            // unforeseen change can never silently let an Error escape this function.
            throw MalformedPeerRecordException("peer record field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from Secp256k1PublicKey's curve check / IdentityBinding's
            // signature-size check, and any RuntimeException Multiaddr.deserialize throws on
            // malformed multiaddr bytes (Protocol.getOrThrow's IllegalArgumentException, Netty's
            // IndexOutOfBoundsException) - decode() must never leak an arbitrary third-party
            // exception type to callers.
            throw MalformedPeerRecordException("invalid peer record field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
