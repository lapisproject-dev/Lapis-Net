package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.time.Instant

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

/** [notValidAfterEpochSecond] defaults to a near-future (not far-future) value - since
 * [PeerRecord.create]'s round-4 [PeerRecord.MAX_TTL_WINDOW_SECONDS] cap rejects anything claiming
 * validity more than 24h beyond "now", the old `9_999_999_999L` (year 2286) placeholder this file
 * used before that fix would now throw at construction time. */
private fun freshRecord(
    identity: DualKeyIdentity = DualKeyIdentity.generate(),
    addresses: List<Multiaddr> = listOf(testAddress(4001)),
    capabilities: Set<PeerCapability> = setOf(PeerCapability.DM),
    sequenceNumber: Long = 0,
    notValidAfterEpochSecond: Long = Instant.now().epochSecond + 3600,
): PeerRecord = PeerRecord.create(identity, addresses, capabilities, sequenceNumber, notValidAfterEpochSecond)

/** Hand-builds a structurally-minimal (magic/version/flags/identity/edPublicKey/bindingSignature/
 * possessionProof only) buffer declaring [addressCount] addresses that are never actually present
 * - the shape the "oversized address list bounded before allocation" test needs to prove the cap
 * is enforced BEFORE any per-address allocation is attempted. */
private fun recordBytesDeclaringAddressCount(
    identity: DualKeyIdentity,
    addressCount: Int,
): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNPR".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0)
        write(identity.secp256k1KeyPair.publicKey.bytes)
        write(identity.binding.ed25519PublicKey.bytes)
        write(identity.binding.signature)
        write(ByteArray(64)) // possessionProof placeholder - irrelevant, decode() never reaches it
        writeShort(addressCount)
    }
    return out.toByteArray()
}

class PeerRecordCodecTest :
    FunSpec({
        test("decode(encode(record)) round-trips for zero addresses") {
            val record = freshRecord(addresses = emptyList())
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("decode(encode(record)) round-trips for one address") {
            val record = freshRecord(addresses = listOf(testAddress(4001)))
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("decode(encode(record)) round-trips for MAX_ADDRESSES addresses") {
            val addresses = (1..PeerRecordCodec.MAX_ADDRESSES).map { testAddress(4000 + it) }
            val record = freshRecord(addresses = addresses)
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("decode(encode(record)) round-trips for the empty capability set") {
            val record = freshRecord(capabilities = emptySet())
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("decode(encode(record)) round-trips for the full capability set") {
            val record = freshRecord(capabilities = PeerCapability.entries.toSet())
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("decode(encode(record)) round-trips for every single capability individually") {
            PeerCapability.entries.forEach { capability ->
                val record = freshRecord(capabilities = setOf(capability))
                PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
            }
        }

        test("decode rejects a buffer truncated mid-magic") {
            val bytes = PeerRecordCodec.encode(freshRecord())
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes.copyOf(2)) }
        }

        test("decode rejects a buffer truncated mid-identity") {
            val bytes = PeerRecordCodec.encode(freshRecord())
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes.copyOf(4 + 1 + 1 + 10)) }
        }

        test("decode rejects a buffer truncated mid-address-list") {
            val record = freshRecord(addresses = listOf(testAddress(4001), testAddress(4002)))
            val bytes = PeerRecordCodec.encode(record)
            // Cut somewhere inside the address-list section, well before the trailing signature.
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes.copyOf(bytes.size - 40)) }
        }

        test("decode rejects a buffer truncated mid-signature") {
            val bytes = PeerRecordCodec.encode(freshRecord())
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes.copyOf(bytes.size - 10)) }
        }

        test("decode rejects trailing bytes after the signature") {
            val bytes = PeerRecordCodec.encode(freshRecord()) + byteArrayOf(1, 2, 3)
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("decode rejects bad magic") {
            val bytes = PeerRecordCodec.encode(freshRecord())
            bytes[0] = 'X'.code.toByte()
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val bytes = PeerRecordCodec.encode(freshRecord())
            bytes[4] = 99
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("decode rejects non-zero reserved top-level flag bits") {
            val bytes = PeerRecordCodec.encode(freshRecord())
            bytes[5] = (bytes[5].toInt() or 0x01).toByte() // flags byte, right after magic(4) + version(1)
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("decode rejects non-zero reserved capability bits") {
            val identity = DualKeyIdentity.generate()
            val record = freshRecord(identity, addresses = emptyList(), capabilities = emptySet())
            val bytes = PeerRecordCodec.encode(record).copyOf()
            // capBits sits right after: magic(4)+version(1)+flags(1)+identity(33)+edKey(32)+
            // bindingSig(64)+addressCount(2) with zero addresses declared.
            val capBitsOffset = 4 + 1 + 1 + 33 + 32 + 64 + 64 + 2
            bytes[capBitsOffset] = 0xFF.toByte()
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("oversized declared address count is rejected BEFORE any per-address allocation is attempted") {
            val identity = DualKeyIdentity.generate()
            // Declares MAX_ADDRESSES + 1 addresses, then simply stops - no per-address bytes
            // follow at all. If the cap were enforced only after attempting to read the (absent)
            // address bytes, this would surface as a truncation error instead of the specific
            // "too many addresses" rejection - proving the count check runs first.
            val bytes = recordBytesDeclaringAddressCount(identity, PeerRecordCodec.MAX_ADDRESSES + 1)
            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("malformed multiaddr bytes are rejected cleanly, never propagate a raw third-party exception") {
            val identity = DualKeyIdentity.generate()
            val body =
                PeerRecordCodec.encodeSignedBody(
                    identity = identity.secp256k1KeyPair.publicKey,
                    binding = identity.binding,
                    possessionProof = ByteArray(64),
                    addresses = listOf(testAddress(4001)),
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 0,
                )
            val signature = identity.secp256k1KeyPair.sign(ByteArray(32))
            val bytes = (body + signature).copyOf()

            // Locate the address bytes: they sit right after the 2-byte addrLen that itself
            // follows magic(4)+version(1)+flags(1)+identity(33)+edKey(32)+bindingSig(64)+
            // possessionProof(64)+addressCount(2). Overwrite them with garbage the Protocol parser
            // cannot understand.
            val addrLenOffset = 4 + 1 + 1 + 33 + 32 + 64 + 64 + 2
            val addrLen = ((bytes[addrLenOffset].toInt() and 0xFF) shl 8) or (bytes[addrLenOffset + 1].toInt() and 0xFF)
            val addrStart = addrLenOffset + 2
            for (i in 0 until addrLen) bytes[addrStart + i] = 0xFF.toByte()

            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("sequenceNumber 0 round-trips") {
            val record = freshRecord(sequenceNumber = 0)
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("sequenceNumber Long.MAX_VALUE round-trips") {
            val record = freshRecord(sequenceNumber = Long.MAX_VALUE)
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        test("a hand-crafted encoding with sequenceNumber -1 on the wire is rejected") {
            val identity = DualKeyIdentity.generate()
            val encodedBody =
                PeerRecordCodec.encodeSignedBody(
                    identity = identity.secp256k1KeyPair.publicKey,
                    binding = identity.binding,
                    possessionProof = ByteArray(64),
                    addresses = emptyList(),
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 0,
                )
            val body = encodedBody.copyOf()
            // sequenceNumber(8) sits right after magic(4)+version(1)+flags(1)+identity(33)+
            // edKey(32)+bindingSig(64)+possessionProof(64)+addressCount(2)+capabilityBits(1).
            val seqOffset = 4 + 1 + 1 + 33 + 32 + 64 + 64 + 2 + 1
            for (i in 0 until 8) body[seqOffset + i] = 0xFF.toByte() // -1 as an 8-byte two's complement long
            val signature = identity.secp256k1KeyPair.sign(ByteArray(32))
            val bytes = body + signature

            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }

        test("a negative notValidAfterEpochSecond round-trips without throwing (deliberately unchecked)") {
            val record = freshRecord(notValidAfterEpochSecond = -1L)
            PeerRecordCodec.decode(PeerRecordCodec.encode(record)) shouldBe record
        }

        // Security regression (V0.8.1 sub-wave audit round 1, major finding 1): a wire-supplied
        // ed25519 public key of the right length is not necessarily a valid point on the curve.
        // Before the fix (Ed25519PublicKey's constructor now validates, see Ed25519KeyPairTest),
        // this decode() call succeeded and produced a structurally-valid, cryptographically-valid
        // (both PeerRecord.verify() and verifyBinding() could pass, since the binding is
        // self-consistent when the attacker signs their own garbage ed25519 bytes) but
        // undereferenceable record: record.peerId and record.toString() threw
        // IllegalArgumentException, poisoning any index slot/persistence reservation this record
        // reached. Now the malformed key is rejected structurally, right here at decode(), before
        // any signature/binding check ever runs.
        test(
            "decode rejects a garbage (non-curve-point) ed25519 public key instead of producing " +
                "an undereferenceable record",
        ) {
            val identity = DualKeyIdentity.generate()
            val bytes = PeerRecordCodec.encode(freshRecord(identity)).copyOf()
            // edPublicKeyBytes(32) sits right after magic(4)+version(1)+flags(1)+identity(33).
            val edKeyOffset = 4 + 1 + 1 + 33
            for (i in 0 until 32) bytes[edKeyOffset + i] = 0xFF.toByte()

            shouldThrow<MalformedPeerRecordException> { PeerRecordCodec.decode(bytes) }
        }
    })
