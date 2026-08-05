package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

private fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        (
            (Character.digit(s[i * 2], 16) shl 4) +
                Character.digit(s[i * 2 + 1], 16)
        ).toByte()
    }

/** A known low-order X25519 u-coordinate (order 8) - used to prove decode() rejects it structurally. */
private val LOW_ORDER_POINT = hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")

private fun freshBundle(oneTimePrekeyCount: Int): PrekeyBundle {
    val identity = DualKeyIdentity.generate()
    val x25519Identity = X25519KeyPair.generate()
    val binding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, x25519Identity.publicKey)
    val signedPrekey = X25519KeyPair.generate()
    val oneTimePrekeys = (0 until oneTimePrekeyCount).map { OneTimePrekey(it, X25519KeyPair.generate().publicKey) }
    return PrekeyBundle.create(
        identity = identity,
        encryptionBinding = binding,
        signedPrekeyId = 0,
        signedPrekey = signedPrekey.publicKey,
        oneTimePrekeys = oneTimePrekeys,
        sequenceNumber = 1,
        notValidAfterEpochSecond = 500_000L,
        nowEpochSecond = 0,
    )
}

class PrekeyBundleCodecTest :
    FunSpec({
        test("round-trip with 0 one-time prekeys") {
            val bundle = freshBundle(0)
            val decoded = PrekeyBundleCodec.decode(PrekeyBundleCodec.encode(bundle))
            decoded shouldBe bundle
        }

        test("round-trip with 1 one-time prekey") {
            val bundle = freshBundle(1)
            val decoded = PrekeyBundleCodec.decode(PrekeyBundleCodec.encode(bundle))
            decoded shouldBe bundle
        }

        test("round-trip with MAX_ONE_TIME_PREKEYS one-time prekeys") {
            val bundle = freshBundle(PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS)
            val decoded = PrekeyBundleCodec.decode(PrekeyBundleCodec.encode(bundle))
            decoded shouldBe bundle
        }

        test("truncation at every field boundary throws MalformedPrekeyBundleException") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(1))
            for (len in 0 until bytes.size) {
                shouldThrow<MalformedPrekeyBundleException> {
                    PrekeyBundleCodec.decode(bytes.copyOfRange(0, len))
                }
            }
        }

        test("bad magic is rejected") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(0))
            val tampered = bytes.copyOf().also { it[0] = 'X'.code.toByte() }
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(tampered) }
        }

        test("unsupported version is rejected") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(0))
            val tampered = bytes.copyOf().also { it[4] = 2 }
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(tampered) }
        }

        test("non-zero reserved flags are rejected") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(0))
            val tampered = bytes.copyOf().also { it[5] = 1 }
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(tampered) }
        }

        test("oneTimePrekeyCount = 0xFFFF is rejected before any allocation") {
            val bundle = freshBundle(0)
            val body = PrekeyBundleCodec.encodeSignedBody(bundle)
            // Body ends right after the (zero-entry) oneTimePrekeyCount field. Overwrite that
            // count with 0xFFFF and supply no further bytes at all - if decode() tried to read
            // 0xFFFF * 36 bytes before checking the cap, this would throw an EOFException /
            // truncation error instead of the expected malformed-count rejection.
            val countOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32 + 64
            val hostile = body.copyOf()
            hostile[countOffset] = 0xFF.toByte()
            hostile[countOffset + 1] = 0xFF.toByte()
            val truncatedAfterCount = hostile.copyOfRange(0, countOffset + 2)
            truncatedAfterCount.size shouldBe (countOffset + 2)
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(truncatedAfterCount) }
        }

        test("negative signedPrekeyId is rejected") {
            val bundle = freshBundle(0)
            val bytes = PrekeyBundleCodec.encode(bundle).copyOf()
            val offset = 4 + 1 + 1 + 33 + 32 + 64
            bytes[offset] = 0xFF.toByte()
            bytes[offset + 1] = 0xFF.toByte()
            bytes[offset + 2] = 0xFF.toByte()
            bytes[offset + 3] = 0xFF.toByte()
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("negative one-time prekey id is rejected") {
            val bundle = freshBundle(1)
            val bytes = PrekeyBundleCodec.encode(bundle).copyOf()
            val idOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32 + 64 + 2
            bytes[idOffset] = 0xFF.toByte()
            bytes[idOffset + 1] = 0xFF.toByte()
            bytes[idOffset + 2] = 0xFF.toByte()
            bytes[idOffset + 3] = 0xFF.toByte()
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("negative sequenceNumber is rejected") {
            val bundle = freshBundle(0)
            val bytes = PrekeyBundleCodec.encode(bundle).copyOf()
            val seqOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32 + 64 + 2
            for (i in 0 until 8) bytes[seqOffset + i] = 0xFF.toByte()
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("trailing bytes after the signature are rejected") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(0)) + byteArrayOf(0)
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("a garbage 33-byte identity that is not a curve point is rejected") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(0)).copyOf()
            val identityOffset = 4 + 1 + 1
            for (i in 0 until 33) bytes[identityOffset + i] = 0xFF.toByte()
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("a low-order X25519 key in the signed prekey slot is rejected - before any DH runs") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(0)).copyOf()
            val signedPrekeyOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4
            LOW_ORDER_POINT.copyInto(bytes, signedPrekeyOffset)
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("a low-order X25519 key in a one-time prekey slot is rejected - before any DH runs") {
            val bytes = PrekeyBundleCodec.encode(freshBundle(1)).copyOf()
            val oneTimeKeyOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32 + 64 + 2 + 4
            LOW_ORDER_POINT.copyInto(bytes, oneTimeKeyOffset)
            shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(bytes) }
        }

        test("encodeSignedBody(bundle) is a strict prefix of encode(bundle)") {
            val bundle = freshBundle(2)
            val body = PrekeyBundleCodec.encodeSignedBody(bundle)
            val full = PrekeyBundleCodec.encode(bundle)
            full.copyOfRange(0, body.size) shouldBe body
            full.size shouldBe body.size + 64
        }

        test("encoded worst-case size equals the documented 3917 bytes") {
            val bundle = freshBundle(PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS)
            val encoded = PrekeyBundleCodec.encode(bundle)
            encoded.size shouldBe 3917
        }

        // Sanity check on the test's own byte-offset arithmetic, so a future field reorder is
        // caught here rather than producing confusing failures in the tests above.
        test("byte-offset arithmetic used by the hand-crafted tests above matches a real encoding") {
            val bundle = freshBundle(1)
            val body = PrekeyBundleCodec.encodeSignedBody(bundle)
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNPB".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(bundle.identity.bytes)
                write(bundle.encryptionBinding.x25519PublicKey.bytes)
                write(bundle.encryptionBinding.signature)
                writeInt(bundle.signedPrekeyId)
                write(bundle.signedPrekey.bytes)
                write(bundle.signedPrekeySignature)
                writeShort(bundle.oneTimePrekeys.size)
                bundle.oneTimePrekeys.forEach {
                    writeInt(it.id)
                    write(it.publicKey.bytes)
                }
                writeLong(bundle.sequenceNumber)
                writeLong(bundle.notValidAfterEpochSecond)
            }
            out.toByteArray() shouldBe body
        }
    })
