package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

/** All twelve published low-order/degenerate X25519 u-coordinates - mirrors `X3dhAdversarialTest`'s
 * identical list (see [net.lapisphilosophorum.lapisnet.identity.X25519PublicKey]'s doc comment for
 * the full measured evidence behind it), duplicated here for this file's own self-containedness. */
private val ALL_LOW_ORDER_POINTS =
    listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "d9" + "ff".repeat(31),
        "da" + "ff".repeat(31),
        "db" + "ff".repeat(31),
    ).map { hexBytes(it) }

class RatchetMessageCodecTest :
    FunSpec({
        test("round trip: encode(decode(bytes)) is byte-identical, and parsed fields match") {
            val (alice, _) = establishedPair()
            val message = alice.encrypt("round trip".toByteArray())
            val bytes = RatchetMessageCodec.encode(message)
            val decoded = RatchetMessageCodec.decode(bytes)
            RatchetMessageCodec.encode(decoded) shouldBe bytes
            decoded.header.ratchetPublicKey shouldBe message.header.ratchetPublicKey
            decoded.header.previousChainLength shouldBe message.header.previousChainLength
            decoded.header.messageNumber shouldBe message.header.messageNumber
            decoded.ciphertext shouldBe message.ciphertext
        }

        test("decode preserves headerBytes verbatim") {
            val (alice, _) = establishedPair()
            val message = alice.encrypt("headers".toByteArray())
            val bytes = RatchetMessageCodec.encode(message)
            val decoded = RatchetMessageCodec.decode(bytes)
            decoded.headerBytes shouldBe bytes.copyOfRange(0, RatchetMessageCodec.HEADER_SIZE)
        }

        test("every truncation prefix throws MalformedRatchetMessageException") {
            val (alice, _) = establishedPair()
            val bytes = RatchetMessageCodec.encode(alice.encrypt("truncate me".toByteArray()))
            for (length in 0 until bytes.size) {
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(bytes.copyOf(length)) }
            }
        }

        test("trailing bytes after a complete, valid message are rejected") {
            val (alice, _) = establishedPair()
            val bytes = RatchetMessageCodec.encode(alice.encrypt("trailer".toByteArray()))
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(bytes + byteArrayOf(0)) }
        }

        test("bad magic is rejected") {
            val (alice, _) = establishedPair()
            val bytes = RatchetMessageCodec.encode(alice.encrypt("magic".toByteArray())).copyOf()
            bytes[0] = (bytes[0] + 1).toByte()
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(bytes) }
        }

        test("unsupported versions (0, 2, 0xFF) are rejected") {
            val (alice, _) = establishedPair()
            val original = RatchetMessageCodec.encode(alice.encrypt("version".toByteArray()))
            listOf(0, 2, 0xFF).forEach { version ->
                val tampered = original.copyOf()
                tampered[4] = version.toByte()
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(tampered) }
            }
        }

        test("every reserved flag bit is rejected") {
            val (alice, _) = establishedPair()
            val original = RatchetMessageCodec.encode(alice.encrypt("flags".toByteArray()))
            for (bit in 0 until 8) {
                val tampered = original.copyOf()
                tampered[5] = (1 shl bit).toByte()
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(tampered) }
            }
        }

        test("previousChainLength / messageNumber out-of-range values are rejected, MAX_CHAIN_LENGTH itself accepted") {
            val (alice, bob) = establishedPair()
            // Prime a real ratchet step so previousChainLength has a genuine non-zero baseline path too.
            bob.decrypt(alice.encrypt("prime".toByteArray()))
            val bytes = RatchetMessageCodec.encode(alice.encrypt("range".toByteArray())).copyOf()

            fun withIntAt(
                offset: Int,
                value: Int,
            ): ByteArray {
                val tampered = bytes.copyOf()
                tampered[offset] = (value ushr 24).toByte()
                tampered[offset + 1] = (value ushr 16).toByte()
                tampered[offset + 2] = (value ushr 8).toByte()
                tampered[offset + 3] = value.toByte()
                return tampered
            }

            listOf(-1, Int.MIN_VALUE, Int.MAX_VALUE, RatchetMessageCodec.MAX_CHAIN_LENGTH + 1).forEach { bad ->
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(withIntAt(38, bad)) }
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(withIntAt(42, bad)) }
            }
            // MAX_CHAIN_LENGTH itself must be accepted structurally by the codec (decode() must not
            // throw) - this test only asserts the codec's own range check accepts the boundary
            // value; what a session does with it afterwards is DoubleRatchetSession's own concern,
            // covered by DoubleRatchetAdversarialTest's DoS-gate cases.
            RatchetMessageCodec.decode(withIntAt(42, RatchetMessageCodec.MAX_CHAIN_LENGTH))
        }

        test("ciphertextLength of 0 or GCM_TAG_SIZE (tag-only) is rejected") {
            val (alice, _) = establishedPair()
            val original = RatchetMessageCodec.encode(alice.encrypt("ciphertext length".toByteArray()))
            listOf(0, GCM_TAG_SIZE).forEach { badLength ->
                val tampered = original.copyOf()
                tampered[58] = (badLength ushr 8).toByte()
                tampered[59] = badLength.toByte()
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(tampered) }
            }
        }

        test("ciphertextLength exceeding MAX_CIPHERTEXT_BYTES is rejected") {
            val (alice, _) = establishedPair()
            val original = RatchetMessageCodec.encode(alice.encrypt("max ciphertext".toByteArray()))
            val tampered = original.copyOf()
            val badLength = RatchetMessageCodec.MAX_CIPHERTEXT_BYTES + 1
            tampered[58] = (badLength ushr 8).toByte()
            tampered[59] = badLength.toByte()
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(tampered) }
        }

        test(
            "a declared ciphertextLength disagreeing with the actual frame size is rejected immediately - " +
                "no allocation proportional to a bogus declared size",
        ) {
            // A 61-byte frame (60-byte header + 1 byte of "ciphertext") declaring ciphertextLength =
            // 0xFFFF: the size mismatch must be caught before any 0xFFFF-sized allocation is attempted.
            val frame = ByteArray(RatchetMessageCodec.HEADER_SIZE + 1)
            "LNDR".toByteArray(Charsets.US_ASCII).copyInto(frame, 0)
            frame[4] = 1 // version
            frame[5] = 0 // flags
            // ratchetPublicKey (offset 6..37): leave zeroed - will fail X25519 canonical checks too,
            // but the length mismatch must be caught first regardless.
            frame[58] = 0xFF.toByte()
            frame[59] = 0xFF.toByte()
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(frame) }
        }

        test("a frame exceeding MAX_MESSAGE_BYTES is rejected on the first check, before any stream is opened") {
            val oversized = ByteArray(RatchetMessageCodec.MAX_MESSAGE_BYTES + 1)
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(oversized) }
        }

        test("every low-order X25519 value in the ratchetPublicKey slot is rejected") {
            val (alice, _) = establishedPair()
            val original = RatchetMessageCodec.encode(alice.encrypt("low order".toByteArray()))
            ALL_LOW_ORDER_POINTS.forEach { lowOrder ->
                val tampered = original.copyOf()
                lowOrder.copyInto(tampered, 6)
                shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(tampered) }
            }
        }
    })
