package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.util.Random

class OnionRelayDescriptorCodecTest :
    FunSpec({
        val good = OnionRelayPublisher().descriptor()
        val bytes = OnionRelayDescriptorCodec.encode(good)

        test("encoding is exactly 379 bytes and round-trips") {
            bytes.size shouldBe OnionRelayDescriptorCodec.ENCODED_SIZE
            (bytes.size <= OnionRelayDescriptorCodec.MAX_ENCODED_BYTES) shouldBe true
            OnionRelayDescriptorCodec.decode(bytes) shouldBe good
            OnionRelayDescriptorCodec.decode(bytes).contentId().contentEquals(good.contentId()) shouldBe true
        }

        test("too short, too long, trailing bytes and oversize input are refused") {
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(bytes.copyOf(378)) }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(bytes + 0) }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(ByteArray(0)) }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(ByteArray(100_000)) }
        }

        test("a wrong version and a non-empty family list are refused") {
            val v = bytes.copyOf().also { it[0] = 2 }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(v) }
            val familyOffset = 1 + 33 + 32 + 64 + 32 + 8 + 64 + 8 + 8
            val f = bytes.copyOf().also { it[familyOffset] = 1 }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(f) }
        }

        test("an off-curve identity and a low-order onion key are refused structurally") {
            val badIdentity = bytes.copyOf().also { for (i in 1..33) it[i] = 0x05 }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(badIdentity) }
            val badOnion = bytes.copyOf().also { for (i in 0 until 32) it[1 + 33 + 32 + 64 + i] = 0 }
            shouldThrow<MalformedOnionRelayDescriptorException> { OnionRelayDescriptorCodec.decode(badOnion) }
        }

        test("10000 random inputs of the right length only ever raise the Malformed exception") {
            val rnd = Random(42)
            repeat(10_000) {
                val b = ByteArray(OnionRelayDescriptorCodec.ENCODED_SIZE)
                rnd.nextBytes(b)
                if (it % 2 == 0) b[0] = 1
                try {
                    OnionRelayDescriptorCodec.decode(b)
                } catch (e: MalformedOnionRelayDescriptorException) {
                    // expected
                }
            }
        }

        test("10000 mutations of a valid descriptor never throw anything but Malformed, and never verify") {
            val rnd = Random(7)
            val now =
                java.time.Instant
                    .now()
                    .epochSecond
            repeat(10_000) {
                val b = bytes.copyOf()
                b[1 + rnd.nextInt(b.size - 1)] = rnd.nextInt().toByte()
                try {
                    val d = OnionRelayDescriptorCodec.decode(b)
                    if (!b.contentEquals(bytes)) OnionRelayDescriptor.verify(d, now) shouldBe false
                } catch (e: MalformedOnionRelayDescriptorException) {
                    // expected
                }
            }
        }
    })
