package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.security.SecureRandom

class AnonymousPeerRecordCodecTest :
    FunSpec({
        val bytes = AnonymousPeerRecordCodec.encode(AnonymousPublisher().record(1))

        test("the encoded size is exactly 248 bytes and no other length is accepted") {
            AnonymousPeerRecordCodec.ENCODED_SIZE shouldBe 248
            bytes.size shouldBe 248
            shouldThrow<MalformedAnonymousPeerRecordException> { AnonymousPeerRecordCodec.decode(bytes.copyOf(247)) }
            shouldThrow<MalformedAnonymousPeerRecordException> { AnonymousPeerRecordCodec.decode(bytes + 0) }
            shouldThrow<MalformedAnonymousPeerRecordException> { AnonymousPeerRecordCodec.decode(ByteArray(0)) }
        }

        test("a wrong magic or version is malformed") {
            shouldThrow<MalformedAnonymousPeerRecordException> {
                AnonymousPeerRecordCodec.decode(bytes.copyOf().also { it[0] = 'X'.code.toByte() })
            }
            shouldThrow<MalformedAnonymousPeerRecordException> {
                AnonymousPeerRecordCodec.decode(bytes.copyOf().also { it[4] = 2 })
            }
        }

        test("a negative sequence number is malformed") {
            val t = bytes.copyOf()
            // sequence number at 4+1+1+33+32+64+1+32 = 168
            t[168] = 0x80.toByte()
            shouldThrow<MalformedAnonymousPeerRecordException> { AnonymousPeerRecordCodec.decode(t) }
        }

        test("10,000 random 248-byte inputs never throw anything but the documented exception") {
            val random = SecureRandom()
            repeat(10_000) {
                val input = ByteArray(248).also { random.nextBytes(it) }
                if (it % 2 == 0) bytes.copyInto(input, 0, 0, 4) // reach past the magic check half of the time
                try {
                    AnonymousPeerRecordCodec.decode(input)
                } catch (e: MalformedAnonymousPeerRecordException) {
                    // expected
                }
            }
        }

        test("the content id differs between different records and is stable for the same one") {
            val p = AnonymousPublisher()
            val a = p.record(1)
            val b = p.record(2)
            a.contentId().contentEquals(a.contentId()) shouldBe true
            a.contentId().contentEquals(b.contentId()) shouldBe false
        }
    })
