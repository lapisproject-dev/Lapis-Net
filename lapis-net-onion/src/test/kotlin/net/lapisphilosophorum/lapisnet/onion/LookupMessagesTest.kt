package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.SecureRandom

class LookupMessagesTest :
    FunSpec({
        val random = SecureRandom()
        val key = ByteArray(36) { (it + 1).toByte() }

        test("a request round-trips and is exactly 720 bytes; it fits the relay-message capacity at the maximum hops") {
            val body = LookupRequestBody.encode(17, LookupOperation.GET_IPNS_RECORD, key, random)
            body.size shouldBe 720
            (body.size <= RelayMessageCodec.maxData(OnionConstants.MAX_HOPS)) shouldBe true
            val d = LookupRequestBody.decode(body).shouldBeInstanceOf<LookupRequestBody.Decoded.Request>()
            d.requestId shouldBe 17
            d.op shouldBe LookupOperation.GET_IPNS_RECORD
            d.key.contentEquals(key) shouldBe true
        }

        test("the padding is random: two encodings of the same request differ") {
            val a = LookupRequestBody.encode(1, LookupOperation.GET_BLOCK, key, random)
            val b = LookupRequestBody.encode(1, LookupOperation.GET_BLOCK, key, random)
            a.copyOfRange(0, 42).contentEquals(b.copyOfRange(0, 42)) shouldBe true
            a.contentEquals(b) shouldBe false
        }

        test("wrong length, flags, key length 0, above 256 or beyond the body are format errors") {
            val good = LookupRequestBody.encode(1, LookupOperation.GET_BLOCK, key, random)
            shouldThrow<CellFormatException> { LookupRequestBody.decode(good.copyOf(719)) }
            shouldThrow<CellFormatException> { LookupRequestBody.decode(good.copyOf(721)) }
            shouldThrow<CellFormatException> { LookupRequestBody.decode(good.copyOf().also { it[3] = 1 }) }
            shouldThrow<CellFormatException> {
                LookupRequestBody.decode(
                    good.copyOf().also {
                        it[4] = 0
                        it[5] = 0
                    },
                )
            }
            shouldThrow<CellFormatException> {
                LookupRequestBody.decode(
                    good.copyOf().also {
                        it[4] = 1
                        it[5] = 1
                    },
                ) // 257
            }
            shouldThrow<CellFormatException> {
                LookupRequestBody.decode(
                    good.copyOf().also {
                        it[4] = 0x7F
                        it[5] = 0x7F
                    },
                )
            }
        }

        test("an unknown version or operation is answered, not a violation") {
            val good = LookupRequestBody.encode(9, LookupOperation.GET_BLOCK, key, random)
            val v = LookupRequestBody.decode(good.copyOf().also { it[0] = 2 })
            v.shouldBeInstanceOf<LookupRequestBody.Decoded.Unsupported>().status shouldBe
                LookupStatus.UNSUPPORTED_VERSION
            v.requestId shouldBe 9
            val o = LookupRequestBody.decode(good.copyOf().also { it[2] = 99 })
            o.shouldBeInstanceOf<LookupRequestBody.Decoded.Unsupported>().status shouldBe
                LookupStatus.UNSUPPORTED_OPERATION
        }

        test(
            "size classes: 2/8/32/128 KiB including the header; 3/12/46/184 fragments; the largest content is 131066",
        ) {
            LookupSizeClass.CLASSES.toList() shouldBe listOf(2048, 8192, 32768, 131072)
            (0 until 4).map { LookupSizeClass.fragmentCount(it) } shouldBe listOf(3, 12, 46, 184)
            LookupSizeClass.MAX_CONTENT shouldBe 131_066
            LookupSizeClass.classFor(0) shouldBe 0
            LookupSizeClass.classFor(2042) shouldBe 0
            LookupSizeClass.classFor(2043) shouldBe 1
            LookupSizeClass.classFor(131_066) shouldBe 3
            LookupSizeClass.classFor(131_067) shouldBe null
        }

        test("an answer round-trips over its fragments; every fragment is 720 bytes") {
            for (size in listOf(0, 1, 2042, 2043, 9000, 40_000, 131_066)) {
                val content = ByteArray(size).also(random::nextBytes)
                val frags = LookupResponseBody.encodeAnswer(200, LookupStatus.FOUND, content, random)
                frags.size shouldBe LookupSizeClass.fragmentCount(LookupSizeClass.classFor(size)!!)
                frags.all { it.size == 720 } shouldBe true
                val h0 = LookupResponseBody.decodeFragmentHeader(frags[0])
                h0.requestId shouldBe 200
                h0.fragCount shouldBe frags.size
                val ah = LookupResponseBody.decodeAnswerHeader(frags[0], h0.fragCount)
                ah.status shouldBe LookupStatus.FOUND
                ah.length shouldBe size
                val payload = frags.map { LookupResponseBody.fragmentData(it) }.reduce { a, b -> a + b }
                payload.copyOfRange(6, 6 + size).contentEquals(content) shouldBe true
                frags.forEachIndexed { i, f -> LookupResponseBody.decodeFragmentHeader(f).fragIndex shouldBe i }
            }
        }

        test("error statuses use class 0 (3 fragments), whatever the status") {
            for (status in listOf(
                LookupStatus.NOT_FOUND,
                LookupStatus.RATE_LIMITED,
                LookupStatus.MALFORMED,
                LookupStatus.DISABLED,
                LookupStatus.TIMEOUT,
            )) {
                val frags = LookupResponseBody.encodeAnswer(1, status, ByteArray(0), random)
                frags.size shouldBe 3
                LookupResponseBody.decodeAnswerHeader(frags[0], 3).status shouldBe status
            }
            shouldThrow<IllegalArgumentException> {
                LookupResponseBody.encodeAnswer(1, LookupStatus.NOT_FOUND, ByteArray(5), random)
            }
            shouldThrow<IllegalArgumentException> {
                LookupResponseBody.encodeAnswer(1, LookupStatus.FOUND, ByteArray(131_067), random)
            }
        }

        test("fragment and answer headers reject a wrong count, index, class, length or status") {
            val frags = LookupResponseBody.encodeAnswer(1, LookupStatus.FOUND, ByteArray(3000), random) // class 1
            shouldThrow<CellFormatException> { LookupResponseBody.decodeFragmentHeader(frags[0].copyOf(719)) }
            shouldThrow<CellFormatException> {
                LookupResponseBody.decodeFragmentHeader(frags[0].copyOf().also { it[0] = 2 })
            }
            shouldThrow<CellFormatException> {
                LookupResponseBody.decodeFragmentHeader(frags[0].copyOf().also { it[5] = 13 }) // not a class count
            }
            shouldThrow<CellFormatException> {
                LookupResponseBody.decodeFragmentHeader(frags[0].copyOf().also { it[3] = 12 }) // index == count
            }
            // class 1 claimed with the 3 fragments of class 0
            shouldThrow<CellFormatException> { LookupResponseBody.decodeAnswerHeader(frags[0], 3) }
            // length beyond the class
            shouldThrow<CellFormatException> {
                LookupResponseBody.decodeAnswerHeader(frags[0].copyOf().also { it[9] = 0x7F }, 12)
            }
            shouldThrow<CellFormatException> {
                LookupResponseBody.decodeAnswerHeader(frags[0].copyOf().also { it[6] = 42 }, 12)
            }
            // an error status with content
            shouldThrow<CellFormatException> {
                LookupResponseBody.decodeAnswerHeader(frags[0].copyOf().also { it[6] = LookupStatus.NOT_FOUND }, 12)
            }
        }
    })
