package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.MessageDigest
import java.security.SecureRandom

/** A deterministic "random" source so byte-exact vectors are possible. */
private class FixedRandom : SecureRandom() {
    private var c = 0

    override fun nextBytes(bytes: ByteArray) {
        for (i in bytes.indices) bytes[i] = ((c++ * 31 + 7) and 0xFF).toByte()
    }
}

private fun sha256Hex(b: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(b).joinToString("") {
        "%02x".format(it)
    }

class LookupBatchMessagesTest :
    FunSpec({
        val random = SecureRandom()

        fun keys(
            n: Int,
            len: Int = 36,
        ) = List(n) { i -> ByteArray(len) { (i * 16 + it + 1).toByte() } }

        test("a batch of 1, 2 and 8 items round-trips; the body is always 720 bytes") {
            for (n in listOf(1, 2, 8)) {
                for (op in LookupOperation.entries) {
                    val ks = keys(n, if (op == LookupOperation.GET_BLOCK) 36 else 44)
                    val body = LookupBatchRequestBody.encode(7, op, ks, random)
                    body.size shouldBe 720
                    (body.size <= RelayMessageCodec.maxData(OnionConstants.MAX_HOPS)) shouldBe true
                    val d =
                        LookupBatchRequestBody
                            .decode(
                                body,
                            ).shouldBeInstanceOf<LookupBatchRequestBody.Decoded.Batch>()
                    d.requestId shouldBe 7
                    d.op shouldBe op
                    d.keys.size shouldBe n
                    d.keys.zip(ks).all { (a, b) -> a.contentEquals(b) } shouldBe true
                    d.toString().contains("items=$n") shouldBe true
                }
            }
        }

        test("a maximal batch (8 keys of 64 bytes) still fits") {
            val ks = List(8) { i -> ByteArray(64) { (i + it).toByte() } }
            val d =
                LookupBatchRequestBody.decode(
                    LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, ks, random),
                )
            d.shouldBeInstanceOf<LookupBatchRequestBody.Decoded.Batch>().itemCount shouldBe 8
        }

        test("encode refuses bad inputs") {
            shouldThrow<IllegalArgumentException> {
                LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, emptyList(), random)
            }
            shouldThrow<IllegalArgumentException> {
                LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, keys(9), random)
            }
            shouldThrow<IllegalArgumentException> {
                LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, listOf(ByteArray(65)), random)
            }
            shouldThrow<IllegalArgumentException> {
                LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, listOf(ByteArray(0)), random)
            }
        }

        test("decode rejects a wrong length, version, flags, item count, key length and duplicates") {
            val good = LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, keys(3), random)
            shouldThrow<CellFormatException> { LookupBatchRequestBody.decode(good.copyOf(719)) }
            shouldThrow<CellFormatException> { LookupBatchRequestBody.decode(good.copyOf().also { it[0] = 1 }) }
            shouldThrow<CellFormatException> { LookupBatchRequestBody.decode(good.copyOf().also { it[3] = 1 }) }
            for (n in listOf(0, 9, 300)) {
                shouldThrow<CellFormatException> {
                    LookupBatchRequestBody.decode(
                        good.copyOf().also {
                            it[4] = (n ushr 8).toByte()
                            it[5] = n.toByte()
                        },
                    )
                }
            }
            shouldThrow<CellFormatException> { LookupBatchRequestBody.decode(good.copyOf().also { it[6] = 0 }) }
            shouldThrow<CellFormatException> {
                LookupBatchRequestBody.decode(
                    good.copyOf().also { it[6] = 65.toByte() },
                )
            }
            val dup =
                LookupBatchRequestBody.encode(
                    1,
                    LookupOperation.GET_BLOCK,
                    listOf(
                        ByteArray(36) {
                            5
                        },
                        ByteArray(36) { 6 },
                    ),
                    random,
                )
            for (i in 0 until 36) dup[6 + 37 + 1 + i] = 5
            shouldThrow<CellFormatException> { LookupBatchRequestBody.decode(dup) }
        }

        test("an unknown operation is answered per item, not a violation") {
            val good = LookupBatchRequestBody.encode(9, LookupOperation.GET_BLOCK, keys(3), random)
            val d = LookupBatchRequestBody.decode(good.copyOf().also { it[2] = 99 })
            val u = d.shouldBeInstanceOf<LookupBatchRequestBody.Decoded.Unsupported>()
            u.status shouldBe LookupStatus.UNSUPPORTED_OPERATION
            u.itemCount shouldBe 3
            u.requestId shouldBe 9
        }

        test(
            "compatibility: the UNCHANGED version-1 decoder of a 0.13 relay answers a batch with UNSUPPORTED_VERSION",
        ) {
            repeat(300) {
                val n = 1 + random.nextInt(LookupBatchRequestBody.MAX_ITEMS)
                val ks =
                    List(n) {
                        ByteArray(1 + random.nextInt(LookupBatchRequestBody.MAX_ITEM_KEY)).also { k ->
                            random.nextBytes(k)
                        }
                    }.distinctBy { it.toList() }
                val op = LookupOperation.entries[random.nextInt(2)]
                val body = LookupBatchRequestBody.encode(random.nextInt(256), op, ks, random)
                val d = LookupRequestBody.decode(body)
                d.shouldBeInstanceOf<LookupRequestBody.Decoded.Unsupported>().status shouldBe
                    LookupStatus.UNSUPPORTED_VERSION
                lookupRequestVersion(body) shouldBe 2
            }
        }

        test("peekItemCount reads only bytes 4 and 5") {
            val body = LookupBatchRequestBody.encode(1, LookupOperation.GET_BLOCK, keys(5), random)
            LookupBatchRequestBody.peekItemCount(body) shouldBe 5
            LookupBatchRequestBody.peekItemCount(body.copyOf(10)) shouldBe null
            LookupBatchRequestBody.peekItemCount(body.copyOf().also { it[5] = 0 }) shouldBe null
            LookupBatchRequestBody.peekItemCount(body.copyOf().also { it[5] = 9 }) shouldBe null
        }

        test("v2 fragment counts per class equal the version-1 counts (3, 12, 46, 184); the largest content fits") {
            (0 until LookupSizeClass.COUNT).map { LookupBatchResponseBody.fragmentCount(it) } shouldBe
                listOf(3, 12, 46, 184)
            for (i in 0 until LookupSizeClass.COUNT) {
                LookupBatchResponseBody.fragmentCount(i) shouldBe LookupSizeClass.fragmentCount(i)
            }
            val max = ByteArray(LookupSizeClass.MAX_CONTENT) { it.toByte() }
            val frags = LookupBatchResponseBody.encodeItemAnswer(3, 0, LookupStatus.FOUND, max, random)
            frags.size shouldBe 184
            frags.all { it.size == 720 } shouldBe true
        }

        test("a batch response is in request order; every item keeps its class and content") {
            val c1 = ByteArray(100) { 1 }
            val c2 = ByteArray(5000) { 2 }
            val frags =
                LookupBatchResponseBody.encodeBatch(
                    11,
                    listOf(
                        LookupStatus.FOUND to c1,
                        LookupStatus.NOT_FOUND to ByteArray(0),
                        LookupStatus.FOUND to c2,
                    ),
                    random,
                )
            frags.size shouldBe 3 + 3 + 12
            var idx = 0
            val expected = listOf(0 to 3, 1 to 3, 2 to 12)
            for ((item, count) in expected) {
                repeat(count) { f ->
                    val h = LookupBatchResponseBody.decodeFragmentHeader(frags[idx], 3)
                    h.requestId shouldBe 11
                    h.itemIndex shouldBe item
                    h.fragIndex shouldBe f
                    h.fragCount shouldBe count
                    idx++
                }
            }
            val a0 = LookupBatchResponseBody.decodeAnswerHeader(frags[0], 3)
            a0.status shouldBe LookupStatus.FOUND
            a0.length shouldBe 100
            LookupBatchResponseBody.decodeAnswerHeader(frags[3], 3).status shouldBe LookupStatus.NOT_FOUND
            val a2 = LookupBatchResponseBody.decodeAnswerHeader(frags[6], 12)
            a2.classIndex shouldBe 1
            a2.length shouldBe 5000
        }

        test("only a found answer carries content; unknown status and oversize content are refused") {
            shouldThrow<IllegalArgumentException> {
                LookupBatchResponseBody.encodeItemAnswer(1, 0, LookupStatus.NOT_FOUND, ByteArray(1), random)
            }
            shouldThrow<IllegalArgumentException> {
                LookupBatchResponseBody.encodeItemAnswer(1, 0, 99, ByteArray(0), random)
            }
            shouldThrow<IllegalArgumentException> {
                LookupBatchResponseBody.encodeItemAnswer(
                    1,
                    0,
                    LookupStatus.FOUND,
                    ByteArray(
                        LookupSizeClass.MAX_CONTENT + 1,
                    ),
                    random,
                )
            }
            shouldThrow<IllegalArgumentException> {
                LookupBatchResponseBody.encodeItemAnswer(1, 8, LookupStatus.NOT_FOUND, ByteArray(0), random)
            }
        }

        test("tampered batch fragments are format errors") {
            val frags =
                LookupBatchResponseBody.encodeBatch(
                    5,
                    List(2) { LookupStatus.NOT_FOUND to ByteArray(0) },
                    random,
                )
            val f = frags[0]
            LookupBatchResponseBody.decodeFragmentHeader(f, 2).itemIndex shouldBe 0
            shouldThrow<CellFormatException> { LookupBatchResponseBody.decodeFragmentHeader(f.copyOf(719), 2) }
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeFragmentHeader(
                    f.copyOf().also { it[0] = 1 },
                    2,
                )
            }
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeFragmentHeader(
                    f.copyOf().also { it[2] = 2 },
                    2,
                )
            }
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeFragmentHeader(
                    f.copyOf().also { it[4] = 3 },
                    2,
                )
            }
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeFragmentHeader(
                    f.copyOf().also { it[6] = 4 },
                    2,
                )
            }
            // an error status in a bigger class, an unknown status, a class that does not match the fragment count
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeAnswerHeader(f.copyOf().also { it[7] = 99 }, 3)
            }
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeAnswerHeader(f.copyOf().also { it[8] = 1 }, 3)
            }
            shouldThrow<CellFormatException> {
                LookupBatchResponseBody.decodeAnswerHeader(f.copyOf().also { it[10] = 1 }, 3)
            }
        }

        test("version 1 is byte-identical to the state before wave Q16 (golden vectors)") {
            val req =
                LookupRequestBody.encode(
                    17,
                    LookupOperation.GET_BLOCK,
                    ByteArray(36) { (it + 1).toByte() },
                    FixedRandom(),
                )
            req.size shouldBe 720
            val resp =
                LookupResponseBody.encodeAnswer(
                    17,
                    LookupStatus.FOUND,
                    ByteArray(100) { it.toByte() },
                    FixedRandom(),
                )
            resp.size shouldBe 3
            sha256Hex(req) shouldBe GOLDEN_REQ
            sha256Hex(resp.reduce { a, b -> a + b }) shouldBe GOLDEN_RESP
        }
    })

private const val GOLDEN_REQ = "0aaa784f6aa6d33f437649460e00a317ba5c8f864f240c5373911bffcdfac98b"

/** Computed from the unchanged version-1 encoders at master (HEAD 85b3836) with the same fixed byte source. */
private const val GOLDEN_RESP = "057c57a3963c84842e8005780d02e8648a14c702d4377657b88e015aabbf19f9"
