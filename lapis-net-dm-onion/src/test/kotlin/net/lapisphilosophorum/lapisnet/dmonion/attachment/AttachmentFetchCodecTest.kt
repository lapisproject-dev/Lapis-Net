package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.onion.LookupSizeClass
import java.nio.ByteBuffer
import java.security.SecureRandom

class AttachmentTransferClassTest :
    FunSpec({
        val max = AnonymousAttachmentLimits.MAX_BLOB_BYTES
        val chunk = AnonymousAttachmentLimits.MAX_CHUNK_DATA

        test("the limits are the documented numbers") {
            chunk shouldBe 131_062
            max shouldBe 4_193_984
            AnonymousAttachmentLimits.REQUEST_SIZE shouldBe 720
        }

        test("boundaries: one chunk of the smallest class that holds the blob, then powers of two of 128 KiB") {
            AttachmentTransferClass.forLength(0).shouldBeNull()
            AttachmentTransferClass.forLength(-1).shouldBeNull()
            AttachmentTransferClass.forLength(1) shouldBe (0 to 1)
            AttachmentTransferClass.forLength(2_038) shouldBe (0 to 1)
            AttachmentTransferClass.forLength(2_039) shouldBe (1 to 1)
            AttachmentTransferClass.forLength(8_182) shouldBe (1 to 1)
            AttachmentTransferClass.forLength(8_183) shouldBe (2 to 1)
            AttachmentTransferClass.forLength(32_758) shouldBe (2 to 1)
            AttachmentTransferClass.forLength(32_759) shouldBe (3 to 1)
            AttachmentTransferClass.forLength(131_062) shouldBe (3 to 1)
            AttachmentTransferClass.forLength(131_063) shouldBe (3 to 2)
            AttachmentTransferClass.forLength(2 * 131_062) shouldBe (3 to 2)
            AttachmentTransferClass.forLength(2 * 131_062 + 1) shouldBe (3 to 4)
            AttachmentTransferClass.forLength(max) shouldBe (3 to 32)
            AttachmentTransferClass.forLength(max + 1).shouldBeNull()
        }

        test("only nine transfer sizes are observable") {
            val sizes = (1..max step 997).mapNotNull { AttachmentTransferClass.transferBytes(it) }.toSet()
            sizes shouldBe
                setOf(2_048L, 8_192L, 32_768L, 131_072L, 262_144L, 524_288L, 1_048_576L, 2_097_152L, 4_194_304L)
        }

        test("isConsistent accepts exactly the computed class and rejects every other combination") {
            for (length in listOf(1, 2_039, 32_759, 131_063, 2 * chunk + 1, max)) {
                val (c, n) = AttachmentTransferClass.forLength(length)!!
                AttachmentTransferClass.isConsistent(c, n, length) shouldBe true
                for (otherClass in 0 until LookupSizeClass.COUNT) {
                    for (otherCount in listOf(1, 2, 3, 4, 8, 16, 32, 64)) {
                        if (otherClass == c && otherCount == n) continue
                        AttachmentTransferClass.isConsistent(otherClass, otherCount, length) shouldBe false
                    }
                }
            }
            AttachmentTransferClass.isConsistent(0, 1, 0) shouldBe false
            AttachmentTransferClass.isConsistent(3, 32, max + 1) shouldBe false
        }

        test("data lengths of the chunks add up to the blob; padding chunks carry no data") {
            val length = 2 * chunk + 1
            val (_, n) = AttachmentTransferClass.forLength(length)!!
            val parts = (0 until n).map { AttachmentTransferClass.dataLength(length, n, it) }
            parts shouldBe listOf(chunk, chunk, 1, 0)
            parts.sum() shouldBe length
        }
    })

class AttachmentFetchCodecTest :
    FunSpec({
        val random = SecureRandom()
        val cid = rawCid("blob".toByteArray())
        val token = ByteArray(32) { it.toByte() }

        test("a request is exactly 720 bytes and round-trips") {
            val body = AttachmentFetchCodec.encodeRequest(cid, token, random)
            body.size shouldBe 720
            val decoded = AttachmentFetchCodec.decodeRequest(body)
            decoded.cid shouldBe cid
            decoded.token shouldBe token
            decoded.toString() shouldNotContain cid.toString()
            AttachmentFetchCodec.requestFrame(body).size shouldBe AttachmentFetchCodec.REQUEST_FRAME_SIZE
        }

        test("a wrong length, set flags, a wrong cidLen, a foreign CID shape or version 2 are refused") {
            val good = AttachmentFetchCodec.encodeRequest(cid, token, random)
            shouldThrow<MalformedAttachmentFetchException> { AttachmentFetchCodec.decodeRequest(good.copyOf(719)) }
            shouldThrow<MalformedAttachmentFetchException> { AttachmentFetchCodec.decodeRequest(good.copyOf(721)) }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeRequest(good.copyOf().also { it[0] = 2 })
            }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeRequest(good.copyOf().also { it[1] = 1 })
            }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeRequest(good.copyOf().also { ByteBuffer.wrap(it).putShort(2, 37) })
            }
            // CIDv1 with the dag-cbor codec instead of raw: refused by hand, before Cid.cast
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeRequest(good.copyOf().also { it[5] = 0x71 })
            }
            // a multihash other than sha2-256
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeRequest(good.copyOf().also { it[6] = 0x13 })
            }
            // a digest length other than 32
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeRequest(good.copyOf().also { it[7] = 0x7F })
            }
            shouldThrow<IllegalArgumentException> {
                AttachmentFetchCodec.encodeRequest(
                    Cid.buildCidV1(Cid.Codec.DagCbor, Multihash.Type.sha2_256, ByteArray(32)),
                    token,
                    random,
                )
            }
        }

        test("every answer frame has exactly its class size; errors are one class-0 frame") {
            for (length in listOf(
                1,
                2_038,
                2_039,
                100_000,
                131_063,
                300_000,
                AnonymousAttachmentLimits.MAX_BLOB_BYTES,
            )) {
                val frames = AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, ByteArray(length) { 1 })
                val (c, n) = AttachmentTransferClass.forLength(length)!!
                frames shouldHaveSize n
                frames.forEachIndexed { i, f ->
                    f.size shouldBe LookupSizeClass.size(c)
                    val h = AttachmentFetchCodec.decodeChunkHeader(f, f.size)
                    h.chunkIndex shouldBe i
                    h.totalLength shouldBe length
                }
            }
            for (status in AttachmentFetchStatus.entries - AttachmentFetchStatus.FOUND) {
                val frames = AttachmentFetchCodec.encodeAnswer(status, null)
                frames shouldHaveSize 1
                frames[0].size shouldBe LookupSizeClass.size(0)
                val h = AttachmentFetchCodec.decodeChunkHeader(frames[0], frames[0].size)
                h.status shouldBe status
                h.totalLength shouldBe 0
            }
        }

        test("FOUND with one byte has the same frame count and size as NOT_FOUND") {
            val hit = AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, byteArrayOf(9))
            val miss = AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.NOT_FOUND, null)
            hit.map { it.size } shouldBe miss.map { it.size }
            answerMessages(hit).map { it.size } shouldBe answerMessages(miss).map { it.size }
        }

        test("a chunk header is refused for a wrong frame size, an inconsistent class or a non-zero error answer") {
            val frame = AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, ByteArray(10))[0]
            shouldThrow<MalformedAttachmentFetchException> { AttachmentFetchCodec.decodeChunkHeader(frame, 8192) }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeChunkHeader(rawChunk(0, 1, 0, 1, 10, 8192), 8192)
            }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeChunkHeader(rawChunk(1, 0, 0, 1, 5, 2048), 2048)
            }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeChunkHeader(rawChunk(9, 0, 0, 1, 0, 2048), 2048)
            }
            shouldThrow<MalformedAttachmentFetchException> {
                AttachmentFetchCodec.decodeChunkHeader(rawChunk(0, 3, 2, 2, 131_063, 131_072), 131_072)
            }
        }
    })

class AttachmentFetchTokenTest :
    FunSpec({
        val key = ByteArray(32) { 5 }
        val cid = rawCid("x".toByteArray())

        test("deterministic; another key or another CID gives another token") {
            val a = AttachmentFetchToken.compute(key, cid)
            a.size shouldBe 32
            AttachmentFetchToken.compute(key, cid) shouldBe a
            AttachmentFetchToken.compute(ByteArray(32) { 6 }, cid) shouldNotBe a
            AttachmentFetchToken.compute(key, rawCid("y".toByteArray())) shouldNotBe a
            AttachmentFetchToken.matches(a, a.copyOf()) shouldBe true
            AttachmentFetchToken.matches(a, a.copyOf().also { it[31] = (it[31] + 1).toByte() }) shouldBe false
        }

        test("matches is false for any length other than 32") {
            val a = AttachmentFetchToken.compute(key, cid)
            AttachmentFetchToken.matches(a, a.copyOf(31)) shouldBe false
            AttachmentFetchToken.matches(a.copyOf(31), a.copyOf(31)) shouldBe false
            AttachmentFetchToken.matches(a, a.copyOf(33)) shouldBe false
            AttachmentFetchToken.matches(ByteArray(0), ByteArray(0)) shouldBe false
        }

        test("a new Mac per call: concurrent computations all agree") {
            val expected = AttachmentFetchToken.compute(key, cid)
            val pool =
                java.util.concurrent.Executors
                    .newFixedThreadPool(8)
            val results =
                try {
                    (1..64).map { pool.submit<ByteArray> { AttachmentFetchToken.compute(key, cid) } }.map { it.get() }
                } finally {
                    pool.shutdownNow()
                }
            results.all { it.contentEquals(expected) } shouldBe true
        }
    })
