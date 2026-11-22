package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.dmonion.FakeChannel
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor

private val key = ByteArray(32) { 11 }

private class Rig {
    val scheduler = ManualScheduler()
    val port = FakeAttachmentPort()
    val peer = hiddenPeer()
    val client = OnionAttachmentClient(port, AttachmentClientConfig(), SecureRandom(), scheduler, Executor { it.run() })

    /** The service end of the last connect (scripted by the test). */
    @Volatile var service: FakeChannel? = null
    val requests = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()

    init {
        port.reachability = { peer.second }
        port.onConnect = { s ->
            service = s
            s.onReceive { requests += it }
        }
    }

    fun withServer(source: OutboundAttachmentSource): OnionAttachmentServer {
        val server = OnionAttachmentServer(source, AttachmentServerConfig(), scheduler)
        port.onConnect = { s -> server.handleChannel(s) }
        return server
    }

    fun fetch(
        blob: ByteArray,
        maxBytes: Int = AnonymousAttachmentLimits.MAX_BLOB_BYTES,
    ): CompletableFuture<AttachmentFetchResult> = client.fetch(peer.first.key, rawCid(blob), key, maxBytes)

    fun script(messages: List<ByteArray>) = messages.forEach { checkNotNull(service).send(it) }
}

private fun source(blob: ByteArray) =
    OutboundAttachmentSource { cid ->
        if (cid == rawCid(blob)) OutboundAttachment(key, blob.size) { blob } else null
    }

private fun CompletableFuture<AttachmentFetchResult>.reason(): AttachmentFetchFailure? =
    (getNow(null) as? AttachmentFetchResult.Unavailable)?.reason

class OnionAttachmentClientTest :
    FunSpec({
        test("happy path: one chunk") {
            val r = Rig()
            val blob = ByteArray(1_000) { (it * 7).toByte() }
            r.withServer(source(blob))
            val f = r.fetch(blob)
            r.scheduler.advance(10_000)
            val found = f.getNow(null).shouldBeInstanceOf<AttachmentFetchResult.Found>()
            found.bytes shouldBe blob
            r.port.clientEnds
                .single()
                .isClosed shouldBe true
            r.client.inFlight() shouldBe 0
        }

        test("happy path: 32 chunks, exactly MAX_BLOB_BYTES") {
            val r = Rig()
            val blob = ByteArray(AnonymousAttachmentLimits.MAX_BLOB_BYTES) { (it % 253).toByte() }
            r.withServer(source(blob))
            val f = r.fetch(blob)
            r.scheduler.advance(150_000)
            f.getNow(null).shouldBeInstanceOf<AttachmentFetchResult.Found>().bytes shouldBe blob
        }

        test("a NOT_FOUND answer (wrong token) is NotFound, an unreachable sender never connects") {
            val r = Rig()
            val blob = ByteArray(10) { 1 }
            r.port.onConnect = { s ->
                OnionAttachmentServer(
                    OutboundAttachmentSource { OutboundAttachment(ByteArray(32) { 99 }, blob.size) { blob } },
                    AttachmentServerConfig(),
                    r.scheduler,
                ).handleChannel(s)
            }
            val f = r.fetch(blob)
            r.scheduler.advance(10_000)
            f.getNow(null) shouldBe AttachmentFetchResult.NotFound

            val r2 = Rig()
            r2.port.reachability = { DirectoryReachability.Unknown }
            r2.fetch(blob).reason() shouldBe AttachmentFetchFailure.NOT_REACHABLE
            r2.port.connects.get() shouldBe 0
        }

        test("totalLength above maxBytes is TOO_LARGE after the first header, without reading on") {
            val r = Rig()
            val blob = ByteArray(5_000) { 2 }
            val f = r.fetch(blob, maxBytes = 1_000)
            val messages = answerMessages(AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, blob))
            r.script(messages.take(1))
            f.reason() shouldBe AttachmentFetchFailure.TOO_LARGE
            r.port.clientEnds
                .single()
                .isClosed shouldBe true
        }

        test("tampering is MANIPULATED and returns nothing") {
            val small = ByteArray(1_000) { 5 }
            val multi = ByteArray(300_000) { 6 }
            val honestMulti = AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, multi)
            val cases: List<Pair<ByteArray, List<ByteArray>>> =
                listOf(
                    // a flipped bit in the data: the SHA-256 does not match the CID
                    small to
                        answerMessages(
                            AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, small).map { p ->
                                p.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
                            },
                        ),
                    // a chunk count that does not fit the length
                    multi to answerMessages(listOf(rawChunk(0, 3, 0, 8, multi.size, 131_072))),
                    // an index jump
                    multi to answerMessages(listOf(honestMulti[0], honestMulti[2])),
                    // an index repeated
                    multi to answerMessages(listOf(honestMulti[0], honestMulti[0])),
                    // a class other than the largest for a multi-chunk answer
                    multi to answerMessages(listOf(rawChunk(0, 2, 0, 4, multi.size, 32_768))),
                    // a frame longer than any class
                    small to DmCircuitFraming.chunks(DmCircuitFraming.frame(7, ByteArray(2_049)), 910),
                    // bytes after the last chunk (in the same message)
                    small to
                        DmCircuitFraming.chunks(
                            AttachmentFetchCodec.chunkFrame(
                                AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, small)[0],
                            ) + AttachmentFetchCodec.chunkFrame(ByteArray(2_048)),
                            910,
                        ),
                )
            for ((blob, messages) in cases) {
                val r = Rig()
                val f = r.fetch(blob)
                r.script(messages)
                f.reason() shouldBe AttachmentFetchFailure.MANIPULATED
                r.port.clientEnds
                    .single()
                    .isClosed shouldBe true
            }
        }

        test("no answer: TIMEOUT after the frame gap, stream closed") {
            val r = Rig()
            val f = r.fetch(ByteArray(10))
            r.scheduler.advance(14_999)
            f.isDone shouldBe false
            r.scheduler.advance(1)
            f.reason() shouldBe AttachmentFetchFailure.TIMEOUT
            r.port.clientEnds
                .single()
                .isClosed shouldBe true
            r.requests.fold(0) { a, m -> a + m.size } shouldBe AttachmentFetchCodec.REQUEST_FRAME_SIZE
        }

        test("a trickling answer ends at the overall deadline") {
            val r = Rig()
            val blob = ByteArray(200_000) { 8 }
            val f = r.fetch(blob)
            val bytes =
                answerMessages(AttachmentFetchCodec.encodeAnswer(AttachmentFetchStatus.FOUND, blob))
                    .fold(ByteArray(0)) { a, b -> a + b }
            var i = 0
            while (!f.isDone && i < 100) {
                r.script(listOf(byteArrayOf(bytes[i++])))
                r.scheduler.advance(10_000)
            }
            f.reason() shouldBe AttachmentFetchFailure.TIMEOUT
            (i in 17..19) shouldBe true
            r.port.clientEnds
                .single()
                .isClosed shouldBe true
        }

        test("cancelling the future closes the stream") {
            val r = Rig()
            val f = r.fetch(ByteArray(10))
            f.cancel(true)
            r.port.clientEnds
                .single()
                .isClosed shouldBe true
            r.client.inFlight() shouldBe 0
        }

        test("a pending connect that completes after a cancel is closed at once") {
            val r = Rig()
            val pending = CompletableFuture<net.lapisphilosophorum.lapisnet.dmonion.FrameChannel>()
            r.port.hold = pending
            val f = r.fetch(ByteArray(10))
            f.cancel(true)
            val late = FakeChannel()
            pending.complete(late)
            late.isClosed shouldBe true
        }

        test("an older node closes the stream after HELLO: NOT_REACHABLE; a runtime that is not ready: NOT_READY") {
            val r = Rig()
            r.port.onConnect = { s -> s.onReceive { s.close() } }
            r.fetch(ByteArray(10)).reason() shouldBe AttachmentFetchFailure.NOT_REACHABLE

            val r2 = Rig()
            r2.port.ready = false
            r2.fetch(ByteArray(10)).reason() shouldBe AttachmentFetchFailure.NOT_READY
            r2.port.connects.get() shouldBe 0
        }
    })
