package net.lapisphilosophorum.lapisnet.dmonion.attachment

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.dmonion.FakeChannel
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import org.slf4j.LoggerFactory
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** A source holding exactly one blob; counts loads. */
private class OneBlobSource(
    val blob: ByteArray,
    val key: ByteArray = ByteArray(32) { 7 },
    var declared: Int = blob.size,
    var present: Boolean = true,
) : OutboundAttachmentSource {
    val cid: Cid = rawCid(blob)
    val loads = AtomicInteger()

    override fun find(cid: Cid): OutboundAttachment? =
        if (cid == this.cid) {
            OutboundAttachment(key, declared) {
                loads.incrementAndGet()
                if (present) blob else null
            }
        } else {
            null
        }

    fun token(): ByteArray = AttachmentFetchToken.compute(key, cid)
}

/** One client end against the server: records received messages with their virtual arrival time. */
private class Probe(
    val scheduler: ManualScheduler,
    server: OnionAttachmentServer,
) {
    val client: FakeChannel
    val service: FakeChannel
    val received = CopyOnWriteArrayList<ByteArray>()
    val times = CopyOnWriteArrayList<Long>()

    init {
        val (c, s) = FakeChannel.pair()
        client = c
        service = s
        client.onReceive { m ->
            received += m
            times += scheduler.nowMillis()
        }
        server.handleChannel(service)
    }

    fun request(
        cid: Cid,
        token: ByteArray,
    ) = requestMessages(cid, token).forEach { client.send(it) }
}

private fun noJitter(base: AttachmentServerConfig = AttachmentServerConfig()) =
    base.copy(answerJitterMax = 0.milliseconds)

class OnionAttachmentServerTest :
    FunSpec({
        test("happy path: a 300 KB blob arrives as four 128 KiB chunks after the minimum delay, nothing sooner") {
            val s = ManualScheduler()
            val blob = ByteArray(300_000) { (it % 251).toByte() }
            val source = OneBlobSource(blob)
            val server = OnionAttachmentServer(source, noJitter(), s)
            val p = Probe(s, server)
            p.request(source.cid, source.token())
            s.advance(1_499)
            p.received shouldHaveSize 0
            s.advance(60_000)
            val frames = answerFrames(p.received)
            frames shouldHaveSize 4
            frames.forEach { it.payload.size shouldBe 131_072 }
            frames.map { it.header.chunkIndex } shouldBe listOf(0, 1, 2, 3)
            val data =
                frames.fold(ByteArray(0)) { acc, f ->
                    val h = f.header
                    val len = AttachmentTransferClass.dataLength(h.totalLength, h.chunkCount, h.chunkIndex)
                    acc + f.payload.copyOfRange(10, 10 + len)
                }
            data shouldBe blob
            server.statsForTest().found shouldBe 1
            p.client.close()
            server.statsForTest().openStreams shouldBe 0
        }

        test("an unknown CID and a wrong token give byte-identical answers after the same delay") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(100) { 1 })
            val server = OnionAttachmentServer(source, noJitter(), s)
            val unknown = Probe(s, server)
            val wrongToken = Probe(s, server)
            unknown.request(rawCid("other".toByteArray()), source.token())
            wrongToken.request(source.cid, ByteArray(32))
            val start = s.nowMillis()
            s.advance(10_000)
            unknown.times.first() - start shouldBe 1_500L
            wrongToken.times.first() - start shouldBe 1_500L
            unknown.received.map { it.size } shouldBe wrongToken.received.map { it.size }
            val a = answerFrames(unknown.received)
            val b = answerFrames(wrongToken.received)
            a.map { it.payload.toList() } shouldBe b.map { it.payload.toList() }
            a.single().header.status shouldBe AttachmentFetchStatus.NOT_FOUND
            source.loads.get() shouldBe 0
            // and as small as the smallest hit
            val hit = Probe(s, OnionAttachmentServer(OneBlobSource(byteArrayOf(1)), noJitter(), s))
            val tiny = OneBlobSource(byteArrayOf(1))
            hit.request(tiny.cid, tiny.token())
            s.advance(10_000)
            hit.received.map { it.size } shouldBe unknown.received.map { it.size }
        }

        test("an old direct-HMAC token is refused: NOT_FOUND, byte-identical to a wrong token, same delay") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(100) { 1 })
            val server = OnionAttachmentServer(source, noJitter(), s)
            val legacy = Probe(s, server)
            val zero = Probe(s, server)
            legacy.request(source.cid, legacyDirectToken(source.key, source.cid))
            zero.request(source.cid, ByteArray(32))
            val start = s.nowMillis()
            s.advance(10_000)
            legacy.times.first() - start shouldBe 1_500L
            zero.times.first() - start shouldBe 1_500L
            legacy.received.map { it.size } shouldBe zero.received.map { it.size }
            val a = answerFrames(legacy.received)
            val b = answerFrames(zero.received)
            a.map { it.payload.toList() } shouldBe b.map { it.payload.toList() }
            a.single().header.status shouldBe AttachmentFetchStatus.NOT_FOUND
            source.loads.get() shouldBe 0
        }

        test("a blob above the maximum is TOO_LARGE without loading; a missing local blob is NOT_FOUND") {
            val s = ManualScheduler()
            val big = OneBlobSource(ByteArray(10), declared = AnonymousAttachmentLimits.MAX_BLOB_BYTES + 1)
            val server = OnionAttachmentServer(big, noJitter(), s)
            val p = Probe(s, server)
            p.request(big.cid, big.token())
            s.advance(5_000)
            answerFrames(p.received).single().header.status shouldBe AttachmentFetchStatus.TOO_LARGE
            big.loads.get() shouldBe 0

            val gone = OneBlobSource(ByteArray(10), present = false)
            val server2 = OnionAttachmentServer(gone, noJitter(), s)
            val q = Probe(s, server2)
            q.request(gone.cid, gone.token())
            s.advance(5_000)
            answerFrames(q.received).single().header.status shouldBe AttachmentFetchStatus.NOT_FOUND
        }

        test("a third concurrent stream is closed without an answer") {
            val s = ManualScheduler()
            val server = OnionAttachmentServer(OneBlobSource(ByteArray(10)), noJitter(), s)
            val one = Probe(s, server)
            val two = Probe(s, server)
            val three = Probe(s, server)
            one.service.isClosed shouldBe false
            two.service.isClosed shouldBe false
            three.service.isClosed shouldBe true
            server.statsForTest().refusedStreams shouldBe 1
            one.client.close()
            Probe(s, server).service.isClosed shouldBe false
        }

        test("the 13th fetch within a minute is RATE_LIMITED") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(50) { 3 })
            val server = OnionAttachmentServer(source, noJitter(), s)
            val statuses =
                (1..13).map {
                    val p = Probe(s, server)
                    p.request(source.cid, source.token())
                    s.advance(2_000)
                    p.client.close()
                    answerFrames(p.received).single().header.status
                }
            statuses.take(12).all { it == AttachmentFetchStatus.FOUND } shouldBe true
            statuses.last() shouldBe AttachmentFetchStatus.RATE_LIMITED
            source.loads.get() shouldBe 12
        }

        test("the byte budget is reserved from the transfer class BEFORE the blob is loaded") {
            val s = ManualScheduler()
            // 200 KB travel as 256 KiB; a 300 KiB budget allows one such transfer per minute
            val source = OneBlobSource(ByteArray(200_000) { 4 })
            val server = OnionAttachmentServer(source, noJitter().copy(bytesPerMinute = 300L * 1024), s)
            val first = Probe(s, server)
            first.request(source.cid, source.token())
            s.advance(30_000)
            first.client.close()
            answerFrames(first.received).first().header.status shouldBe AttachmentFetchStatus.FOUND
            val second = Probe(s, server)
            second.request(source.cid, source.token())
            s.advance(5_000)
            answerFrames(second.received).single().header.status shouldBe AttachmentFetchStatus.RATE_LIMITED
            source.loads.get() shouldBe 1
        }

        test("a second request on the same stream closes it; no request within 10 s closes it") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(10))
            val server = OnionAttachmentServer(source, noJitter(), s)
            val p = Probe(s, server)
            p.request(source.cid, source.token())
            p.request(source.cid, source.token())
            p.service.isClosed shouldBe true
            server.statsForTest().openStreams shouldBe 0

            val idle = Probe(s, server)
            s.advance(9_999)
            idle.service.isClosed shouldBe false
            s.advance(1)
            idle.service.isClosed shouldBe true
            server.statsForTest().openStreams shouldBe 0
        }

        test("pacing: never more than 8 messages per 50 ms") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(140_000) { 9 })
            val server = OnionAttachmentServer(source, noJitter(), s)
            val p = Probe(s, server)
            p.request(source.cid, source.token())
            s.advance(120_000)
            answerFrames(p.received) shouldHaveSize 2
            val times = p.times.toList()
            for (i in times.indices) {
                val inWindow = times.count { it >= times[i] && it < times[i] + 50 }
                (inWindow <= 8) shouldBe true
            }
        }

        test("a refused send ends the transfer and frees the slot and the byte budget") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(200_000) { 4 })
            val server = OnionAttachmentServer(source, noJitter().copy(bytesPerMinute = 300L * 1024), s)
            val (client, service) = FakeChannel.pair()
            val failing = FailingChannel(service, okSends = 20)
            server.handleChannel(failing)
            requestMessages(source.cid, source.token()).forEach { client.send(it) }
            s.advance(30_000)
            failing.sends.get() shouldBe 21
            server.statsForTest().aborted shouldBe 1
            server.statsForTest().openStreams shouldBe 0
            // the budget was given back: another full transfer fits
            val p = Probe(s, server)
            p.request(source.cid, source.token())
            s.advance(30_000)
            answerFrames(p.received).first().header.status shouldBe AttachmentFetchStatus.FOUND
            // the linger and the lifetime timer of the one open stream, nothing of the aborted one
            s.pending() shouldBe 2
        }

        test("the stream lifetime bounds every stream") {
            val s = ManualScheduler()
            val source = OneBlobSource(ByteArray(10))
            val server = OnionAttachmentServer(source, noJitter().copy(lingerAfterAnswer = 600.seconds), s)
            val p = Probe(s, server)
            p.request(source.cid, source.token())
            s.advance(179_000)
            p.service.isClosed shouldBe false
            s.advance(1_000)
            p.service.isClosed shouldBe true
            server.statsForTest().openStreams shouldBe 0
        }

        test("no CID, token or key in any log line") {
            val logRoot = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = logRoot.level
            logRoot.level = Level.DEBUG
            logRoot.addAppender(appender)
            try {
                val s = ManualScheduler()
                val source = OneBlobSource(ByteArray(5_000) { 2 })
                val server = OnionAttachmentServer(source, noJitter(), s)
                val ok = Probe(s, server)
                ok.request(source.cid, source.token())
                val bad = Probe(s, server)
                bad.request(source.cid, ByteArray(32) { 1 })
                s.advance(10_000)
                ok.client.close()
                bad.client.close()
                Probe(s, server).request(source.cid, source.token())
                Probe(s, server).request(source.cid, source.token())
                Probe(s, server) // refused
                s.advance(20_000)
                val text = appender.list.joinToString("\n") { it.formattedMessage }
                val tokenHex = source.token().joinToString("") { "%02x".format(it) }
                val keyHex = source.key.joinToString("") { "%02x".format(it) }
                text shouldNotContain source.cid.toString()
                text shouldNotContain tokenHex
                text shouldNotContain keyHex
                val cidBytes = requireNotNull(RemoteContentVerifier.rawSha256CidBytes(source.cid))
                text shouldNotContain hex(AttachmentFetchToken.deriveTokenKey(source.key, cidBytes))
            } finally {
                logRoot.detachAppender(appender)
                logRoot.level = oldLevel
            }
        }
    })
