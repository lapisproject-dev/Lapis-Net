package net.lapisphilosophorum.lapisnet.onionwire.lookup

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.LookupOperation
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onion.RelayAction
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock
import net.lapisphilosophorum.lapisnet.onionwire.contains
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.time.Duration
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/** A sink answering from maps; counts calls. */
private class MapSink(
    val blocks: MutableMap<String, ByteArray> = HashMap(),
    val records: MutableMap<String, ByteArray> = HashMap(),
) : OnionLookupSink {
    val calls = AtomicInteger()
    var override: LookupOutcome? = null

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): LookupOutcome {
        calls.incrementAndGet()
        override?.let { return it }
        return blocks[cid.toString()]?.let { LookupOutcome.Found(it) } ?: LookupOutcome.NotFound
    }

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): LookupOutcome {
        calls.incrementAndGet()
        override?.let { return it }
        return records[routingKey.toHexString()]?.let { LookupOutcome.Found(it) } ?: LookupOutcome.NotFound
    }
}

private class ServiceRig(
    config: OnionLookupServiceConfig = OnionLookupServiceConfig(answerDelayJitter = 0.milliseconds),
    executor: Executor = Executor { it.run() },
) {
    val clock = WireTestClock()
    val scheduler = ManualScheduler(clock)
    val sink = MapSink()
    val sent = ArrayList<Pair<Long, ByteArray>>()
    val service =
        OnionLookupService(
            sink,
            config,
            reply = { h, b -> synchronized(sent) { sent += h to b } },
            schedule = scheduler::schedule,
            clock = clock,
            random = SecureRandom(),
            executor = executor,
        )

    fun request(
        op: LookupOperation,
        key: ByteArray,
        handle: Long = 1,
        id: Int = 5,
    ) = service.onRequest(RelayAction.DeliverLookupRequest(handle, id, op, key))

    /** Status and content of the answer on [handle], once all its fragments are out. */
    fun answer(handle: Long = 1): Pair<Byte, ByteArray>? {
        val frags = synchronized(sent) { sent.filter { it.first == handle }.map { it.second } }
        if (frags.isEmpty()) return null
        val h = LookupResponseBody.decodeFragmentHeader(frags[0])
        if (frags.size < h.fragCount) return null
        val ah = LookupResponseBody.decodeAnswerHeader(frags[0], h.fragCount)
        val payload = frags.take(h.fragCount).map { LookupResponseBody.fragmentData(it) }.reduce { a, b -> a + b }
        return ah.status to payload.copyOfRange(6, 6 + ah.length)
    }

    fun clear() = synchronized(sent) { sent.clear() }
}

class OnionLookupServiceTest :
    FunSpec({
        test("a block is fetched, verified and answered after the minimum delay; found content travels in its class") {
            val r = ServiceRig()
            val block = ByteArray(9000) { (it % 7).toByte() }
            val cid = rawCid(block)
            r.sink.blocks[cid.toString()] = block
            r.request(LookupOperation.GET_BLOCK, cidKey(cid))
            r.sent.size shouldBe 0
            r.scheduler.advance(1499)
            r.sent.size shouldBe 0
            r.scheduler.advance(1000)
            val (status, content) = r.answer()!!
            status shouldBe LookupStatus.FOUND
            content.contentEquals(block) shouldBe true
            r.sent.size shouldBe 46
        }

        test("pacing: at most eight fragments per tick") {
            val r = ServiceRig()
            val block = ByteArray(100_000) { 1 }
            val cid = rawCid(block)
            r.sink.blocks[cid.toString()] = block
            r.request(LookupOperation.GET_BLOCK, cidKey(cid))
            r.scheduler.advance(1500)
            r.sent.size shouldBe 8
            r.scheduler.advance(50)
            r.sent.size shouldBe 16
            r.scheduler.advance(10_000)
            r.sent.size shouldBe 184
            r.answer()!!.second.contentEquals(block) shouldBe true
        }

        test("a block that does not match its CID is answered NOT_FOUND and its bytes are never sent") {
            val r = ServiceRig()
            val cid = rawCid("the real block".toByteArray())
            val forged = ByteArray(500) { 0x5A }
            r.sink.blocks[cid.toString()] = forged
            r.request(LookupOperation.GET_BLOCK, cidKey(cid))
            r.scheduler.advance(3000)
            r.answer()!!.first shouldBe LookupStatus.NOT_FOUND
            r.sent.none { contains(it.second, forged.copyOf(64)) } shouldBe true
            r.service.statsForTest().invalidContent shouldBe 1
            // and it is negatively cached: no second sink call
            r.clear()
            r.request(LookupOperation.GET_BLOCK, cidKey(cid))
            r.scheduler.advance(3000)
            r.answer()!!.first shouldBe LookupStatus.NOT_FOUND
            r.sink.calls.get() shouldBe 1
        }

        test("an IPNS record is verified: a valid one is forwarded, one of another name or tampered is not") {
            val r = ServiceRig()
            val publisher = TestIpnsPublisher()
            val other = TestIpnsPublisher()
            val record = publisher.record(sequence = 4)
            r.sink.records[publisher.routingKey.toHexString()] = record
            r.sink.records[other.routingKey.toHexString()] = publisher.record()
            r.request(LookupOperation.GET_IPNS_RECORD, publisher.routingKey, handle = 1)
            r.request(LookupOperation.GET_IPNS_RECORD, other.routingKey, handle = 2)
            r.scheduler.advance(3000)
            r.answer(1)!!.let {
                it.first shouldBe LookupStatus.FOUND
                it.second.contentEquals(record) shouldBe true
            }
            r.answer(2)!!.first shouldBe LookupStatus.NOT_FOUND
        }

        test("keys of a foreign shape are MALFORMED and never reach the sink") {
            val r = ServiceRig()
            val dagPb = cidKey(rawCid(byteArrayOf(1))).also { it[1] = 0x70 }
            r.request(LookupOperation.GET_BLOCK, dagPb, handle = 1)
            r.request(LookupOperation.GET_BLOCK, ByteArray(200) { 9 }, handle = 2)
            r.request(LookupOperation.GET_IPNS_RECORD, "/ipns/not-a-key".toByteArray(), handle = 3)
            r.request(LookupOperation.GET_IPNS_RECORD, cidKey(rawCid(byteArrayOf(2))), handle = 4)
            r.scheduler.advance(3000)
            (1L..4L).forEach { r.answer(it)!!.first shouldBe LookupStatus.MALFORMED }
            r.sink.calls.get() shouldBe 0
        }

        test("a key that is found is never attempt-limited: a third and fifth client still get it") {
            val r = ServiceRig()
            val block = "popular".toByteArray()
            val cid = rawCid(block)
            r.sink.blocks[cid.toString()] = block
            // the censorship pattern of the security audit: the same existing key asked again and again
            (1L..5L).forEach { r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = it) }
            r.scheduler.advance(3000)
            (1L..5L).map { r.answer(it)!!.first } shouldBe List(5) { LookupStatus.FOUND }
            r.sink.calls.get() shouldBe 5
            r.service.statsForTest().attemptLimited shouldBe 0
            r.service.statsForTest().negativeHits shouldBe 0
        }

        test("the attempt limit counts lookups without content only: two misses per window, then NOT_FOUND") {
            val r = ServiceRig()
            val cid = rawCid("slow".toByteArray())
            r.sink.override = LookupOutcome.Timeout
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 3)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.TIMEOUT
            r.answer(2)!!.first shouldBe LookupStatus.TIMEOUT
            r.answer(3)!!.first shouldBe LookupStatus.NOT_FOUND
            r.sink.calls.get() shouldBe 2
            r.service.statsForTest().attemptLimited shouldBe 1
            // the refusal writes no negative entry: once the window has passed, it is asked again
            r.sink.override = null
            val block = "slow".toByteArray()
            r.sink.blocks[cid.toString()] = block
            r.clock.millis += 11.minutes.inWholeMilliseconds
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 4)
            r.scheduler.advance(3000)
            r.answer(4)!!.first shouldBe LookupStatus.FOUND
        }

        test("a found key clears its misses") {
            val r = ServiceRig()
            val block = "flaky".toByteArray()
            val cid = rawCid(block)
            r.sink.override = LookupOutcome.Timeout
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.sink.override = null
            r.sink.blocks[cid.toString()] = block
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.sink.override = LookupOutcome.Timeout
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 3)
            r.sink.override = null
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 4)
            r.scheduler.advance(3000)
            r.answer(2)!!.first shouldBe LookupStatus.FOUND
            r.answer(4)!!.first shouldBe LookupStatus.FOUND
            r.sink.calls.get() shouldBe 4
            r.service.statsForTest().attemptLimited shouldBe 0
        }

        test("a found key can not be pushed into NOT_FOUND: Found, Timeout, NotFound, later served") {
            // a sink that misses after one FOUND (a holder offline or at its re-send limit - before fix wave F6 also
            // Nabu's responder that never resent a block): Timeout, then NotFound - security audit of wave J2, round 2
            val r = ServiceRig()
            val block = "post body held by one holder".toByteArray()
            val cid = rawCid(block)
            r.sink.override = LookupOutcome.Found(block)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.sink.override = LookupOutcome.Timeout
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.sink.override = LookupOutcome.NotFound
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 3)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 4)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.FOUND
            // never NOT_FOUND (the client would cache it and not ask a second relay): TIMEOUT sends it on
            (2L..4L).map { r.answer(it)!!.first } shouldBe List(3) { LookupStatus.TIMEOUT }
            r.sink.calls.get() shouldBe 4
            r.service.statsForTest().attemptLimited shouldBe 0
            r.service.statsForTest().negativeHits shouldBe 0
            r.service.statsForTest().foundMarkShielded shouldBe 3
            // later: no negative entry, no attempt limit; a further client reaches the sink and gets the block
            r.clock.millis += 20.minutes.inWholeMilliseconds
            r.sink.override = LookupOutcome.NotFound
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 5)
            r.sink.override = LookupOutcome.Found(block)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 6)
            r.scheduler.advance(3000)
            r.answer(5)!!.first shouldBe LookupStatus.TIMEOUT
            r.answer(6)!!.first shouldBe LookupStatus.FOUND
            r.sink.calls.get() shouldBe 6
        }

        test("content that does not verify for a found key is answered TIMEOUT without a negative entry") {
            val r = ServiceRig()
            val block = "real".toByteArray()
            val cid = rawCid(block)
            r.sink.override = LookupOutcome.Found(block)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.sink.override = LookupOutcome.Found("forged by a fake provider".toByteArray())
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 3)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 4)
            r.scheduler.advance(3000)
            (2L..4L).map { r.answer(it)!!.first } shouldBe List(3) { LookupStatus.TIMEOUT }
            r.sink.calls.get() shouldBe 4
            r.service.statsForTest().invalidContent shouldBe 3
            r.service.statsForTest().negativeHits shouldBe 0
        }

        test("the found mark expires: a key not asked for longer than its lifetime counts misses again") {
            val r = ServiceRig()
            val block = "gone later".toByteArray()
            val cid = rawCid(block)
            r.sink.override = LookupOutcome.Found(block)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.FOUND
            r.clock.millis += 31.minutes.inWholeMilliseconds
            r.sink.override = LookupOutcome.NotFound
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 3)
            r.scheduler.advance(3000)
            r.answer(2)!!.first shouldBe LookupStatus.NOT_FOUND
            r.answer(3)!!.first shouldBe LookupStatus.NOT_FOUND
            r.sink.calls.get() shouldBe 2
            r.service.statsForTest().negativeHits shouldBe 1
            r.service.statsForTest().foundMarkShielded shouldBe 0
        }

        test("a missing key never gets a found mark") {
            val r = ServiceRig()
            val cid = rawCid("never there".toByteArray())
            r.sink.override = LookupOutcome.Timeout
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.sink.override = LookupOutcome.NotFound
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 3)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.TIMEOUT
            r.answer(2)!!.first shouldBe LookupStatus.NOT_FOUND
            r.answer(3)!!.first shouldBe LookupStatus.NOT_FOUND
            r.sink.calls.get() shouldBe 2
            r.service.statsForTest().foundMarkShielded shouldBe 0
        }

        test("an oversized block is charged to the byte budget and negatively cached as TOO_LARGE") {
            val r =
                ServiceRig(
                    OnionLookupServiceConfig(bytesPerMinuteGlobal = 131_072L, answerDelayJitter = 0.milliseconds),
                )
            val bigCid = rawCid("big".toByteArray())
            r.sink.override = LookupOutcome.TooLarge(2_000_000)
            r.request(LookupOperation.GET_BLOCK, cidKey(bigCid), handle = 1)
            r.sink.override = null
            // same key again: answered from the negative cache, nothing is downloaded a second time
            r.request(LookupOperation.GET_BLOCK, cidKey(bigCid), handle = 2)
            // the download spent the budget: another key is refused without a lookup
            val small = "small".toByteArray()
            r.sink.blocks[rawCid(small).toString()] = small
            r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(small)), handle = 3)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.TOO_LARGE
            r.answer(2)!!.first shouldBe LookupStatus.TOO_LARGE
            r.answer(3)!!.first shouldBe LookupStatus.RATE_LIMITED
            r.sink.calls.get() shouldBe 1
            r.service.statsForTest().negativeHits shouldBe 1
            // the window turns: lookups run again
            r.clock.millis += 61_000
            r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(small)), handle = 4)
            r.scheduler.advance(3000)
            r.answer(4)!!.first shouldBe LookupStatus.FOUND
        }

        test("the negative cache answers NOT_FOUND without the sink; the minimum delay applies to cache hits too") {
            val r = ServiceRig()
            val cid = rawCid("missing".toByteArray())
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.NOT_FOUND
            r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 2)
            r.scheduler.advance(1400)
            r.answer(2) shouldBe null
            r.scheduler.advance(200)
            r.answer(2)!!.first shouldBe LookupStatus.NOT_FOUND
            r.sink.calls.get() shouldBe 1
            r.service.statsForTest().negativeHits shouldBe 1
        }

        test("the in-flight limit and a saturated pool answer RATE_LIMITED") {
            val held = ArrayList<Runnable>()
            val r = ServiceRig(OnionLookupServiceConfig(maxInFlight = 2), Executor { held += it })
            (1L..3L).forEach {
                r.request(
                    LookupOperation.GET_BLOCK,
                    cidKey(rawCid(byteArrayOf(it.toByte()))),
                    handle = it,
                )
            }
            r.scheduler.advance(3000)
            r.answer(3)!!.first shouldBe LookupStatus.RATE_LIMITED
            held.size shouldBe 2
            val rejecting = ServiceRig(executor = Executor { throw RejectedExecutionException() })
            rejecting.request(LookupOperation.GET_BLOCK, cidKey(rawCid(byteArrayOf(9))))
            rejecting.scheduler.advance(3000)
            rejecting.answer()!!.first shouldBe LookupStatus.RATE_LIMITED
        }

        test("the byte budget counts answers by class and refuses beyond it") {
            val r =
                ServiceRig(
                    OnionLookupServiceConfig(
                        bytesPerMinuteGlobal = 131_072L + 32_768L,
                        answerDelayJitter = 0.milliseconds,
                    ),
                )
            val blocks = (1..3).map { i -> ByteArray(20_000) { i.toByte() } } // class 2 (32 KiB) each
            blocks.forEach { r.sink.blocks[rawCid(it).toString()] = it }
            blocks.forEachIndexed { i, b -> r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(b)), handle = i + 1L) }
            r.scheduler.advance(10_000)
            // 3 x 32 KiB = 96 KiB fit the 160 KiB budget; a 128 KiB answer then no longer does
            (1L..3L).map { r.answer(it)!!.first } shouldBe List(3) { LookupStatus.FOUND }
            val big = ByteArray(100_000) { 4 }
            r.sink.blocks[rawCid(big).toString()] = big
            r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(big)), handle = 9)
            r.scheduler.advance(10_000)
            r.answer(9)!!.first shouldBe LookupStatus.RATE_LIMITED
        }

        test("timeout, too large and a throwing sink map to TIMEOUT, TOO_LARGE and NOT_FOUND") {
            val r = ServiceRig()
            r.sink.override = LookupOutcome.Timeout
            r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(byteArrayOf(1))), handle = 1)
            r.sink.override = LookupOutcome.TooLarge(200_000)
            r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(byteArrayOf(2))), handle = 2)
            r.sink.override = LookupOutcome.Found(ByteArray(131_067))
            r.request(LookupOperation.GET_BLOCK, cidKey(rawCid(byteArrayOf(3))), handle = 3)
            r.scheduler.advance(3000)
            r.answer(1)!!.first shouldBe LookupStatus.TIMEOUT
            r.answer(2)!!.first shouldBe LookupStatus.TOO_LARGE
            r.answer(3)!!.first shouldBe LookupStatus.TOO_LARGE
        }

        test("nothing is logged that names a CID or an IPNS key") {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            try {
                val r = ServiceRig()
                val cid = rawCid("secret block".toByteArray())
                val publisher = TestIpnsPublisher()
                r.sink.blocks[cid.toString()] = "forged".toByteArray()
                r.request(LookupOperation.GET_BLOCK, cidKey(cid), handle = 1)
                r.request(LookupOperation.GET_IPNS_RECORD, publisher.routingKey, handle = 2)
                r.request(LookupOperation.GET_BLOCK, ByteArray(40) { 7 }, handle = 3)
                r.scheduler.advance(5000)
                val lines = appender.list.map { it.formattedMessage }
                lines.none { it.contains(cid.toString()) } shouldBe true
                lines.none { it.contains(publisher.peerId.toBase58()) } shouldBe true
                lines.none { it.contains(publisher.routingKey.toHexString()) } shouldBe true
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
            }
        }
    })
