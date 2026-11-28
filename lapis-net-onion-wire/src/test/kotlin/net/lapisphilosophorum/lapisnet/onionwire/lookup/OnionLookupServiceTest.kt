package net.lapisphilosophorum.lapisnet.onionwire.lookup

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.LookupBatchResponseBody
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

    fun batch(
        op: LookupOperation,
        keys: List<ByteArray>,
        handle: Long = 1,
        id: Int = 5,
    ) = service.onBatch(RelayAction.DeliverLookupBatch(handle, id, op, keys))

    /** The answers of a batch on [handle] (status and content per item), once every fragment is out. */
    fun batchAnswers(
        itemCount: Int,
        handle: Long = 1,
    ): List<Pair<Byte, ByteArray>>? {
        val frags = synchronized(sent) { sent.filter { it.first == handle }.map { it.second } }
        val out = ArrayList<Pair<Byte, ByteArray>>()
        var pos = 0
        for (item in 0 until itemCount) {
            if (pos >= frags.size) return null
            val h = LookupBatchResponseBody.decodeFragmentHeader(frags[pos], itemCount)
            if (h.itemIndex != item || h.fragIndex != 0) return null
            if (pos + h.fragCount > frags.size) return null
            val ah = LookupBatchResponseBody.decodeAnswerHeader(frags[pos], h.fragCount)
            val payload =
                frags.subList(pos, pos + h.fragCount).map { LookupBatchResponseBody.fragmentData(it) }.reduce { a, b ->
                    a +
                        b
                }
            out += ah.status to payload.copyOfRange(6, 6 + ah.length)
            pos += h.fragCount
        }
        return if (pos == frags.size) out else null
    }
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

        test("a batch is answered item by item in request order, all at once after the minimum delay") {
            val r = ServiceRig()
            val found = ByteArray(3000) { 3 }
            val big = ByteArray(40_000) { 4 }
            r.sink.blocks[rawCid(found).toString()] = found
            r.sink.blocks[rawCid(big).toString()] = big
            val missing = rawCid("missing".toByteArray())
            val keys = listOf(cidKey(rawCid(found)), cidKey(missing), cidKey(rawCid(big)), ByteArray(40) { 7 })
            r.batch(LookupOperation.GET_BLOCK, keys)
            r.scheduler.advance(1499)
            r.sent.size shouldBe 0
            r.scheduler.advance(30_000)
            val answers = r.batchAnswers(4)!!
            answers.map { it.first } shouldBe
                listOf(LookupStatus.FOUND, LookupStatus.NOT_FOUND, LookupStatus.FOUND, LookupStatus.MALFORMED)
            answers[0].second.contentEquals(found) shouldBe true
            answers[2].second.contentEquals(big) shouldBe true
            r.service.statsForTest().batches shouldBe 1
            r.service.statsForTest().batchItems shouldBe 4
            r.service.statsForTest().malformed shouldBe 1
            // the malformed key never reached the sink
            r.sink.calls.get() shouldBe 3
        }

        test("a batch answer waits for its slowest item and is paced over all items") {
            val held = ArrayList<Runnable>()
            val r = ServiceRig(executor = Executor { held += it })
            val a = ByteArray(100) { 1 }
            val b = ByteArray(100) { 2 }
            r.sink.blocks[rawCid(a).toString()] = a
            r.sink.blocks[rawCid(b).toString()] = b
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(a)), cidKey(rawCid(b))))
            held.size shouldBe 2
            held[0].run()
            r.scheduler.advance(20_000)
            // one item is still looking: nothing leaves, no matter how long the other took
            r.sent.size shouldBe 0
            held[1].run()
            r.scheduler.advance(0)
            // the minimum delay passed long ago: the first tick sends eight fragments over both items
            r.sent.size shouldBe 6
            r.scheduler.advance(100)
            r.batchAnswers(2)!!.map { it.first } shouldBe listOf(LookupStatus.FOUND, LookupStatus.FOUND)
        }

        test("pacing: eight fragments per tick over all items of a batch") {
            val r = ServiceRig()
            val big = ByteArray(100_000) { 1 }
            r.sink.blocks[rawCid(big).toString()] = big
            val other = ByteArray(100_000) { 2 }
            r.sink.blocks[rawCid(other).toString()] = other
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(big)), cidKey(rawCid(other))))
            r.scheduler.advance(1500)
            r.sent.size shouldBe 8
            r.scheduler.advance(50)
            r.sent.size shouldBe 16
            r.scheduler.advance(20_000)
            r.sent.size shouldBe 368
            r.batchAnswers(2)!!.all { it.first == LookupStatus.FOUND } shouldBe true
        }

        test("negative cache, attempt limit and the found mark work per item inside a batch") {
            val r = ServiceRig()
            val cached = rawCid("cached miss".toByteArray())
            r.request(LookupOperation.GET_BLOCK, cidKey(cached), handle = 9)
            r.scheduler.advance(3000)
            r.sink.calls.get() shouldBe 1
            val popular = "popular".toByteArray()
            r.sink.blocks[rawCid(popular).toString()] = popular
            val slow = rawCid("slow".toByteArray())
            r.batch(
                LookupOperation.GET_BLOCK,
                listOf(cidKey(cached), cidKey(rawCid(popular)), cidKey(slow)),
                handle = 1,
            )
            r.scheduler.advance(3000)
            val first = r.batchAnswers(3)!!
            first.map { it.first } shouldBe listOf(LookupStatus.NOT_FOUND, LookupStatus.FOUND, LookupStatus.NOT_FOUND)
            // the cached miss never reached the sink again
            r.sink.calls.get() shouldBe 3
            r.service.statsForTest().negativeHits shouldBe 1
            // the censorship pattern: the popular key asked again and again in batches is never attempt-limited
            repeat(4) { i ->
                r.clear()
                r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(popular))), handle = 20L + i)
                r.scheduler.advance(3000)
                r.batchAnswers(1, 20L + i)!!.single().first shouldBe LookupStatus.FOUND
            }
            r.service.statsForTest().attemptLimited shouldBe 0
        }

        test(
            "the found mark shields a key that is found in a batch: its later miss is TIMEOUT, not a cached NOT_FOUND",
        ) {
            val r = ServiceRig()
            val block = "marked".toByteArray()
            val cid = rawCid(block)
            r.sink.blocks[cid.toString()] = block
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(cid)), handle = 1)
            r.scheduler.advance(3000)
            r.batchAnswers(1, 1)!!.single().first shouldBe LookupStatus.FOUND
            r.sink.blocks.clear()
            repeat(3) { i ->
                r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(cid)), handle = 2L + i)
                r.scheduler.advance(3000)
                r.batchAnswers(1, 2L + i)!!.single().first shouldBe LookupStatus.TIMEOUT
            }
            r.service.statsForTest().foundMarkShielded shouldBe 3
        }

        test("the in-flight limit is per item: the excess of a batch is RATE_LIMITED, a rejecting pool too") {
            val held = ArrayList<Runnable>()
            val r =
                ServiceRig(
                    OnionLookupServiceConfig(maxInFlight = 2, answerDelayJitter = 0.milliseconds),
                    Executor {
                        held +=
                            it
                    },
                )
            val keys = (1..4).map { cidKey(rawCid(byteArrayOf(it.toByte()))) }
            r.batch(LookupOperation.GET_BLOCK, keys)
            held.size shouldBe 2
            held.forEach { it.run() }
            r.scheduler.advance(3000)
            r.batchAnswers(4)!!.map { it.first } shouldBe
                listOf(
                    LookupStatus.NOT_FOUND,
                    LookupStatus.NOT_FOUND,
                    LookupStatus.RATE_LIMITED,
                    LookupStatus.RATE_LIMITED,
                )
            // the permits came back
            r.clear()
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(byteArrayOf(9)))), handle = 2)
            held.size shouldBe 3

            val rejecting = ServiceRig(executor = Executor { throw RejectedExecutionException() })
            rejecting.batch(
                LookupOperation.GET_BLOCK,
                listOf(cidKey(rawCid(byteArrayOf(1))), cidKey(rawCid(byteArrayOf(2)))),
            )
            rejecting.scheduler.advance(3000)
            rejecting.batchAnswers(2)!!.map { it.first } shouldBe List(2) { LookupStatus.RATE_LIMITED }
        }

        test("the byte budget is charged per item by class and refuses beyond it") {
            val r =
                ServiceRig(
                    OnionLookupServiceConfig(
                        bytesPerMinuteGlobal = 131_072L + 32_768L,
                        answerDelayJitter = 0.milliseconds,
                    ),
                )
            val blocks = (1..3).map { i -> ByteArray(20_000) { i.toByte() } } // class 2 (32 KiB) each
            blocks.forEach { r.sink.blocks[rawCid(it).toString()] = it }
            r.batch(LookupOperation.GET_BLOCK, blocks.map { cidKey(rawCid(it)) }, handle = 1)
            r.scheduler.advance(20_000)
            r.batchAnswers(3, 1)!!.map { it.first } shouldBe List(3) { LookupStatus.FOUND }
            // 96 KiB are spent; a 128 KiB answer no longer fits, while a small neighbour in the same batch does
            val big = ByteArray(100_000) { 4 }
            val small = ByteArray(10) { 5 }
            r.sink.blocks[rawCid(big).toString()] = big
            r.sink.blocks[rawCid(small).toString()] = small
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(big)), cidKey(rawCid(small))), handle = 9)
            r.scheduler.advance(20_000)
            r.batchAnswers(2, 9)!!.map { it.first } shouldBe listOf(LookupStatus.RATE_LIMITED, LookupStatus.FOUND)
        }

        test("a content that does not verify is never sent in a batch; the item is NOT_FOUND") {
            val r = ServiceRig()
            val cid = rawCid("the real block".toByteArray())
            val forged = ByteArray(500) { 0x5A }
            r.sink.blocks[cid.toString()] = forged
            val ok = "fine".toByteArray()
            r.sink.blocks[rawCid(ok).toString()] = ok
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(cid), cidKey(rawCid(ok))))
            r.scheduler.advance(5000)
            r.batchAnswers(2)!!.map { it.first } shouldBe listOf(LookupStatus.NOT_FOUND, LookupStatus.FOUND)
            r.sent.none { contains(it.second, forged.copyOf(64)) } shouldBe true
            r.service.statsForTest().invalidContent shouldBe 1
        }

        test("an IPNS batch is verified per item") {
            val r = ServiceRig()
            val publisher = TestIpnsPublisher()
            val other = TestIpnsPublisher()
            val record = publisher.record(sequence = 4)
            r.sink.records[publisher.routingKey.toHexString()] = record
            r.sink.records[other.routingKey.toHexString()] = publisher.record()
            r.batch(LookupOperation.GET_IPNS_RECORD, listOf(publisher.routingKey, other.routingKey))
            r.scheduler.advance(5000)
            val a = r.batchAnswers(2)!!
            a[0].first shouldBe LookupStatus.FOUND
            a[0].second.contentEquals(record) shouldBe true
            a[1].first shouldBe LookupStatus.NOT_FOUND
        }

        test("closing the service in the middle of a batch sends nothing and frees every permit") {
            val held = ArrayList<Runnable>()
            val r =
                ServiceRig(
                    OnionLookupServiceConfig(maxInFlight = 2, answerDelayJitter = 0.milliseconds),
                    Executor {
                        held +=
                            it
                    },
                )
            r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(byteArrayOf(1))), cidKey(rawCid(byteArrayOf(2)))))
            r.service.close()
            held.forEach { it.run() }
            r.scheduler.advance(10_000)
            r.sent.size shouldBe 0
            r.service.onBatch(
                RelayAction.DeliverLookupBatch(1, 1, LookupOperation.GET_BLOCK, listOf(cidKey(rawCid(byteArrayOf(3))))),
            )
            r.scheduler.advance(10_000)
            r.sent.size shouldBe 0
        }

        test("nothing is logged that names a key of a batch") {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            try {
                val r = ServiceRig()
                val cid = rawCid("secret batch block".toByteArray())
                val publisher = TestIpnsPublisher()
                r.sink.blocks[cid.toString()] = "forged".toByteArray()
                r.batch(LookupOperation.GET_BLOCK, listOf(cidKey(cid), ByteArray(40) { 7 }), handle = 1)
                r.batch(LookupOperation.GET_IPNS_RECORD, listOf(publisher.routingKey), handle = 2)
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
