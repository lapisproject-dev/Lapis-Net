package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockState
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** A backend whose futures the test completes by hand. */
private class HandBackend : LookupBackend {
    val pending = ConcurrentHashMap<Cid, CompletableFuture<LookupResult>>()
    val calls = AtomicInteger()
    val ipnsCalls = AtomicInteger()
    val contexts = java.util.concurrent.ConcurrentLinkedQueue<LookupContext>()
    var ipnsAnswer: LookupResult = LookupResult.NotFound(confirmed = true)

    override fun fetchBlock(
        cid: Cid,
        timeout: kotlin.time.Duration,
    ): CompletableFuture<LookupResult> {
        calls.incrementAndGet()
        return pending.computeIfAbsent(cid) { CompletableFuture() }
    }

    override fun fetchBlock(
        cid: Cid,
        timeout: kotlin.time.Duration,
        context: LookupContext,
    ): CompletableFuture<LookupResult> {
        contexts += context
        return fetchBlock(cid, timeout)
    }

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: kotlin.time.Duration,
    ): CompletableFuture<LookupResult> {
        ipnsCalls.incrementAndGet()
        return CompletableFuture.completedFuture(ipnsAnswer)
    }
}

class CircuitRemoteContentSourceTest :
    FunSpec({
        test("blockIfCached never blocks, schedules exactly one fetch per miss and answers from the cache afterwards") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend)
            val bytes = "block".toByteArray()
            val cid = rawCid(bytes)
            val start = System.nanoTime()
            source.blockIfCached(cid).shouldBeNull()
            source.blockIfCached(cid).shouldBeNull()
            (System.nanoTime() - start < 1_000_000_000L) shouldBe true
            backend.calls.get() shouldBe 1
            backend.pending[cid]!!.complete(LookupResult.Found(bytes))
            source.blockIfCached(cid) shouldBe bytes
            backend.calls.get() shouldBe 1
        }

        test("a block that does not match its CID never enters the cache") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend)
            val cid = rawCid("real".toByteArray())
            source.blockIfCached(cid).shouldBeNull()
            backend.pending[cid]!!.complete(LookupResult.Found("forged".toByteArray()))
            source.blockIfCached(cid).shouldBeNull()
            source.cacheStatsForTest().first shouldBe 0
        }

        test("fetchBlock waits for the answer; the cache is bounded by entries and by bytes") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend, cacheEntries = 2, cacheBytes = 1000)
            val blocks = (1..3).map { i -> ByteArray(300) { i.toByte() } }
            for (b in blocks) {
                val cid = rawCid(b)
                backend.pending.computeIfAbsent(cid) { CompletableFuture() }.complete(LookupResult.Found(b))
                source.fetchBlock(cid, 131_066, Duration.ofSeconds(1)) shouldBe b
            }
            source.cacheStatsForTest() shouldBe (2 to 600L)
            val big = ByteArray(900) { 9 }
            backend.pending.computeIfAbsent(rawCid(big)) { CompletableFuture() }.complete(LookupResult.Found(big))
            source.fetchBlock(rawCid(big), 131_066, Duration.ofSeconds(1)) shouldBe big
            (source.cacheStatsForTest().second <= 1000L) shouldBe true
            // an answer that never comes is a timeout, not a hang
            source.fetchBlock(rawCid(byteArrayOf(42)), 131_066, Duration.ofMillis(200)).shouldBeNull()
        }

        test("IPNS records are passed through and never cached; a closed source answers null") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend)
            backend.ipnsAnswer = LookupResult.Found(byteArrayOf(1, 2))
            val key = TestIpnsPublisher().routingKey
            source.resolveIpnsRecord(key, Duration.ofSeconds(1)) shouldBe byteArrayOf(1, 2)
            source.resolveIpnsRecord(key, Duration.ofSeconds(1)) shouldBe byteArrayOf(1, 2)
            backend.ipnsCalls.get() shouldBe 2
            source.close()
            source.resolveIpnsRecord(key, Duration.ofSeconds(1)).shouldBeNull()
            source.blockIfCached(rawCid(byteArrayOf(1))).shouldBeNull()
        }

        test("J3 blockState: CACHED, FETCHING, NOT_FOUND, UNAVAILABLE and NONE; schedule=false never schedules") {
            var now = 0L
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend, nanoClock = { now })
            val found = "found".toByteArray()
            val cFound = rawCid(found)
            val cMissing = rawCid("missing".toByteArray())
            val cUnconfirmed = rawCid("unconfirmed".toByteArray())
            val cFailed = rawCid("failed".toByteArray())
            val cNone = rawCid("none".toByteArray())

            source.blockState(cNone, schedule = false).state shouldBe RemoteBlockState.NONE
            backend.calls.get() shouldBe 0

            for (c in listOf(cFound, cMissing, cUnconfirmed, cFailed)) {
                val v = source.blockState(c, schedule = true)
                v.state shouldBe RemoteBlockState.FETCHING
                v.newlyScheduled shouldBe true
            }
            // a second ask while it runs schedules nothing new
            source.blockState(cFound, schedule = true).newlyScheduled shouldBe false
            backend.calls.get() shouldBe 4
            // background lookups are timeline lookups
            backend.contexts.toSet() shouldBe setOf(LookupContext.TIMELINE)

            backend.pending[cFound]!!.complete(LookupResult.Found(found))
            backend.pending[cMissing]!!.complete(LookupResult.NotFound(confirmed = true))
            backend.pending[cUnconfirmed]!!.complete(LookupResult.NotFound(confirmed = false))
            backend.pending[cFailed]!!.complete(LookupResult.Unavailable(LookupFailure.TIMEOUT))
            source.blockState(cFound, schedule = false).let {
                it.state shouldBe RemoteBlockState.CACHED
                it.bytes shouldBe found
            }
            source.blockState(cMissing, schedule = true).state shouldBe RemoteBlockState.NOT_FOUND
            source.blockState(cUnconfirmed, schedule = true).state shouldBe RemoteBlockState.UNAVAILABLE
            source.blockState(cFailed, schedule = true).state shouldBe RemoteBlockState.UNAVAILABLE
            backend.calls.get() shouldBe 4

            // the unavailable memo ends after two minutes, the not-found memo after ten
            now +=
                java.time.Duration
                    .ofMinutes(2)
                    .plusMillis(1)
                    .toNanos()
            source.blockState(cUnconfirmed, schedule = false).state shouldBe RemoteBlockState.NONE
            source.blockState(cMissing, schedule = false).state shouldBe RemoteBlockState.NOT_FOUND
            now +=
                java.time.Duration
                    .ofMinutes(8)
                    .toNanos()
            source.blockState(cMissing, schedule = false).state shouldBe RemoteBlockState.NONE
            source.close()
            source.memoSizeForTest() shouldBe 0
        }

        test("J3 a lookup that reached no relay is not remembered: the next request asks again") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend)
            for (reason in listOf(LookupFailure.NO_RELAY, LookupFailure.ADMISSION, LookupFailure.CLOSED)) {
                val cid = rawCid("no relay ${reason.name}".toByteArray())
                source.blockState(cid, schedule = true).state shouldBe RemoteBlockState.FETCHING
                backend.pending.remove(cid)!!.complete(LookupResult.Unavailable(reason))
                source.blockState(cid, schedule = false).state shouldBe RemoteBlockState.NONE
                source.blockState(cid, schedule = true).newlyScheduled shouldBe true
            }
            source.memoSizeForTest() shouldBe 0
        }

        test("J3 the outcome memo is bounded: the 1025th entry evicts the eldest") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend)
            repeat(1025) { i ->
                val cid = rawCid("memo $i".toByteArray())
                source.blockState(cid, schedule = true)
                backend.pending[cid]!!.complete(LookupResult.NotFound(confirmed = true))
            }
            source.memoSizeForTest() shouldBe 1024
            source.blockState(rawCid("memo 0".toByteArray()), schedule = false).state shouldBe RemoteBlockState.NONE
            source.blockState(rawCid("memo 1024".toByteArray()), schedule = false).state shouldBe
                RemoteBlockState.NOT_FOUND
        }

        test("J3 a block that does not verify is not cached and reads as unavailable; blocking fetches are mailbox") {
            val backend = HandBackend()
            val source = CircuitRemoteContentSource(backend)
            val cid = rawCid("genuine".toByteArray())
            source.blockState(cid, schedule = true).state shouldBe RemoteBlockState.FETCHING
            backend.pending[cid]!!.complete(LookupResult.Found("forged".toByteArray()))
            source.blockState(cid, schedule = false).state shouldBe RemoteBlockState.UNAVAILABLE
            source.cacheStatsForTest().first shouldBe 0
            backend.contexts.clear()
            val other = rawCid("other".toByteArray())
            backend.pending.computeIfAbsent(other) { CompletableFuture() }.complete(LookupResult.NotFound(true))
            source.fetchBlock(other, 131_066, Duration.ofSeconds(1)).shouldBeNull()
            backend.contexts.toList() shouldBe listOf(LookupContext.MAILBOX)
        }
    })
