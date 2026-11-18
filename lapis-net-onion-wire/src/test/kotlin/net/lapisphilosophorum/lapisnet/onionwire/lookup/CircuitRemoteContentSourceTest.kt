package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** A backend whose futures the test completes by hand. */
private class HandBackend : LookupBackend {
    val pending = ConcurrentHashMap<Cid, CompletableFuture<LookupResult>>()
    val calls = AtomicInteger()
    val ipnsCalls = AtomicInteger()
    var ipnsAnswer: LookupResult = LookupResult.NotFound

    override fun fetchBlock(
        cid: Cid,
        timeout: kotlin.time.Duration,
    ): CompletableFuture<LookupResult> {
        calls.incrementAndGet()
        return pending.computeIfAbsent(cid) { CompletableFuture() }
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
    })
