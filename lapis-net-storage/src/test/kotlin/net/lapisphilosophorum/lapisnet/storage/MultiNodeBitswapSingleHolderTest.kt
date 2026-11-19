package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.nio.file.Files
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Fix wave F6 on real loopback nodes: A is the ONLY holder, B the DHT peer in between, C the lookup relay. Before F6
 * the relay got the block once - A's Nabu responder then silently skipped every later WANT_BLOCK of C for it.
 */
class MultiNodeBitswapSingleHolderTest :
    FunSpec({
        test("a relay fetches the same block three times in a row from a single holder").config(timeout = 120.seconds) {
            val holder = newNode()
            val dht = newNode()
            val relayNode = newNode()
            try {
                val storageA = storageOn(holder)
                storageOn(dht)
                val relay = storageOn(relayNode)
                storageA.connectToDhtPeer(addressOf(dht)) shouldBe true
                relay.connectToDhtPeer(addressOf(dht)) shouldBe true
                val payload = ByteArray(7000) { (it % 241).toByte() }
                val cid = storageA.put(payload)
                storageA.provide(cid)

                val times = ArrayList<Long>()
                repeat(3) {
                    val started = System.nanoTime()
                    val fetched = relay.fetchTransient(cid, Duration.ofSeconds(20)).shouldNotBeNull()
                    times += (System.nanoTime() - started) / 1_000_000
                    fetched.toList() shouldBe payload.toList()
                }
                relay.getLocal(cid).shouldBeNull()
                println(
                    "F6 measurement: single holder, three lookups ms=$times holder ${storageA.bitswapResendStats()}",
                )
                storageA.bitswapResendStats().allowed shouldBe 2
            } finally {
                listOf(holder, dht, relayNode).forEach { runCatching { it.stop() } }
            }
        }

        test("with a small per-peer bucket the next re-send waits for the refill").config(timeout = 120.seconds) {
            val holder = newNode()
            val dht = newNode()
            val relayNode = newNode()
            try {
                // one re-send token, refilled every 7.5 s
                val limits = BitswapResendLimits(perPeerPerMinute = 8, perPeerBurst = 1)
                val storageA =
                    NabuStorage.attachWithClock(
                        holder,
                        Files.createTempDirectory("f6-holder"),
                        true,
                        DhtLimits(),
                        System::nanoTime,
                        resendLimits = limits,
                    )
                storageOn(dht)
                val relay = storageOn(relayNode)
                storageA.connectToDhtPeer(addressOf(dht)) shouldBe true
                relay.connectToDhtPeer(addressOf(dht)) shouldBe true
                val payload = "bounded re-send".toByteArray()
                val cid = storageA.put(payload)
                storageA.provide(cid)

                relay.fetchTransient(cid, Duration.ofSeconds(20)) shouldBe payload // first send: Nabu's own
                relay.fetchTransient(cid, Duration.ofSeconds(20)) shouldBe payload // the one token
                val started = System.nanoTime()
                relay.fetchTransient(cid, Duration.ofSeconds(30)) shouldBe payload // waits for the refill
                val waitedMs = (System.nanoTime() - started) / 1_000_000
                val stats = storageA.bitswapResendStats()
                println("F6 measurement: bucket refill, third lookup took ms=$waitedMs holder $stats")
                stats.allowed shouldBe 2
                (stats.deniedPeer + stats.deniedInterval) shouldBeGreaterThanOrEqual 1
                // at least one requester re-send period (5 s) passed before the holder answered
                waitedMs shouldBeGreaterThanOrEqual 4_000
            } finally {
                listOf(holder, dht, relayNode).forEach { runCatching { it.stop() } }
            }
        }
    })
