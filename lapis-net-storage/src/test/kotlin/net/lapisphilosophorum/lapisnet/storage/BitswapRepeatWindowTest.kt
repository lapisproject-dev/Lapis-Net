package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.seconds

/**
 * The (block, peer) repeat window of [NabuStorage.get]: a Bitswap request that was really sent is not
 * sent again for five minutes, but a pair for which NO request went out (no address, connect failed)
 * must stay eligible - otherwise a provider that comes online shortly after a failed first attempt
 * would be skipped for the whole window.
 */
class BitswapRepeatWindowTest :
    FunSpec({
        test("a second get for the same block and peer inside the window sends no new request").config(
            timeout = 60.seconds,
        ) {
            val nodeA = newNode()
            val nodeB = newNode()
            val stranger = newNode()
            try {
                storageOn(nodeA) // A is only an (empty) provider
                val storageB = storageOn(nodeB)
                storageB.registerPeerAddress(addressOf(nodeA))
                // a block nobody reachable holds: B's request goes out and is simply never answered with data
                val missing = storageOn(stranger).put("held by nobody B can reach".toByteArray())

                storageB.get(missing, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(2)) shouldBe null
                storageB.bitswapRequestsSent.get() shouldBe 1

                val started = System.nanoTime()
                storageB.get(missing, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(5)) shouldBe null
                storageB.bitswapRequestsSent.get() shouldBe 1
                // every target was suppressed, so the call returns at once instead of waiting its deadline
                (System.nanoTime() - started < Duration.ofSeconds(2).toNanos()) shouldBe true
            } finally {
                listOf(nodeA, nodeB, stranger).forEach { runCatching { it.stop() } }
            }
        }

        test("a get whose first attempt could not connect still fetches once the provider is reachable").config(
            timeout = 60.seconds,
        ) {
            val nodeA = newNode()
            val nodeB = newNode()
            try {
                val storageA = storageOn(nodeA)
                val storageB = storageOn(nodeB)
                val payload = "fetched after a failed first attempt".toByteArray()
                val cid = storageA.put(payload)

                // B knows no address for A: nothing can be sent, and the pair must not be marked
                storageB.get(cid, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(1)) shouldBe null
                storageB.bitswapRequestsSent.get() shouldBe 0

                storageB.registerPeerAddress(addressOf(nodeA))
                storageB.get(cid, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(10)) shouldBe payload
                storageB.bitswapRequestsSent.get() shouldBe 1
            } finally {
                listOf(nodeA, nodeB).forEach { runCatching { it.stop() } }
            }
        }

        test("a block whose first fetch failed is fetched after the five-minute want lifetime too").config(
            timeout = 60.seconds,
        ) {
            val nodeA = newNode()
            val nodeB = newNode()
            try {
                val storageA = storageOn(nodeA)
                // B's view of time, so that the test can let the want of the first attempt grow old
                val skew = AtomicLong()
                val storageB = storageOn(nodeB, clock = { System.nanoTime() + skew.get() })
                val payload = "provider reachable only after the want expired".toByteArray()
                val cid = storageA.put(payload)

                // first attempt: B knows no address for A, so nothing goes out - but Nabu has stamped the want
                storageB.get(cid, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(1)) shouldBe null
                storageB.bitswapRequestsSent.get() shouldBe 0

                skew.addAndGet(Duration.ofMinutes(6).toNanos())
                storageB.registerPeerAddress(addressOf(nodeA))
                // Nabu alone would now send an empty want list for this block, for good
                storageB.get(cid, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(10)) shouldBe payload
                storageB.bitswapRequestsSent.get() shouldBe 1
            } finally {
                listOf(nodeA, nodeB).forEach { runCatching { it.stop() } }
            }
        }
    })
