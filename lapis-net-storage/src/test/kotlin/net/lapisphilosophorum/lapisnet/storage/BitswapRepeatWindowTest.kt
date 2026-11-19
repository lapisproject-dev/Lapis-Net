package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.peergos.Hash
import java.time.Duration
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
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

        test("a relay lookup inside the window waits for the running request instead of failing at once").config(
            timeout = 90.seconds,
        ) {
            val holder = newNode()
            val dht = newNode()
            val relayNode = newNode()
            try {
                val storageA = storageOn(holder)
                storageOn(dht)
                val relay = storageOn(relayNode)
                storageA.connectToDhtPeer(addressOf(dht)) shouldBe true
                relay.connectToDhtPeer(addressOf(dht)) shouldBe true
                val payload = "the holder gets it only after the first lookup".toByteArray()
                // the CID of the payload, announced before the holder has the block
                val cid = rawCid(payload)
                storageA.provide(cid)

                relay.fetchTransient(cid, Duration.ofSeconds(4)) shouldBe null
                relay.bitswapRequestsSent.get() shouldBe 1

                // the holder gets the block while the second lookup is already waiting
                val putter =
                    thread {
                        Thread.sleep(1_000)
                        storageA.put(payload)
                    }
                relay.fetchTransient(cid, Duration.ofSeconds(20)) shouldBe payload
                putter.join()
                // delivered by the re-send of the first request: no new request went out
                relay.bitswapRequestsSent.get() shouldBe 1
                relay.getLocal(cid) shouldBe null
            } finally {
                listOf(holder, dht, relayNode).forEach { runCatching { it.stop() } }
            }
        }

        test("a stale mark (the want completed meanwhile) is dropped and the provider asked again").config(
            timeout = 120.seconds,
        ) {
            val holder = newNode()
            val dht = newNode()
            val relayNode = newNode()
            try {
                val storageA = storageOn(holder)
                storageOn(dht)
                val relay = storageOn(relayNode)
                storageA.connectToDhtPeer(addressOf(dht)) shouldBe true
                relay.connectToDhtPeer(addressOf(dht)) shouldBe true
                val payload = "delivered after the deadline, nobody waited".toByteArray()
                val cid = rawCid(payload)
                storageA.provide(cid)

                relay.fetchTransient(cid, Duration.ofSeconds(4)) shouldBe null
                relay.bitswapRequestsSent.get() shouldBe 1
                // the block arrives through the re-send after the deadline: the want completes, the mark stays
                storageA.put(payload)
                awaitCondition(timeoutMs = 30_000) { !relay.isWantLiveFor(cid, holder.peerId) } shouldBe true

                // Nabu alone would now stay silent (it sent the block to the relay already); F6 resends it
                relay.fetchTransient(cid, Duration.ofSeconds(20)) shouldBe payload
                relay.bitswapRequestsSent.get() shouldBe 2
                storageA.bitswapResendStats().allowed shouldBe 1
            } finally {
                listOf(holder, dht, relayNode).forEach { runCatching { it.stop() } }
            }
        }
    })

/** The CID [NabuStorage.put] gives [bytes] (CIDv1, raw, SHA-256), without storing them anywhere. */
private fun rawCid(bytes: ByteArray): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, Hash.sha256(bytes))
