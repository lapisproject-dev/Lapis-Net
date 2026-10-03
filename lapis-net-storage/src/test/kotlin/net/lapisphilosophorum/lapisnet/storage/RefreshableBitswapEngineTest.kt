package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import org.peergos.BlockRequestAuthoriser
import org.peergos.Hash
import org.peergos.Want
import org.peergos.blockstore.RamBlockstore
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicLong

class RefreshableBitswapEngineTest :
    FunSpec({
        val now = AtomicLong()
        val authoriser = BlockRequestAuthoriser { _, _, _ -> CompletableFuture.completedFuture(true) }

        fun engine() = RefreshableBitswapEngine(RamBlockstore(), authoriser, 2 * 1024 * 1024) { now.get() }

        fun wantOf(text: String) =
            Want(Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, Hash.sha256(text.toByteArray())))

        fun advance(d: Duration) = now.addAndGet(d.toNanos())

        test("a want is sent to a single peer at first, but not again within five seconds") {
            now.set(0)
            val engine = engine()
            val peer = realPeerId()
            val want = wantOf("a")
            engine.getWant(want, true)
            engine.refresh(want, peer)
            engine.getWants(setOf(peer)) shouldBe setOf(want)
            engine.getWants(setOf(peer)) shouldBe emptySet()
            advance(Duration.ofSeconds(6))
            engine.getWants(setOf(peer)) shouldBe setOf(want)
        }

        test("a want stops being sent five minutes after it was last requested, and refresh renews it") {
            now.set(0)
            val engine = engine()
            val peer = realPeerId()
            val want = wantOf("b")
            engine.getWant(want, true)
            engine.refresh(want, peer)
            advance(Duration.ofMinutes(6))
            engine.getWants(setOf(peer)) shouldBe emptySet()

            engine.refresh(want, peer)
            engine.getWants(setOf(peer)) shouldBe setOf(want)
            advance(Duration.ofMinutes(4))
            engine.getWants(setOf(peer)) shouldBe setOf(want)
            advance(Duration.ofMinutes(2))
            engine.getWants(setOf(peer)) shouldBe emptySet()
        }

        test("a want that was never requested from the peer is not sent to it") {
            now.set(0)
            val engine = engine()
            val peer = realPeerId()
            engine.getWant(wantOf("never"), true)
            engine.getWants(setOf(peer)) shouldBe emptySet()
        }

        test("a completed want is forgotten, and refresh of it does nothing") {
            now.set(0)
            val engine = engine()
            val peer = realPeerId()
            val want = wantOf("c")
            val future = engine.getWant(want, true)
            future.complete(null)
            advance(Duration.ofSeconds(10))
            engine.refresh(want, peer)
            engine.getWants(setOf(peer)) shouldBe emptySet()
        }

        test("a want is tracked per peer: sending to one peer does not silence another") {
            now.set(0)
            val engine = engine()
            val first = realPeerId()
            val second = realPeerId()
            val want = wantOf("d")
            engine.getWant(want, true)
            engine.refresh(want, first)
            engine.refresh(want, second)
            engine.getWants(setOf(first)) shouldBe setOf(want)
            engine.getWants(setOf(second)) shouldBe setOf(want)
        }

        test("a want requested from one peer is never put in another peer's wantlist") {
            now.set(0)
            val engine = engine()
            val first = realPeerId()
            val second = realPeerId()
            val secret = wantOf("requested from the first peer only")
            val other = wantOf("requested from the second peer only")
            engine.getWant(secret, true)
            engine.getWant(other, true)
            engine.refresh(secret, first)
            engine.refresh(other, second)

            engine.getWants(setOf(second)) shouldBe setOf(other)
            engine.getWants(setOf(first)) shouldBe setOf(secret)
            // and still not, however often or long afterwards the second peer is asked
            repeat(5) {
                advance(Duration.ofSeconds(6))
                engine.refresh(other, second)
                engine.getWants(setOf(second)) shouldBe setOf(other)
            }
        }

        test("activity for another peer does not keep this peer's re-send alive") {
            now.set(0)
            val engine = engine()
            val slow = realPeerId()
            val busy = realPeerId()
            val first = wantOf("asked of the slow peer")
            engine.getWant(first, true)
            engine.refresh(first, slow)
            // the busy peer is asked for one new block after another for ten minutes
            repeat(20) { i ->
                advance(Duration.ofSeconds(30))
                val next = wantOf("block $i for the busy peer")
                engine.getWant(next, true)
                engine.refresh(next, busy)
                engine.getWants(setOf(busy)) shouldContain next
            }
            // the re-send thread of the slow peer ends by itself: its wantlist has been empty for five minutes
            engine.getWants(setOf(slow)) shouldBe emptySet()
        }

        test("a want is tracked for at most MAX_TRACKED_PEERS_PER_WANT peers, the least recent dropped first") {
            now.set(0)
            val engine = engine()
            val want = wantOf("many peers")
            engine.getWant(want, true)
            val peers = List(MAX_TRACKED_PEERS_PER_WANT + 5) { realPeerId() }
            peers.forEach {
                advance(Duration.ofSeconds(1))
                engine.refresh(want, it)
            }
            peers.take(5).forEach { engine.getWants(setOf(it)) shouldBe emptySet() }
            peers.drop(5).forEach { engine.getWants(setOf(it)) shouldBe setOf(want) }
        }

        test("for several peers or none the base behaviour is kept: every pending want") {
            now.set(0)
            val engine = engine()
            val want = wantOf("e")
            engine.getWant(want, true)
            advance(Duration.ofMinutes(10))
            engine.getWants(setOf(realPeerId(), realPeerId())) shouldBe setOf(want)
            engine.getWants(emptySet()) shouldBe setOf(want)
        }
    })
