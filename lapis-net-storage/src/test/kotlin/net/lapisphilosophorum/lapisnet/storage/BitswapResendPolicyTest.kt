package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import org.peergos.Hash
import org.peergos.Want
import java.time.Duration
import java.util.Optional
import java.util.concurrent.atomic.AtomicLong

/** Fix wave F6: the bounds of a holder's re-send of a block it already sent (negative tests first of all). */
class BitswapResendPolicyTest :
    FunSpec({
        val now = AtomicLong()

        fun policy(limits: BitswapResendLimits = BitswapResendLimits()) = BitswapResendPolicy(limits) { now.get() }

        fun wantOf(text: String) =
            Want(Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, Hash.sha256(text.toByteArray())))

        fun advance(d: Duration) = now.addAndGet(d.toNanos())

        test("a flood of the same duplicate is answered at most once per minimum interval") {
            now.set(0)
            val p = policy()
            val peer = realPeerId()
            val want = wantOf("flood")
            var allowed = 0
            // 200 duplicates spread over 60 s of fake time (one every 300 ms)
            repeat(200) {
                if (p.decide(peer, want) == ResendDecision.ALLOWED) allowed++
                advance(Duration.ofMillis(300))
            }
            allowed shouldBeLessThanOrEqual 1 + 60 / 5
            allowed shouldBe 12 // 0 s, 5.1 s, ... - one per started interval within the 60 s
            p.stats().deniedInterval shouldBe (200L - allowed)
        }

        test("the same pair is answered again once the minimum interval has passed") {
            now.set(0)
            val p = policy()
            val peer = realPeerId()
            val want = wantOf("again")
            p.decide(peer, want) shouldBe ResendDecision.ALLOWED
            p.decide(peer, want) shouldBe ResendDecision.DENIED_INTERVAL
            advance(Duration.ofSeconds(4))
            p.decide(peer, want) shouldBe ResendDecision.DENIED_INTERVAL
            advance(Duration.ofSeconds(1))
            p.decide(peer, want) shouldBe ResendDecision.ALLOWED
        }

        test("a want with auth is another pair than the same CID without") {
            now.set(0)
            val p = policy()
            val peer = realPeerId()
            val plain = wantOf("auth")
            val withAuth = Want(plain.cid, Optional.of("abcd"))
            p.decide(peer, plain) shouldBe ResendDecision.ALLOWED
            p.decide(peer, withAuth) shouldBe ResendDecision.ALLOWED
        }

        test("one peer's many distinct duplicates hit its bucket, which refills over time") {
            now.set(0)
            val limits = BitswapResendLimits()
            val p = policy(limits)
            val peer = realPeerId()
            repeat(limits.perPeerBurst) { p.decide(peer, wantOf("burst-$it")) shouldBe ResendDecision.ALLOWED }
            p.decide(peer, wantOf("burst-over")) shouldBe ResendDecision.DENIED_PEER_LIMIT
            // another peer is not affected
            p.decide(realPeerId(), wantOf("burst-over")) shouldBe ResendDecision.ALLOWED
            // 60 per minute: one token per second
            advance(Duration.ofMillis(500))
            p.decide(peer, wantOf("burst-over")) shouldBe ResendDecision.DENIED_PEER_LIMIT
            advance(Duration.ofMillis(600))
            p.decide(peer, wantOf("burst-over")) shouldBe ResendDecision.ALLOWED
            p.decide(peer, wantOf("burst-next")) shouldBe ResendDecision.DENIED_PEER_LIMIT
            p.stats().deniedPeer shouldBe 3
        }

        test("many peers together hit the global bucket") {
            now.set(0)
            val limits = BitswapResendLimits(globalPerMinute = 600, globalBurst = 30)
            val p = policy(limits)
            var denied = 0
            var allowed = 0
            repeat(100) {
                when (p.decide(realPeerId(), wantOf("global-$it"))) {
                    ResendDecision.ALLOWED -> allowed++
                    ResendDecision.DENIED_GLOBAL_LIMIT -> denied++
                    else -> error("unexpected decision")
                }
            }
            allowed shouldBe 30
            denied shouldBe 70
            advance(Duration.ofSeconds(1)) // 10 tokens per second
            var later = 0
            repeat(20) { if (p.decide(realPeerId(), wantOf("global-later-$it")) == ResendDecision.ALLOWED) later++ }
            later shouldBe 10
        }

        test("a denied decision consumes nothing") {
            now.set(0)
            val p =
                policy(
                    BitswapResendLimits(perPeerPerMinute = 2, perPeerBurst = 1, globalPerMinute = 2, globalBurst = 1),
                )
            val peer = realPeerId()
            val want = wantOf("consume")
            p.decide(peer, want) shouldBe ResendDecision.ALLOWED
            repeat(10) { p.decide(peer, want) shouldBe ResendDecision.DENIED_INTERVAL }
            advance(Duration.ofSeconds(30)) // one token per 30 s, both buckets
            p.decide(peer, want) shouldBe ResendDecision.ALLOWED
        }

        test("the LRU bounds of pairs and peers are never exceeded") {
            now.set(0)
            val p =
                policy(
                    BitswapResendLimits(
                        maxTrackedPairs = 50,
                        maxTrackedPeers = 10,
                        globalPerMinute = 100_000,
                        globalBurst = 100_000,
                    ),
                )
            val peers = List(25) { realPeerId() }
            for (i in 0 until 1_000) {
                p.decide(peers[i % peers.size], wantOf("lru-$i"))
                p.trackedPairsForTest() shouldBeLessThanOrEqual 50
                p.trackedPeersForTest() shouldBeLessThanOrEqual 10
            }
            p.trackedPeersForTest() shouldBe 10
        }

        test("a clock that runs backwards neither adds tokens nor reopens an interval") {
            now.set(Duration.ofMinutes(10).toNanos())
            val p = policy(BitswapResendLimits(perPeerPerMinute = 1, perPeerBurst = 1))
            val peer = realPeerId()
            val want = wantOf("rollback")
            p.decide(peer, want) shouldBe ResendDecision.ALLOWED
            now.set(0) // backwards by ten minutes
            p.decide(peer, want) shouldBe ResendDecision.DENIED_INTERVAL
            p.decide(peer, wantOf("rollback-2")) shouldBe ResendDecision.DENIED_PEER_LIMIT
            now.set(Duration.ofMinutes(10).toNanos()) // back to where it was: still no time has passed
            p.decide(peer, wantOf("rollback-3")) shouldBe ResendDecision.DENIED_PEER_LIMIT
            now.set(Duration.ofMinutes(11).toNanos())
            p.decide(peer, wantOf("rollback-3")) shouldBe ResendDecision.ALLOWED
            p.stats().allowed shouldBe 2
            p.stats().deniedPeer shouldBeGreaterThan 0
            p.stats().deniedGlobal shouldBe 0L
        }

        test("invalid limits are rejected") {
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(minInterval = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(minInterval = Duration.ofSeconds(-1)) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(perPeerPerMinute = 0) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(perPeerBurst = 0) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(perPeerPerMinute = 10, perPeerBurst = 11) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(globalPerMinute = -1) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(globalBurst = 0) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(globalPerMinute = 10, globalBurst = 11) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(maxTrackedPairs = 0) }
            shouldThrow<IllegalArgumentException> { BitswapResendLimits(maxTrackedPeers = 0) }
        }
    })
