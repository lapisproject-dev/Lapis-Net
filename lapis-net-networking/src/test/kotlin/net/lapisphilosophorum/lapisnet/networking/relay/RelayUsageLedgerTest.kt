package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread

private fun peer(seed: Int): PeerId = PeerId(ByteArray(32) { seed.toByte() })

private fun peerOfIndex(i: Int): PeerId =
    PeerId(ByteArray(32) { idx -> (i shr ((idx % 4) * 8)).toByte() }.also { it[31] = (i % 251).toByte() })

private class ManualClock(
    var now: Instant = Instant.parse("2026-10-18T12:00:00Z"),
) : () -> Instant {
    override fun invoke(): Instant = now

    fun advance(duration: Duration) {
        now = now.plus(duration)
    }
}

class RelayUsageLedgerTest :
    FunSpec({
        test("an unknown peer has balance 0") {
            RelayUsageLedger().balanceOf(peer(1)) shouldBe 0L
        }

        test("serving a peer drives its balance negative, receiving from a relay drives it positive") {
            val ledger = RelayUsageLedger()
            ledger.recordServed(peer(1), 1_000)
            ledger.recordReceivedFrom(peer(2), 500)
            ledger.balanceOf(peer(1)) shouldBe -1_000L
            ledger.balanceOf(peer(2)) shouldBe 500L
            ledger.recordReceivedFrom(peer(1), 400)
            ledger.balanceOf(peer(1)) shouldBe -600L
        }

        test("arithmetic saturates instead of overflowing") {
            val ledger = RelayUsageLedger(clock = ManualClock())
            ledger.recordReceivedFrom(peer(1), Long.MAX_VALUE)
            ledger.recordReceivedFrom(peer(1), Long.MAX_VALUE)
            ledger.balanceOf(peer(1)) shouldBe Long.MAX_VALUE
            ledger.recordServed(peer(2), Long.MAX_VALUE)
            ledger.recordServed(peer(2), Long.MAX_VALUE)
            ledger.recordServed(peer(2), Long.MAX_VALUE)
            ledger.balanceOf(peer(2)) shouldBe Long.MIN_VALUE
        }

        test("negative byte counts are rejected") {
            val ledger = RelayUsageLedger()
            shouldThrow<IllegalArgumentException> { ledger.recordServed(peer(1), -1) }
            shouldThrow<IllegalArgumentException> { ledger.recordReceivedFrom(peer(1), -1) }
        }

        test("zero-byte records do not create entries") {
            val ledger = RelayUsageLedger()
            ledger.recordServed(peer(1), 0)
            ledger.trackedPeers() shouldBe 0
        }

        test("balances decay toward zero with the configured half-life") {
            val clock = ManualClock()
            val ledger = RelayUsageLedger(halfLife = Duration.ofDays(7), clock = clock)
            ledger.recordServed(peer(1), 1_000_000)
            ledger.balanceOf(peer(1)) shouldBe -1_000_000L
            clock.advance(Duration.ofDays(7))
            ledger.balanceOf(peer(1)) shouldBe -500_000L
            clock.advance(Duration.ofDays(7))
            ledger.balanceOf(peer(1)) shouldBe -250_000L
        }

        test("a debt that has fully decayed is forgotten") {
            val clock = ManualClock()
            val ledger = RelayUsageLedger(halfLife = Duration.ofHours(1), clock = clock)
            ledger.recordServed(peer(1), 10)
            clock.advance(Duration.ofDays(30))
            ledger.balanceOf(peer(1)) shouldBe 0L
            ledger.trackedPeers() shouldBe 0
        }

        test("a clock running backwards never inflates a balance") {
            val clock = ManualClock()
            val ledger = RelayUsageLedger(clock = clock)
            ledger.recordServed(peer(1), 1_000)
            clock.advance(Duration.ofDays(-3))
            ledger.balanceOf(peer(1)) shouldBe -1_000L
            ledger.recordServed(peer(1), 1_000)
            ledger.balanceOf(peer(1)) shouldBe -2_000L
        }

        test("at the cap the entry with the smallest absolute balance is evicted") {
            val ledger = RelayUsageLedger(maxTrackedPeers = 3)
            ledger.recordServed(peer(1), 100)
            ledger.recordServed(peer(2), 5_000)
            ledger.recordReceivedFrom(peer(3), 50)
            ledger.recordServed(peer(4), 1_000) // evicts peer 3 (|50| is smallest)
            ledger.trackedPeers() shouldBe 3
            ledger.balanceOf(peer(3)) shouldBe 0L
            ledger.balanceOf(peer(1)) shouldBe -100L
            ledger.balanceOf(peer(4)) shouldBe -1_000L
        }

        test("a newcomer smaller than everything tracked is not tracked") {
            val ledger = RelayUsageLedger(maxTrackedPeers = 2)
            ledger.recordServed(peer(1), 1_000)
            ledger.recordServed(peer(2), 2_000)
            ledger.recordServed(peer(3), 10)
            ledger.trackedPeers() shouldBe 2
            ledger.balanceOf(peer(3)) shouldBe 0L
        }

        test("flooding the ledger with 5000 fresh identities does not evict a heavy debtor") {
            val ledger = RelayUsageLedger(clock = ManualClock())
            val debtor = peer(99)
            ledger.recordServed(debtor, 1_000_000_000L)
            for (i in 1..5_000) ledger.recordServed(peerOfIndex(i), 1_000L + (i % 7))
            ledger.trackedPeers() shouldBe RelayUsageLedger.DEFAULT_MAX_TRACKED_PEERS
            ledger.balanceOf(debtor) shouldBe -1_000_000_000L
        }

        test("concurrent updates from 8 threads add up exactly") {
            val ledger = RelayUsageLedger()
            val target = peer(7)
            val start = CountDownLatch(1)
            val threads =
                (1..8).map {
                    thread {
                        start.await()
                        repeat(10_000) { ledger.recordReceivedFrom(target, 3) }
                    }
                }
            start.countDown()
            threads.forEach { it.join() }
            ledger.balanceOf(target) shouldBe 8L * 10_000L * 3L
        }

        test("snapshot returns the non-zero balances and is a copy") {
            val ledger = RelayUsageLedger()
            ledger.recordServed(peer(1), 10)
            val snap = ledger.snapshot()
            snap shouldBe mapOf(peer(1) to -10L)
            ledger.recordServed(peer(2), 20)
            snap.size shouldBe 1
        }
    })
