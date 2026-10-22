package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class OnionRelayQualityTrackerTest :
    FunSpec({
        val clock = WireTestClock()
        val day = { clock.millis() / 86_400_000L }

        test("counts attempts, link successes and early destroys per relay and day") {
            val t = OnionRelayQualityTracker(clock)
            val a = Secp256k1KeyPair.generate().publicKey
            repeat(4) { t.recordExtendAttempt(a) }
            repeat(3) { t.recordExtendLinkSuccess(a) }
            t.recordDestroyedByTarget(a)
            val c = t.counts(day())[a]!!
            c shouldBe OnionRelayQualityCounts(4, 3, 1)
            c.toReliabilityCounts()!!.reliabilityMicros() shouldBe 500_000
        }

        test("the tracker is bounded: older identities are dropped") {
            val t = OnionRelayQualityTracker(clock, maxTracked = 8)
            repeat(100) { t.recordExtendAttempt(Secp256k1KeyPair.generate().publicKey) }
            t.trackedRelays() shouldBe 8
        }

        test("day buckets older than seven days are pruned") {
            val t = OnionRelayQualityTracker(clock)
            val a = Secp256k1KeyPair.generate().publicKey
            t.recordExtendAttempt(a)
            val first = day()
            clock.advanceSeconds(8 * 86_400)
            t.recordExtendAttempt(a)
            t.counts(first).isEmpty() shouldBe true
            t.counts(day())[a]!!.extendAttempts shouldBe 1
        }

        test("a relay without attempts has no reliability value") {
            OnionRelayQualityCounts(0, 0, 0).toReliabilityCounts() shouldBe null
        }

        test("own CREATE counters are kept separately") {
            val t = OnionRelayQualityTracker(clock)
            t.recordCreateAccepted()
            t.recordCreateRejected()
            t.recordCreateRejected()
            t.ownCreateCounts() shouldBe (1L to 2L)
        }
    })
