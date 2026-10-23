@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class CircuitBuildGovernorTest :
    FunSpec({
        val purpose = CircuitPurpose.DIRECTORY_PUBLISH
        val granted = CircuitBuildGovernor.Admission.Granted

        test("the fourth build in a burst is delayed, then allowed after the refill (6 per minute)") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, maxOpenClientCircuits = 100)
            repeat(3) { g.admit(purpose, "t$it") shouldBe granted }
            val d = g.admit(purpose, "t3").shouldBeInstanceOf<CircuitBuildGovernor.Admission.Delayed>()
            (d.retryAfter > 0.seconds && d.retryAfter <= 10.seconds) shouldBe true
            clock.advanceSeconds(11)
            g.admit(purpose, "t3") shouldBe granted
        }

        test("more than four client circuits are refused as pool full; closing one frees a slot") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, ratePerMinute = 600, burst = 100)
            val handles = List(4) { Any() }
            handles.forEachIndexed { i, h ->
                g.admit(purpose, "t$i") shouldBe granted
                g.onBuilt(h, purpose, "t$i")
            }
            g.admit(purpose, "t4") shouldBe CircuitBuildGovernor.Admission.PoolFull
            g.poolOpenCount() shouldBe 4
            g.onClosed(handles[0])
            g.admit(purpose, "t4") shouldBe granted
        }

        test("builds in flight count against the pool, a failed build releases the slot") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, maxOpenClientCircuits = 1, ratePerMinute = 600, burst = 100)
            g.admit(purpose, "a") shouldBe granted
            g.admit(purpose, "b") shouldBe CircuitBuildGovernor.Admission.PoolFull
            g.onFailed(purpose)
            clock.advanceSeconds(6)
            g.admit(purpose, "b") shouldBe granted
        }

        test("long-lived introduction circuits do not use the client pool but pay the rate") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, maxOpenClientCircuits = 1, ratePerMinute = 600, burst = 100)
            repeat(5) {
                g.admit(CircuitPurpose.INTRO, "i$it") shouldBe granted
                g.onBuilt(Any(), CircuitPurpose.INTRO, "i$it")
            }
            g.poolOpenCount() shouldBe 0
            g.openCount() shouldBe 5
            g.admit(purpose, "p") shouldBe granted
        }

        test("a circuit older than ten minutes is reported as expired") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, ratePerMinute = 600, burst = 100)
            val h = Any()
            g.admit(purpose, "t")
            g.onBuilt(h, purpose, "t")
            g.expired(clock.instant()) shouldBe emptyList()
            clock.advanceSeconds(9 * 60)
            g.expired(clock.instant()) shouldBe emptyList()
            clock.advanceSeconds(61)
            g.expired(clock.instant()) shouldBe listOf(h)
            g.onClosed(h)
            g.openCount() shouldBe 0
        }

        test("the backoff after failures grows from 5 seconds up to 5 minutes and a success resets it") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, maxOpenClientCircuits = 100, ratePerMinute = 6000, burst = 1000)
            var expected = 5
            repeat(10) {
                g.admit(purpose, "t") shouldBe granted
                g.onFailed(purpose)
                val d = g.admit(purpose, "t").shouldBeInstanceOf<CircuitBuildGovernor.Admission.Delayed>()
                d.retryAfter.inWholeSeconds shouldBe expected.coerceAtMost(300).toLong()
                clock.advanceSeconds(d.retryAfter.inWholeSeconds + 1)
                expected *= 2
            }
            g.admit(purpose, "t") shouldBe granted
            g.onBuilt(Any(), purpose, "t")
            g.admit(purpose, "t") shouldBe granted
            g.onFailed(purpose)
            g.admit(purpose, "t").shouldBeInstanceOf<CircuitBuildGovernor.Admission.Delayed>().retryAfter shouldBe
                5.seconds
            (5.minutes.inWholeSeconds) shouldBe 300L
        }

        test("after a lockdown nothing is admitted") {
            val g = CircuitBuildGovernor(WireTestClock())
            g.lockdown()
            g.admit(purpose, "t") shouldBe CircuitBuildGovernor.Admission.Locked
        }

        test("every new target is its own circuit: two admissions are two handles") {
            val g = CircuitBuildGovernor(WireTestClock(), ratePerMinute = 600, burst = 100)
            g.admit(purpose, "x") shouldBe granted
            g.onBuilt(Any(), purpose, "x")
            g.admit(purpose, "y") shouldBe granted
            g.onBuilt(Any(), purpose, "y")
            g.openCount() shouldBe 2
        }

        test("a circuit that was already closed when it was reported is not registered") {
            val g = CircuitBuildGovernor(WireTestClock())
            g.admit(purpose, "x") shouldBe granted
            g.onBuilt(Any(), purpose, "x", closed = true)
            g.openCount() shouldBe 0
            g.poolOpenCount() shouldBe 0
        }

        test("an INTRODUCE flood with failing rendezvous points does not block publication or intro refresh") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, ratePerMinute = 6, burst = 3)
            val rp = CircuitPurpose.RENDEZVOUS_RECEIVER
            repeat(200) {
                if (g.admit(rp, "rp$it") == granted) g.onFailed(rp)
                clock.advanceSeconds(1)
                // the node's own builds keep their budget and are never delayed by the receiver failures
                if (it % 20 == 0) {
                    g.admit(CircuitPurpose.DIRECTORY_PUBLISH, "pub$it") shouldBe granted
                    g.onBuilt(Any(), CircuitPurpose.DIRECTORY_PUBLISH, "pub$it", closed = true)
                    clock.advanceSeconds(10)
                    g.admit(CircuitPurpose.INTRO, "intro$it") shouldBe granted
                    g.onBuilt(Any(), CircuitPurpose.INTRO, "intro$it", closed = true)
                }
            }
        }

        test("service rendezvous circuits have their own budget and are dropped, not delayed, over it") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, serviceRendezvousPerMinute = 60, serviceRendezvousBurst = 2)
            val rp = CircuitPurpose.RENDEZVOUS_RECEIVER
            g.admit(rp, "a") shouldBe granted
            g.admit(rp, "b") shouldBe granted
            g.admit(rp, "c") shouldBe CircuitBuildGovernor.Admission.Dropped
            // own tokens untouched
            repeat(3) { g.admit(CircuitPurpose.DIRECTORY_PUBLISH, "p$it") shouldBe granted }
            clock.advanceSeconds(2)
            g.admit(rp, "c") shouldBe granted
        }

        test("a rendezvous failure starts no global backoff and a rendezvous success does not clear one") {
            val clock = WireTestClock()
            val g = CircuitBuildGovernor(clock, ratePerMinute = 600, burst = 100)
            g.admit(CircuitPurpose.RENDEZVOUS_RECEIVER, "x") shouldBe granted
            g.onFailed(CircuitPurpose.RENDEZVOUS_RECEIVER)
            g.admit(CircuitPurpose.DIRECTORY_PUBLISH, "p") shouldBe granted
            g.onFailed(CircuitPurpose.DIRECTORY_PUBLISH)
            g.admit(CircuitPurpose.RENDEZVOUS_RECEIVER, "y") shouldBe granted
            g.onBuilt(Any(), CircuitPurpose.RENDEZVOUS_RECEIVER, "y", closed = true)
            g.admit(CircuitPurpose.INTRO, "i").shouldBeInstanceOf<CircuitBuildGovernor.Admission.Delayed>()
        }
    })
