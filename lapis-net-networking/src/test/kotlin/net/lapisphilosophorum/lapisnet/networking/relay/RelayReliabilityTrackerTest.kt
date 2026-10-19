package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import java.time.Instant

private fun relay(seed: Int): PeerId = PeerId(ByteArray(32) { seed.toByte() })

private fun relayIdx(i: Int): PeerId = PeerId(ByteArray(32) { idx -> if (idx < 2) (i shr (idx * 8)).toByte() else 1 })

class RelayReliabilityTrackerTest :
    FunSpec({
        val day10 = Instant.parse("1970-01-11T12:00:00Z") // epoch day 10
        val epochDay = 10L

        test("successes and failures of reserve/renew/dial attempts are counted per relay") {
            val tracker = RelayReliabilityTracker(clock = { day10 })
            tracker.recordAttempt(relay(1), true)
            tracker.recordAttempt(relay(1), true)
            tracker.recordAttempt(relay(1), false)
            tracker.recordAttempt(relay(2), false)
            val counts = tracker.countsForDay(epochDay)
            counts[relay(1)] shouldBe RelayReliabilityCounts(3, 2)
            counts[relay(2)] shouldBe RelayReliabilityCounts(1, 0)
        }

        test("reliabilityMicros is the floored success fraction") {
            RelayReliabilityCounts(3, 2).reliabilityMicros() shouldBe 666_666
            RelayReliabilityCounts(4, 4).reliabilityMicros() shouldBe 1_000_000
            RelayReliabilityCounts(5, 0).reliabilityMicros() shouldBe 0
        }

        test("reliabilityMicros with zero attempts is rejected") {
            shouldThrow<IllegalArgumentException> { RelayReliabilityCounts(0, 0).reliabilityMicros() }
        }

        test("counts must be consistent") {
            shouldThrow<IllegalArgumentException> { RelayReliabilityCounts(1, 2) }
            shouldThrow<IllegalArgumentException> { RelayReliabilityCounts(-1, 0) }
        }

        test("attempts are bucketed by UTC day and only two days are kept") {
            var now = Instant.parse("1970-01-11T23:59:59Z") // day 10
            val tracker = RelayReliabilityTracker(clock = { now })
            tracker.recordAttempt(relay(1), true)
            now = Instant.parse("1970-01-12T00:00:01Z") // day 11
            tracker.recordAttempt(relay(1), false)
            tracker.countsForDay(10)[relay(1)] shouldBe RelayReliabilityCounts(1, 1)
            tracker.countsForDay(11)[relay(1)] shouldBe RelayReliabilityCounts(1, 0)
            now = Instant.parse("1970-01-13T00:00:01Z") // day 12 -> day 10 dropped
            tracker.recordAttempt(relay(1), true)
            tracker.countsForDay(10) shouldBe emptyMap()
            tracker.countsForDay(11)[relay(1)] shouldBe RelayReliabilityCounts(1, 0)
            tracker.countsForDay(12)[relay(1)] shouldBe RelayReliabilityCounts(1, 1)
        }

        test("at most maxTrackedRelays relays are tracked per day") {
            val tracker = RelayReliabilityTracker(maxTrackedRelays = 256, clock = { day10 })
            for (i in 1..1_000) tracker.recordAttempt(relayIdx(i), true)
            tracker.countsForDay(epochDay).size shouldBe 256
            // An already-tracked relay still counts.
            tracker.recordAttempt(relayIdx(1), true)
            tracker.countsForDay(epochDay)[relayIdx(1)] shouldBe RelayReliabilityCounts(2, 2)
        }

        test("a full bucket does not starve relays we hold a reservation with") {
            val tracker = RelayReliabilityTracker(maxTrackedRelays = 4, clock = { day10 })
            // Attacker floods dial observations for fake relays first.
            for (i in 1..4) tracker.recordDial(relayIdx(i), relay(77), true)
            tracker.recordDial(relayIdx(50), relay(77), true) // dial-only entry cannot displace
            tracker.countsForDay(epochDay).containsKey(relayIdx(50)) shouldBe false
            // The real relay, reserved with, still gets tracked (evicting a dial-only entry).
            tracker.recordReservationAttempt(relay(1), true)
            tracker.recordReservationAttempt(relay(1), false)
            tracker.countsForDay(epochDay)[relay(1)] shouldBe RelayReliabilityCounts(2, 1)
            tracker.countsForDay(epochDay).size shouldBe 4
            // Dial observations of the real relay now count too (it is already tracked).
            tracker.recordDial(relay(1), relay(78), true)
            tracker.countsForDay(epochDay)[relay(1)] shouldBe RelayReliabilityCounts(3, 2)
        }

        test("reservation entries are never evicted by other reservation entries when all are held") {
            val tracker = RelayReliabilityTracker(maxTrackedRelays = 2, clock = { day10 })
            tracker.recordReservationAttempt(relay(1), true)
            tracker.recordReservationAttempt(relay(2), true)
            tracker.recordReservationAttempt(relay(3), true)
            tracker.countsForDay(epochDay).keys shouldBe setOf(relay(1), relay(2))
        }

        test("at most one failed circuit dial per relay and target and day is counted") {
            var now = day10
            val tracker = RelayReliabilityTracker(clock = { now })
            repeat(10) { tracker.recordDial(relay(1), relay(9), false) }
            tracker.countsForDay(epochDay)[relay(1)] shouldBe RelayReliabilityCounts(1, 0)
            // another target counts separately
            tracker.recordDial(relay(1), relay(10), false)
            tracker.countsForDay(epochDay)[relay(1)] shouldBe RelayReliabilityCounts(2, 0)
            // successes are not limited
            repeat(3) { tracker.recordDial(relay(1), relay(9), true) }
            tracker.countsForDay(epochDay)[relay(1)] shouldBe RelayReliabilityCounts(5, 3)
            // next day the pair counts again
            now = Instant.parse("1970-01-12T12:00:00Z")
            tracker.recordDial(relay(1), relay(9), false)
            tracker.countsForDay(11)[relay(1)] shouldBe RelayReliabilityCounts(1, 0)
        }

        test("the result is a copy") {
            val tracker = RelayReliabilityTracker(clock = { day10 })
            tracker.recordAttempt(relay(1), true)
            val copy = tracker.countsForDay(epochDay)
            tracker.recordAttempt(relay(1), true)
            copy[relay(1)] shouldBe RelayReliabilityCounts(1, 1)
        }
    })
