package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class PublicationRateGuardTest :
    FunSpec({
        test("at most maxPerWindow acquisitions per rolling window, the window edge is exclusive") {
            var now = 1_000L
            val guard = PublicationRateGuard(2, 10_000L) { now }
            guard.tryAcquire() shouldBe true
            now += 4_000
            guard.tryAcquire() shouldBe true
            guard.tryAcquire() shouldBe false
            now = 1_000L + 9_999
            guard.tryAcquire() shouldBe false
            now = 1_000L + 10_000 // the first stamp just left the window
            guard.tryAcquire() shouldBe true
            guard.tryAcquire() shouldBe false
        }

        test("nextAllowedAtMillis is now while below the limit and the oldest stamp plus window when full") {
            var now = 0L
            val guard = PublicationRateGuard(2, 60_000L) { now }
            guard.nextAllowedAtMillis() shouldBe 0L
            guard.tryAcquire()
            now = 10_000
            guard.nextAllowedAtMillis() shouldBe 10_000L
            guard.tryAcquire()
            now = 20_000
            guard.nextAllowedAtMillis() shouldBe 60_000L
            now = 60_000
            guard.nextAllowedAtMillis() shouldBe 60_000L // first stamp expired: allowed now
            guard.tryAcquire() shouldBe true
        }

        test("invalid parameters are rejected") {
            shouldThrow<IllegalArgumentException> { PublicationRateGuard(0, 1_000L) { 0L } }
            shouldThrow<IllegalArgumentException> { PublicationRateGuard(1, 0L) { 0L } }
        }
    })
