package net.lapisphilosophorum.lapisnet.core.ratelimit

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration

/**
 * MINOR review-round finding (2026-09-02): [FixedWindowRateLimiter] was extracted from
 * `DmSessionManager` into this shared, PUBLIC location with two independent consumers
 * (`DmSessionManager.prekeyConsumptionRateLimiter`, `CallManager.inviteRateLimiters`) but shipped with
 * no test of its own - a later change here would silently break both consumers at once with nothing
 * to catch it. Pins every behavior [FixedWindowRateLimiter.tryAcquire]'s own body actually implements,
 * including the two specific properties that finding calls out by name: the window rolls to `now`
 * (never `+= window`), and a clock that ever runs backward relative to [FixedWindowRateLimiter]'s own
 * `windowStartMillis` permanently freezes the limiter once its window is exhausted.
 */
class FixedWindowRateLimiterTest :
    FunSpec({
        test("allows up to maxPerWindow acquisitions, then rejects the next one in the same window") {
            var now = 0L
            val limiter = FixedWindowRateLimiter(3, Duration.ofSeconds(60), clockMillis = { now })

            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe false

            // Still exhausted a moment later, well before the window elapses.
            now += 1_000
            limiter.tryAcquire() shouldBe false
        }

        test("a single-permit window rejects a second immediate acquisition") {
            var now = 0L
            val limiter = FixedWindowRateLimiter(1, Duration.ofSeconds(60), clockMillis = { now })

            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe false
        }

        test("once the window elapses, the count resets and acquisitions succeed again") {
            var now = 0L
            val window = Duration.ofSeconds(60)
            val limiter = FixedWindowRateLimiter(2, window, clockMillis = { now })

            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe false

            // Exactly at the window boundary - tryAcquire's own check is `>=`, not `>`, so this must
            // already count as elapsed.
            now = window.toMillis()
            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe false
        }

        test("one millisecond before the window boundary, the old window's exhaustion still holds") {
            var now = 0L
            val window = Duration.ofSeconds(60)
            val limiter = FixedWindowRateLimiter(1, window, clockMillis = { now })

            limiter.tryAcquire() shouldBe true
            now = window.toMillis() - 1
            limiter.tryAcquire() shouldBe false
        }

        test(
            "the window rolls to the current clock reading, not by adding fixed window increments - " +
                "a gap of several window lengths still only ever grants ONE fresh window's worth",
        ) {
            var now = 0L
            val window = Duration.ofSeconds(60)
            val limiter = FixedWindowRateLimiter(1, window, clockMillis = { now })

            limiter.tryAcquire() shouldBe true

            // Jump forward by more than three full window lengths at once - if the implementation
            // ever changed to `windowStartMillis += window.toMillis()` (repeatedly, to catch up to
            // `now`) rather than `windowStartMillis = now`, the new window's own boundary would land
            // at a DIFFERENT, earlier point than `now` itself. Observable difference: immediately
            // after this jump, exactly ONE fresh acquisition is available (the new window starts AT
            // `now`), and the window it opened is anchored to `now`, not to some multiple of the
            // original window length - the very next assertion below pins that anchor directly.
            now += window.toMillis() * 3 + 500
            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe false

            // The new window is anchored at THIS `now` (not at a `windowStartMillis += window`
            // multiple that would land earlier) - one millisecond before a full window has elapsed
            // from here, the limiter must still be exhausted.
            now += window.toMillis() - 1
            limiter.tryAcquire() shouldBe false
            now += 1
            limiter.tryAcquire() shouldBe true
        }

        test(
            "a clock that runs backward after the window is exhausted freezes the limiter permanently " +
                "- documented limitation, pinned here so a future change is a deliberate decision, " +
                "not a silent regression",
        ) {
            var now = 1_000_000L
            val window = Duration.ofSeconds(60)
            val limiter = FixedWindowRateLimiter(1, window, clockMillis = { now })

            limiter.tryAcquire() shouldBe true
            limiter.tryAcquire() shouldBe false

            // Clock moves BACKWARD relative to the limiter's own windowStartMillis (e.g. an NTP
            // correction, a VM/host clock adjustment) - `now - windowStartMillis` is then negative,
            // which never satisfies tryAcquire's own `>= window.toMillis()` reset check, so the window
            // never rolls no matter how far back the clock goes or how long this state persists.
            now -= Duration.ofDays(1).toMillis()
            limiter.tryAcquire() shouldBe false

            // Moving forward again, but still short of a full window measured from the ORIGINAL
            // windowStartMillis, stays frozen too - the reset is purely a function of the two absolute
            // timestamps, not of however much wall-clock time has actually elapsed for the caller.
            now = 1_000_000L + window.toMillis() - 1
            limiter.tryAcquire() shouldBe false

            // Only once `now` genuinely reaches windowStartMillis + window again does it recover.
            now = 1_000_000L + window.toMillis()
            limiter.tryAcquire() shouldBe true
        }

        test("independent limiter instances never share state") {
            var now = 0L
            val a = FixedWindowRateLimiter(1, Duration.ofSeconds(60), clockMillis = { now })
            val b = FixedWindowRateLimiter(1, Duration.ofSeconds(60), clockMillis = { now })

            a.tryAcquire() shouldBe true
            a.tryAcquire() shouldBe false
            // b's own budget is untouched by a's exhaustion.
            b.tryAcquire() shouldBe true
        }
    })
