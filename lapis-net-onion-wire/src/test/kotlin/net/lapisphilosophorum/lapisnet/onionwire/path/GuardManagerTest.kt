@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock

private const val DAY = 86_400L

class GuardManagerTest :
    FunSpec({
        fun candidates(n: Int = 6) = List(n) { syntheticDescriptor(expiresInSeconds = DAY - 400) }

        fun manager(
            store: GuardStateStore,
            clock: WireTestClock,
            seed: Long = 1,
            missingIsReset: Boolean = false,
            onReset: () -> Unit = {},
        ) = GuardManager(store, seededRandom(seed), clock, missingIsReset, onReset)

        test("the guards persist across a restart") {
            val store = InMemoryGuardStateStore()
            val clock = WireTestClock()
            val cands = candidates()
            val first = manager(store, clock).primaryUsable(cands) { it.first() }!!
            val again = manager(store, clock, seed = 99).primaryUsable(cands) { it.last() }!!
            again.identity shouldBe first.identity
        }

        test("a fresh guard has a lifetime between 30 and 60 days and a backup") {
            val store = InMemoryGuardStateStore()
            val clock = WireTestClock()
            val g = manager(store, clock)
            g.primaryUsable(candidates()) { it.first() }
            val s = g.snapshot()
            val life = s.primary!!.expiresAtEpochSecond - s.primary!!.chosenAtEpochSecond
            (life in 30 * DAY..60 * DAY) shouldBe true
            s.backup shouldBe s.backup
            (s.backup != null) shouldBe true
            (s.backup!!.identity != s.primary!!.identity) shouldBe true
            g.guardCount() shouldBe 2
        }

        test("two failures leave the guard, three failures within less than a day do not rotate it") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            val guard = g.primaryUsable(cands) { it.first() }!!
            g.recordFirstHopFailure(guard.identity)
            g.recordFirstHopFailure(guard.identity)
            g.snapshot().primary!!.identity shouldBe guard.identity
            clock.advanceSeconds(3600)
            g.recordFirstHopFailure(guard.identity)
            g.snapshot().primary!!.identity shouldBe guard.identity
        }

        test("three failures over at least a day rotate to the backup") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            val guard = g.primaryUsable(cands) { it.first() }!!
            val backup = g.snapshot().backup!!.identity
            g.recordFirstHopFailure(guard.identity)
            clock.advanceSeconds(DAY + 1)
            g.recordFirstHopFailure(guard.identity)
            g.recordFirstHopFailure(guard.identity)
            g.snapshot().primary!!.identity shouldBe backup
        }

        test("a success resets the failure counter") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val guard = g.primaryUsable(candidates()) { it.first() }!!
            g.recordFirstHopFailure(guard.identity)
            g.recordFirstHopFailure(guard.identity)
            g.recordFirstHopSuccess(guard.identity)
            clock.advanceSeconds(2 * DAY)
            g.recordFirstHopFailure(guard.identity)
            g.snapshot().primary!!.identity shouldBe guard.identity
        }

        test("a replacement because of a failure happens at most once per 24 hours") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            var guard = g.primaryUsable(cands) { it.first() }!!

            fun fail(id: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey) {
                g.recordFirstHopFailure(id)
                clock.advanceSeconds(DAY + 1)
                g.recordFirstHopFailure(id)
                g.recordFirstHopFailure(id)
            }
            fail(guard.identity)
            val second = g.snapshot().primary!!.identity
            (second != guard.identity) shouldBe true
            // the new primary fails out right away: still within 24 hours of the first rotation
            g.recordFirstHopFailure(second)
            clock.advanceSeconds(DAY / 2)
            g.recordFirstHopFailure(second)
            g.recordFirstHopFailure(second)
            g.snapshot().primary!!.identity shouldBe second
            // a day later the rate limit has passed
            clock.advanceSeconds(DAY)
            g.recordFirstHopFailure(second)
            (g.snapshot().primary?.identity != second) shouldBe true
        }

        test("a guard is replaced at the end of its lifetime, independent of the failure rate limit") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            g.primaryUsable(cands) { it.first() }!!
            val chosenBefore = g.snapshot().primary!!.chosenAtEpochSecond
            // both guards are past 60 days; the descriptors stay (the selector filters validity)
            clock.advanceSeconds(61 * DAY)
            g.primaryUsable(cands) { it.first() }!!
            val after = g.snapshot()
            (after.primary!!.chosenAtEpochSecond > chosenBefore) shouldBe true
            (after.primary!!.expiresAtEpochSecond > clock.millis() / 1000) shouldBe true
            after.lastFailureRotationEpochSecond shouldBe null // expiry is not a failure rotation
        }

        test("while the primary's descriptor is missing the backup is the first hop, then the primary again") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            val first = g.primaryUsable(cands) { it.first() }!!
            val backup = g.snapshot().backup!!.identity
            val without = cands.filter { it.identity != first.identity }
            g.primaryUsable(without) { it.first() }!!.identity shouldBe backup
            g.snapshot().primary!!.identity shouldBe first.identity // nothing rotated
            g.primaryUsable(cands) { it.last() }!!.identity shouldBe first.identity
        }

        test("a descriptor missing for 72 hours rotates the guard, 71 hours do not") {
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            val first = g.primaryUsable(cands) { it.first() }!!
            val without = cands.filter { it.identity != first.identity }
            g.maintain(without)
            clock.advanceSeconds(71 * 3600)
            g.maintain(without)
            g.snapshot().primary!!.identity shouldBe first.identity
            clock.advanceSeconds(2 * 3600)
            g.maintain(without)
            (g.snapshot().primary!!.identity != first.identity) shouldBe true
        }

        test("a failure at the second or third hop is not reported to the guard (only first-hop results are)") {
            // the manager only has first-hop APIs; a failure of another relay's identity changes nothing
            val clock = WireTestClock()
            val g = manager(InMemoryGuardStateStore(), clock)
            val cands = candidates()
            val guard = g.primaryUsable(cands) { it.first() }!!
            val other = cands.first { it.identity != guard.identity }
            repeat(5) { g.recordFirstHopFailure(other.identity) }
            clock.advanceSeconds(2 * DAY)
            repeat(5) { g.recordFirstHopFailure(other.identity) }
            g.snapshot().primary!!.identity shouldBe guard.identity
            g.snapshot().primary!!.consecutiveFailures shouldBe 0
        }

        test("an invalid state always resets with a callback, a missing one only when a state was expected") {
            val clock = WireTestClock()
            var resets = 0
            manager(InMemoryGuardStateStore(GuardLoad.Invalid), clock) { resets++ }.guardCount() shouldBe 0
            resets shouldBe 1
            manager(InMemoryGuardStateStore(GuardLoad.Missing), clock, missingIsReset = false) { resets++ }
            resets shouldBe 1
            manager(InMemoryGuardStateStore(GuardLoad.Missing), clock, missingIsReset = true) { resets++ }
            resets shouldBe 2
        }
    })
