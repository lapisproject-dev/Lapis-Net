@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock

/**
 * The in-memory reachability fallback of [GuardManager] (fix wave "rendezvous after guard failover"): a first-hop failure
 * of the primary moves builds to the persisted backup without rotating anything; one probe per retry delay.
 */
class GuardReachabilityTest :
    FunSpec({
        val day = 86_400L

        fun candidates(n: Int = 6) = List(n) { syntheticDescriptor(expiresInSeconds = day - 400) }

        class Setup(
            val store: InMemoryGuardStateStore = InMemoryGuardStateStore(),
            val clock: WireTestClock = WireTestClock(),
            val cands: List<OnionRelayDescriptor> = candidates(),
        ) {
            val g = GuardManager(store, seededRandom(1), clock)
            val p = g.primaryUsable(cands) { it.first() }!!.identity
            val k = g.snapshot().backup!!.identity

            fun build() = g.firstHop(cands, { it.first() }, forBuild = true)!!.identity

            fun check() = g.firstHop(cands, { it.first() }, forBuild = false)!!.identity
        }

        test(
            "one first-hop failure with a valid descriptor: builds use the backup, the persisted primary is unchanged",
        ) {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            s.build() shouldBe s.k
            s.check() shouldBe s.k
            s.g.primaryUsable(s.cands) { it.first() }!!.identity shouldBe s.k
            // reload the file: primary P, backup K, the failure is counted, nothing rotated
            val reloaded = (s.store.load() as GuardLoad.Loaded).state
            reloaded.primary!!.identity shouldBe s.p
            reloaded.primary!!.consecutiveFailures shouldBe 1
            reloaded.backup!!.identity shouldBe s.k
        }

        test("after the retry delay exactly one build probes the primary; parallel builds get the backup") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            // first delay is 30 s +/- 20 %: not due after 23 s, due after 37 s
            s.clock.advanceSeconds(23)
            s.build() shouldBe s.k
            s.clock.advanceSeconds(14)
            s.build() shouldBe s.p
            repeat(5) { s.build() shouldBe s.k }
        }

        test("a successful probe returns to the primary") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            s.clock.advanceSeconds(40)
            s.build() shouldBe s.p
            s.g.recordFirstHopSuccess(s.p)
            s.g.isPrimaryMarkedUnreachable() shouldBe false
            repeat(3) { s.build() shouldBe s.p }
        }

        test("a failed probe doubles the delay up to the 10-minute cap") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            var expected = GuardManager.PRIMARY_RETRY_MIN_SECONDS
            repeat(8) {
                // within the lower jitter bound the primary is not due yet
                s.clock.advanceSeconds((expected * 0.8).toLong() - 1)
                s.build() shouldBe s.k
                s.clock.advanceSeconds((expected * 0.4).toLong() + 2)
                s.build() shouldBe s.p
                s.g.recordFirstHopFailure(s.p)
                expected = (expected * 2).coerceAtMost(GuardManager.PRIMARY_RETRY_MAX_SECONDS)
            }
            expected shouldBe GuardManager.PRIMARY_RETRY_MAX_SECONDS
        }

        test("failures of builds already under way when the mark was set do not extend the delay") {
            val s = Setup()
            repeat(5) { s.g.recordFirstHopFailure(s.p) }
            s.clock.advanceSeconds(37)
            s.build() shouldBe s.p
        }

        test("a probe that never reports counts as failed after the probe timeout") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            s.clock.advanceSeconds(40)
            s.build() shouldBe s.p
            s.clock.advanceSeconds(GuardManager.PROBE_TIMEOUT_SECONDS - 1)
            s.build() shouldBe s.k
            s.clock.advanceSeconds(2)
            // the lost probe extended the delay to 60 s +/- 20 %
            s.build() shouldBe s.k
            s.clock.advanceSeconds(73)
            s.build() shouldBe s.p
        }

        test("a probe handed back unused (no build started) is free again at once and does not extend the delay") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            s.clock.advanceSeconds(40)
            val first = s.g.firstHopWithProbe(s.cands, { it.first() }, forBuild = true)
            first.probe shouldBe true
            first.descriptor!!.identity shouldBe s.p
            s.build() shouldBe s.k // the probe is out
            s.g.releaseProbe(s.p)
            // the next build gets the probe again, without waiting for the probe timeout
            s.build() shouldBe s.p
            // and the released probe did not count as failed: well past the timeout the delay is still the first one
            s.g.releaseProbe(s.p)
            s.clock.advanceSeconds(GuardManager.PROBE_TIMEOUT_SECONDS + 1)
            s.build() shouldBe s.p
        }

        test("releaseProbe is a no-op for the backup, for a primary that is not marked and without a probe out") {
            val s = Setup()
            s.g.releaseProbe(s.p)
            s.build() shouldBe s.p
            s.g.recordFirstHopFailure(s.p)
            s.g.releaseProbe(s.p) // no probe out yet: the delay stays
            s.build() shouldBe s.k
            s.clock.advanceSeconds(40)
            s.build() shouldBe s.p
            s.g.releaseProbe(s.k)
            s.build() shouldBe s.k
            s.g.firstHopWithProbe(s.cands, { it.first() }, forBuild = true).probe shouldBe false
        }

        test("forBuild = false never takes the probe") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            s.clock.advanceSeconds(40)
            repeat(5) { s.check() shouldBe s.k }
            s.build() shouldBe s.p
        }

        test("a restart forgets the mark and starts with the primary") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            s.build() shouldBe s.k
            val again = GuardManager(s.store, seededRandom(2), s.clock)
            again.firstHop(s.cands, { it.first() }, forBuild = true)!!.identity shouldBe s.p
            again.isPrimaryMarkedUnreachable() shouldBe false
        }

        test("without a usable backup the marked primary stays the first hop") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.p)
            val withoutBackup = s.cands.filter { it.identity != s.k }
            s.g.firstHop(withoutBackup, { null }, forBuild = true)!!.identity shouldBe s.p
            s.g.firstHop(withoutBackup, { null }, forBuild = false)!!.identity shouldBe s.p
        }

        test("a failure of the backup does not mark the primary") {
            val s = Setup()
            s.g.recordFirstHopFailure(s.k)
            s.g.isPrimaryMarkedUnreachable() shouldBe false
            s.build() shouldBe s.p
        }

        test("three failures within less than a day still do not rotate the primary") {
            val s = Setup()
            repeat(3) {
                s.g.recordFirstHopFailure(s.p)
                s.clock.advanceSeconds(3600)
                s.g.maintain(s.cands) { it.first() }
            }
            s.g
                .snapshot()
                .primary!!
                .identity shouldBe s.p
            s.g
                .snapshot()
                .backup!!
                .identity shouldBe s.k
        }

        test("alternativeGuard names the other persisted guard if its descriptor is known, never a new one") {
            val s = Setup()
            s.g.alternativeGuard(s.p, s.cands)!!.identity shouldBe s.k
            s.g.alternativeGuard(s.k, s.cands)!!.identity shouldBe s.p
            s.g.alternativeGuard(s.k, s.cands.filter { it.identity != s.p }) shouldBe null
        }
    })
