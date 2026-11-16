@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock

/**
 * The primary guard dies while its relay descriptor is still valid for a day (production defaults: 24-hour descriptor
 * TTL, governor backoff 5 s to 5 min, 30-second deferral limit of the circuit policy). Governor and guard manager share
 * one manual clock; a build is attempted every 30 seconds (the maintenance interval), as the policy would admit it.
 *
 * "Before" models the selection of master before this wave exactly: the primary as long as its descriptor is known,
 * whatever its first-hop results (the failures are still recorded, they only counted for the 24-hour rotation).
 */
class GuardFailoverScenarioTest :
    FunSpec({
        val day = 86_400L
        val maxDeferMillis = 30_000L

        class Scenario(
            val beforeFix: Boolean,
        ) {
            val clock = WireTestClock()
            val cands: List<OnionRelayDescriptor> = List(6) { syntheticDescriptor(expiresInSeconds = day) }
            val guards = GuardManager(InMemoryGuardStateStore(), seededRandom(3), clock)
            val governor = CircuitBuildGovernor(clock)
            val p: Secp256k1PublicKey = guards.primaryUsable(cands) { it.first() }!!.identity
            val k: Secp256k1PublicKey = guards.snapshot().backup!!.identity
            var builtOverK = 0
            var failedAtP = 0
            var rateLimited = 0
            var firstBuildOverKAtSeconds: Long? = null
            val start = clock.millis()

            private fun firstHop(): Secp256k1PublicKey =
                if (beforeFix) {
                    val primary = guards.snapshot().primary!!.identity
                    if (cands.any { it.identity == primary }) primary else guards.snapshot().backup!!.identity
                } else {
                    guards.firstHop(cands, { it.first() }, forBuild = true)!!.identity
                }

            /** One build attempt as `OnionClientCircuitFactory.admitted` handles it. */
            fun attempt() {
                var waited = 0L
                while (true) {
                    when (val a = governor.admit(CircuitPurpose.INTRO, "target")) {
                        CircuitBuildGovernor.Admission.Granted -> break
                        is CircuitBuildGovernor.Admission.Delayed -> {
                            val wait = a.retryAfter.inWholeMilliseconds.coerceAtLeast(1)
                            if (waited + wait > maxDeferMillis) {
                                rateLimited++
                                return
                            }
                            waited += wait
                            clock.millis += wait
                        }
                        else -> return
                    }
                }
                val hop = firstHop()
                if (hop == p) {
                    // the dead primary: the link fails at the first hop
                    governor.onFailed(CircuitPurpose.INTRO)
                    guards.recordFirstHopFailure(p)
                    failedAtP++
                } else {
                    val handle = Any()
                    governor.onBuilt(handle, CircuitPurpose.INTRO, "target")
                    governor.onClosed(handle)
                    guards.recordFirstHopSuccess(hop)
                    builtOverK++
                    if (firstBuildOverKAtSeconds == null) firstBuildOverKAtSeconds = (clock.millis() - start) / 1000
                }
            }

            /** Several circuits fail at once when the primary dies (introduction points, publication), then one per round. */
            fun run(seconds: Long) {
                repeat(3) { attempt() }
                val end = start + seconds * 1000
                while (clock.millis() < end) {
                    clock.millis += 30_000
                    attempt()
                }
            }
        }

        test(
            "before the fix: no build over the backup while the dead primary's descriptor is valid, only RATE_LIMITED",
        ) {
            val s = Scenario(beforeFix = true)
            s.run(seconds = 2 * 3600)
            s.builtOverK shouldBe 0
            (s.rateLimited > s.failedAtP) shouldBe true
            // at most one build every five minutes reaches the governor, and it goes to the dead primary again
            (s.failedAtP <= 2 * 3600 / 300 + 10) shouldBe true
            // H2: the failures push the backoff beyond the 30-second deferral limit
            (s.governor.maxConsecutiveFailuresSeen() >= 4) shouldBe true
        }

        test("after the fix: the backup carries a build within backoffMin, the success resets the backoff") {
            val s = Scenario(beforeFix = false)
            s.run(seconds = 2 * 3600)
            (s.firstBuildOverKAtSeconds!! <= 5) shouldBe true
            // after that, every round builds (over the backup or, after a probe, never over the dead primary twice in a row)
            (s.builtOverK > 2 * 3600 / 30 - 20) shouldBe true
            // the probes towards the dead primary are spaced by the retry plan (30 s doubling to 10 min): a handful only
            (s.failedAtP <= 3 + 2 * 3600 / 480) shouldBe true
            // nothing rotated: the persisted primary is still the dead one, the backup still the backup
            s.guards
                .snapshot()
                .primary!!
                .identity shouldBe s.p
            s.guards
                .snapshot()
                .backup!!
                .identity shouldBe s.k
            s.governor.maxConsecutiveFailuresSeen() shouldBe 1
        }
    })
