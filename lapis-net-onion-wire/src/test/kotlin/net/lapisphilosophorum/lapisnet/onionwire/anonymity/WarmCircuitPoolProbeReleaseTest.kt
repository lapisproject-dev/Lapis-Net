@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestNode
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardManager
import net.lapisphilosophorum.lapisnet.onionwire.path.PathSelectionResult
import net.lapisphilosophorum.lapisnet.onionwire.path.SelectorFixture

/**
 * The warm pool selects a path (which may carry the primary probe) before it asks the governor; when
 * [CircuitBuildGovernor.tryAdmitNow] says no, the probe must go back unused, so the next real build still probes the
 * primary instead of letting the probe time out as a failure.
 */
class WarmCircuitPoolProbeReleaseTest :
    FunSpec({
        val node = WireTestNode(relay = false)
        afterSpec { node.close() }

        test("tryAdmitNow refused while the probe is due: the next select still probes the primary") {
            repeat(3) { seed ->
                val f = SelectorFixture(seed = seed.toLong())
                repeat(8) { f.add(it + 1, 1) }
                f.selector.select(null)
                val p =
                    f.guards
                        .snapshot()
                        .primary!!
                        .identity
                f.guards.recordFirstHopFailure(p)
                f.clock.advanceSeconds(GuardManager.PRIMARY_RETRY_MAX_SECONDS + 1)
                // one token: tryAdmitNow keeps a reserve for a real build and refuses
                val governor = CircuitBuildGovernor(clock = f.clock, burst = 1, ratePerMinute = 1)
                val pool = WarmCircuitPool(governor, node.wire.circuitFactory(), f.selector, f.clock, target = 1)
                try {
                    pool.maintain()
                    pool.buildsStarted() shouldBe 0L
                    val next = f.selector.select(null) as PathSelectionResult.Selected
                    next.hops.first().identity shouldBe p
                    next.probe shouldBe true
                } finally {
                    pool.close()
                }
            }
        }
    })
