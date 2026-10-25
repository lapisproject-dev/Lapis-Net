@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay

/** DROP counts against the per-circuit cell limit (wave V0.10.0-H) and produces no answer cell: no amplification. */
class OnionRelayDropRateLimitTest :
    FunSpec({
        test("with five cells per second, the sixth DROP in a second tears the circuit down with RESOURCE_LIMIT") {
            val clock = FixedClock()
            val r = newTestRelay(clock, limits = OnionRelayLimits(cellsPerSecondPerCircuit = 5))
            val builder = ClientCircuitBuilder(listOf(r.binding), clock = clock)
            val created = r.relay.onCell(LinkId(1), builder.start())
            val step = builder.onCell((created.single() as RelayAction.SendCell).cell) as BuilderStep.Built
            val drop = RelayMessage(RelayCommand.DROP, 0, ByteArray(0))

            fun send() =
                r.relay.onCell(
                    LinkId(1),
                    Cell(builder.firstLinkCircuitId, CellCommand.RELAY, step.circuit.wrapForward(drop)),
                )
            repeat(5) { send() shouldBe emptyList() } // accepted, and not one cell comes back
            val actions = send()
            actions.filterIsInstance<RelayAction.SendCell>().all { it.cell.command == CellCommand.DESTROY } shouldBe
                true
            r.relay.circuitCount shouldBe 0
        }
    })
