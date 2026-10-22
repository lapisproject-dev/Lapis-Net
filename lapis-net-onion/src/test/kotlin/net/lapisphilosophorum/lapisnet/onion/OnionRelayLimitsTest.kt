package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import kotlin.time.Duration.Companion.minutes

private fun createCell(relay: net.lapisphilosophorum.lapisnet.onion.fake.TestRelay): Cell =
    ClientCircuitBuilder(listOf(relay.binding), clock = FixedClock()).start()

private fun reasonOf(actions: List<RelayAction>): DestroyReason? {
    val cell = (actions.firstOrNull() as? RelayAction.SendCell)?.cell ?: return null
    return if (cell.command == CellCommand.DESTROY) DestroyBody.decode(cell.body) else null
}

private val HIGH = 1_000_000_000

class OnionRelayLimitsTest :
    FunSpec({
        test("CREATE flood per link: refused before any X25519 work") {
            val clock = FixedClock()
            val r =
                newTestRelay(
                    clock,
                    limits = OnionRelayLimits(createsPerSecondPerLink = 5, createsPerSecondTotal = HIGH),
                )
            var handshakes = 0
            r.relay.beforeHandshake = { handshakes++ }
            var refused = 0
            repeat(20) {
                if (reasonOf(r.relay.onCell(LinkId(1), createCell(r))) ==
                    DestroyReason.RESOURCE_LIMIT
                ) {
                    refused++
                }
            }
            handshakes shouldBe 5
            refused shouldBe 15
            r.relay.circuitCount shouldBe 5
            // another link has its own bucket
            reasonOf(r.relay.onCell(LinkId(2), createCell(r))) shouldBe null
            // the bucket refills with time
            clock.advanceMillis(1000)
            reasonOf(r.relay.onCell(LinkId(1), createCell(r))) shouldBe null
        }

        test("CREATE flood across many links: the global bucket bites") {
            val r = newTestRelay(limits = OnionRelayLimits(createsPerSecondPerLink = HIGH, createsPerSecondTotal = 3))
            var handshakes = 0
            r.relay.beforeHandshake = { handshakes++ }
            repeat(10) { r.relay.onCell(LinkId(it.toLong()), createCell(r)) }
            handshakes shouldBe 3
            r.relay.circuitCount shouldBe 3
        }

        test("total circuit cap") {
            val r =
                newTestRelay(
                    limits =
                        OnionRelayLimits(
                            maxCircuitsTotal = 4,
                            createsPerSecondPerLink = HIGH,
                            createsPerSecondTotal = HIGH,
                        ),
                )
            var ok = 0
            repeat(10) { if (reasonOf(r.relay.onCell(LinkId(it.toLong()), createCell(r))) == null) ok++ }
            ok shouldBe 4
            r.relay.circuitCount shouldBe 4
        }

        test("per-link circuit cap, and a refused CREATE leaves no reservation behind") {
            val r =
                newTestRelay(
                    limits =
                        OnionRelayLimits(
                            maxCircuitsPerLink = 2,
                            maxCircuitsTotal = 10,
                            createsPerSecondPerLink = HIGH,
                            createsPerSecondTotal = HIGH,
                        ),
                )
            var ok = 0
            repeat(6) { if (reasonOf(r.relay.onCell(LinkId(1), createCell(r))) == null) ok++ }
            ok shouldBe 2
            r.relay.circuitCount shouldBe 2
            // total counter was released for the refused ones, other links still have room
            repeat(2) { reasonOf(r.relay.onCell(LinkId(2), createCell(r))) shouldBe null }
            r.relay.circuitCount shouldBe 4
        }

        test("a malformed CREATE releases its reserved slot") {
            val r = newTestRelay()
            val bogus = Cell(9, CellCommand.CREATE, ByteArray(OnionConstants.BODY_SIZE))
            repeat(5) { reasonOf(r.relay.onCell(LinkId(1), bogus)) shouldBe DestroyReason.PROTOCOL }
            r.relay.circuitCount shouldBe 0
        }

        test("cell flood on one circuit closes it instead of buffering") {
            val clock = FixedClock()
            val r = newTestRelay(clock, limits = OnionRelayLimits(cellsPerSecondPerCircuit = 3))
            val builder = ClientCircuitBuilder(listOf(r.binding), clock = clock)
            val created = r.relay.onCell(LinkId(1), builder.start())
            val step = builder.onCell((created.single() as RelayAction.SendCell).cell) as BuilderStep.Built
            val drop = RelayMessage(RelayCommand.DROP, 0, ByteArray(0))
            repeat(3) {
                r.relay.onCell(
                    LinkId(1),
                    Cell(builder.firstLinkCircuitId, CellCommand.RELAY, step.circuit.wrapForward(drop)),
                ) shouldBe
                    emptyList()
            }
            r.relay.circuitCount shouldBe 1
            val actions =
                r.relay.onCell(
                    LinkId(1),
                    Cell(builder.firstLinkCircuitId, CellCommand.RELAY, step.circuit.wrapForward(drop)),
                )
            reasonOf(actions) shouldBe DestroyReason.RESOURCE_LIMIT
            r.relay.circuitCount shouldBe 0
        }

        test("sweepExpired enforces the lifetime") {
            val clock = FixedClock()
            val r = newTestRelay(clock, limits = OnionRelayLimits(circuitMaxLifetime = 10.minutes))
            r.relay.onCell(LinkId(1), createCell(r))
            clock.advanceMillis(9 * 60_000L)
            r.relay.sweepExpired() shouldBe emptyList()
            r.relay.circuitCount shouldBe 1
            clock.advanceMillis(2 * 60_000L)
            val actions = r.relay.sweepExpired()
            r.relay.circuitCount shouldBe 0
            actions.filterIsInstance<RelayAction.CircuitClosed>().single().reason shouldBe DestroyReason.FINISHED
        }

        test("onLinkClosed tears down every circuit of that link only") {
            val r =
                newTestRelay(limits = OnionRelayLimits(createsPerSecondPerLink = HIGH, createsPerSecondTotal = HIGH))
            repeat(5) { r.relay.onCell(LinkId(1), createCell(r)) }
            repeat(3) { r.relay.onCell(LinkId(2), createCell(r)) }
            r.relay.circuitCount shouldBe 8
            r.relay.onLinkClosed(LinkId(1))
            r.relay.circuitCount shouldBe 3
            r.relay.onLinkClosed(LinkId(2))
            r.relay.circuitCount shouldBe 0
        }

        test("close() tears everything down and the relay stops answering") {
            val r = newTestRelay()
            r.relay.onCell(LinkId(1), createCell(r))
            r.relay.close()
            r.relay.circuitCount shouldBe 0
            r.relay.onCell(LinkId(1), createCell(r)) shouldBe emptyList()
        }

        test("pending EXTENDs are bounded") {
            val clock = FixedClock()
            val relays = List(2) { newTestRelay(clock) }
            val r =
                newTestRelay(
                    clock,
                    limits =
                        OnionRelayLimits(
                            maxPendingExtends = 1,
                            createsPerSecondPerLink = HIGH,
                            createsPerSecondTotal = HIGH,
                        ),
                )
            var pendingSeen = 0
            var refused = 0
            repeat(3) { i ->
                val builder = ClientCircuitBuilder(listOf(r.binding, relays[1].binding), clock = clock)
                val link = LinkId(i.toLong() + 1)
                val created = r.relay.onCell(link, builder.start())
                val built = builder.onCell((created.single() as RelayAction.SendCell).cell)
                val extend = (built as BuilderStep.Send).cell
                val out = r.relay.onCell(link, extend)
                if (out.any { it is RelayAction.OpenLinkForExtend }) {
                    pendingSeen++
                } else if (reasonOf(out) ==
                    DestroyReason.RESOURCE_LIMIT
                ) {
                    refused++
                }
            }
            pendingSeen shouldBe 1
            refused shouldBe 2
        }
    })
