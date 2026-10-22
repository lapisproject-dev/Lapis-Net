package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay

class ClientCircuitBuilderFailureTest :
    FunSpec({
        fun network(n: Int = 3) = InMemoryOnionNetwork(List(n) { newTestRelay() })

        test("a tampered EXTENDED fails the build and the DESTROY cell frees all relay state") {
            val net = network()
            val builder =
                ClientCircuitBuilder(listOf(net.relays[0].binding, net.relays[1].binding), clock = FixedClock())
            val link = net.connectClient(0)
            net.filter = { t ->
                if (t.toRelay == null && t.cell.command == CellCommand.RELAY) {
                    val body = t.cell.body.copyOf()
                    body[10] = (body[10].toInt() xor 0x55).toByte()
                    listOf(Cell(t.cell.circuitId, CellCommand.RELAY, body))
                } else {
                    listOf(t.cell)
                }
            }
            var step: BuilderStep = BuilderStep.Send(builder.start())
            while (step is BuilderStep.Send) {
                net.clientSend(0, link, step.cell)
                step = builder.onCell(net.clientInbox.removeFirst())
            }
            val failed = step.shouldBeInstanceOf<BuilderStep.Failed>()
            failed.reason shouldBe DestroyReason.AUTH_FAILED
            net.relays[0].relay.circuitCount shouldBe 1
            val destroy = failed.destroyCell!!
            destroy.command shouldBe CellCommand.DESTROY
            destroy.circuitId shouldBe builder.firstLinkCircuitId
            net.clientSend(0, link, destroy)
            net.relays.forEach { it.relay.circuitCount shouldBe 0 }
        }

        test("abort mid-build returns a DESTROY that frees the relay") {
            val net = network()
            val builder =
                ClientCircuitBuilder(listOf(net.relays[0].binding, net.relays[1].binding), clock = FixedClock())
            val link = net.connectClient(0)
            net.clientSend(0, link, builder.start())
            builder.onCell(net.clientInbox.removeFirst()).shouldBeInstanceOf<BuilderStep.Send>()
            net.relays[0].relay.circuitCount shouldBe 1
            val destroy = builder.abort()!!
            net.clientSend(0, link, destroy)
            net.relays[0].relay.circuitCount shouldBe 0
            builder.abort() shouldBe null
        }

        test("a peer DESTROY yields no DESTROY cell back") {
            val net = network()
            val builder = ClientCircuitBuilder(listOf(net.relays[0].binding), clock = FixedClock())
            builder.start()
            val peerDestroy =
                Cell(builder.firstLinkCircuitId, CellCommand.DESTROY, DestroyBody.encode(DestroyReason.INTERNAL))
            val failed = builder.onCell(peerDestroy).shouldBeInstanceOf<BuilderStep.Failed>()
            failed.destroyCell shouldBe null
        }

        test("oversized link specifiers are rejected up front") {
            val net = network(2)
            shouldThrow<IllegalArgumentException> {
                ClientCircuitBuilder(
                    net.relays.map { it.binding },
                    clock = FixedClock(),
                    linkSpecifiers = listOf(ByteArray(0), ByteArray(OnionConstants.MAX_LINK_SPECIFIER + 1)),
                )
            }
        }

        test("PADDING and cells of other circuits are ignored") {
            val net = network()
            val builder = ClientCircuitBuilder(listOf(net.relays[0].binding), clock = FixedClock())
            val link = net.connectClient(0)
            val create = builder.start()
            builder.onCell(Cell(0, CellCommand.PADDING, ByteArray(OnionConstants.BODY_SIZE))) shouldBe
                BuilderStep.Ignored
            builder
                .onCell(
                    Cell(builder.firstLinkCircuitId xor 1, CellCommand.RELAY, ByteArray(OnionConstants.BODY_SIZE)),
                ) shouldBe
                BuilderStep.Ignored
            net.clientSend(0, link, create)
            builder.onCell(net.clientInbox.removeFirst()).shouldBeInstanceOf<BuilderStep.Built>()
        }

        test("close() racing a CREATE in flight leaves no circuit behind") {
            val r = newTestRelay()
            val relay = r.relay
            val builder = ClientCircuitBuilder(listOf(r.binding), clock = FixedClock())
            val create = builder.start()
            relay.beforeHandshake = { relay.close() }
            relay.onCell(LinkId(1), create) shouldBe emptyList()
            relay.circuitCount shouldBe 0
        }
    })
