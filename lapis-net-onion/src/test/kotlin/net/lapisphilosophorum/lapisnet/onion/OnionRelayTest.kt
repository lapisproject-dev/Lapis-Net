package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay

private fun data(size: Int) = RelayMessage(RelayCommand.DATA, 1, ByteArray(size) { (it * 7).toByte() })

private fun network(n: Int = 3) = InMemoryOnionNetwork(List(n) { newTestRelay() })

class OnionRelayTest :
    FunSpec({
        test("a three-hop circuit is built through CREATE, EXTEND, EXTEND") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            c.circuit.hopCount shouldBe 3
            net.relays.forEach { it.relay.circuitCount shouldBe 1 }
            net.clientInbox.isEmpty() shouldBe true
        }

        test("DATA reaches the exit and a reply comes back, for each hop as target") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            for (k in 1..3) {
                net.delivered.clear()
                val payload = data(RelayMessageCodec.maxData(k))
                net.clientSend(0, c.link, Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(payload, k)))
                net.delivered.size shouldBe 1
                val d = net.delivered.single()
                d.relayIndex shouldBe k - 1
                d.message.data.contentEquals(payload.data) shouldBe true
                // reply from that hop
                val answer = data(RelayMessageCodec.maxData(k))
                net.apply(d.relayIndex, net.relays[d.relayIndex].relay.reply(d.circuitHandle, answer))
                val (origin, got) = c.circuit.unwrapBackward(net.clientInbox.removeFirst().body)
                origin shouldBe k
                got.data.contentEquals(answer.data) shouldBe true
            }
        }

        test("END is delivered and DROP is swallowed") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            net.clientSend(
                0,
                c.link,
                Cell(
                    c.circuitId,
                    CellCommand.RELAY,
                    c.circuit.wrapForward(RelayMessage(RelayCommand.DROP, 0, ByteArray(0))),
                ),
            )
            net.delivered.isEmpty() shouldBe true
            net.clientSend(
                0,
                c.link,
                Cell(
                    c.circuitId,
                    CellCommand.RELAY,
                    c.circuit.wrapForward(RelayMessage(RelayCommand.END, 3, ByteArray(0))),
                ),
            )
            net.delivered
                .single()
                .message.command shouldBe RelayCommand.END
        }

        test("DESTROY from the client propagates forward and zeroises every relay") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            net.clientSend(
                0,
                c.link,
                Cell(c.circuitId, CellCommand.DESTROY, DestroyBody.encode(DestroyReason.FINISHED)),
            )
            net.relays.forEach { it.relay.circuitCount shouldBe 0 }
            net.closed.map { it.relayIndex }.toSet() shouldBe setOf(0, 1, 2)
        }

        test("expiry at the exit propagates DESTROY backwards to the client") {
            val clock = FixedClock()
            val net = InMemoryOnionNetwork(List(3) { newTestRelay(clock) })
            val built = net.buildCircuit(listOf(0, 1, 2), clock = clock)
            net.relays.forEach { it.relay.circuitCount shouldBe 1 }
            clock.advanceMillis(11 * 60_000L)
            net.apply(2, net.relays[2].relay.sweepExpired())
            net.relays.forEach { it.relay.circuitCount shouldBe 0 }
            net.clientInbox.removeFirst().command shouldBe CellCommand.DESTROY
            built.circuit.close()
        }

        test("a duplicated cell destroys the circuit") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            net.filter = { t -> if (t.fromRelay == null) listOf(t.cell, t.cell) else listOf(t.cell) }
            net.clientSend(0, c.link, Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(data(10))))
            net.relays.forEach { it.relay.circuitCount shouldBe 0 }
            net.clientInbox.last().command shouldBe CellCommand.DESTROY
        }

        test("reordered cells destroy the circuit") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            val first = Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(data(10)))
            val second = Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(data(10)))
            net.clientSend(0, c.link, second)
            net.relays[0].relay.circuitCount shouldBe 0
            net.clientSend(0, c.link, first)
            net.delivered.isEmpty() shouldBe true
        }

        test("a dropped cell desynchronises and destroys the circuit on the next cell") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            c.circuit.wrapForward(data(10)) // never sent
            net.clientSend(0, c.link, Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(data(10))))
            net.relays[0].relay.circuitCount shouldBe 0
        }

        test("a tampered cell destroys the circuit; downstream relays are told too") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            // tamper on the middle -> exit link
            net.filter = { t ->
                if (t.fromRelay == 1 && t.toRelay == 2 && t.cell.command == CellCommand.RELAY) {
                    val b = t.cell.body
                    b[100] = (b[100].toInt() xor 1).toByte()
                    listOf(Cell(t.cell.circuitId, CellCommand.RELAY, b))
                } else {
                    listOf(t.cell)
                }
            }
            net.clientSend(0, c.link, Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(data(10))))
            net.relays.forEach { it.relay.circuitCount shouldBe 0 }
            net.clientInbox.last().command shouldBe CellCommand.DESTROY
        }

        test("tampering on the way back is detected by the client") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1, 2))
            net.clientSend(0, c.link, Cell(c.circuitId, CellCommand.RELAY, c.circuit.wrapForward(data(10))))
            val d = net.delivered.single()
            net.filter = { t ->
                if (t.toRelay == null && t.cell.command == CellCommand.RELAY) {
                    val b = t.cell.body
                    b[3] = (b[3].toInt() xor 0x10).toByte()
                    listOf(Cell(t.cell.circuitId, CellCommand.RELAY, b))
                } else {
                    listOf(t.cell)
                }
            }
            net.apply(2, net.relays[2].relay.reply(d.circuitHandle, data(10)))
            shouldThrow<OnionIntegrityException> { c.circuit.unwrapBackward(net.clientInbox.removeFirst().body) }
        }

        test("an EXTEND to the relay itself is refused") {
            val net = network()
            val c = net.buildCircuit(listOf(0))
            val payload =
                ExtendPayload(
                    2,
                    net.relays[0].binding.relayIdDigest(),
                    ByteArray(32),
                    X25519KeyPair.generate().publicKey,
                    ByteArray(0),
                )
            val body =
                c.circuit.wrapForward(
                    RelayMessage(RelayCommand.EXTEND, 0, ExtendPayloadCodec.encode(payload)),
                    1,
                )
            net.clientSend(0, c.link, Cell(c.circuitId, CellCommand.RELAY, body))
            net.relays[0].relay.circuitCount shouldBe 0
            net.clientInbox.last().command shouldBe CellCommand.DESTROY
        }

        test("an EXTEND with the wrong hop index, and a second EXTEND, are refused") {
            val net = network()
            val c = net.buildCircuit(listOf(0))
            val bad =
                ExtendPayload(
                    3,
                    net.relays[1].binding.relayIdDigest(),
                    net.relays[1].binding.onionKeyFingerprint(),
                    X25519KeyPair.generate().publicKey,
                    ByteArray(0),
                )
            net.clientSend(
                0,
                c.link,
                Cell(
                    c.circuitId,
                    CellCommand.RELAY,
                    c.circuit.wrapForward(RelayMessage(RelayCommand.EXTEND, 0, ExtendPayloadCodec.encode(bad)), 1),
                ),
            )
            net.relays[0].relay.circuitCount shouldBe 0
        }

        test("an EXTENDED message from the client side is a protocol violation") {
            val net = network()
            val c = net.buildCircuit(listOf(0, 1))
            net.clientSend(
                0,
                c.link,
                Cell(
                    c.circuitId,
                    CellCommand.RELAY,
                    c.circuit.wrapForward(RelayMessage(RelayCommand.EXTENDED, 0, ByteArray(64)), 2),
                ),
            )
            net.relays[1].relay.circuitCount shouldBe 0
        }

        test("extending to an unknown relay fails the build cleanly") {
            val inNet = List(2) { newTestRelay() }
            val ghost = newTestRelay()
            val net = InMemoryOnionNetwork(inNet)
            val builder = ClientCircuitBuilder(listOf(inNet[0].binding, ghost.binding), clock = FixedClock())
            val link = net.connectClient(0)
            var step: BuilderStep = BuilderStep.Send(builder.start())
            while (step is BuilderStep.Send) {
                net.clientSend(0, link, step.cell)
                step = builder.onCell(net.clientInbox.removeFirst())
            }
            (step as BuilderStep.Failed).reason shouldBe DestroyReason.INTERNAL
            net.relays[0].relay.circuitCount shouldBe 0
        }

        test("the builder rejects duplicate relays, bad paths and expired bindings") {
            val a = newTestRelay()
            val b = newTestRelay()
            shouldThrow<IllegalArgumentException> {
                ClientCircuitBuilder(listOf(a.binding, b.binding, a.binding), clock = FixedClock())
            }
            shouldThrow<IllegalArgumentException> { ClientCircuitBuilder(emptyList(), clock = FixedClock()) }
            shouldThrow<IllegalArgumentException> {
                ClientCircuitBuilder(
                    List(6) { newTestRelay().binding },
                    clock = FixedClock(),
                )
            }
            val late = FixedClock(FixedClock.START_MILLIS + 3 * 86_400_000L)
            shouldThrow<IllegalArgumentException> { ClientCircuitBuilder(listOf(a.binding), clock = late) }
        }

        test("a relay refuses a binding that does not match its onion key") {
            val r = newTestRelay()
            val other = X25519KeyPair.generate()
            shouldThrow<IllegalArgumentException> { OnionRelay(r.binding, other.privateKey) }
        }

        test("a CREATE addressed to another relay is answered with DESTROY(AUTH_FAILED)") {
            val a = newTestRelay()
            val b = newTestRelay()
            val builder = ClientCircuitBuilder(listOf(a.binding))
            val actions = b.relay.onCell(LinkId(1), builder.start())
            val reply = (actions.single() as RelayAction.SendCell).cell
            reply.command shouldBe CellCommand.DESTROY
            DestroyBody.decode(reply.body) shouldBe DestroyReason.AUTH_FAILED
            b.relay.circuitCount shouldBe 0
        }

        test("a duplicate CREATE with a live circuit id does not disturb the existing circuit") {
            val a = newTestRelay()
            val builder = ClientCircuitBuilder(listOf(a.binding))
            val create = builder.start()
            a.relay.onCell(LinkId(1), create)
            val again = a.relay.onCell(LinkId(1), create)
            (again.single() as RelayAction.SendCell).cell.command shouldBe CellCommand.DESTROY
            a.relay.circuitCount shouldBe 1
        }

        test("stray cells for unknown circuits are ignored") {
            val a = newTestRelay()
            a.relay.onCell(LinkId(1), Cell(5, CellCommand.RELAY, ByteArray(OnionConstants.BODY_SIZE))) shouldBe
                emptyList()
            a.relay.onCell(LinkId(1), Cell(5, CellCommand.DESTROY, ByteArray(OnionConstants.BODY_SIZE))) shouldBe
                emptyList()
            a.relay.onCell(LinkId(1), Cell(5, CellCommand.CREATED, ByteArray(OnionConstants.BODY_SIZE))) shouldBe
                emptyList()
            a.relay.onCell(LinkId(1), Cell(0, CellCommand.PADDING, ByteArray(OnionConstants.BODY_SIZE))) shouldBe
                emptyList()
        }
    })
