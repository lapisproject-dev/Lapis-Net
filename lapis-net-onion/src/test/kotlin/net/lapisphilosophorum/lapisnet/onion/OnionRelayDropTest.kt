@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.Probe
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.security.SecureRandom

/**
 * The relay side of cover traffic (wave V0.10.0-H): a DROP addressed to a relay is discarded, answered with nothing,
 * keeps no state and does not tear down a circuit that has a role. No relay code was added for the wave; this test
 * pins the behaviour the cover scheme depends on.
 */
class OnionRelayDropTest :
    FunSpec({
        class Fx {
            val clock = FixedClock()
            val relay = newTestRelay(clock = clock)
            val net = InMemoryOnionNetwork(listOf(relay))
            val rnd = SecureRandom()

            fun probe() = Probe(net, clock)

            fun counts() =
                listOf(
                    relay.relay.circuitCount,
                    relay.relay.introPointCount,
                    relay.relay.pendingRendezvousCount,
                    relay.relay.splicedPairCount,
                )

            fun cookie() = ByteArray(HsConstants.COOKIE_SIZE).also { rnd.nextBytes(it) }
        }

        test("a DROP gets no answer, creates no state and the circuit keeps working afterwards") {
            val f = Fx()
            val p = f.probe()
            val before = f.counts()
            repeat(20) { p.send(RelayCommand.DROP, ByteArray(0)) shouldBe emptyList() }
            f.counts() shouldBe before
            p.destroyed shouldBe false
            // the layer counters are still in step: a real message works
            p.send(RelayCommand.ESTABLISH_RENDEZVOUS, f.cookie()).single().command shouldBe
                RelayCommand.RENDEZVOUS_ESTABLISHED
        }

        test("a DROP on a circuit with the introduction role does not tear it down") {
            val f = Fx()
            val p = f.probe()
            val body =
                EstablishIntroBody
                    .create(
                        Ed25519KeyPair.generate(),
                        f.relay.binding.relayIdDigest(),
                        f.clock.millis() / 1000 + 600,
                        1,
                    ).encode()
            p.send(RelayCommand.ESTABLISH_INTRO, body).single().command shouldBe RelayCommand.INTRO_ESTABLISHED
            val before = f.counts()
            repeat(10) { p.send(RelayCommand.DROP, ByteArray(0)) shouldBe emptyList() }
            f.counts() shouldBe before
            p.destroyed shouldBe false
        }

        test("a DROP on a circuit that waits as rendezvous point does not tear it down or change the table") {
            val f = Fx()
            val p = f.probe()
            p.send(RelayCommand.ESTABLISH_RENDEZVOUS, f.cookie()).single().command shouldBe
                RelayCommand.RENDEZVOUS_ESTABLISHED
            val before = f.counts()
            repeat(10) { p.send(RelayCommand.DROP, ByteArray(0)) shouldBe emptyList() }
            f.counts() shouldBe before
            p.destroyed shouldBe false
        }

        test(
            "a DROP addressed to the middle hop of a three hop circuit is discarded there and nothing reaches the exit",
        ) {
            val clock = FixedClock()
            val relays = List(3) { newTestRelay(clock = clock) }
            val net = InMemoryOnionNetwork(relays)
            val client = net.newClient(0)
            val circuit = net.buildCircuitFor(client, listOf(0, 1, 2), SecureRandom(), clock)
            val before = relays.map { it.relay.circuitCount }
            repeat(5) {
                net.clientSend(
                    0,
                    client.link,
                    Cell(
                        client.circuitId,
                        CellCommand.RELAY,
                        circuit.wrapForward(RelayMessage(RelayCommand.DROP, 0, ByteArray(0)), 2),
                    ),
                )
            }
            client.inbox.isEmpty() shouldBe true
            relays.map { it.relay.circuitCount } shouldBe before
        }
    })
