package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.Connection
import io.libp2p.core.PeerId
import java.time.Duration

private fun connect(vararg ips: String) = HolePunchMessage(HolePunchType.CONNECT, ips.map { publicAddress(it) })

private val sync = HolePunchMessage(HolePunchType.SYNC)

class HolePunchManagerTimingTest :
    FunSpec({
        test("B sends CONNECT, answers the reply with SYNC and dials after exactly RTT/2") {
            val h = Harness()
            val a = PeerId.random()
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.sent
                .map { it.type } shouldBe listOf(HolePunchType.CONNECT)
            h.clock.advance(300) // the round trip takes 300 ms
            h.env.wire.deliver(connect("1.1.1.1"))
            h.env.wire.sent
                .map { it.type } shouldBe listOf(HolePunchType.CONNECT, HolePunchType.SYNC)
            h.env.dials.size shouldBe 0
            h.clock.advance(149)
            h.env.dials.size shouldBe 0
            h.clock.advance(1)
            h.env.dials.size shouldBe 1
            h.env.dials[0].initiatorRole shouldBe false
            h.env.dials[0].expected shouldBe a
            h.env.registrations[0].third shouldBe false
        }

        test("A answers with CONNECT at once and dials the moment SYNC arrives, as the client") {
            val h = Harness()
            val b = PeerId.random()
            val wire = FakeWire()
            h.manager.onInboundStream(fakeConnection(b, relayed = true).connection, wire)
            wire.deliver(connect("2.2.2.2"))
            wire.sent.map { it.type } shouldBe listOf(HolePunchType.CONNECT)
            h.env.registrations.size shouldBe 0 // registered only once SYNC arrived
            h.env.dials.size shouldBe 0
            wire.deliver(sync)
            h.env.registrations[0].third shouldBe true
            h.clock.advance(0)
            h.env.dials.size shouldBe 1
            h.env.dials[0].initiatorRole shouldBe true
        }

        test("a rendezvous completes the attempt, resets the backoff and releases the relay after the grace period") {
            val h = Harness()
            val a = PeerId.random()
            val relayed = fakeConnection(a, relayed = true)
            h.manager.handleConnection(relayed.connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            val direct = fakeConnection(a, relayed = false)
            h.env.dials[0]
                .future
                .complete(direct.connection)
            h.manager.status().succeeded shouldBe 1
            h.manager.status().activeSessions shouldBe 0
            relayed.closed.isDone shouldBe false
            h.clock.advance(9_999)
            relayed.closed.isDone shouldBe false
            h.clock.advance(1)
            relayed.closed.isDone shouldBe true
            direct.closed.isDone shouldBe false
        }

        context("the direct connection is announced again once the relayed one is gone") {
            // Both peers run the grace timer; whichever closes the relayed connection first ends it for the
            // other one too. Each side must announce the direct connection exactly once, whoever closed.
            fun punched(announced: MutableList<Connection>): Triple<Harness, FakeConnection, FakeConnection> {
                val h = Harness(onRelayReplaced = { announced += it })
                val a = PeerId.random()
                val relayed = fakeConnection(a, relayed = true)
                h.manager.handleConnection(relayed.connection)
                h.env.wire.deliver(connect("1.1.1.1"))
                h.clock.advance(0)
                val direct = fakeConnection(a, relayed = false)
                h.env.dials[0]
                    .future
                    .complete(direct.connection)
                return Triple(h, relayed, direct)
            }

            test("this side closed it after the grace period: announced once") {
                val announced = mutableListOf<Connection>()
                val (h, relayed, direct) = punched(announced)
                h.clock.advance(10_000)
                relayed.closed.isDone shouldBe true
                announced.size shouldBe 0
                h.clock.advance(249)
                announced.size shouldBe 0
                h.clock.advance(1)
                announced shouldBe listOf(direct.connection)
                h.clock.advance(60_000)
                announced.size shouldBe 1
            }

            test("the peer closed it first, before this side's grace timer fires: still announced once") {
                val announced = mutableListOf<Connection>()
                val (h, relayed, direct) = punched(announced)
                h.clock.advance(9_999)
                relayed.closed.complete(Unit) // the peer's timer won the race by a hair
                h.clock.advance(1) // our timer fires and finds the connection already closed
                relayed.closed.isDone shouldBe true
                h.clock.advance(250)
                announced shouldBe listOf(direct.connection)
                h.clock.advance(60_000)
                announced.size shouldBe 1
            }

            test("the relayed connection died long before the grace period: announced once, nothing closed twice") {
                val announced = mutableListOf<Connection>()
                val (h, relayed, direct) = punched(announced)
                h.clock.advance(1_000)
                relayed.closed.complete(Unit)
                h.clock.advance(250)
                announced shouldBe listOf(direct.connection)
                h.clock.advance(60_000)
                announced.size shouldBe 1
            }

            test("a direct connection that is gone by then is not announced") {
                val announced = mutableListOf<Connection>()
                val (h, relayed, direct) = punched(announced)
                h.clock.advance(10_000)
                relayed.closed.isDone shouldBe true
                direct.closed.complete(Unit)
                h.clock.advance(60_000)
                announced.size shouldBe 0
            }

            test("a stopped manager announces nothing") {
                val announced = mutableListOf<Connection>()
                val (h, relayed, _) = punched(announced)
                h.manager.stop()
                relayed.closed.complete(Unit)
                h.clock.advance(60_000)
                announced.size shouldBe 0
            }
        }

        test("the protocol timeout ends an attempt whose peer never answers") {
            val h = Harness()
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.clock.advance(9_999)
            h.manager.status().failed shouldBe 0
            h.clock.advance(1)
            h.manager.status().failed shouldBe 1
            h.manager.status().lastFailure!! shouldContain "no CONNECT reply"
            h.env.wire.closed shouldBe true
            h.env.activeRegistrations shouldBe 0
        }

        test("the punch timeout ends an attempt whose dials never connect") {
            val h = Harness()
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            h.clock.advance(4_999)
            h.manager.status().failed shouldBe 0
            h.clock.advance(1)
            h.manager.status().failed shouldBe 1
            h.manager.status().lastFailure!! shouldContain "punch timed out"
            h.env.activeRegistrations shouldBe 0
            h.env.dials[0]
                .future.isCancelled shouldBe true
        }

        test("backoff doubles from 30 s, is capped, and gives up after maxAttemptsPerPeer") {
            val h = Harness()
            val a = PeerId.random()

            fun failOnce() {
                h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
                h.clock.advance(10_000) // protocol timeout
            }
            failOnce()
            h.manager.backoffRemainingMillis(a) shouldBe 30_000
            // inside the backoff nothing starts
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.manager.status().attemptsStarted shouldBe 1
            h.clock.advance(30_000)
            failOnce()
            h.manager.backoffRemainingMillis(a) shouldBe 60_000
            h.clock.advance(60_000)
            failOnce()
            // third failure = gave up: the long maximum backoff applies
            h.manager.backoffRemainingMillis(a) shouldBe Duration.ofMinutes(30).toMillis()
            h.manager.status().attemptsStarted shouldBe 3
            h.clock.advance(Duration.ofMinutes(29).toMillis())
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.manager.status().attemptsStarted shouldBe 3
            h.clock.advance(Duration.ofMinutes(1).toMillis())
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.manager.status().attemptsStarted shouldBe 4
        }

        test("a success clears the peer's backoff state") {
            val h = Harness()
            val a = PeerId.random()
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.clock.advance(10_000)
            h.manager.trackedPeerCount() shouldBe 1
            h.clock.advance(30_000)
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            h.env.dials[0]
                .future
                .complete(fakeConnection(a, relayed = false).connection)
            h.manager.trackedPeerCount() shouldBe 0
        }

        test("the number of tracked peers stays at the cap") {
            val h = Harness(HolePunchConfig(mode = HolePunchMode.ON, maxTrackedPeers = 5, maxConcurrentUpgrades = 1))
            repeat(20) {
                h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
                h.clock.advance(10_000)
            }
            h.manager.trackedPeerCount() shouldBe 5
        }

        test("the fifth concurrent attempt is turned away") {
            val h = Harness(HolePunchConfig(mode = HolePunchMode.ON, maxConcurrentUpgrades = 4))
            repeat(5) { h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection) }
            h.manager.status().attemptsStarted shouldBe 4
            h.manager.status().activeSessions shouldBe 4
        }

        test("exhausting the initiator permits does not block the responder role") {
            val h = Harness(HolePunchConfig(mode = HolePunchMode.ON, maxConcurrentUpgrades = 4))
            repeat(4) { h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection) }
            h.manager.onInboundStream(fakeConnection(PeerId.random(), relayed = true).connection, FakeWire())
            h.manager.status().attemptsStarted shouldBe 5
        }

        test("without an observed address there is no attempt on the wire") {
            val h = Harness(observed = emptyList())
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.env.refreshCalls shouldBe 1
            h.manager.status().failed shouldBe 1
            h.manager.status().lastFailure shouldBe "no observed address"
            h.env.wire.sent.size shouldBe 0
        }

        test("a peer offering nothing dialable fails the attempt without dialling") {
            val h = Harness()
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.env.wire.deliver(connect("10.0.0.1", "127.0.0.1"))
            h.manager.status().lastFailure shouldBe "peer offered no dialable address"
            h.env.dials.size shouldBe 0
            h.env.wire.sent
                .map { it.type } shouldBe listOf(HolePunchType.CONNECT)
        }

        test("a full role register aborts the attempt before SYNC") {
            val h = Harness()
            h.env.registryCapacity = 0
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.manager.status().lastFailure shouldBe "role registry full"
            h.env.wire.sent
                .map { it.type } shouldBe listOf(HolePunchType.CONNECT)
        }

        test("a relayed connection is only a trigger when no direct connection exists") {
            val h = Harness()
            h.env.direct = true
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.manager.status().attemptsStarted shouldBe 0
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = false).connection)
            h.manager.status().attemptsStarted shouldBe 0
        }
    })
