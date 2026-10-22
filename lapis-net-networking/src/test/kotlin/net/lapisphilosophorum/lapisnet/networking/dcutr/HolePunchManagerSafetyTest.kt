package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import java.net.InetAddress
import java.net.InetSocketAddress

private fun connect(vararg ips: String) = HolePunchMessage(HolePunchType.CONNECT, ips.map { publicAddress(it) })

class HolePunchManagerSafetyTest :
    FunSpec({
        test("a connection with the wrong authenticated peer id is discarded, counted and fails the attempt") {
            val h = Harness()
            val a = PeerId.random()
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            val stranger = fakeConnection(PeerId.random(), relayed = false)
            h.env.dials[0]
                .future
                .complete(stranger.connection)
            stranger.closed.isDone shouldBe true
            h.manager.status().identityMismatches shouldBe 1
            h.manager.status().failed shouldBe 1
            h.manager.status().succeeded shouldBe 0
            h.manager.status().lastFailure shouldBe "identity mismatch"
        }

        test("an accepted direct connection registered for another peer is ignored, not closed") {
            val h = Harness()
            val a = PeerId.random()
            h.env.expectedPeer = a
            val stranger = fakeConnection(PeerId.random(), relayed = false)
            h.manager.onDirectConnection(stranger.connection)
            stranger.closed.isDone shouldBe false
            h.manager.status().identityMismatches shouldBe 1
        }

        test("an outbound connection with a mismatching registry entry is neither closed nor discarded") {
            val h = Harness()
            val a = PeerId.random()
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            h.env.expectedPeer = PeerId.random()
            val outbound = fakeConnection(a, relayed = false, initiator = true)
            h.manager.onDirectConnection(outbound.connection)
            outbound.closed.isDone shouldBe false
            h.manager.status().identityMismatches shouldBe 0
            h.manager.status().succeeded shouldBe 1
        }

        test("an unrelated inbound connection with a mismatching registry entry is ignored, not closed") {
            val h = Harness()
            h.env.expectedPeer = PeerId.random()
            val inbound = fakeConnection(PeerId.random(), relayed = false, initiator = false)
            h.manager.onDirectConnection(inbound.connection)
            inbound.closed.isDone shouldBe false
        }

        test("an address refused for registration is skipped, the other target is still punched") {
            val h = Harness()
            val a = PeerId.random()
            h.env.refusedAddresses += InetSocketAddress(InetAddress.getByName("1.1.1.1"), 4001)
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.deliver(
                HolePunchMessage(
                    HolePunchType.CONNECT,
                    listOf(publicAddress("1.1.1.1"), Multiaddr("/ip6/2606:4700::1111/tcp/4001").serialize()),
                ),
            )
            h.clock.advance(0)
            h.env.dials.size shouldBe 1
            h.env.dials[0]
                .remote.address.hostAddress shouldContain ":"
        }

        test("a refused registration of every target fails the attempt") {
            val h = Harness()
            h.env.refusedAddresses += InetSocketAddress(InetAddress.getByName("1.1.1.1"), 4001)
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            h.manager.status().lastFailure shouldBe "role registry full"
        }

        test("a foreign claim on the address does not push the honest initiator into backoff") {
            val h = Harness()
            val c = PeerId.random()
            val wire = FakeWire()
            h.env.foreignAddresses += InetSocketAddress(InetAddress.getByName("2.2.2.2"), 4001)
            h.manager.onInboundStream(fakeConnection(c, relayed = true).connection, wire)
            wire.deliver(connect("2.2.2.2"))
            wire.deliver(HolePunchMessage(HolePunchType.SYNC))
            h.clock.advance(0)
            h.env.dials.size shouldBe 1
            h.clock.advance(6_000)
            h.manager.status().failed shouldBe 1
            h.manager.backoffRemainingMillis(c) shouldBe 0
        }

        test("a failure on an uncontested address still counts against the peer") {
            val h = Harness()
            val c = PeerId.random()
            val wire = FakeWire()
            h.manager.onInboundStream(fakeConnection(c, relayed = true).connection, wire)
            wire.deliver(connect("2.2.2.2"))
            wire.deliver(HolePunchMessage(HolePunchType.SYNC))
            h.clock.advance(0)
            h.clock.advance(6_000)
            h.manager.status().failed shouldBe 1
            (h.manager.backoffRemainingMillis(c) > 0) shouldBe true
        }

        test("a full role register does not push the peer into backoff") {
            val h = Harness()
            val a = PeerId.random()
            h.env.refusedAddresses += InetSocketAddress(InetAddress.getByName("1.1.1.1"), 4001)
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.manager.status().lastFailure shouldBe "role registry full"
            h.manager.backoffRemainingMillis(a) shouldBe 0
        }

        test("a connected third peer's address cannot be claimed, the owner's own address can") {
            val owner = PeerId.random()
            val attacker = PeerId.random()
            val bootstrap = fakeConnection(owner, relayed = false, address = "/ip4/5.5.5.5/tcp/4001")
            val remote = InetSocketAddress(InetAddress.getByName("5.5.5.5"), 4001)
            isClaimedByOther(listOf(bootstrap.connection), attacker, remote) shouldBe true
            isClaimedByOther(listOf(bootstrap.connection), owner, remote) shouldBe false
            isClaimedByOther(
                listOf(bootstrap.connection),
                attacker,
                InetSocketAddress(InetAddress.getByName("5.5.5.5"), 4002),
            ) shouldBe false
            bootstrap.connection.close()
            isClaimedByOther(listOf(bootstrap.connection), attacker, remote) shouldBe false
            Multiaddr("/ip4/5.5.5.5/tcp/4001") shouldBe bootstrap.connection.remoteAddress()
        }

        test("an accepted direct connection completes a waiting session") {
            val h = Harness()
            val a = PeerId.random()
            val relayed = fakeConnection(a, relayed = true)
            h.manager.handleConnection(relayed.connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            h.manager.onDirectConnection(fakeConnection(a, relayed = false).connection)
            h.manager.status().succeeded shouldBe 1
        }

        test("the responder refuses dcutr over a direct connection") {
            val h = Harness()
            val wire = FakeWire()
            h.manager.onInboundStream(fakeConnection(PeerId.random(), relayed = false).connection, wire)
            wire.closed shouldBe true
            h.manager.status().attemptsStarted shouldBe 0
            h.manager.status().rejected shouldBe 1
        }

        test("the responder refuses when a direct connection to the peer already exists") {
            val h = Harness()
            h.env.direct = true
            val wire = FakeWire()
            h.manager.onInboundStream(fakeConnection(PeerId.random(), relayed = true).connection, wire)
            wire.closed shouldBe true
        }

        test("the responder refuses a second parallel session with the same peer") {
            val h = Harness()
            val b = PeerId.random()
            val first = FakeWire()
            val second = FakeWire()
            h.manager.onInboundStream(fakeConnection(b, relayed = true).connection, first)
            h.manager.onInboundStream(fakeConnection(b, relayed = true).connection, second)
            first.closed shouldBe false
            second.closed shouldBe true
            h.manager.status().activeSessions shouldBe 1
        }

        test("the responder rate-limits a peer per window") {
            val h =
                Harness(
                    HolePunchConfig(
                        mode = HolePunchMode.ON,
                        maxResponderSessionsPerPeerPerWindow = 2,
                        maxAttemptsPerPeer = 100,
                    ),
                )
            val b = PeerId.random()

            fun open(): FakeWire {
                val w = FakeWire()
                h.manager.onInboundStream(fakeConnection(b, relayed = true).connection, w)
                h.clock.advance(10_001) // the session times out
                return w
            }
            open().closed shouldBe true // timed out, but it was accepted
            h.clock.advance(60_000)
            open()
            h.clock.advance(120_000)
            val third = FakeWire()
            h.manager.onInboundStream(fakeConnection(b, relayed = true).connection, third)
            third.closed shouldBe true
            h.manager.status().rejected shouldBe 1
        }

        test("a wrong message type from the peer fails the attempt") {
            val h = Harness()
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.env.wire.deliver(HolePunchMessage(HolePunchType.SYNC))
            h.manager.status().lastFailure!! shouldContain "unexpected message"
        }

        test("stop() mid-attempt aborts the session, releases everything and is idempotent") {
            val h = Harness()
            val a = PeerId.random()
            h.manager.handleConnection(fakeConnection(a, relayed = true).connection)
            h.env.wire.deliver(connect("1.1.1.1"))
            h.clock.advance(0)
            h.env.activeRegistrations shouldBe 1
            h.manager.stop()
            h.manager.stop()
            h.env.activeRegistrations shouldBe 0
            h.env.wire.closed shouldBe true
            h.env.dials[0]
                .future.isCancelled shouldBe true
            h.clock.closed shouldBe true
            h.manager.status().activeSessions shouldBe 0
            // after stop nothing starts any more
            h.manager.handleConnection(fakeConnection(PeerId.random(), relayed = true).connection)
            h.manager.status().attemptsStarted shouldBe 1
        }
    })
