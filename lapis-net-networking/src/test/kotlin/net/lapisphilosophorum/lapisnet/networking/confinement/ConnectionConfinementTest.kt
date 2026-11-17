package net.lapisphilosophorum.lapisnet.networking.confinement

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.libp2p.core.ChannelVisitor
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.P2PChannel
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.transport.Transport
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.atomic.AtomicInteger

private fun peer(): PeerId = PeerId.random()

/** Records calls; never opens a socket. */
private class RecordingTransport : Transport {
    val dials = AtomicInteger()
    val listens = AtomicInteger()
    override val activeListeners: Int get() = 0
    override val activeConnections: Int get() = 0

    override fun listenAddresses(): List<Multiaddr> = emptyList()

    override fun handles(addr: Multiaddr): Boolean = true

    override fun initialize() = Unit

    override fun close(): CompletableFuture<Unit> = CompletableFuture.completedFuture(Unit)

    override fun listen(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Unit> {
        listens.incrementAndGet()
        return CompletableFuture.completedFuture(Unit)
    }

    override fun unlisten(addr: Multiaddr): CompletableFuture<Unit> = CompletableFuture.completedFuture(Unit)

    override fun dial(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Connection> {
        dials.incrementAndGet()
        return CompletableFuture.failedFuture(IllegalStateException("not a real transport"))
    }
}

class ConnectionConfinementTest :
    FunSpec({
        test("the allowed set is the guards, plus the bootstrap peers only while allowed") {
            val c = ConnectionConfinement()
            val g = peer()
            val b = peer()
            val other = peer()
            c.isAllowed(g) shouldBe false
            c.setGuardPeers(setOf(g))
            c.setBootstrapPeers(setOf(b))
            c.isAllowed(g) shouldBe true
            // bootstrap peers start NOT allowed (fail-closed)
            c.isAllowed(b) shouldBe false
            c.setBootstrapAllowed(true)
            c.isAllowed(b) shouldBe true
            c.allowedSnapshot() shouldBe setOf(g, b)
            c.isAllowed(other) shouldBe false
            c.setBootstrapAllowed(false)
            c.isAllowed(b) shouldBe false
            c.allowedSnapshot() shouldBe setOf(g)
        }

        test("a shrinking allowed set notifies the listeners, a growing one does not") {
            val c = ConnectionConfinement()
            val calls = AtomicInteger()
            c.addShrinkListener { calls.incrementAndGet() }
            val g = peer()
            c.setGuardPeers(setOf(g))
            calls.get() shouldBe 0
            c.setBootstrapPeers(setOf(peer()))
            c.setBootstrapAllowed(true)
            calls.get() shouldBe 0
            c.setBootstrapAllowed(false)
            calls.get() shouldBe 1
            c.setGuardPeers(emptySet())
            calls.get() shouldBe 2
        }

        test("permitsDial needs /p2p, refuses /p2p-circuit and otherwise follows isAllowed") {
            val c = ConnectionConfinement()
            val g = peer()
            c.setGuardPeers(setOf(g))
            c.permitsDial(Multiaddr("/ip4/127.0.0.1/tcp/4001")) shouldBe false
            c.permitsDial(Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/$g")) shouldBe true
            c.permitsDial(Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/${peer()}")) shouldBe false
            c.permitsDial(Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/$g/p2p-circuit/p2p/$g")) shouldBe false
        }

        test("ConfiningTransport refuses a dial without touching the delegate and never listens") {
            val c = ConnectionConfinement()
            val g = peer()
            c.setGuardPeers(setOf(g))
            val delegate = RecordingTransport()
            val t = ConfiningTransport(delegate, c)
            val refused = t.dial(Multiaddr("/ip4/127.0.0.1/tcp/9/p2p/${peer()}"), ConnectionHandler { })
            val e = shouldThrow<ExecutionException> { refused.get() }
            (e.cause is ConnectionConfinedException) shouldBe true
            e.cause!!.message!! shouldNotContain "127.0.0.1"
            delegate.dials.get() shouldBe 0
            c.refusedDials shouldBe 1
            // an allowed dial reaches the delegate
            t.dial(Multiaddr("/ip4/127.0.0.1/tcp/9/p2p/$g"), ConnectionHandler { })
            delegate.dials.get() shouldBe 1
            val listen = t.listen(Multiaddr("/ip4/127.0.0.1/tcp/0"), ConnectionHandler { }, null)
            shouldThrow<ExecutionException> { listen.get() }
            delegate.listens.get() shouldBe 0
        }
    })
