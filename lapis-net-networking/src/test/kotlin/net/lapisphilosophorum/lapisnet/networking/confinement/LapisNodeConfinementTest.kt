package net.lapisphilosophorum.lapisnet.networking.confinement

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.config.TransportKeyPolicy
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

private fun awaitTrue(
    timeout: Duration = Duration.ofSeconds(10),
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(20)
    }
    return condition()
}

/** A plain TCP listener that only counts accepted sockets (stands in for a peer outside the confined set). */
private class AcceptCounter : AutoCloseable {
    private val socket = ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())
    val accepts = AtomicInteger()
    val port: Int get() = socket.localPort

    @Volatile private var running = true
    private val worker =
        thread(isDaemon = true, name = "accept-counter") {
            socket.soTimeout = 100
            while (running) {
                try {
                    socket.accept().use { accepts.incrementAndGet() }
                } catch (e: SocketTimeoutException) {
                    // poll running
                } catch (e: java.io.IOException) {
                    if (!running) break
                }
            }
        }

    override fun close() {
        running = false
        socket.close()
        worker.join(2000)
    }
}

private fun confinedNode(confinement: ConnectionConfinement): LapisNode =
    LapisNode.create(
        DualKeyIdentity.generate(),
        transportKey = TransportKeyPolicy.EphemeralPerRun,
        mdnsEnabled = false,
        confinement = confinement,
    )

/** Wave V0.10.0-J1b: a confined node on loopback (no listener, dials only inside the allowed set). */
class LapisNodeConfinementTest :
    FunSpec({
        test("a confined node listens nowhere and starts; it refuses bootstrap dials of its own") {
            val c = ConnectionConfinement()
            val a = confinedNode(c)
            try {
                a.start()
                a.listenAddresses().shouldBeEmpty()
                a.host.network.transports
                    .sumOf { it.activeListeners } shouldBe 0
            } finally {
                a.stop()
            }
            val b = confinedNode(ConnectionConfinement())
            try {
                shouldThrow<IllegalArgumentException> { b.start(listOf(Multiaddr("/ip4/127.0.0.1/tcp/1"))) }
            } finally {
                runCatching { b.stop() }
            }
        }

        test("an allowed peer is reached; any other dial path is refused before a TCP connection exists") {
            val c = ConnectionConfinement()
            val a = confinedNode(c)
            val b = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            val stranger = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            AcceptCounter().use { counter ->
                try {
                    a.start()
                    b.start()
                    stranger.start()
                    GossipPubSub.attach(a)
                    c.setGuardPeers(setOf(b.peerId))
                    a.connect(PeerInfo(b.peerId, b.listenAddresses()))
                    a.host.network.connections
                        .map { it.secureSession().remoteId }
                        .toSet() shouldBe setOf(b.peerId)

                    // the stranger's peer id at the counting listener: whatever path is taken, nothing is accepted
                    val target = Multiaddr("/ip4/127.0.0.1/tcp/${counter.port}")
                    shouldThrow<ConnectionConfinedException> {
                        a.connect(PeerInfo(stranger.peerId, listOf(target)))
                    }
                    val viaNetwork = a.host.network.connect(stranger.peerId, target)
                    val failure = shouldThrow<ExecutionException> { viaNetwork.get(5, TimeUnit.SECONDS) }
                    generateSequence<Throwable>(failure) { it.cause }.any { it is ConnectionConfinedException } shouldBe
                        true
                    (c.refusedDials >= 2) shouldBe true
                    val viaStream = a.host.newStream<Any>(listOf("/lapis/test/1.0.0"), stranger.peerId, target)
                    shouldThrow<ExecutionException> { viaStream.stream.get(5, TimeUnit.SECONDS) }
                    // a bare bootstrap-style dial without /p2p never reaches the transport (the library needs the peer id)
                    runCatching {
                        a.host.network
                            .connect(target)
                            .get(5, TimeUnit.SECONDS)
                    }.isFailure shouldBe true
                    Thread.sleep(300)
                    counter.accepts.get() shouldBe 0

                    // the stranger can not reach A: A has no address at all
                    a.listenAddresses().shouldBeEmpty()

                    // B leaves the allowed set: its connection is closed
                    c.setGuardPeers(emptySet())
                    awaitTrue {
                        a.host.network.connections
                            .none { !it.closeFuture().isDone }
                    } shouldBe true
                    shouldThrow<ConnectionConfinedException> { a.connect(PeerInfo(b.peerId, b.listenAddresses())) }
                } finally {
                    runCatching { a.stop() }
                    runCatching { b.stop() }
                    runCatching { stranger.stop() }
                }
            }
        }

        test("the confinement handler closes an established connection from outside the allowed set") {
            // A relayed inbound connection can not be built towards a confined node (it holds no reservation), so the
            // handler is driven with a real connection between two normal nodes instead.
            val x = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            val y = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                x.start()
                y.start()
                val conn = x.connect(PeerInfo(y.peerId, y.listenAddresses()))
                val c = ConnectionConfinement()
                val handler = ConnectionConfinementHandler(c)
                handler.admits(conn) shouldBe false
                handler.handleConnection(conn)
                awaitTrue { conn.closeFuture().isDone } shouldBe true
                c.closedConnections shouldBe 1
            } finally {
                runCatching { x.stop() }
                runCatching { y.stop() }
            }
        }

        test("closeConnectionsOutside keeps allowed peers and closes the rest") {
            val x = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            val y = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            val z = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                listOf(x, y, z).forEach { it.start() }
                val toY = x.connect(PeerInfo(y.peerId, y.listenAddresses()))
                val toZ = x.connect(PeerInfo(z.peerId, z.listenAddresses()))
                x.closeConnectionsOutside(setOf(y.peerId)) shouldBe 1
                awaitTrue { toZ.closeFuture().isDone } shouldBe true
                toY.closeFuture().isDone shouldBe false
            } finally {
                listOf(x, y, z).forEach { runCatching { it.stop() } }
            }
        }

        test("under the anonymity policy GossipSub accepts and sends no PX peers and its connect callback is a no-op") {
            val params = GossipPubSub.buildGossipParams(anonymous = true)
            params.maxPeersAcceptedInPruneMsg shouldBe 0
            params.maxPeersSentInPruneMsg shouldBe 0
            // normal mode keeps the library defaults
            val normal = GossipPubSub.buildGossipParams()
            (normal.maxPeersAcceptedInPruneMsg > 0) shouldBe true
        }
    })
