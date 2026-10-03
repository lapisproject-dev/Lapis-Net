package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.protocol.Ping
import io.libp2p.protocol.ProtocolHandler
import io.libp2p.transport.implementation.P2PChannelOverNetty
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.relay.HOP_PROTOCOL_ID
import net.lapisphilosophorum.lapisnet.networking.relay.HopSender
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayServerLimits
import net.lapisphilosophorum.lapisnet.networking.relay.queuedBytes
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** How long a leg may stay paused before the relay closes its circuit - short, to keep the test fast. */
private val STALL_TIMEOUT: Duration = Duration.ofSeconds(2)

/** Extra time on top of [STALL_TIMEOUT] that an exchange stuck behind the stall may take to complete. */
private const val STALL_TOLERANCE_MILLIS = 6_000L

private const val FLOOD_PROTOCOL = "/lapis-test/flood/1"
private const val SINK_PROTOCOL = "/lapis-test/sink/1"

/**
 * The flood is much larger than anything the loopback socket buffers (several MiB with autotuning)
 * plus the relay's water marks can absorb, so the receiving side not reading really does back the
 * relay's write queue up to its high water mark.
 */
private const val FLOOD_TOTAL_BYTES = 32L * 1024 * 1024
private const val FLOOD_CHUNK_BYTES = 16 * 1024

/**
 * Pumps [FLOOD_TOTAL_BYTES] into a stream in [FLOOD_CHUNK_BYTES] chunks, one at a time, and only
 * while the stream's *connection* is writable - the stream itself always reports writable (see
 * `CircuitProxyHandler`'s doc comment), so without this the sender would just park the whole flood
 * on its own heap. Stops as soon as the stream goes away.
 */
private fun pump(stream: Stream) {
    val channel: Channel = (stream as P2PChannelOverNetty).nettyChannel
    var remaining = FLOOD_TOTAL_BYTES

    fun next() {
        if (remaining <= 0 || !channel.isActive) return
        val connection = channel.parent() ?: channel
        if (!connection.isWritable) {
            channel.eventLoop().schedule({ next() }, 5, TimeUnit.MILLISECONDS)
            return
        }
        remaining -= FLOOD_CHUNK_BYTES
        channel
            .writeAndFlush(Unpooled.wrappedBuffer(ByteArray(FLOOD_CHUNK_BYTES)))
            .addListener { future -> if (future.isSuccess) next() }
    }
    // Started a moment later, not inline: a write issued from inside the protocol-activation call
    // stack can be dropped (see relayControlExecutor's doc comment in the relay module).
    channel.eventLoop().schedule({ next() }, 200, TimeUnit.MILLISECONDS)
}

/** A protocol whose *responder* floods the dialler with bytes (used to make a relay leg stall). */
private class FloodBinding :
    StrictProtocolBinding<Unit>(
        FLOOD_PROTOCOL,
        object : ProtocolHandler<Unit>(Long.MAX_VALUE, Long.MAX_VALUE) {
            override fun onStartInitiator(stream: Stream) = CompletableFuture.completedFuture(Unit)

            override fun onStartResponder(stream: Stream): CompletableFuture<Unit> {
                pump(stream)
                return CompletableFuture.completedFuture(Unit)
            }
        },
    )

/** A protocol whose *initiator* floods the responder with bytes - the mirror image of [FloodBinding]. */
private class SinkBinding :
    StrictProtocolBinding<Unit>(
        SINK_PROTOCOL,
        object : ProtocolHandler<Unit>(Long.MAX_VALUE, Long.MAX_VALUE) {
            override fun onStartInitiator(stream: Stream): CompletableFuture<Unit> {
                pump(stream)
                return CompletableFuture.completedFuture(Unit)
            }

            override fun onStartResponder(stream: Stream) = CompletableFuture.completedFuture(Unit)
        },
    )

/** A [ConnectionHandler] that records every connection (direct or relayed) its node accepts. */
private fun collecting(into: MutableList<Connection>) =
    object : ConnectionHandler {
        override fun handleConnection(conn: Connection) {
            into += conn
        }
    }

private fun closedConnectionFrom(
    accepted: List<Connection>,
    peer: PeerId,
): Boolean = accepted.toList().any { it.secureSession().remoteId == peer && it.closeFuture().isDone }

private fun relayInfo(relay: LapisNode) = PeerInfo(relay.peerId, relay.directListenAddresses())

private fun LapisNode.circuitAddressOf(): Multiaddr = listenAddresses().first { it.has(Protocol.P2PCIRCUIT) }

/** The Netty channel of the *direct* connection [node] holds to [remote] (never a relayed one). */
private fun directChannel(
    node: LapisNode,
    remote: PeerId,
): Channel {
    val connection =
        node.host.network.connections.first {
            it.secureSession().remoteId == remote && !it.remoteAddress().has(Protocol.P2PCIRCUIT)
        }
    return (connection as P2PChannelOverNetty).nettyChannel
}

/** Pings [target] through [address]; a fresh `Ping` per dial because one instance shuts its timer
 * down when its first stream closes. Returns the wall time the exchange took. */
private fun pingThrough(
    from: LapisNode,
    target: PeerId,
    address: Multiaddr,
): Duration {
    val started = Instant.now()
    Ping()
        .dial(from.host, target, address)
        .controller
        .get(STALL_TIMEOUT.toMillis() + STALL_TOLERANCE_MILLIS, TimeUnit.MILLISECONDS)
        .ping()
        .get(STALL_TIMEOUT.toMillis() + STALL_TOLERANCE_MILLIS, TimeUnit.MILLISECONDS)
    return Duration.between(started, Instant.now())
}

/** Whether [condition] held continuously for [stableFor] before [timeout] elapsed. */
private fun awaitStably(
    timeout: Duration,
    stableFor: Duration,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    var since: Instant? = null
    while (Instant.now().isBefore(deadline)) {
        if (condition()) {
            val start = since ?: Instant.now().also { since = it }
            if (!Instant.now().isBefore(start.plus(stableFor))) return true
        } else {
            since = null
        }
        Thread.sleep(20)
    }
    return false
}

private fun awaitTrue(
    timeout: Duration,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(20)
    }
    return condition()
}

/**
 * Real nodes, real TCP, no mocks: proves that **one** peer that stops reading cannot hold the
 * relay's connection-wide read pause for longer than `circuitStallTimeout`, and that closing that
 * one circuit leaves everything else on the shared connection alone.
 *
 * Why this exists: pausing a relay leg means turning off reads on a whole connection (mplex has no
 * per-stream flow control), so *every other stream* on it - other circuits, reservation renewals -
 * is blocked for as long as the pause lasts. `CircuitProxyBackpressureTest` proves the mechanism on
 * isolated channels; only a test with a real relay, a real reserved peer and a real bystander can
 * prove that the bystander's traffic actually gets through once the stall bound fires.
 *
 * Both directions of the pause are covered: the receiving peer not reading (the reserved side's
 * connection is paused), and the *sending* side's connection being paused because the reserved peer
 * stopped reading.
 */
class MultiNodeCircuitStallTest :
    FunSpec({
        val stallingRelayConfig =
            RelayConfig.relayServer(
                RelayServerLimits(
                    circuitStallTimeout = STALL_TIMEOUT,
                    circuitMaxDuration = Duration.ofMinutes(5),
                    circuitMaxBytes = 256L * 1024 * 1024,
                ),
            )

        test("a non-reading circuit peer stalls the shared relay connection for at most the stall timeout") {
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = stallingRelayConfig)
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            val acceptedByB = Collections.synchronizedList(mutableListOf<Connection>())
            var aChannelToRelay: Channel? = null
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())
                // Every node that dials a protocol must have it registered locally too.
                nodeB.host.addProtocolHandler(Ping())
                nodeC.host.addProtocolHandler(Ping())
                nodeB.host.addProtocolHandler(FloodBinding())
                nodeA.host.addProtocolHandler(FloodBinding())
                nodeB.addConnectionHandler(collecting(acceptedByB))

                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.circuitAddressOf()

                // Warm-up: C reaches B through the relay, so a healthy relayed connection exists
                // and is the bystander whose traffic must survive the stall.
                nodeC.connect(PeerInfo(nodeB.peerId, listOf(circuitToB)), Duration.ofSeconds(45))
                pingThrough(nodeC, nodeB.peerId, circuitToB)

                // A opens the flood stream and then stops reading its connection to the relay.
                nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitToB)), Duration.ofSeconds(45))
                FloodBinding().dial(nodeA.host, nodeB.peerId, circuitToB).controller.get(30, TimeUnit.SECONDS)
                val aToRelay = directChannel(nodeA, relay.peerId)
                aChannelToRelay = aToRelay
                aToRelay.config().isAutoRead = false

                // Precondition: the stall is real - the relay has paused a leg because A's side is
                // backed up. Everything below would be vacuous without it.
                awaitTrue(Duration.ofSeconds(30)) { relay.relayFlowStats.pausedLegs() > 0 } shouldBe true
                val t0 = Instant.now()
                val circuitsBefore = relay.relayCircuitCount()
                circuitsBefore shouldBe 2
                relay.relayFlowStats.stallClosures() shouldBe 0L

                // (a) Other streams on the stalled connection wait for the bound, not forever:
                //     B's reservation renewal (same connection, same direction as the paused leg) and
                //     C's ping through the relay both complete.
                val relayToA = directChannel(relay, nodeA.peerId)
                var peakQueued = 0L
                val sampleDeadline = Instant.now().plusSeconds(20)
                val renewal =
                    CompletableFuture.supplyAsync {
                        val started = Instant.now()
                        nodeB.relayClient.reserve(relayInfo(relay))
                        Duration.between(started, Instant.now())
                    }
                val bystanderPing = CompletableFuture.supplyAsync { pingThrough(nodeC, nodeB.peerId, circuitToB) }
                // While the stall lasts, sample the relay's heap footprint on A's connection.
                while (relay.relayFlowStats.stallClosures() < 1L && Instant.now().isBefore(sampleDeadline)) {
                    peakQueued = maxOf(peakQueued, queuedBytes(relayToA))
                    Thread.sleep(50)
                }
                val closedAt = Instant.now()
                val renewalTook = renewal.get(30, TimeUnit.SECONDS)
                val pingTook = bystanderPing.get(30, TimeUnit.SECONDS)
                (renewalTook.toMillis() < STALL_TIMEOUT.toMillis() + STALL_TOLERANCE_MILLIS) shouldBe true
                (pingTook.toMillis() < STALL_TIMEOUT.toMillis() + STALL_TOLERANCE_MILLIS) shouldBe true

                // Not closed early: the circuit lived for (about) the whole stall timeout. The
                // 200 ms slack covers the polling granularity of t0.
                Duration.between(t0, closedAt).toMillis() shouldBeGreaterThanOrEqual (STALL_TIMEOUT.toMillis() - 200)

                // (b) Exactly one circuit was closed, and only that one.
                relay.relayFlowStats.stallClosures() shouldBe 1L
                awaitTrue(Duration.ofSeconds(10)) { closedConnectionFrom(acceptedByB, nodeA.peerId) } shouldBe true
                val bToC = acceptedByB.first { it.secureSession().remoteId == nodeC.peerId }
                bToC.closeFuture().isDone shouldBe false
                pingThrough(nodeC, nodeB.peerId, circuitToB)
                nodeB.relayClient.holdsReservationWith(relay.peerId) shouldBe true
                awaitTrue(Duration.ofSeconds(10)) { relay.relayCircuitCount() == circuitsBefore - 1 } shouldBe true
                relay.relayFlowStats.pausedLegs() shouldBe 0

                // (c) The relay's heap stayed bounded the whole time. The write queue toward the
                //     non-reading peer sits at the 256 KiB high water mark plus whatever was already in
                //     flight when the pause took effect: the paused connection's event loop can read
                //     (up to 16 reads of up to 64 KiB) and forward before the other connection's loop
                //     has accounted those writes, so the overshoot varies from run to run (measured
                //     peaks over repeated runs: 0.35 - 1.06 MiB). The bound below is 4 MiB: roughly 4x
                //     the worst observation, yet an eighth of the 32 MiB the sender pushes - and it
                //     is what an unbounded queue would blow straight through.
                peakQueued shouldBeLessThan (4L * 1024 * 1024)
            } finally {
                runCatching { aChannelToRelay?.config()?.isAutoRead = true }
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
                runCatching { relay.stop() }
            }
        }

        test("a reserved peer that stops reading stalls the sender's relay connection for at most the stall timeout") {
            // The mirror image: here it is B (the reserved peer) that stops reading, so the paused
            // connection is A's - which also carries A's attempt to open a second circuit, to C.
            val relay = LapisNode.create(DualKeyIdentity.generate(), relayConfig = stallingRelayConfig)
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            val acceptedByB = Collections.synchronizedList(mutableListOf<Connection>())
            val acceptedByC = Collections.synchronizedList(mutableListOf<Connection>())
            var bChannelToRelay: Channel? = null
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())
                nodeB.host.addProtocolHandler(SinkBinding())
                nodeA.host.addProtocolHandler(SinkBinding())
                nodeC.host.addProtocolHandler(Ping())
                nodeA.host.addProtocolHandler(Ping())
                nodeB.addConnectionHandler(collecting(acceptedByB))
                nodeC.addConnectionHandler(collecting(acceptedByC))

                nodeB.relayClient.reserve(relayInfo(relay))
                nodeC.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.circuitAddressOf()
                val circuitToC = nodeC.circuitAddressOf()

                // A floods B through the relay while B (the receiving end) stops reading.
                val aToB = nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitToB)), Duration.ofSeconds(45))
                // The stream is opened (negotiated) BEFORE B stops reading - a stream cannot be
                // negotiated with a peer that no longer reads - and the pump starts shortly after.
                SinkBinding().dial(nodeA.host, nodeB.peerId, circuitToB).controller.get(30, TimeUnit.SECONDS)
                val bToRelay = directChannel(nodeB, relay.peerId)
                bChannelToRelay = bToRelay
                bToRelay.config().isAutoRead = false

                awaitTrue(Duration.ofSeconds(30)) { relay.relayFlowStats.pausedLegs() > 0 } shouldBe true
                val t0 = Instant.now()
                relay.relayFlowStats.stallClosures() shouldBe 0L

                // A's second circuit, to C, rides the paused connection: it can only complete once the
                // stall bound has fired - and it must complete.
                val started = Instant.now()
                nodeA.connect(PeerInfo(nodeC.peerId, listOf(circuitToC)), Duration.ofSeconds(45))
                val connectTook = Duration.between(started, Instant.now())
                (connectTook.toMillis() < STALL_TIMEOUT.toMillis() + STALL_TOLERANCE_MILLIS) shouldBe true
                pingThrough(nodeA, nodeC.peerId, circuitToC)
                Duration.between(t0, Instant.now()).toMillis() shouldBeGreaterThanOrEqual
                    (STALL_TIMEOUT.toMillis() - 200)

                relay.relayFlowStats.stallClosures() shouldBe 1L
                // Only A <-> B was closed; A <-> C is alive. Observed on A's side: B stopped reading
                // its relay connection, so it cannot see the close frame until it reads again.
                awaitTrue(Duration.ofSeconds(10)) { aToB.closeFuture().isDone } shouldBe true
                acceptedByC.first { it.secureSession().remoteId == nodeA.peerId }.closeFuture().isDone shouldBe false
                relay.relayFlowStats.pausedLegs() shouldBe 0
            } finally {
                runCatching { bChannelToRelay?.config()?.isAutoRead = true }
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
                runCatching { relay.stop() }
            }
        }

        test("a non-reader that reopens its circuit cannot keep the reserved peer's relay connection paused") {
            val budget = Duration.ofSeconds(3)
            val relay =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig =
                        RelayConfig.relayServer(
                            RelayServerLimits(
                                circuitStallTimeout = STALL_TIMEOUT,
                                connectionStallBudget = budget,
                                connectionStallBudgetWindow = Duration.ofMinutes(10),
                                // Small relative to the 2 s stall timeout: with the budget used up each
                                // reopened circuit may still pause the connection for one grace period.
                                connectionStallGrace = Duration.ofMillis(200),
                                circuitMaxDuration = Duration.ofMinutes(5),
                                circuitMaxBytes = 256L * 1024 * 1024,
                            ),
                        ),
                )
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            var aToRelay: Channel? = null
            val sampling = AtomicBoolean(true)
            val pausedSamples = AtomicLong(0)
            var sampler: Thread? = null
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeB.host.addProtocolHandler(FloodBinding())
                nodeA.host.addProtocolHandler(FloodBinding())
                nodeB.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.circuitAddressOf()

                // One attacker identity: open a circuit to B, make B flood it, stop reading, wait for
                // the relay to cut the circuit, read just long enough to reopen - five times. Without
                // the connection budget every cycle pauses B's connection for a full stall timeout
                // (about 98 % of the time at the defaults, 84 % measured with a 2 s timeout).
                val cycles = 5
                for (i in 1..cycles) {
                    if (i > 1) {
                        awaitTrue(
                            Duration.ofSeconds(20),
                        ) { relay.relayFlowStats.stallClosures() >= (i - 1).toLong() } shouldBe
                            true
                    }
                    aToRelay?.config()?.isAutoRead = true
                    Thread.sleep(150)
                    awaitTrue(Duration.ofSeconds(20)) { relay.relayFlowStats.pausedLegs() == 0 } shouldBe true
                    if (i >
                        1
                    ) {
                        awaitTrue(Duration.ofSeconds(20)) { directChannel(relay, nodeA.peerId).isWritable } shouldBe
                            true
                    }
                    nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitToB)), Duration.ofSeconds(45))
                    FloodBinding().dial(nodeA.host, nodeB.peerId, circuitToB).controller.get(30, TimeUnit.SECONDS)
                    aToRelay = directChannel(nodeA, relay.peerId)
                    aToRelay.config().isAutoRead = false
                    if (sampler == null) {
                        sampler =
                            Thread {
                                while (sampling.get()) {
                                    if (relay.relayFlowStats.pausedLegs() > 0) pausedSamples.incrementAndGet()
                                    Thread.sleep(10)
                                }
                            }.also {
                                it.isDaemon = true
                                it.start()
                            }
                    }
                    awaitTrue(Duration.ofSeconds(30)) {
                        relay.relayFlowStats.pausedLegs() > 0 || relay.relayFlowStats.stallClosures() >= i.toLong()
                    } shouldBe true
                }
                awaitTrue(Duration.ofSeconds(20)) { relay.relayFlowStats.stallClosures() >= cycles.toLong() } shouldBe
                    true
                sampling.set(false)
                sampler?.join()
                // Unbounded this is about cycles x STALL_TIMEOUT = 10 s. The budget caps the total
                // paused time of B's connection, plus sampling and scheduling slack.
                val pausedMillis = pausedSamples.get() * 10
                (pausedMillis < budget.toMillis() + 2_000L) shouldBe true
                (pausedMillis < cycles * STALL_TIMEOUT.toMillis() - 2_000L) shouldBe true
            } finally {
                sampling.set(false)
                runCatching { aToRelay?.config()?.isAutoRead = true }
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { relay.stop() }
            }
        }
        test(
            "a CONNECT from an initiator whose relay connection is not draining is refused before it reaches the target",
        ) {
            // Long stall timeout: the flood circuit must stay put for the whole test, so the relay's
            // write queue toward A stays over the high water mark for as long as A does not read.
            val relay =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    relayConfig =
                        RelayConfig.relayServer(
                            RelayServerLimits(
                                circuitStallTimeout = Duration.ofMinutes(2),
                                circuitMaxDuration = Duration.ofMinutes(5),
                                circuitMaxBytes = 256L * 1024 * 1024,
                            ),
                        ),
                )
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            val acceptedByC = Collections.synchronizedList(mutableListOf<Connection>())
            var aChannelToRelay: Channel? = null
            try {
                relay.start(bootstrapPeers = emptyList())
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())
                nodeB.host.addProtocolHandler(FloodBinding())
                nodeA.host.addProtocolHandler(FloodBinding())
                nodeC.addConnectionHandler(collecting(acceptedByC))

                nodeB.relayClient.reserve(relayInfo(relay))
                nodeC.relayClient.reserve(relayInfo(relay))
                val circuitToB = nodeB.circuitAddressOf()
                val circuitToC = nodeC.circuitAddressOf()

                // A hop control stream to the relay, negotiated NOW: a stream cannot be negotiated
                // once A stops reading. It carries the CONNECT under test later.
                val hopPromise =
                    nodeA.host.newStream<Any>(
                        listOf(HOP_PROTOCOL_ID),
                        relay.peerId,
                        *relay.directListenAddresses().toTypedArray(),
                    )
                val hopSender = hopPromise.controller.get(30, TimeUnit.SECONDS) as HopSender

                // A floods itself through the relay from B, then stops reading - the relay's write
                // queue toward A fills up and stays over the high water mark.
                nodeA.connect(PeerInfo(nodeB.peerId, listOf(circuitToB)), Duration.ofSeconds(45))
                FloodBinding().dial(nodeA.host, nodeB.peerId, circuitToB).controller.get(30, TimeUnit.SECONDS)
                val aToRelay = directChannel(nodeA, relay.peerId)
                aChannelToRelay = aToRelay
                aToRelay.config().isAutoRead = false
                val relayToA = directChannel(relay, nodeA.peerId)

                // Precondition: the relay's connection toward A really is not draining, and stays so.
                // The kernel keeps absorbing bytes for a while after Netty first reports "not
                // writable", which can flip it straight back - so wait until it has been unwritable
                // for a full second, i.e. the socket buffers toward A are saturated. Everything
                // below would be vacuous (or racy) otherwise.
                withClue("relay paused a leg") {
                    awaitTrue(Duration.ofSeconds(30)) { relay.relayFlowStats.pausedLegs() > 0 } shouldBe true
                }
                withClue("relay connection toward A stably unwritable") {
                    awaitStably(Duration.ofSeconds(60), Duration.ofSeconds(1)) { !relayToA.isWritable } shouldBe true
                }
                val circuitsBefore = relay.relayCircuitCount()
                withClue("circuits before the CONNECT") { circuitsBefore shouldBe 1 }

                // A (the not-draining initiator) asks for a circuit to C. The refusal is written
                // toward A, so A only sees it once it reads again.
                val refused = hopSender.connect(nodeC.peerId)
                // Long enough for the relay to have handled the CONNECT; the connection stays
                // unwritable the whole time because A reads nothing.
                Thread.sleep(1_000)
                withClue("relay connection toward A still unwritable") { relayToA.isWritable shouldBe false }
                aToRelay.config().isAutoRead = true

                val failure = runCatching { refused.get(30, TimeUnit.SECONDS) }.exceptionOrNull()
                withClue("the CONNECT was refused (it succeeded instead)") { (failure != null) shouldBe true }
                failure.toString() shouldContain "RESOURCE_LIMIT_EXCEEDED"

                // The target never got a STOP (so no connection from A, and the relay claimed no
                // circuit slot) - the refusal happened before anything reached C.
                Thread.sleep(500)
                withClue("C accepted no connection from A") {
                    acceptedByC.none { it.secureSession().remoteId == nodeA.peerId } shouldBe true
                }
                withClue("the relay claimed no circuit slot for the refused CONNECT") {
                    relay.relayCircuitCount() shouldBe circuitsBefore
                }
            } finally {
                runCatching { aChannelToRelay?.config()?.isAutoRead = true }
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
                runCatching { relay.stop() }
            }
        }
    })
