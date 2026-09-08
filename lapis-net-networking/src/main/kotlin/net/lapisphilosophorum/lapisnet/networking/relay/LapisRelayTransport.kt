package net.lapisphilosophorum.lapisnet.networking.relay

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.ChannelVisitor
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.Host
import io.libp2p.core.P2PChannel
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.transport.Transport
import io.libp2p.protocol.circuit.RelayTransport
import io.libp2p.transport.ConnectionUpgrader
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

/**
 * A libp2p [Transport] for `/p2p-circuit` addresses: dials **through** a relay, and turns an
 * inbound relayed stream (accepted by [StopReceiver]) into a real, Noise-secured, muxed
 * [Connection].
 *
 * **Written here rather than reusing `io.libp2p.protocol.circuit.RelayTransport` as a whole.** That
 * class's dialling half is sound and is reused verbatim through its public
 * [RelayTransport.upgradeStream] helper - the end-to-end Noise handshake and muxer negotiation that
 * make a relayed connection exactly as confidential as a direct one, with the relay seeing only
 * ciphertext, happen in that shared helper. What is *not* reusable is its reservation half:
 * `ensureEnoughCurrentRelays` stores a freshly-allocated, entirely blank `RelayState` for every
 * relay it reserves with (no addresses, no controller, no renewal deadline), so the very next
 * `listenAddresses()` or renewal pass dereferences `null` - and its `dial` blocks the calling
 * thread on `CompletableFuture.join()` three times over, which deadlocks outright when the caller
 * is a Netty event-loop thread. Reservations are therefore driven explicitly by
 * [RelayReservationClient], and this transport stays a thin, fully asynchronous dialler.
 */
class LapisRelayTransport internal constructor(
    private val upgrader: ConnectionUpgrader,
    private val hopBinding: LapisCircuitHopBinding,
    private val clientLimits: RelayClientLimits,
) : Transport {
    @Volatile
    private var host: Host? = null

    /** Supplies this node's currently-valid `/p2p-circuit` listen addresses. Wired by
     * [RelayReservationClient]; empty until this node actually holds a reservation. */
    @Volatile
    internal var circuitAddresses: () -> List<Multiaddr> = { emptyList() }

    /** Every relayed [Connection] this transport currently owns, dialled or accepted. Tracked
     * because `io.libp2p.network.NetworkImpl` only tracks connections it created itself, so without
     * this an accepted relayed connection would survive `LapisNode.stop()` as a leaked stream. */
    private val liveConnections = CopyOnWriteArrayList<Connection>()

    internal fun setHost(host: Host) {
        this.host = host
    }

    private fun requireHost(): Host =
        host ?: throw IllegalStateException("relay transport used before its Host was set")

    override val activeListeners: Int get() = circuitAddresses().size
    override val activeConnections: Int get() = liveConnections.size

    override fun listenAddresses(): List<Multiaddr> = circuitAddresses()

    override fun handles(addr: Multiaddr): Boolean = addr.hasAny(Protocol.P2PCIRCUIT)

    override fun initialize() = Unit

    override fun close(): CompletableFuture<Unit> {
        val closing = liveConnections.map { it.close() }
        liveConnections.clear()
        return if (closing.isEmpty()) {
            CompletableFuture.completedFuture(Unit)
        } else {
            CompletableFuture.allOf(*closing.toTypedArray()).thenApply { }
        }
    }

    /**
     * Listening on a `/p2p-circuit` address is not how this node becomes relay-reachable - a
     * reservation is (see [RelayReservationClient]). Failing loudly is deliberate: silently
     * succeeding here would let a caller believe it had become reachable when nothing was reserved.
     */
    override fun listen(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Unit> =
        CompletableFuture.failedFuture(
            RelayException(
                "cannot listen on $addr directly - obtain a relay reservation with " +
                    "LapisNode.reserveRelaySlot(...) instead",
            ),
        )

    override fun unlisten(addr: Multiaddr): CompletableFuture<Unit> = CompletableFuture.completedFuture(Unit)

    /**
     * Dials `<relay addr>/p2p/<relay>/p2p-circuit/p2p/<target>`: opens a hop control stream to the
     * relay, asks it to connect us to the target, and upgrades the resulting raw byte pipe with
     * Noise + a muxer exactly like a direct TCP dial.
     *
     * Fully asynchronous end to end - no `join()` anywhere, so this is safe to invoke from a Netty
     * event-loop thread (`io.libp2p.protocol.circuit.RelayTransport.dial` is not).
     */
    override fun dial(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Connection> {
        val us = host ?: return CompletableFuture.failedFuture(IllegalStateException("relay transport has no Host"))
        val split =
            splitCircuitAddress(addr)
                ?: return CompletableFuture.failedFuture(RelayException("not a dialable circuit address: $addr"))
        val (relayAddress, target) = split
        if (target == us.peerId) {
            return CompletableFuture.failedFuture(RelayException("refusing to relay-dial ourselves"))
        }
        val timeoutMillis = clientLimits.controlTimeout.toMillis()
        // Held so a failure anywhere downstream can close the hop control stream. Without this, a
        // relay that accepts the stream and then never answers leaves it open until the whole
        // connection dies - one leaked stream per failed dial, entirely attacker-triggerable by a
        // hostile or merely broken relay.
        val hopStream = CompletableFuture<Stream>()
        return CompletableFuture
            .completedFuture(Unit)
            .thenCompose {
                val promise = hopBinding.dial(us, relayAddress)
                promise.stream.whenComplete { stream, error ->
                    if (error != null) hopStream.completeExceptionally(error) else hopStream.complete(stream)
                }
                promise.controller
            }.orTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            // thenComposeAsync, never thenCompose - see relayControlExecutor's doc comment: the
            // CONNECT written below is silently dropped if this continuation runs inline on the
            // stack that completed the hop stream's negotiation.
            .thenComposeAsync({ controller ->
                val sender =
                    controller as? HopSender ?: throw RelayException("hop protocol returned a responder controller")
                sender.connect(target).orTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            }, relayControlExecutor)
            .thenCompose { stream ->
                stream.pushHandler(
                    io.libp2p.etc.util.netty
                        .InboundTrafficLimitHandler(clientLimits.maxInboundBytesPerCircuit),
                )
                RelayTransport.upgradeStream(stream, true, upgrader, this, target, connHandler)
            }.whenComplete { connection, error ->
                if (error != null) {
                    hopStream.thenAccept { runCatching { it.close() } }
                } else if (connection != null) {
                    track(connection)
                }
            }
    }

    /**
     * Circuits accepted by the stop protocol whose end-to-end Noise handshake has not finished yet.
     * See [RelayClientLimits.maxConcurrentInboundCircuits] for why this node has to count these
     * itself rather than leaning on `ConnectionCapHandler`.
     */
    private val pendingInboundCircuits = PendingCircuitCounter(clientLimits.maxConcurrentInboundCircuits)

    /**
     * Completes the destination side of a circuit: the stop protocol already answered `OK` and
     * stripped the stream back down to raw bytes, so all that is left is the same Noise + muxer
     * upgrade the dialling side performs, after which [connHandler] sees an ordinary [Connection].
     *
     * Admission-controlled: at most [RelayClientLimits.maxConcurrentInboundCircuits] upgrades may be
     * in flight, and each has [RelayClientLimits.circuitAcceptTimeout] to finish. A relay this node
     * reserved with is still an untrusted intermediary, and offering circuits that never complete
     * their handshake is the cheapest way for it to spend this node's memory and CPU.
     */
    internal fun acceptCircuit(
        stream: Stream,
        initiator: io.libp2p.core.PeerId,
        connHandler: ConnectionHandler,
    ) {
        requireHost()
        guardInboundCircuit(
            counter = pendingInboundCircuits,
            timeout = clientLimits.circuitAcceptTimeout,
            onRejected = {
                logger.warn {
                    "refusing relayed inbound connection from $initiator - already upgrading " +
                        "${clientLimits.maxConcurrentInboundCircuits} circuits"
                }
                runCatching { stream.close() }
            },
            upgrade = { RelayTransport.upgradeStream(stream, false, upgrader, this, initiator, connHandler) },
            onSettled = { connection, error ->
                if (error != null || connection == null) {
                    logger.warn { "failed to accept relayed connection from $initiator: ${error?.message}" }
                    runCatching { stream.close() }
                } else {
                    logger.info { "accepted relayed inbound connection from $initiator" }
                    track(connection)
                }
            },
        )
    }

    private fun track(connection: Connection) {
        liveConnections += connection
        connection.closeFuture().whenComplete { _, _ -> liveConnections -= connection }
    }
}

/**
 * A plain "at most N of these at once" gauge for inbound circuits that are past the stop protocol
 * but not yet finished upgrading.
 *
 * Separate from `MAX_CONCURRENT_CONNECTIONS`/`ConnectionCapHandler` because that cap only ever
 * observes a [Connection] that already exists - i.e. one whose Noise handshake *completed*. A relay
 * that offers circuits and then stalls each handshake forever is invisible to it, so the pending
 * ones need a counter of their own.
 */
internal class PendingCircuitCounter(
    private val max: Int,
) {
    private val inFlight = AtomicInteger(0)

    /** Reserves one slot, or returns `false` when [max] are already in use. */
    fun tryAcquire(): Boolean {
        if (inFlight.incrementAndGet() > max) {
            inFlight.decrementAndGet()
            return false
        }
        return true
    }

    fun release() {
        inFlight.decrementAndGet()
    }

    fun inFlight(): Int = inFlight.get()
}

/**
 * Runs [upgrade] under [counter] and [timeout], releasing the slot exactly once - whether the
 * upgrade succeeds, fails, or never answers at all.
 *
 * Extracted from [LapisRelayTransport.acceptCircuit] so the admission rule is testable on its own:
 * proving "a hostile relay cannot force an unbounded number of hanging handshakes" needs a stalled
 * upgrade and a short timeout, neither of which a real relayed connection can be talked into.
 *
 * [onRejected] is invoked instead of [upgrade] when the counter is full; [upgrade] is then never
 * called at all, so a refused circuit costs nothing beyond closing its stream.
 */
internal fun <T> guardInboundCircuit(
    counter: PendingCircuitCounter,
    timeout: Duration,
    onRejected: () -> Unit,
    upgrade: () -> CompletableFuture<T>,
    onSettled: (T?, Throwable?) -> Unit,
) {
    if (!counter.tryAcquire()) {
        onRejected()
        return
    }
    val released = AtomicBoolean(false)
    val release = { if (released.compareAndSet(false, true)) counter.release() }
    val upgrading =
        try {
            upgrade()
        } catch (e: RuntimeException) {
            release()
            onSettled(null, e)
            return
        }
    upgrading
        .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS)
        .whenComplete { result, error ->
            release()
            onSettled(result, error)
        }
}
