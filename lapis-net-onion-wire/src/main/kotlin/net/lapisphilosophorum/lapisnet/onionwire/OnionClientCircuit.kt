package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.onion.BuilderStep
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.ClientCircuit
import net.lapisphilosophorum.lapisnet.onion.ClientCircuitBuilder
import net.lapisphilosophorum.lapisnet.onion.DestroyBody
import net.lapisphilosophorum.lapisnet.onion.DestroyReason
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.OnionIntegrityException
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledFuture
import kotlin.time.Duration

private val logger = KotlinLogging.logger {}

/**
 * One client-side circuit that can carry ANY relay message in both directions (hidden-service wave V0.10.0-C);
 * the diagnostic [ClientRoute] only knows DATA. Lock discipline: the internal lock is NEVER held while a callback
 * runs (callbacks are collected and executed after it is released), so a callback that takes another lock (the
 * session lock of a host or client) can never deadlock against a thread that holds that lock and calls [send].
 */
internal class OnionClientCircuit(
    private val links: OnionLinkManager,
    private val link: LinkId,
    private val builder: ClientCircuitBuilder,
    private val random: SecureRandom,
    private val onDone: (OnionClientCircuit) -> Unit,
) {
    private enum class State { BUILDING, BUILT, CLOSED }

    private val lock = Any()
    private var state = State.BUILDING
    private var circuit: ClientCircuit? = null
    private var timeout: ScheduledFuture<*>? = null

    /** Completes when the circuit is built; fails if it could not be. */
    val built = CompletableFuture<OnionClientCircuit>()

    /** Messages from the LAST hop. */
    @Volatile var onInbound: (RelayMessage) -> Unit = {}

    /** Invoked once when a BUILT circuit goes away (destroyed, link lost, closed locally). */
    @Volatile var onClosed: () -> Unit = {}

    val circuitId: Int get() = builder.firstLinkCircuitId
    val linkId: LinkId get() = link
    val isClosed: Boolean get() = synchronized(lock) { state == State.CLOSED }

    fun armTimeout(handle: ScheduledFuture<*>?) = synchronized(lock) { timeout = handle }

    fun hopCount(): Int = synchronized(lock) { circuit?.hopCount ?: 0 }

    fun onCell(cell: Cell) {
        val post = ArrayList<() -> Unit>(2)
        synchronized(lock) {
            when (state) {
                State.CLOSED -> Unit
                State.BUILDING -> building(cell, post)
                State.BUILT -> builtCell(cell, post)
            }
        }
        post.forEach { it() }
    }

    private fun building(
        cell: Cell,
        post: MutableList<() -> Unit>,
    ) {
        when (val step = builder.onCell(cell)) {
            is BuilderStep.Send -> links.send(link, step.cell)
            is BuilderStep.Built -> {
                circuit = step.circuit
                state = State.BUILT
                timeout?.cancel(false)
                post += { built.complete(this) }
            }
            is BuilderStep.Failed -> {
                step.destroyCell?.let { links.send(link, it) }
                finish(IllegalStateException("circuit build failed: ${step.reason}"), post)
            }
            BuilderStep.Ignored -> Unit
        }
    }

    private fun builtCell(
        cell: Cell,
        post: MutableList<() -> Unit>,
    ) {
        val c = checkNotNull(circuit)
        when (cell.command) {
            CellCommand.DESTROY -> {
                DestroyBody.decode(cell.body)
                finish(IllegalStateException("circuit destroyed by the network"), post)
            }
            CellCommand.RELAY ->
                try {
                    val (origin, msg) = c.unwrapBackward(cell.body)
                    if (origin == c.hopCount) post += { onInbound(msg) }
                } catch (e: OnionIntegrityException) {
                    destroy(DestroyReason.AUTH_FAILED, post)
                }
            else -> Unit
        }
    }

    /** Sends [msg] to the last hop. `false` if the circuit is not usable or the link refused. */
    fun send(msg: RelayMessage): Boolean {
        val post = ArrayList<() -> Unit>(1)
        val ok =
            synchronized(lock) {
                val c = circuit
                if (state != State.BUILT || c == null) return@synchronized false
                val body =
                    try {
                        c.wrapForward(msg, c.hopCount)
                    } catch (e: RuntimeException) {
                        destroy(DestroyReason.INTERNAL, post)
                        return@synchronized false
                    }
                if (!links.send(link, Cell(circuitId, CellCommand.RELAY, body))) {
                    finish(IllegalStateException("link lost"), post)
                    return@synchronized false
                }
                true
            }
        post.forEach { it() }
        return ok
    }

    fun timedOut() {
        val post = ArrayList<() -> Unit>(1)
        synchronized(lock) {
            if (state != State.BUILDING) return
            builder.abort()?.let { links.send(link, it) }
            finish(IllegalStateException("circuit build timed out"), post)
        }
        post.forEach { it() }
    }

    private fun destroy(
        reason: DestroyReason,
        post: MutableList<() -> Unit>,
    ) {
        links.send(link, Cell(circuitId, CellCommand.DESTROY, DestroyBody.encode(reason, random)))
        finish(IllegalStateException("circuit destroyed locally"), post)
    }

    fun close() {
        val post = ArrayList<() -> Unit>(1)
        synchronized(lock) {
            when (state) {
                State.CLOSED -> Unit
                State.BUILDING -> {
                    builder.abort()?.let { links.send(link, it) }
                    finish(IllegalStateException("circuit closed"), post)
                }
                State.BUILT -> destroy(DestroyReason.FINISHED, post)
            }
        }
        post.forEach { it() }
    }

    /** The link below the circuit is gone. */
    fun linkLost() {
        val post = ArrayList<() -> Unit>(1)
        synchronized(lock) { if (state != State.CLOSED) finish(IllegalStateException("link lost"), post) }
        post.forEach { it() }
    }

    private fun finish(
        cause: Throwable,
        post: MutableList<() -> Unit>,
    ) {
        if (state == State.CLOSED) return
        val wasBuilding = state == State.BUILDING
        state = State.CLOSED
        timeout?.cancel(false)
        circuit?.close()
        if (wasBuilding) builder.close()
        post += {
            if (wasBuilding) built.completeExceptionally(cause) else onClosed()
            onDone(this)
        }
    }
}

/**
 * Builds [OnionClientCircuit]s over an EXPLICITLY given path of relay descriptors. Like [OnionCircuitClient] it
 * performs no path selection and no policy; the paths come from an injected [OnionPathProvider].
 */
internal class OnionCircuitFactory(
    private val links: OnionLinkManager,
    private val peerDirectory: PeerDirectoryGossip?,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val routes = ConcurrentHashMap<Pair<Long, Int>, OnionClientCircuit>()

    @Volatile private var closed = false

    init {
        links.addSink({ link, cell ->
            routes[link.value to cell.circuitId]?.let {
                it.onCell(cell)
                true
            } ?: false
        }, priority = true)
        links.addClosedSink { link -> routes.values.filter { it.linkId == link }.forEach { it.linkLost() } }
    }

    fun openRoutes(): Int = routes.size

    fun build(
        path: List<OnionRelayDescriptor>,
        timeout: Duration,
    ): CompletableFuture<OnionClientCircuit> {
        require(path.isNotEmpty()) { "path must not be empty" }
        if (closed) return CompletableFuture.failedFuture(IllegalStateException("closed"))
        val builder = ClientCircuitBuilder(path.map { it.onionKeyBinding }, random, clock)
        val result = CompletableFuture<OnionClientCircuit>()
        val first = path[0]
        val addresses = peerDirectory?.lookup(first.identity, clock.millis() / 1000)?.addresses.orEmpty()
        links.linkTo(first.peerId, addresses).whenComplete { linkId, error ->
            if (error != null || linkId == null || closed) {
                builder.close()
                result.completeExceptionally(error ?: IllegalStateException("no link"))
                return@whenComplete
            }
            lateinit var route: OnionClientCircuit
            route =
                OnionClientCircuit(links, linkId, builder, random) {
                    routes.remove(it.linkId.value to it.circuitId, it)
                }
            val firstCell = builder.start()
            routes[linkId.value to builder.firstLinkCircuitId] = route
            route.built.whenComplete { c, e -> if (e != null) result.completeExceptionally(e) else result.complete(c) }
            route.armTimeout(links.schedule(timeout.inWholeMilliseconds) { route.timedOut() })
            if (!links.send(linkId, firstCell)) route.linkLost()
        }
        return result
    }

    override fun close() {
        closed = true
        routes.values.toList().forEach { it.close() }
        logger.debug { "circuit factory closed" }
    }
}
