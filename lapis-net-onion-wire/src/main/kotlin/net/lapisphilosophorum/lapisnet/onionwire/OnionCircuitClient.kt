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
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.OnionIntegrityException
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.RelayMessageCodec
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.time.Duration

private val logger = KotlinLogging.logger {}

/** A built circuit that can carry opaque DATA to its exit and back. Diagnostics and tests only. */
@ExperimentalOnionApi
class OnionDiagnosticCircuit internal constructor(
    private val route: ClientRoute,
) : AutoCloseable {
    /** Largest payload [send] accepts. */
    val maxPayload: Int get() = route.maxPayload()

    /** Sends [data] to the exit hop; the future completes with the exit's reply (or fails on destroy/timeout). */
    fun send(data: ByteArray): CompletableFuture<ByteArray> = route.send(data)

    override fun close() = route.close()
}

/** Client-side state of one circuit on its first link. All access is serialised by [lock]. */
internal class ClientRoute(
    private val links: OnionLinkManager,
    private val link: LinkId,
    private val builder: ClientCircuitBuilder,
    private val result: CompletableFuture<*>,
    private val onDone: (ClientRoute) -> Unit,
    private val random: SecureRandom,
) {
    private enum class State { BUILDING, BUILT, CLOSED }

    private val lock = Any()
    private var state = State.BUILDING
    private var circuit: ClientCircuit? = null
    private val replies = ArrayDeque<CompletableFuture<ByteArray>>()
    private var timeout: ScheduledFuture<*>? = null
    val circuitId: Int get() = builder.firstLinkCircuitId
    val linkId: LinkId get() = link

    @ExperimentalOnionApi
    var onBuilt: (ClientCircuit) -> Unit = {}

    fun armTimeout(handle: ScheduledFuture<*>?) = synchronized(lock) { timeout = handle }

    fun maxPayload(): Int =
        synchronized(lock) { RelayMessageCodec.maxData(circuit?.hopCount ?: throw IllegalStateException("not built")) }

    @OptIn(ExperimentalOnionApi::class)
    fun onCell(cell: Cell) =
        synchronized(lock) {
            when (state) {
                State.CLOSED -> Unit
                State.BUILDING -> building(cell)
                State.BUILT -> built(cell)
            }
        }

    @OptIn(ExperimentalOnionApi::class)
    private fun building(cell: Cell) {
        when (val step = builder.onCell(cell)) {
            is BuilderStep.Send -> links.send(link, step.cell)
            is BuilderStep.Built -> {
                circuit = step.circuit
                state = State.BUILT
                timeout?.cancel(false)
                onBuilt(step.circuit)
            }
            is BuilderStep.Failed -> {
                step.destroyCell?.let { links.send(link, it) }
                finish(IllegalStateException("circuit build failed: ${step.reason}"))
            }
            BuilderStep.Ignored -> Unit
        }
    }

    private fun built(cell: Cell) {
        val c = checkNotNull(circuit)
        when (cell.command) {
            CellCommand.DESTROY -> {
                DestroyBody.decode(cell.body)
                finish(IllegalStateException("circuit destroyed by the network"))
            }
            CellCommand.RELAY ->
                try {
                    val (origin, msg) = c.unwrapBackward(cell.body)
                    if (origin == c.hopCount && msg.command == RelayCommand.DATA) {
                        replies.removeFirstOrNull()?.complete(msg.data)
                    } else if (msg.command == RelayCommand.END) {
                        replies.removeFirstOrNull()?.completeExceptionally(IllegalStateException("stream ended"))
                    }
                } catch (e: OnionIntegrityException) {
                    destroy(DestroyReason.AUTH_FAILED)
                }
            else -> Unit
        }
    }

    fun send(data: ByteArray): CompletableFuture<ByteArray> =
        synchronized(lock) {
            val c = circuit
            if (state != State.BUILT || c == null) {
                return CompletableFuture.failedFuture(IllegalStateException("circuit not usable"))
            }
            require(data.size <= RelayMessageCodec.maxData(c.hopCount)) { "payload too large" }
            val future = CompletableFuture<ByteArray>()
            val body = c.wrapForward(RelayMessage(RelayCommand.DATA, 1, data), c.hopCount)
            replies.addLast(future)
            if (!links.send(link, Cell(circuitId, CellCommand.RELAY, body))) {
                replies.remove(future)
                finish(IllegalStateException("link lost"))
            }
            future
                .orTimeout(REPLY_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .also { f -> f.whenComplete { _, _ -> synchronized(lock) { replies.remove(future) } } }
        }

    fun timedOut() =
        synchronized(lock) {
            if (state != State.BUILDING) return@synchronized
            builder.abort()?.let { links.send(link, it) }
            finish(IllegalStateException("circuit build timed out"))
        }

    private fun destroy(reason: DestroyReason) {
        links.send(link, Cell(circuitId, CellCommand.DESTROY, DestroyBody.encode(reason, random)))
        finish(IllegalStateException("circuit destroyed locally"))
    }

    fun close() =
        synchronized(lock) {
            when (state) {
                State.CLOSED -> Unit
                State.BUILDING -> {
                    builder.abort()?.let { links.send(link, it) }
                    finish(IllegalStateException("circuit closed"))
                }
                State.BUILT -> destroy(DestroyReason.FINISHED)
            }
        }

    /** The link below the circuit is gone. */
    fun linkLost() = synchronized(lock) { if (state != State.CLOSED) finish(IllegalStateException("link lost")) }

    private fun finish(cause: Throwable) {
        if (state == State.CLOSED) return
        val wasBuilding = state == State.BUILDING
        state = State.CLOSED
        timeout?.cancel(false)
        circuit?.close()
        if (wasBuilding) builder.close()
        while (replies.isNotEmpty()) replies.removeFirst().completeExceptionally(cause)
        result.completeExceptionally(cause)
        onDone(this)
    }

    private companion object {
        const val REPLY_TIMEOUT_SECONDS = 15L
    }
}

/**
 * Builds circuits over an EXPLICITLY given path of relay descriptors and moves opaque DATA over them. There is no path
 * selection, no guard logic, no policy: this is infrastructure for tests and diagnostics (hence [ExperimentalOnionApi]),
 * NOT an anonymity feature, and no application traffic may use it.
 */
@ExperimentalOnionApi
class OnionCircuitClient internal constructor(
    private val links: OnionLinkManager,
    private val peerDirectory: PeerDirectoryGossip?,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val routes = ConcurrentHashMap<Pair<Long, Int>, ClientRoute>()

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
    ): CompletableFuture<OnionDiagnosticCircuit> {
        require(path.isNotEmpty()) { "path must not be empty" }
        val builder = ClientCircuitBuilder(path.map { it.onionKeyBinding }, random, clock)
        val result = CompletableFuture<OnionDiagnosticCircuit>()
        val first = path[0]
        val addresses = peerDirectory?.lookup(first.identity, clock.millis() / 1000)?.addresses.orEmpty()
        links.linkTo(first.peerId, addresses).whenComplete { linkId, error ->
            if (error != null || linkId == null) {
                builder.close()
                result.completeExceptionally(error ?: IllegalStateException("no link"))
                return@whenComplete
            }
            lateinit var route: ClientRoute
            route =
                ClientRoute(links, linkId, builder, result, { routes.remove(it.linkId.value to it.circuitId) }, random)
            route.onBuilt = { result.complete(OnionDiagnosticCircuit(route)) }
            val firstCell = builder.start()
            routes[linkId.value to builder.firstLinkCircuitId] = route
            route.armTimeout(links.schedule(timeout.inWholeMilliseconds) { route.timedOut() })
            if (!links.send(linkId, firstCell)) route.linkLost()
        }
        return result
    }

    override fun close() {
        routes.values.toList().forEach { it.close() }
    }
}
