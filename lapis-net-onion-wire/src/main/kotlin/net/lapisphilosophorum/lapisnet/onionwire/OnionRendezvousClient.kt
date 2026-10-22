package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDht
import net.lapisphilosophorum.lapisnet.onion.CircuitRef
import net.lapisphilosophorum.lapisnet.onion.ClientCommand
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.HsEvent
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientConfig
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientStateMachine
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.ScheduledFuture
import kotlin.time.Duration

private val logger = KotlinLogging.logger {}

/**
 * Connects to onion services (sender side, wave V0.10.0-C). Looks the descriptor up (given, local gossip index, or the
 * DHT if one is supplied), then runs a [RendezvousClientStateMachine] over real circuits built along paths from the
 * injected [OnionPathProvider]. The rendezvous point is given explicitly by the caller: choosing it well is path
 * selection, which is wave E. NOT an anonymity feature.
 */
@ExperimentalOnionApi
class OnionRendezvousClient internal constructor(
    private val factory: OnionCircuitFactory,
    private val links: OnionLinkManager,
    private val relays: OnionRelayDescriptorIndex,
    private val services: OnionServiceDescriptorIndex,
    private val dht: OnionServiceDht?,
    private val config: RendezvousClientConfig,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val sessions = CopyOnWriteArraySet<Session>()
    private val openStreams = CopyOnWriteArraySet<OnionRendezvousStream>()

    @Volatile private var closed = false

    /** Attempts in flight (leak checks). */
    fun pendingAttempts(): Int = sessions.size

    /**
     * Connects to [address] using [rendezvousPoint]. The future fails if the descriptor cannot be found or the
     * rendezvous does not complete within [timeout] (at most `config.overallTimeout`); on every failure all circuits
     * built for the attempt are destroyed.
     */
    fun connect(
        address: OnionServiceAddress,
        paths: OnionPathProvider,
        rendezvousPoint: OnionRelayDescriptor,
        descriptor: OnionServiceDescriptor? = null,
        timeout: Duration = config.overallTimeout,
    ): CompletableFuture<OnionRendezvousStream> {
        if (closed) return CompletableFuture.failedFuture(IllegalStateException("closed"))
        val now = clock.millis() / 1000
        val found =
            descriptor ?: services.current(address.serviceKey, now) ?: runCatching { dht?.resolve(address) }.getOrNull()
        if (found == null) return CompletableFuture.failedFuture(IllegalStateException("no descriptor for the address"))
        val result = CompletableFuture<OnionRendezvousStream>()
        val session = Session(address, found, rendezvousPoint, paths, result, config.copy(overallTimeout = timeout))
        sessions += session
        result.whenComplete { stream, _ ->
            sessions.remove(session)
            if (stream != null) {
                openStreams += stream
                stream.onOwnerClose { openStreams.remove(stream) }
                if (closed) stream.close()
            }
        }
        session.start()
        return result
    }

    /** Invoked on every close (lets the owning facade drop its reference; must be idempotent). */
    @Volatile internal var onClosed: (() -> Unit)? = null

    override fun close() {
        closed = true
        runCatching { onClosed?.invoke() }
        sessions.toList().forEach { it.abort() }
        openStreams.toList().forEach { runCatching { it.close() } }
    }

    private inner class Session(
        address: OnionServiceAddress,
        descriptor: OnionServiceDescriptor,
        private val rendezvousPoint: OnionRelayDescriptor,
        private val paths: OnionPathProvider,
        private val result: CompletableFuture<OnionRendezvousStream>,
        sessionConfig: RendezvousClientConfig,
    ) {
        private val lock = Any()
        private val machine =
            RendezvousClientStateMachine(
                address,
                descriptor,
                rendezvousPoint.onionKeyBinding,
                sessionConfig,
                clock,
                random,
            )
        private val circuits = HashMap<CircuitRef, OnionClientCircuit>()
        private var stream: OnionRendezvousStream? = null
        private var streamRef: CircuitRef? = null
        private val queue = ArrayDeque<HsEvent>()
        private var draining = false
        private var finished = false
        private var timer: ScheduledFuture<*>? = null
        private val buildTimeout = sessionConfig.introBuildTimeout

        fun start() {
            synchronized(lock) {
                drain { execute(machine.start()) }
                if (!finished) scheduleTick()
            }
        }

        private fun scheduleTick() {
            timer = links.schedule(1000) { tick() }
        }

        private fun tick() {
            synchronized(lock) {
                if (finished) return
                enqueue(HsEvent.Tick)
                if (!finished) scheduleTick()
            }
        }

        fun abort() {
            val toClose: List<OnionClientCircuit>
            val s: OnionRendezvousStream?
            synchronized(lock) {
                if (finished && stream == null) return
                machine.cancel() // the circuits are closed below, which is what its Destroy commands ask for
                finished = true
                timer?.cancel(false)
                queue.clear()
                s = stream
                toClose = circuits.values.toList().also { circuits.clear() }
            }
            s?.close()
            toClose.forEach { runCatching { it.close() } }
            result.completeExceptionally(IllegalStateException("client closed"))
        }

        private fun enqueue(event: HsEvent) {
            queue.addLast(event)
            drain { }
        }

        private fun drain(first: () -> Unit) {
            if (draining) {
                first()
                return
            }
            draining = true
            try {
                first()
                while (queue.isNotEmpty() && !finished) execute(machine.on(queue.removeFirst()))
            } finally {
                draining = false
            }
        }

        private fun execute(commands: List<ClientCommand>) {
            for (c in commands) {
                when (c) {
                    is ClientCommand.BuildCircuit -> build(c)
                    is ClientCommand.Send -> {
                        val circuit = circuits[c.ref]
                        if (circuit == null || !circuit.send(c.message)) queue.addLast(HsEvent.CircuitFailed(c.ref))
                    }
                    is ClientCommand.Destroy -> circuits.remove(c.ref)?.close()
                    is ClientCommand.Opened -> opened(c)
                    is ClientCommand.Failed -> failed(c)
                }
            }
        }

        private fun build(c: ClientCommand.BuildCircuit) {
            val endpoint =
                if (c.purpose == net.lapisphilosophorum.lapisnet.onion.CircuitPurpose.RENDEZVOUS_SENDER) {
                    rendezvousPoint
                } else {
                    relays.current(c.endpoint.relayIdentity, clock.millis() / 1000)
                }
            if (endpoint == null) {
                queue.addLast(HsEvent.CircuitFailed(c.ref))
                return
            }
            val path =
                try {
                    paths.pathEndingAt(endpoint, c.purpose)
                } catch (e: RuntimeException) {
                    queue.addLast(HsEvent.CircuitFailed(c.ref))
                    return
                }
            factory.build(path, buildTimeout).whenComplete { circuit, error ->
                synchronized(lock) {
                    if (finished) {
                        circuit?.close()
                        return@synchronized
                    }
                    if (error != null || circuit == null) {
                        enqueue(HsEvent.CircuitFailed(c.ref))
                        return@synchronized
                    }
                    circuits[c.ref] = circuit
                    circuit.onInbound = { msg -> inbound(c.ref, msg) }
                    circuit.onClosed = { closedByNetwork(c.ref) }
                    if (circuit.isClosed) {
                        circuits.remove(c.ref)
                        enqueue(HsEvent.CircuitFailed(c.ref))
                    } else {
                        enqueue(HsEvent.CircuitBuilt(c.ref))
                    }
                }
            }
        }

        private fun inbound(
            ref: CircuitRef,
            msg: RelayMessage,
        ) {
            synchronized(lock) {
                if (ref == streamRef) {
                    if (msg.command == RelayCommand.RENDEZVOUS_DATA) stream?.deliver(msg.data)
                } else if (!finished) {
                    enqueue(HsEvent.RelayReceived(ref, msg))
                }
            }
        }

        private fun closedByNetwork(ref: CircuitRef) {
            synchronized(lock) {
                circuits.remove(ref)
                if (ref == streamRef) {
                    stream?.networkClosed()
                } else if (!finished) {
                    enqueue(HsEvent.CircuitFailed(ref))
                }
            }
        }

        private fun opened(c: ClientCommand.Opened) {
            val circuit = circuits[c.ref]
            if (circuit == null) {
                c.e2e.close()
                finished = true
                result.completeExceptionally(IllegalStateException("rendezvous circuit lost"))
                return
            }
            val s = OnionRendezvousStream(circuit, c.e2e, random)
            stream = s
            streamRef = c.ref
            finished = true
            timer?.cancel(false)
            result.complete(s)
        }

        private fun failed(c: ClientCommand.Failed) {
            finished = true
            timer?.cancel(false)
            val toClose = circuits.values.toList()
            circuits.clear()
            toClose.forEach { runCatching { it.close() } }
            logger.debug { "rendezvous attempt failed: ${c.reason}" }
            result.completeExceptionally(IllegalStateException("rendezvous failed: ${c.reason}"))
        }
    }
}
