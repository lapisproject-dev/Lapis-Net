package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitRef
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.HsEvent
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceStateMachine
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.ServiceCommand
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ScheduledFuture
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Hosts an onion service (receiver side, wave V0.10.0-C): drives the pure [OnionServiceStateMachine] over real circuits
 * ([OnionCircuitFactory]), publishes the signed descriptor through [publisher], and hands every accepted rendezvous to
 * [onConnection] as an [OnionRendezvousStream]. Paths come from an injected [OnionPathProvider]; there is no path
 * selection. NOT an anonymity feature: see docs/anonymity.adoc (publishing from the own node shows its IP to the gossip
 * neighbours and DHT peers together with the onion address, unless the publisher callback hands the descriptor to a
 * circuit-based publication channel, wave V0.10.0-D).
 *
 * Thread model: events arrive from link event loops and timers; every event runs through one session lock and a
 * re-entrancy-safe queue, and no circuit lock is held while that lock is taken (see [OnionClientCircuit]).
 */
@ExperimentalOnionApi
class OnionServiceHost internal constructor(
    private val serviceKey: Ed25519KeyPair,
    private val config: OnionServiceConfig,
    private val factory: OnionCircuitFactory,
    private val links: OnionLinkManager,
    private val relays: OnionRelayDescriptorIndex,
    private val paths: OnionPathProvider,
    private val publisher: (OnionServiceDescriptor) -> Unit,
    private val clock: Clock = Clock.systemUTC(),
    random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val lock = Any()
    private val machine =
        OnionServiceStateMachine(serviceKey, config, clock, random) { digest, fingerprint ->
            relays.byRelayIdDigest(digest, clock.millis() / 1000)?.onionKeyBinding?.takeIf {
                it.onionKeyFingerprint().contentEquals(fingerprint)
            }
        }
    private val circuits = HashMap<CircuitRef, OnionClientCircuit>()
    private val streams = HashMap<CircuitRef, OnionRendezvousStream>()
    private val queue = ArrayDeque<HsEvent>()
    private var draining = false
    private var stopped = false
    private var timer: ScheduledFuture<*>? = null
    private val usedRelays = HashSet<net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey>()
    private val slotRelays = HashMap<Int, net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey>()
    private val deferred = ArrayList<() -> Unit>()
    private val firstPublish = CompletableFuture<OnionServiceDescriptor>()

    /** Called for every accepted rendezvous; set [OnionRendezvousStream.onReceive] inside the callback. */
    @Volatile var onConnection: (OnionRendezvousStream) -> Unit = { it.close() }

    /** Invoked once when this host is closed (lets the owning facade drop its reference). */
    @Volatile internal var onClosed: (() -> Unit)? = null

    val address: OnionServiceAddress get() = machine.onionAddress

    /** Number of rendezvous sessions currently open. */
    fun openSessions(): Int = synchronized(lock) { streams.size }

    /**
     * Starts the service with the given introduction relays (at least `config.introPoints` of them); the future
     * completes with the first published descriptor.
     */
    fun start(introRelays: List<OnionRelayDescriptor>): CompletableFuture<OnionServiceDescriptor> {
        locked {
            check(!stopped) { "closed" }
            usedRelays += introRelays.map { it.identity }
            introRelays.take(config.introPoints).forEachIndexed { i, r -> slotRelays[i] = r.identity }
            drain {
                execute(machine.start(introRelays.map { it.onionKeyBinding }))
            }
            scheduleTick()
        }
        return firstPublish
    }

    /**
     * Re-signs the current descriptor content as a fresh version and hands it to the publisher (early republication,
     * see [ServiceDescriptorRepublisher]). Takes the session lock; must therefore never be called while holding the
     * republisher's monitor.
     *
     * @return `true` if a new version was produced, `false` if the host is stopped or not all introduction points are
     * established yet
     */
    internal fun refreshDescriptor(): Boolean =
        locked {
            if (stopped) return@locked false
            val commands = machine.refreshDescriptor()
            if (commands.isEmpty()) return@locked false
            drain { execute(commands) }
            true
        }

    /** Runs [block] under the session lock, then the deferred application callbacks OUTSIDE of it. */
    private fun <T> locked(block: () -> T): T {
        val r = synchronized(lock) { block() }
        runDeferred()
        return r
    }

    private fun runDeferred() {
        if (Thread.holdsLock(lock)) return // an outer frame of this thread flushes after it released the lock
        val tasks =
            synchronized(lock) {
                if (deferred.isEmpty()) return
                deferred.toList().also { deferred.clear() }
            }
        for (t in tasks) {
            try {
                t()
            } catch (e: RuntimeException) {
                logger.debug { "application callback failed: ${e.javaClass.simpleName}" }
            }
        }
    }

    private fun scheduleTick() {
        timer = links.schedule(1.seconds.inWholeMilliseconds) { tick() }
    }

    private fun tick() {
        locked {
            if (stopped) return@locked
            enqueue(HsEvent.Tick)
            scheduleTick()
        }
    }

    private fun feed(event: HsEvent) {
        locked {
            if (stopped) return@locked
            enqueue(event)
        }
    }

    /** Caller holds [lock]. Processes [event] and everything it triggers, re-entrancy safe. */
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
            while (queue.isNotEmpty() && !stopped) execute(machine.on(queue.removeFirst()))
        } finally {
            draining = false
        }
    }

    private fun execute(commands: List<ServiceCommand>) {
        for (c in commands) {
            when (c) {
                is ServiceCommand.BuildCircuit -> build(c)
                is ServiceCommand.SendRelay -> {
                    val circuit = circuits[c.ref]
                    if (circuit == null || !circuit.send(c.message)) queue.addLast(HsEvent.CircuitFailed(c.ref))
                }
                is ServiceCommand.Destroy -> {
                    circuits.remove(c.ref)?.close()
                    streams.remove(c.ref)?.let { stream -> deferred += { stream.networkClosed() } }
                }
                is ServiceCommand.Publish -> publish(c.descriptor)
                is ServiceCommand.NeedIntroRelay -> replaceIntro(c.slot)
                is ServiceCommand.Accepted -> accepted(c)
            }
        }
    }

    private fun build(c: ServiceCommand.BuildCircuit) {
        val now = clock.millis() / 1000
        val endpoint = relays.current(c.endpoint.relayIdentity, now)
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
        factory.build(path, config.buildTimeout, c.purpose).whenComplete { circuit, error ->
            locked {
                if (stopped) {
                    circuit?.close()
                    return@locked
                }
                if (error != null || circuit == null) {
                    enqueue(HsEvent.CircuitFailed(c.ref))
                    return@locked
                }
                circuits[c.ref] = circuit
                circuit.onInbound = { msg -> inbound(c.ref, msg) }
                circuit.onClosed = { onCircuitClosed(c.ref) }
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
        msg: net.lapisphilosophorum.lapisnet.onion.RelayMessage,
    ) {
        var stream: OnionRendezvousStream? = null
        locked {
            if (stopped) return@locked
            stream = streams[ref]
            if (stream == null) enqueue(HsEvent.RelayReceived(ref, msg))
        }
        // delivered outside the session lock: a slow application callback must not stall the service
        val s = stream
        if (s != null && msg.command == RelayCommand.RENDEZVOUS_DATA) s.deliver(msg.data)
    }

    private fun onCircuitClosed(ref: CircuitRef) {
        locked {
            if (stopped) return@locked
            circuits.remove(ref)
            val stream = streams.remove(ref)
            if (stream != null) deferred += { stream.networkClosed() } else enqueue(HsEvent.CircuitFailed(ref))
        }
    }

    private fun publish(descriptor: OnionServiceDescriptor) {
        try {
            publisher(descriptor)
        } catch (e: RuntimeException) {
            logger.debug { "descriptor publication failed: ${e.javaClass.simpleName}" }
        }
        firstPublish.complete(descriptor)
    }

    private fun replaceIntro(slot: Int) {
        val now = clock.millis() / 1000
        val snapshot = relays.snapshot(now)
        // prefer a relay never used; otherwise forget relays that no slot uses any more and retry one of them
        val inUseElsewhere = slotRelays.filterKeys { it != slot }.values.toSet()
        val candidate =
            snapshot.firstOrNull { it.identity !in usedRelays }
                ?: snapshot.firstOrNull { it.identity !in inUseElsewhere }
                ?: return
        usedRelays.retainAll(inUseElsewhere)
        usedRelays += candidate.identity
        slotRelays[slot] = candidate.identity
        execute(machine.supplyIntroRelay(slot, candidate.onionKeyBinding))
    }

    private fun accepted(c: ServiceCommand.Accepted) {
        val circuit = circuits[c.ref]
        if (circuit == null) {
            c.e2e.close()
            return
        }
        if (streams.size >= config.maxOpenSessions) {
            // bound on open sessions (pending builds are capped separately by maxConcurrentRendezvous)
            logger.debug { "open session limit reached, rendezvous dropped" }
            c.e2e.close()
            circuits.remove(c.ref)?.close()
            return
        }
        val stream = OnionRendezvousStream(circuit, c.e2e)
        streams[c.ref] = stream
        // the application callback runs outside the session lock; early messages are buffered by the stream
        deferred +=
            {
                try {
                    onConnection(stream)
                } catch (e: RuntimeException) {
                    logger.debug { "onConnection failed: ${e.javaClass.simpleName}" }
                    stream.close()
                }
            }
    }

    override fun close() {
        val toClose: List<OnionClientCircuit>
        val openStreams: List<OnionRendezvousStream>
        synchronized(lock) {
            if (stopped) return
            stopped = true
            timer?.cancel(false)
            queue.clear()
            runCatching { machine.stop() }
            toClose = circuits.values.toList()
            openStreams = streams.values.toList()
            circuits.clear()
            streams.clear()
        }
        openStreams.forEach { runCatching { it.close() } }
        toClose.forEach { runCatching { it.close() } }
        firstPublish.completeExceptionally(IllegalStateException("closed"))
        runCatching { onClosed?.invoke() }
    }
}
