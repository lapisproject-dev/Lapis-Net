@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionCircuitFactory
import net.lapisphilosophorum.lapisnet.onionwire.OnionClientCircuit
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.OnionPathSelector
import net.lapisphilosophorum.lapisnet.onionwire.path.PathConflictException
import net.lapisphilosophorum.lapisnet.onionwire.path.PathSelectionResult
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Pre-built circuits (wave V0.10.0-H), so that the first send does not show a circuit build to an observer of the guard
 * link at the moment of the send. A warm circuit serves EXACTLY ONE use ([take]); there is no reuse. At most [target]
 * circuits are kept (the governor pool is 4: warm circuits never take more than half of it), and a real build that
 * finds the pool full evicts one ([evictOne]) before it would fail.
 *
 * No dial storm: [maintain] starts at most one build, only when the governor admits it at once (the rate limit and the
 * backoff of failed builds apply), and never waits. An idle warm circuit older than [maxIdleAge] is closed (relays drop
 * idle circuits at 10 minutes; a taken circuit keeps at least `lifetime - maxIdleAge`).
 */
internal class WarmCircuitPool(
    private val governor: CircuitBuildGovernor,
    private val factory: OnionCircuitFactory,
    private val selector: OnionPathSelector,
    private val clock: Clock,
    val target: Int = WARM_TARGET,
    private val maxIdleAge: Duration = 6.minutes,
    private val buildTimeout: Duration = 15.seconds,
) : AutoCloseable {
    class Prebuilt(
        val circuit: OnionClientCircuit,
        val lastHop: OnionRelayDescriptor,
        val builtAtMillis: Long,
    )

    init {
        require(target in 0..governor.maxOpenClientCircuits / 2) { "the warm target is at most half of the pool" }
    }

    private val lock = Any()
    private val idle = ArrayList<Prebuilt>()
    private val building = AtomicBoolean(false)

    @Volatile private var closed = false
    private var buildsStarted = 0L

    fun size(): Int = synchronized(lock) { idle.count { !it.circuit.isClosed } }

    /** Builds started so far (tests, rate checks). */
    fun buildsStarted(): Long = synchronized(lock) { buildsStarted }

    /** One maintenance step: drop stale circuits, start at most one build if below target and the governor grants now. */
    fun maintain() {
        if (closed) return
        val stale = ArrayList<Prebuilt>()
        synchronized(lock) {
            val limit = clock.millis() - maxIdleAge.inWholeMilliseconds
            idle.removeAll { p ->
                val drop = p.circuit.isClosed || p.builtAtMillis <= limit
                if (drop && !p.circuit.isClosed) stale += p
                drop
            }
        }
        stale.forEach { runCatching { it.circuit.close() } }
        if (target == 0 || governor.isLocked()) return
        if (synchronized(lock) { idle.size } >= target) return
        if (!building.compareAndSet(false, true)) return
        var started = false
        try {
            val endpoint = selector.selectEndpoint(emptySet()) ?: return
            val path =
                try {
                    (selector.select(endpoint, lastHopChosenRemotely = false) as? PathSelectionResult.Selected)?.hops
                } catch (e: PathConflictException) {
                    null
                } ?: return
            val key =
                endpoint.identity.bytes
                    .joinToString("") { "%02x".format(it) }
            // answered by onBuilt/onFailed inside the factory
            if (!governor.tryAdmitNow(null, key)) return
            started = true
            synchronized(lock) { buildsStarted++ }
            factory.buildGranted(path, buildTimeout).whenComplete { circuit, error ->
                try {
                    if (error != null || circuit == null) {
                        logger.debug { "warm circuit build failed" }
                    } else if (closed || circuit.isClosed) {
                        runCatching { circuit.close() }
                    } else {
                        val keep =
                            synchronized(lock) {
                                if (closed) {
                                    false
                                } else {
                                    idle += Prebuilt(circuit, endpoint, clock.millis())
                                    true
                                }
                            }
                        if (!keep) runCatching { circuit.close() }
                    }
                } finally {
                    building.set(false)
                }
            }
        } catch (e: RuntimeException) {
            logger.debug { "warm circuit preparation failed: ${e.javaClass.simpleName}" }
        } finally {
            if (!started) building.set(false)
        }
    }

    /**
     * Hands out the youngest usable warm circuit for [purpose] (the governor slot moves to it) or `null`. Triggers no build.
     */
    fun take(purpose: CircuitPurpose): Prebuilt? {
        val taken =
            synchronized(lock) {
                if (closed) return null
                val limit = clock.millis() - maxIdleAge.inWholeMilliseconds
                idle.removeAll { it.circuit.isClosed }
                val best = idle.filter { it.builtAtMillis > limit }.maxByOrNull { it.builtAtMillis } ?: return null
                idle.remove(best)
                best
            }
        val key =
            taken.lastHop.identity.bytes
                .joinToString("") { "%02x".format(it) }
        governor.retag(taken.circuit, purpose, key)
        return taken
    }

    /** Closes the oldest idle warm circuit to free a pool slot for a real build; `false` if there is none. */
    fun evictOne(): Boolean {
        val victim =
            synchronized(lock) {
                idle.removeAll { it.circuit.isClosed }
                idle.minByOrNull { it.builtAtMillis }?.also { idle.remove(it) }
            } ?: return false
        runCatching { victim.circuit.close() }
        return true
    }

    override fun close() {
        val all =
            synchronized(lock) {
                closed = true
                idle.toList().also { idle.clear() }
            }
        all.forEach { runCatching { it.circuit.close() } }
    }

    companion object {
        /** Half of the governor pool of 4. */
        const val WARM_TARGET = 2
    }
}
