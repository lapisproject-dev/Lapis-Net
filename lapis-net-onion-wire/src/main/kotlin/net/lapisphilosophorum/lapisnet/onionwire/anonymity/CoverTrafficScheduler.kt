package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onionwire.Cancellable
import net.lapisphilosophorum.lapisnet.onionwire.CoverCircuit
import net.lapisphilosophorum.lapisnet.onionwire.EgressShaper
import net.lapisphilosophorum.lapisnet.onionwire.SliceTimer
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * Token bucket of the cover traffic (wave V0.10.0-H): `bytesPerSecond` of cells (a cell is 1024 bytes) with a burst of
 * `burstCells`. Only cover draws from it; real traffic never calls it and is never slowed down by it. Never blocks.
 */
internal class CoverBudget(
    bytesPerSecond: Int,
    private val burstCells: Int,
    private val clock: Clock,
) {
    private val cellsPerMilli = bytesPerSecond / CELL_BYTES / 1000.0
    private var tokens = burstCells.toDouble()
    private var last = clock.millis()

    @Synchronized
    fun tryAcquireCell(): Boolean {
        val now = clock.millis()
        tokens = minOf(burstCells.toDouble(), tokens + (now - last).coerceAtLeast(0) * cellsPerMilli)
        last = now
        if (tokens < 1.0) return false
        tokens -= 1.0
        return true
    }

    private companion object {
        const val CELL_BYTES = 1024.0
    }
}

/**
 * Sends cover cells (wave V0.10.0-H): a relay DROP addressed to [TrafficPaddingConfig.coverTargetHop] (never the guard,
 * which would recognise it) of a randomly chosen own, already built circuit. The next send follows after
 * `U(1 - j, 1 + j) * coverMeanIntervalMillis`. There is exactly one pending timer entry; [close] cancels it and nothing is
 * sent afterwards. Cover is never the reason for building a circuit: without an open circuit the cell is simply skipped.
 * A spent [CoverBudget] suppresses cover (counted), never real traffic. Only the direction client to relay is covered:
 * relays never create cover, so cover cannot amplify.
 */
internal class CoverTrafficScheduler(
    private val config: TrafficPaddingConfig,
    private val circuits: () -> List<CoverCircuit>,
    private val timer: SliceTimer,
    private val budget: CoverBudget,
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val lock = Any()
    private var pending: Cancellable? = null
    private var closed = false
    private var started = false
    private val sent = AtomicLong(0)
    private val suppressed = AtomicLong(0)

    fun start() {
        synchronized(lock) {
            if (closed || started) return
            started = true
            scheduleNextLocked()
        }
    }

    fun sentCount(): Long = sent.get()

    fun suppressedCount(): Long = suppressed.get()

    /** `true` while a timer entry is outstanding (leak checks). */
    fun timerPending(): Boolean = synchronized(lock) { pending != null }

    /** The delay until the next cover cell, in milliseconds (exposed for the schedule tests). */
    internal fun nextDelayMillis(): Long {
        val j = config.coverJitterFraction
        val factor = 1.0 + j * (2.0 * random.nextDouble() - 1.0)
        return (config.coverMeanIntervalMillis * factor).toLong().coerceAtLeast(1L)
    }

    private fun scheduleNextLocked() {
        if (closed) return
        pending = timer.schedule(nextDelayMillis()) { tick() }
    }

    private fun tick() {
        synchronized(lock) {
            if (closed) return
            pending = null
            try {
                val usable = circuits().filter { !it.isClosed && it.hopCount() >= MIN_HOPS }
                if (usable.isNotEmpty()) sendOne(usable[random.nextInt(usable.size)])
            } catch (e: RuntimeException) {
                logger.debug { "cover cell failed: ${e.javaClass.simpleName}" }
            } finally {
                scheduleNextLocked()
            }
        }
    }

    /** Called by the egress shaper at a slice boundary for a link that owes tail cells; returns the cells sent. */
    fun tailCover(
        link: LinkId,
        count: Int,
    ): Int {
        synchronized(lock) {
            if (closed) return 0
            val onLink = circuits().filter { !it.isClosed && it.linkId == link && it.hopCount() >= MIN_HOPS }
            if (onLink.isEmpty()) return 0
            var n = 0
            repeat(count) { if (sendOne(onLink[random.nextInt(onLink.size)])) n++ }
            return n
        }
    }

    private fun sendOne(circuit: CoverCircuit): Boolean {
        if (!budget.tryAcquireCell()) {
            suppressed.incrementAndGet()
            return false
        }
        val target = minOf(config.coverTargetHop, circuit.hopCount())
        val ok = EgressShaper.asCover { circuit.sendDrop(target) }
        if (ok) sent.incrementAndGet()
        return ok
    }

    override fun close() {
        val cancel: Cancellable?
        synchronized(lock) {
            if (closed) return
            closed = true
            cancel = pending
            pending = null
        }
        cancel?.cancel()
    }

    private companion object {
        /** A circuit of fewer hops cannot carry cover that the guard does not recognise. */
        const val MIN_HOPS = 2
    }
}
