package net.lapisphilosophorum.lapisnet.dmonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.dm.DmInboundSink
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousStream
import java.time.Clock
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/** Fixed-window counter: at most [limit] units (events or bytes) per [windowMillis]. */
class WindowLimiter(
    private val limit: Int,
    private val clock: Clock,
    private val windowMillis: Long = 60_000L,
) {
    private var windowStart = clock.millis()
    private var count = 0

    @Synchronized
    fun tryAcquire(units: Int = 1): Boolean = acquireStamped(units) != null

    /**
     * Like [tryAcquire], but returns the start of the window the units were charged to (null when refused), so that
     * [release] can give them back only if that window is still the current one.
     */
    @Synchronized
    fun acquireStamped(units: Int = 1): Long? {
        val now = clock.millis()
        if (now - windowStart >= windowMillis || now < windowStart) {
            windowStart = now
            count = 0
        }
        if (units < 1 || units > limit - count) return null
        count += units
        return windowStart
    }

    /** Gives [units] back to the window identified by [stamp] (from [acquireStamped]); a window that has ended is left alone. */
    @Synchronized
    fun release(
        units: Int,
        stamp: Long,
    ) {
        if (stamp == windowStart) count = maxOf(0, count - units)
    }
}

/**
 * The receiving end of direct messages over circuits (wave V0.10.0-F1): registered with the node's service stream router
 * for the DM application. Reads [DmCircuitFraming] frames from each stream and hands the envelopes to the
 * [DmInboundSink] on a small bounded executor.
 *
 * Bounds: at most [maxEnvelopesPerStream] envelopes per stream, [maxEnvelopesPerMinute] over all streams (excess is
 * closed without an acknowledgement), an envelope length checked before allocation, [idleMillis] between the pieces of
 * one frame, [lifetimeMillis] per stream, a work queue of [queueCapacity] (a full queue closes the stream without an
 * acknowledgement; the sender then deposits offline and duplicate suppression applies). No per-peer limit exists, the
 * peer is anonymous; that is documented in docs/anonymity.adoc.
 *
 * The acknowledgement is sent as soon as a frame is complete and valid and the work was queued, never after the
 * envelope was processed: its timing is no oracle for decryption, acceptance policy or duplicates. A reply to an
 * incoming message never uses the incoming stream: the answering side opens its own circuit to the sender's service.
 */
@OptIn(ExperimentalOnionApi::class)
class OnionDmInboundHandler(
    private val sink: DmInboundSink,
    private val clock: Clock = Clock.systemUTC(),
    private val maxEnvelopesPerStream: Int = MAX_ENVELOPES_PER_STREAM,
    maxEnvelopesPerMinute: Int = MAX_ENVELOPES_PER_MINUTE,
    queueCapacity: Int = QUEUE_CAPACITY,
    private val idleMillis: Long = IDLE_MILLIS,
    private val lifetimeMillis: Long = LIFETIME_MILLIS,
    sweepMillis: Long = 1_000L,
) : AutoCloseable {
    private class Conn(
        val channel: FrameChannel,
        val reader: DmFrameReader,
        val createdMillis: Long,
    ) {
        val envelopes = AtomicInteger(0)
    }

    private val closed = AtomicBoolean(false)
    private val conns = ConcurrentHashMap.newKeySet<Conn>()
    private val limiter = WindowLimiter(maxEnvelopesPerMinute, clock)
    private val processed = AtomicLong(0)
    private val executor =
        ThreadPoolExecutor(
            1,
            2,
            30,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(queueCapacity),
            { r -> Thread(r, "lapis-net-dm-onion-inbound").apply { isDaemon = true } },
        )
    private val sweeper: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "lapis-net-dm-onion-inbound-sweep").apply { isDaemon = true }
        }

    init {
        sweeper.scheduleWithFixedDelay({ runCatching { sweep() } }, sweepMillis, sweepMillis, TimeUnit.MILLISECONDS)
    }

    /** Streams currently being served (leak checks). */
    fun openStreams(): Int = conns.size

    /** Envelopes handed to the sink so far (tests). */
    fun processedCount(): Long = processed.get()

    /** Registered as the DM handler of the service stream router. */
    fun handle(stream: OnionRendezvousStream) = handleChannel(StreamFrameChannel(stream))

    internal fun handleChannel(channel: FrameChannel) {
        if (closed.get()) {
            channel.close()
            return
        }
        val conn = Conn(channel, DmFrameReader(DmCircuitFraming.TYPE_ENVELOPE, clock::millis), clock.millis())
        conns += conn
        channel.onClose { conns -= conn }
        channel.onReceive { chunk ->
            try {
                conn.reader.feed(chunk) { _, envelope -> onEnvelope(conn, envelope) }
            } catch (e: DmFramingException) {
                logger.debug { "DM stream closed: framing violation" }
                close(conn)
            }
        }
    }

    private fun onEnvelope(
        conn: Conn,
        envelope: ByteArray,
    ) {
        if (conn.envelopes.incrementAndGet() > maxEnvelopesPerStream) throw DmFramingException("too many envelopes")
        if (!limiter.tryAcquire()) {
            logger.debug { "DM stream closed: inbound rate limit" }
            close(conn)
            return
        }
        try {
            executor.execute {
                try {
                    sink.acceptCircuitEnvelope(envelope)
                    processed.incrementAndGet()
                } catch (e: RuntimeException) {
                    logger.debug { "DM envelope processing failed (${e.javaClass.simpleName})" }
                }
            }
        } catch (e: RejectedExecutionException) {
            logger.debug { "DM stream closed: work queue full" }
            close(conn)
            return
        }
        // constant answer, independent of what the sink does with the envelope
        conn.channel.send(DmCircuitFraming.ackFrame())
    }

    private fun close(conn: Conn) {
        conns -= conn
        runCatching { conn.channel.close() }
    }

    private fun sweep() {
        val now = clock.millis()
        for (conn in conns.toList()) {
            val tooOld = now - conn.createdMillis >= lifetimeMillis
            val stalled = conn.reader.inFrame && now - conn.reader.lastProgressMillis >= idleMillis
            if (tooOld || stalled || conn.channel.isClosed) close(conn)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        sweeper.shutdownNow()
        conns.toList().forEach { close(it) }
        executor.shutdownNow()
    }

    companion object {
        const val MAX_ENVELOPES_PER_STREAM = 16
        const val MAX_ENVELOPES_PER_MINUTE = 120
        const val QUEUE_CAPACITY = 64
        const val IDLE_MILLIS = 10_000L
        const val LIFETIME_MILLIS = 600_000L
    }
}
