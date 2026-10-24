package net.lapisphilosophorum.lapisnet.mailonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.dmonion.DmFramingException
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.StreamFrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.WindowLimiter
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailInboundSink
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

/**
 * The receiving end of mail over circuits (wave V0.10.0-F2): registered with the node's service stream router for the MAIL
 * application. Reads one [MailCircuitFraming] bundle frame per stream and hands it to the [AnonymousMailInboundSink] on a
 * small bounded executor.
 *
 * Bounds (assumptions awaiting confirmation, see docs/anonymity.adoc): at most [maxStreams] streams at once (further ones are
 * closed at once), one bundle per stream, [maxBundlesPerMinute] and [maxBytesPerMinute] over all streams, the byte budget
 * reserved from the frame header's declared length BEFORE the body buffer is allocated, [idleMillis] between the pieces of
 * a frame, [firstByteMillis] from stream creation until the COMPLETE frame header has arrived (neither silence nor a header
 * trickle can hold a slot), a body rate of at least [minBodyBytesPerSecond] on average after an [idleMillis] grace period
 * (measured from the end of the header) and a body that must be able to complete within [lifetimeMillis] at its observed
 * rate (so a stream holding its slot until the end of its lifetime has to finish its frame), a stream
 * closed [ackGraceMillis] after its bundle was acknowledged, budget of an incomplete frame returned when the stream ends, [lifetimeMillis] per stream, a work queue of [queueCapacity] (a full queue closes the stream without an
 * acknowledgement; the sender then retries and duplicate suppression applies). No per-peer limit exists, the peer is
 * anonymous.
 *
 * The acknowledgement is sent as soon as the frame is complete and queued, never after the bundle was decoded or accepted,
 * and a refused bundle does not close the stream early: its timing is no oracle for the acceptance policy, duplicates or
 * decryption.
 */
@OptIn(ExperimentalOnionApi::class)
class OnionMailInboundHandler(
    private val sink: AnonymousMailInboundSink,
    private val clock: Clock = Clock.systemUTC(),
    private val maxStreams: Int = MAX_STREAMS,
    maxBundlesPerMinute: Int = MAX_BUNDLES_PER_MINUTE,
    maxBytesPerMinute: Int = MAX_BYTES_PER_MINUTE,
    queueCapacity: Int = QUEUE_CAPACITY,
    private val idleMillis: Long = IDLE_MILLIS,
    private val lifetimeMillis: Long = LIFETIME_MILLIS,
    private val firstByteMillis: Long = FIRST_BYTE_MILLIS,
    private val ackGraceMillis: Long = ACK_GRACE_MILLIS,
    private val minBodyBytesPerSecond: Long = MIN_BODY_BYTES_PER_SECOND,
    sweepMillis: Long = 1_000L,
) : AutoCloseable {
    private class Conn(
        val channel: FrameChannel,
        val createdMillis: Long,
    ) {
        val bundles = AtomicInteger(0)

        /** Budget reserved by `admit` for a frame that has not completed yet; given back if the stream ends first. */
        var bundleStamp: Long? = null
        var byteStamp: Long? = null
        var reservedBytes = 0

        /** Time the single bundle was completed and acknowledged; the stream is closed shortly after. */
        @Volatile var doneMillis: Long = 0L

        @Volatile lateinit var reader: net.lapisphilosophorum.lapisnet.dmonion.DmFrameReader
    }

    private val closed = AtomicBoolean(false)
    private val conns = ConcurrentHashMap.newKeySet<Conn>()
    private val bundleLimiter = WindowLimiter(maxBundlesPerMinute, clock)
    private val byteLimiter = WindowLimiter(maxBytesPerMinute, clock)
    private val processed = AtomicLong(0)
    private val refusedStreams = AtomicLong(0)
    private val executor =
        ThreadPoolExecutor(
            1,
            2,
            30,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(queueCapacity),
            { r -> Thread(r, "lapis-net-mail-onion-inbound").apply { isDaemon = true } },
        )
    private val sweeper: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "lapis-net-mail-onion-inbound-sweep").apply { isDaemon = true }
        }

    init {
        sweeper.scheduleWithFixedDelay({ runCatching { sweep() } }, sweepMillis, sweepMillis, TimeUnit.MILLISECONDS)
    }

    /** Streams currently being served (leak checks). */
    fun openStreams(): Int = conns.size

    /** Bundles handed to the sink so far (tests). */
    fun processedCount(): Long = processed.get()

    /** Streams closed at once because the stream cap or a budget was exceeded (tests, diagnostics). */
    fun refusedStreamCount(): Long = refusedStreams.get()

    /** Registered as the MAIL handler of the service stream router. */
    fun handle(stream: OnionRendezvousStream) = handleChannel(StreamFrameChannel(stream))

    internal fun handleChannel(channel: FrameChannel) {
        if (closed.get()) {
            channel.close()
            return
        }
        val conn = Conn(channel, clock.millis())
        conn.reader =
            MailCircuitFraming.bundleReader(clock::millis) { length ->
                // one bundle per stream; the budgets are reserved BEFORE the body buffer is allocated
                admit(conn, length)
            }
        if (!reserveSlot(conn)) {
            refusedStreams.incrementAndGet()
            channel.close()
            return
        }
        channel.onClose {
            conns -= conn
            releaseReservation(conn)
        }
        channel.onReceive { chunk ->
            try {
                conn.reader.feed(chunk) { _, bundle -> onBundle(conn, bundle) }
            } catch (e: DmFramingException) {
                logger.debug { "mail stream closed: framing violation or budget" }
                refusedStreams.incrementAndGet()
                close(conn)
            }
        }
    }

    @Synchronized
    private fun admit(
        conn: Conn,
        length: Int,
    ): Boolean {
        if (conn.bundles.get() != 0 || conn.bundleStamp != null) return false
        val bundleStamp = bundleLimiter.acquireStamped() ?: return false
        val byteStamp = byteLimiter.acquireStamped(length)
        if (byteStamp == null) {
            bundleLimiter.release(1, bundleStamp)
            return false
        }
        conn.bundleStamp = bundleStamp
        conn.byteStamp = byteStamp
        conn.reservedBytes = length
        return true
    }

    /** Returns the budget reserved for a frame that never completed (stalled or closed stream), so it cannot be drained. */
    @Synchronized
    private fun releaseReservation(conn: Conn) {
        val bundleStamp = conn.bundleStamp ?: return
        val byteStamp = conn.byteStamp ?: return
        conn.bundleStamp = null
        conn.byteStamp = null
        bundleLimiter.release(1, bundleStamp)
        byteLimiter.release(conn.reservedBytes, byteStamp)
    }

    @Synchronized
    private fun reserveSlot(conn: Conn): Boolean {
        if (conns.size >= maxStreams) return false
        conns += conn
        return true
    }

    private fun onBundle(
        conn: Conn,
        bundleBytes: ByteArray,
    ) {
        if (conn.bundles.incrementAndGet() > 1) throw DmFramingException("too many bundles")
        // the frame is complete: its reservation is now a real charge
        synchronized(this) {
            conn.bundleStamp = null
            conn.byteStamp = null
        }
        try {
            executor.execute {
                try {
                    val bundle = MailCircuitBundleCodec.decode(bundleBytes)
                    sink.acceptAnonymousMail(bundle.frame, bundle.blobs)
                    processed.incrementAndGet()
                } catch (e: MalformedMailBundleException) {
                    logger.debug { "mail bundle refused: malformed" }
                } catch (e: RuntimeException) {
                    logger.debug { "mail bundle processing failed (${e.javaClass.simpleName})" }
                }
            }
        } catch (e: RejectedExecutionException) {
            logger.debug { "mail stream closed: work queue full" }
            close(conn)
            return
        }
        // constant answer, independent of what the sink does with the bundle
        conn.channel.send(MailCircuitFraming.ackFrame())
        // one bundle per stream: the sweeper closes the stream shortly after, freeing the slot
        conn.doneMillis = clock.millis()
    }

    private fun close(conn: Conn) {
        conns -= conn
        releaseReservation(conn)
        runCatching { conn.channel.close() }
    }

    private fun sweep() {
        val now = clock.millis()
        for (conn in conns.toList()) {
            val tooOld = now - conn.createdMillis >= lifetimeMillis
            val stalled = conn.reader.inFrame && now - conn.reader.lastProgressMillis >= idleMillis
            // the whole header must arrive within the short deadline from creation: neither silence nor a header trickle holds a slot
            val silent =
                !conn.reader.headerComplete &&
                    conn.doneMillis == 0L &&
                    conn.bundles.get() == 0 &&
                    now - conn.createdMillis >= firstByteMillis
            // a body must keep a minimum average rate after a grace period, so one byte per idle interval cannot hold a slot
            val slow =
                conn.reader.bodyTooSlow(now, idleMillis, minBodyBytesPerSecond, conn.createdMillis + lifetimeMillis)
            val finished = conn.doneMillis != 0L && now - conn.doneMillis >= ackGraceMillis
            if (tooOld || stalled || silent || slow || finished || conn.channel.isClosed) close(conn)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        sweeper.shutdownNow()
        conns.toList().forEach { close(it) }
        executor.shutdownNow()
    }

    override fun toString(): String = "OnionMailInboundHandler(REDACTED)"

    companion object {
        const val MAX_STREAMS = 4
        const val MAX_BUNDLES_PER_MINUTE = 30
        const val MAX_BYTES_PER_MINUTE = 8 * 1024 * 1024
        const val QUEUE_CAPACITY = 8
        const val IDLE_MILLIS = 10_000L
        const val LIFETIME_MILLIS = 120_000L
        const val FIRST_BYTE_MILLIS = 15_000L
        const val ACK_GRACE_MILLIS = 2_000L
        const val MIN_BODY_BYTES_PER_SECOND = 1024L
    }
}
