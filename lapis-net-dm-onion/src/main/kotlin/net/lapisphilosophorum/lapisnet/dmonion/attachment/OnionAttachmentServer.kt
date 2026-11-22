@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.StreamFrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.WindowLimiter
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/** An attachment this node sent (wave Q21): its key (for the fetch token), the size of its blob and a loader. */
class OutboundAttachment(
    attachmentKey: ByteArray,
    /** Size of the encoded blob as the sending node computed it (plaintext plus the blob overhead). */
    val declaredBlobBytes: Int,
    /** Loads the blob from the local store; `null` if it is no longer there. Called only after admission. */
    val loadBlob: () -> ByteArray?,
) {
    private val storedKey = attachmentKey.copyOf()

    /** A fresh copy on every access; never log it. */
    val attachmentKey: ByteArray get() = storedKey.copyOf()

    override fun toString(): String = "OutboundAttachment(REDACTED)"
}

/**
 * The attachments this node may hand out over its onion service: only attachments it SENT itself (decision Q21-G),
 * never received or foreign blobs, so the node never becomes a holder of other people's content.
 */
fun interface OutboundAttachmentSource {
    fun find(cid: Cid): OutboundAttachment?
}

/** Bounds of [OnionAttachmentServer]; provisional values (Q21-C), not measured. */
data class AttachmentServerConfig(
    val maxConcurrentStreams: Int = 2,
    val fetchesPerMinute: Int = 12,
    val bytesPerMinute: Long = 16L shl 20,
    val requestTimeout: Duration = 10.seconds,
    val streamLifetime: Duration = 180.seconds,
    val minAnswerDelay: Duration = 1500.milliseconds,
    val answerJitterMax: Duration = 1.seconds,
    val pacingMessages: Int = 8,
    val pacingInterval: Duration = 50.milliseconds,
    /** After the last answer message the stream stays open this long for the client to close it, then it is closed. */
    val lingerAfterAnswer: Duration = 30.seconds,
) {
    init {
        require(maxConcurrentStreams > 0 && fetchesPerMinute > 0) { "limits must be positive" }
        require(bytesPerMinute in 1..Int.MAX_VALUE) { "bytesPerMinute out of range" }
        require(requestTimeout.isPositive() && streamLifetime.isPositive() && lingerAfterAnswer.isPositive()) {
            "timeouts must be positive"
        }
        require(!minAnswerDelay.isNegative() && !answerJitterMax.isNegative()) { "delays must not be negative" }
        require(pacingMessages > 0 && pacingInterval.isPositive()) { "pacing must be positive" }
    }
}

/** Coarse counters of [OnionAttachmentServer]; numbers only, no CID, identity or token. */
data class AttachmentServerStats(
    val found: Long,
    val notFound: Long,
    val rateLimited: Long,
    val tooLarge: Long,
    val malformed: Long,
    val refusedStreams: Long,
    val aborted: Long,
    val openStreams: Int,
)

/** [Clock] over an [AttachmentScheduler]'s time (so the window limiters follow a test's virtual time). */
private class SchedulerClock(
    private val scheduler: AttachmentScheduler,
) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId?): Clock = this

    override fun instant(): Instant = Instant.ofEpochMilli(scheduler.nowMillis())

    override fun millis(): Long = scheduler.nowMillis()
}

/**
 * The serving end of attachment fetches over circuits (wave Q21, unreleased, design confirmed by the user
 * (2026-11-22)): registered with the node's service stream router for
 * [net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp.ATTACHMENT].
 *
 * One request per stream. The answer comes no earlier than [AttachmentServerConfig.minAnswerDelay] plus a random jitter
 * after the request, as lookup-class sized chunks ([AttachmentFetchCodec]), paced to
 * [AttachmentServerConfig.pacingMessages] stream messages per [AttachmentServerConfig.pacingInterval] (the rendezvous
 * stream has no backpressure: a refused send ends the transfer). An unknown CID and a wrong token give the same
 * NOT_FOUND answer after the same delay, so the service is no oracle for "does this identity hold CID X". Every error is
 * one class-0 chunk, as small as the smallest hit.
 *
 * Bounds: [AttachmentServerConfig.maxConcurrentStreams] streams (beyond: closed without an answer),
 * [AttachmentServerConfig.fetchesPerMinute] requests (beyond: RATE_LIMITED), [AttachmentServerConfig.bytesPerMinute]
 * reserved from the transfer class BEFORE the blob is loaded (not enough left: RATE_LIMITED), a request within
 * [AttachmentServerConfig.requestTimeout], a stream at most [AttachmentServerConfig.streamLifetime]. With two streams at
 * most two blobs of at most [AnonymousAttachmentLimits.MAX_BLOB_BYTES] are in memory. Nothing logged names a CID, an
 * identity, a descriptor, a token or a derived key; no timer or counter is tied to one. The token is checked with
 * [AttachmentFetchToken] (an HMAC under a key derived by HKDF from the attachment key and the CID, wave Q21-Token).
 */
class OnionAttachmentServer(
    private val source: OutboundAttachmentSource,
    private val config: AttachmentServerConfig = AttachmentServerConfig(),
    private val scheduler: AttachmentScheduler = AttachmentScheduler.singleThread("lapis-net-attachment-server"),
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private class Conn(
        val channel: FrameChannel,
    ) {
        val lock = Any()
        val buffer = ByteArray(AttachmentFetchCodec.REQUEST_FRAME_SIZE)
        var fill = 0
        var requested = false
        val released = AtomicBoolean(false)

        @Volatile var requestTimer: AttachmentTimer? = null

        @Volatile var lifetimeTimer: AttachmentTimer? = null

        @Volatile var pendingTimer: AttachmentTimer? = null

        // the transfer (scheduler thread only)
        var blob: ByteArray? = null
        var status: AttachmentFetchStatus = AttachmentFetchStatus.NOT_FOUND
        var chunkCount = 0
        var nextChunk = 0
        var messages: List<ByteArray> = emptyList()
        var nextMessage = 0
        var reservedUnits = 0
        var reservationStamp = 0L
    }

    private val closed = AtomicBoolean(false)
    private val conns = ConcurrentHashMap.newKeySet<Conn>()
    private val active = AtomicInteger(0)
    private val clock = SchedulerClock(scheduler)
    private val fetchLimiter = WindowLimiter(config.fetchesPerMinute, clock)
    private val byteLimiter = WindowLimiter(config.bytesPerMinute.toInt(), clock)
    private val found = AtomicLong()
    private val notFound = AtomicLong()
    private val rateLimited = AtomicLong()
    private val tooLarge = AtomicLong()
    private val malformed = AtomicLong()
    private val refused = AtomicLong()
    private val aborted = AtomicLong()

    internal fun statsForTest(): AttachmentServerStats = stats()

    fun stats(): AttachmentServerStats =
        AttachmentServerStats(
            found.get(),
            notFound.get(),
            rateLimited.get(),
            tooLarge.get(),
            malformed.get(),
            refused.get(),
            aborted.get(),
            conns.size,
        )

    /** Registered as the ATTACHMENT handler of the service stream router. */
    fun handle(stream: OnionRendezvousStream) = handleChannel(StreamFrameChannel(stream))

    /** Serves one stream (one request). */
    fun handleChannel(channel: FrameChannel) {
        if (closed.get()) {
            channel.close()
            return
        }
        if (active.incrementAndGet() > config.maxConcurrentStreams) {
            active.decrementAndGet()
            refused.incrementAndGet()
            logger.debug { "attachment stream refused: all slots busy" }
            channel.close()
            return
        }
        val conn = Conn(channel)
        conns += conn
        channel.onClose { release(conn) }
        conn.requestTimer =
            scheduler.schedule(config.requestTimeout.inWholeMilliseconds) {
                val waiting = synchronized(conn.lock) { !conn.requested }
                if (waiting) {
                    logger.debug { "attachment stream closed: no request in time" }
                    closeConn(conn)
                }
            }
        conn.lifetimeTimer = scheduler.schedule(config.streamLifetime.inWholeMilliseconds) { closeConn(conn) }
        if (conn.requestTimer == null || conn.lifetimeTimer == null) {
            closeConn(conn)
            return
        }
        channel.onReceive { chunk -> onChunk(conn, chunk) }
    }

    private fun onChunk(
        conn: Conn,
        chunk: ByteArray,
    ) {
        val complete: ByteArray?
        synchronized(conn.lock) {
            if (conn.requested || conn.fill + chunk.size > conn.buffer.size) {
                complete = null
            } else {
                chunk.copyInto(conn.buffer, conn.fill)
                conn.fill += chunk.size
                if (conn.fill == conn.buffer.size) {
                    conn.requested = true
                    complete = conn.buffer.copyOf()
                } else {
                    return
                }
            }
        }
        if (complete == null) {
            // a second request, or more bytes than one request frame: protocol violation
            logger.debug { "attachment stream closed: unexpected bytes" }
            closeConn(conn)
            return
        }
        val receivedAt = scheduler.nowMillis()
        conn.requestTimer?.cancel()
        val timer = scheduler.schedule(0L) { process(conn, complete, receivedAt) }
        if (timer == null) closeConn(conn)
    }

    private fun process(
        conn: Conn,
        frame: ByteArray,
        receivedAt: Long,
    ) {
        if (conn.released.get()) return
        val status = decide(conn, frame)
        conn.status = status
        conn.chunkCount = AttachmentFetchCodec.chunkCount(status, conn.blob?.size ?: 0)
        when (status) {
            AttachmentFetchStatus.FOUND -> found.incrementAndGet()
            AttachmentFetchStatus.NOT_FOUND -> notFound.incrementAndGet()
            AttachmentFetchStatus.RATE_LIMITED -> rateLimited.incrementAndGet()
            AttachmentFetchStatus.TOO_LARGE -> tooLarge.incrementAndGet()
            AttachmentFetchStatus.MALFORMED -> malformed.incrementAndGet()
        }
        val jitter =
            if (config.answerJitterMax.inWholeMilliseconds > 0) {
                random.nextLong(config.answerJitterMax.inWholeMilliseconds + 1)
            } else {
                0L
            }
        val due = receivedAt + config.minAnswerDelay.inWholeMilliseconds + jitter
        val delay = maxOf(0L, due - scheduler.nowMillis())
        conn.pendingTimer = scheduler.schedule(delay) { sendBatch(conn) }
        if (conn.pendingTimer == null) abort(conn)
    }

    /** The answer status; for FOUND, [Conn.blob] is set and the bytes are reserved. */
    private fun decide(
        conn: Conn,
        frame: ByteArray,
    ): AttachmentFetchStatus {
        val header = ByteBuffer.wrap(frame, 0, DmCircuitFraming.HEADER_SIZE)
        val type = header.get().toInt() and 0xFF
        val length = header.getInt()
        if (type != AttachmentFetchCodec.TYPE_FETCH_REQUEST || length != AnonymousAttachmentLimits.REQUEST_SIZE) {
            return AttachmentFetchStatus.MALFORMED
        }
        val request =
            try {
                AttachmentFetchCodec.decodeRequest(frame.copyOfRange(DmCircuitFraming.HEADER_SIZE, frame.size))
            } catch (e: MalformedAttachmentFetchException) {
                return AttachmentFetchStatus.MALFORMED
            }
        if (!fetchLimiter.tryAcquire()) return AttachmentFetchStatus.RATE_LIMITED
        val attachment = runCatching { source.find(request.cid) }.getOrNull()
        val expected =
            attachment?.let {
                runCatching { AttachmentFetchToken.compute(it.attachmentKey, request.cid) }.getOrNull()
            }
        // an unknown CID and a wrong token are the same answer
        if (expected == null || !AttachmentFetchToken.matches(expected, request.token)) {
            return AttachmentFetchStatus.NOT_FOUND
        }
        val declared = attachment.declaredBlobBytes
        val transfer = AttachmentTransferClass.transferBytes(declared) ?: return AttachmentFetchStatus.TOO_LARGE
        // the budget is reserved from the transfer class BEFORE the blob is loaded
        val stamp = byteLimiter.acquireStamped(transfer.toInt()) ?: return AttachmentFetchStatus.RATE_LIMITED
        val blob = runCatching { attachment.loadBlob() }.getOrNull()
        if (blob == null || blob.size != declared) {
            byteLimiter.release(transfer.toInt(), stamp)
            if (blob != null &&
                blob.size > AnonymousAttachmentLimits.MAX_BLOB_BYTES
            ) {
                return AttachmentFetchStatus.TOO_LARGE
            }
            return AttachmentFetchStatus.NOT_FOUND
        }
        conn.blob = blob
        conn.reservedUnits = transfer.toInt()
        conn.reservationStamp = stamp
        return AttachmentFetchStatus.FOUND
    }

    /** Sends at most [AttachmentServerConfig.pacingMessages] messages, then schedules the next batch. */
    private fun sendBatch(conn: Conn) {
        if (conn.released.get()) return
        try {
            sendBatchUnchecked(conn)
        } catch (e: RuntimeException) {
            // a release racing with the transfer (the blob is gone) or a channel fault: end the transfer
            logger.debug { "attachment transfer aborted (${e.javaClass.simpleName})" }
            abort(conn)
        }
    }

    private fun sendBatchUnchecked(conn: Conn) {
        val channel = conn.channel
        var sent = 0
        while (sent < config.pacingMessages) {
            if (conn.nextMessage >= conn.messages.size) {
                if (conn.nextChunk >= conn.chunkCount) break
                val payload = AttachmentFetchCodec.encodeChunk(conn.status, conn.blob, conn.nextChunk)
                conn.nextChunk++
                conn.messages = DmCircuitFraming.chunks(AttachmentFetchCodec.chunkFrame(payload), channel.maxPayload)
                conn.nextMessage = 0
            }
            if (!channel.send(conn.messages[conn.nextMessage])) {
                logger.debug { "attachment transfer aborted: send refused" }
                abort(conn)
                return
            }
            conn.nextMessage++
            sent++
        }
        if (conn.nextChunk >= conn.chunkCount && conn.nextMessage >= conn.messages.size) {
            // done: give up the blob, leave the closing to the client (or the linger timer)
            conn.blob = null
            conn.messages = emptyList()
            conn.pendingTimer = scheduler.schedule(config.lingerAfterAnswer.inWholeMilliseconds) { closeConn(conn) }
            return
        }
        conn.pendingTimer = scheduler.schedule(config.pacingInterval.inWholeMilliseconds) { sendBatch(conn) }
        if (conn.pendingTimer == null) abort(conn)
    }

    private fun abort(conn: Conn) {
        aborted.incrementAndGet()
        if (conn.reservedUnits > 0) {
            byteLimiter.release(conn.reservedUnits, conn.reservationStamp)
            conn.reservedUnits = 0
        }
        closeConn(conn)
    }

    private fun closeConn(conn: Conn) {
        runCatching { conn.channel.close() }
        release(conn)
    }

    private fun release(conn: Conn) {
        if (!conn.released.compareAndSet(false, true)) return
        active.decrementAndGet()
        conns -= conn
        conn.requestTimer?.cancel()
        conn.lifetimeTimer?.cancel()
        conn.pendingTimer?.cancel()
        conn.blob = null
        conn.messages = emptyList()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        conns.toList().forEach { closeConn(it) }
        runCatching { scheduler.close() }
    }
}
