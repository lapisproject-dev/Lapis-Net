@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.StreamFrameChannel
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration
import kotlin.time.toKotlinDuration

private val logger = KotlinLogging.logger {}

/** The narrow view of the anonymity runtime the attachment client uses (a seam for tests). */
interface OnionAttachmentRuntimePort {
    fun ready(): Boolean

    fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability

    fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: java.time.Duration,
    ): CompletableFuture<FrameChannel>
}

/** The production port: opens [OnionServiceApp.ATTACHMENT] streams through [AnonymityRuntime.connectToService] only. */
class OnionAttachmentRuntimePortImpl(
    private val runtime: AnonymityRuntime,
) : OnionAttachmentRuntimePort {
    override fun ready(): Boolean = runtime.ready()

    override fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability =
        runtime.resolveIdentity(identity)

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: java.time.Duration,
    ): CompletableFuture<FrameChannel> =
        runtime
            .connectToService(descriptor, OnionServiceApp.ATTACHMENT, timeout.toKotlinDuration())
            .thenApply { StreamFrameChannel(it) as FrameChannel }
}

/** Why a fetch found nothing usable. Coarse on purpose: a manipulated answer and a not-found are told apart only here. */
enum class AttachmentFetchFailure { NOT_READY, NOT_REACHABLE, TIMEOUT, TOO_LARGE, MANIPULATED, RATE_LIMITED, CLOSED }

/** The outcome of one fetch. */
sealed interface AttachmentFetchResult {
    /** The blob, verified against its CID. */
    class Found(
        bytes: ByteArray,
    ) : AttachmentFetchResult {
        private val stored = bytes.copyOf()
        val bytes: ByteArray get() = stored.copyOf()

        override fun toString(): String = "Found(REDACTED)"
    }

    /** The sender answered NOT_FOUND (unknown CID or a wrong token; deliberately the same). */
    data object NotFound : AttachmentFetchResult

    data class Unavailable(
        val reason: AttachmentFetchFailure,
    ) : AttachmentFetchResult
}

/** What a caller of attachment fetches over circuits needs (a seam for the browser's tests). */
fun interface AttachmentFetchClient {
    /** Never throws; cancelling the future ends the fetch and closes its stream. */
    fun fetch(
        sender: Secp256k1PublicKey,
        cid: Cid,
        attachmentKey: ByteArray,
        maxBytes: Int,
    ): CompletableFuture<AttachmentFetchResult>
}

/** Bounds of [OnionAttachmentClient]; provisional values (Q21-C), not measured. */
data class AttachmentClientConfig(
    val connectTimeout: Duration = 30.seconds,
    val deadline: Duration = 180.seconds,
    /** Longest silence between two messages of the answer (from the request on). */
    val frameGap: Duration = 15.seconds,
) {
    init {
        require(connectTimeout.isPositive() && deadline.isPositive() && frameGap.isPositive()) {
            "timeouts must be positive"
        }
    }
}

/**
 * The fetching end of attachments over circuits (wave Q21, unreleased, design confirmed by the user (2026-11-22)).
 * Resolves the sender in the local anonymous directory only (never the DHT), opens one rendezvous stream to the
 * sender's onion service (never a direct connection), sends one request with the fetch token ([AttachmentFetchToken],
 * an HMAC under a key derived by HKDF from the attachment key and the CID) and reassembles the answer.
 *
 * Every chunk header is checked before anything is allocated for it: the reassembly buffer is created after the first
 * header, at most `min(maxBytes, MAX_BLOB_BYTES)` bytes. A chunk count that does not fit the length, a class other than
 * the largest for a multi-chunk answer, a gap or repetition in the indices, a frame longer than its class, bytes after
 * the last chunk or a blob that does not hash to its CID are [AttachmentFetchFailure.MANIPULATED]: the stream is closed
 * and nothing is returned. Results are completed off the stream's delivery thread ([offLoop]). Nothing logged names a
 * CID, an identity, a descriptor or a token.
 */
class OnionAttachmentClient(
    private val port: OnionAttachmentRuntimePort,
    private val config: AttachmentClientConfig = AttachmentClientConfig(),
    private val random: SecureRandom = SecureRandom(),
    private val scheduler: AttachmentScheduler = AttachmentScheduler.singleThread("lapis-net-attachment-client"),
    offLoop: Executor? = null,
) : AttachmentFetchClient,
    AutoCloseable {
    /** Completes results off the stream's delivery thread; an own pool (shut down on [close]) unless one is given. */
    private val ownPool: java.util.concurrent.ExecutorService? = if (offLoop == null) defaultOffLoop() else null
    private val offLoop: Executor = offLoop ?: checkNotNull(ownPool)
    private val closed = AtomicBoolean(false)
    private val running =
        java.util.concurrent.ConcurrentHashMap
            .newKeySet<Fetch>()

    /** Fetches in flight (leak checks). */
    fun inFlight(): Int = running.size

    override fun fetch(
        sender: Secp256k1PublicKey,
        cid: Cid,
        attachmentKey: ByteArray,
        maxBytes: Int,
    ): CompletableFuture<AttachmentFetchResult> {
        val result = CompletableFuture<AttachmentFetchResult>()
        if (closed.get() || !port.ready()) {
            result.complete(AttachmentFetchResult.Unavailable(AttachmentFetchFailure.NOT_READY))
            return result
        }
        val limit = minOf(maxBytes, AnonymousAttachmentLimits.MAX_BLOB_BYTES)
        if (limit < 1) {
            result.complete(AttachmentFetchResult.Unavailable(AttachmentFetchFailure.TOO_LARGE))
            return result
        }
        val token =
            runCatching { AttachmentFetchToken.compute(attachmentKey, cid) }.getOrElse {
                // a CID this format can not carry, or no key: nothing to ask for
                result.complete(AttachmentFetchResult.NotFound)
                return result
            }
        val descriptor =
            when (val reachability = runCatching { port.resolveIdentity(sender) }.getOrNull()) {
                is DirectoryReachability.Hidden -> reachability.descriptor
                else -> null
            }
        if (descriptor == null) {
            result.complete(AttachmentFetchResult.Unavailable(AttachmentFetchFailure.NOT_REACHABLE))
            return result
        }
        val fetch = Fetch(cid, limit, result)
        running += fetch
        // every way the result completes (success, failure, cancel) closes the stream
        result.whenComplete { _, _ -> fetch.cleanup() }
        fetch.deadlineTimer =
            scheduler.schedule(
                config.deadline.inWholeMilliseconds,
            ) { fetch.finish(unavailable(AttachmentFetchFailure.TIMEOUT)) }
        if (fetch.deadlineTimer == null) {
            fetch.finish(unavailable(AttachmentFetchFailure.NOT_READY))
            return result
        }
        val connect =
            try {
                port.connect(descriptor, config.connectTimeout.toJavaDuration())
            } catch (e: RuntimeException) {
                CompletableFuture.failedFuture(e)
            }
        fetch.connectFuture = connect
        connect.whenComplete { channel, error ->
            if (channel == null || error != null) {
                logger.debug { "attachment stream could not be opened" }
                fetch.finish(unavailable(AttachmentFetchFailure.NOT_REACHABLE))
            } else {
                fetch.opened(channel, AttachmentFetchCodec.encodeRequest(cid, token, random))
            }
        }
        return result
    }

    private fun unavailable(reason: AttachmentFetchFailure) = AttachmentFetchResult.Unavailable(reason)

    private inner class Fetch(
        val cid: Cid,
        val limit: Int,
        val result: CompletableFuture<AttachmentFetchResult>,
    ) {
        private val done = AtomicBoolean(false)
        private val lock = Any()

        @Volatile var channel: FrameChannel? = null

        @Volatile var connectFuture: CompletableFuture<FrameChannel>? = null

        @Volatile var deadlineTimer: AttachmentTimer? = null

        @Volatile private var gapTimer: AttachmentTimer? = null

        @Volatile private var lastProgress = 0L

        // reader state (under lock)
        private val frameHeader = ByteArray(DmCircuitFraming.HEADER_SIZE)
        private var frameHeaderFill = 0
        private var frameLength = 0
        private val chunkHeader = ByteArray(AnonymousAttachmentLimits.FRAME_HEADER)
        private var chunkHeaderFill = 0
        private var dataLeft = 0
        private var padLeft = 0
        private var inChunkBody = false
        private var expectedIndex = 0
        private var first: AttachmentFetchCodec.ChunkHeader? = null
        private var buffer: ByteArray? = null
        private var bufferFill = 0
        private var received = false
        private var finished: AttachmentFetchResult? = null

        fun opened(
            opened: FrameChannel,
            request: ByteArray,
        ) {
            if (done.get()) {
                runCatching { opened.close() }
                return
            }
            channel = opened
            opened.onClose {
                val any = synchronized(lock) { received }
                // a stream closed before any answer byte: an older node that does not know the application, or a
                // service that went away - "not reachable"; closed in the middle of an answer: "closed"
                finish(unavailable(if (any) AttachmentFetchFailure.CLOSED else AttachmentFetchFailure.NOT_REACHABLE))
            }
            opened.onReceive { message -> onMessage(message) }
            lastProgress = scheduler.nowMillis()
            armGapTimer(config.frameGap.inWholeMilliseconds)
            val frame = AttachmentFetchCodec.requestFrame(request)
            for (piece in DmCircuitFraming.chunks(frame, opened.maxPayload)) {
                if (!opened.send(piece)) {
                    finish(unavailable(AttachmentFetchFailure.NOT_REACHABLE))
                    return
                }
            }
            // the close may have raced with a done flag set by a cancel before the channel was known
            if (done.get()) runCatching { opened.close() }
        }

        private fun armGapTimer(delayMillis: Long) {
            gapTimer =
                scheduler.schedule(delayMillis) {
                    if (done.get()) return@schedule
                    val silent = scheduler.nowMillis() - lastProgress
                    val gap = config.frameGap.inWholeMilliseconds
                    if (silent >= gap) {
                        logger.debug { "attachment fetch: answer stalled" }
                        finish(unavailable(AttachmentFetchFailure.TIMEOUT))
                    } else {
                        armGapTimer(gap - silent)
                    }
                }
        }

        private fun onMessage(message: ByteArray) {
            if (done.get()) return
            lastProgress = scheduler.nowMillis()
            val outcome =
                synchronized(lock) {
                    received = true
                    try {
                        consume(message)
                        finished
                    } catch (e: TooLargeSignal) {
                        unavailable(AttachmentFetchFailure.TOO_LARGE)
                    } catch (e: MalformedAttachmentFetchException) {
                        logger.debug { "attachment fetch: manipulated answer" }
                        unavailable(AttachmentFetchFailure.MANIPULATED)
                    }
                }
            if (outcome != null) finish(outcome)
        }

        /** Feeds one stream message through the reader; sets [finished] once the answer is complete. */
        private fun consume(message: ByteArray) {
            var offset = 0
            while (offset < message.size) {
                if (finished != null) throw MalformedAttachmentFetchException("bytes after the last chunk")
                if (frameHeaderFill < frameHeader.size) {
                    val take = minOf(frameHeader.size - frameHeaderFill, message.size - offset)
                    message.copyInto(frameHeader, frameHeaderFill, offset, offset + take)
                    frameHeaderFill += take
                    offset += take
                    if (frameHeaderFill == frameHeader.size) {
                        val buf = ByteBuffer.wrap(frameHeader)
                        val type = buf.get().toInt() and 0xFF
                        frameLength = buf.getInt()
                        if (type != AttachmentFetchCodec.TYPE_ATTACHMENT_CHUNK) {
                            throw MalformedAttachmentFetchException("unexpected frame type")
                        }
                        if (!AttachmentFetchCodec.isChunkPayloadLength(frameLength)) {
                            throw MalformedAttachmentFetchException("frame size is not a class size")
                        }
                    }
                    continue
                }
                if (chunkHeaderFill < chunkHeader.size) {
                    val take = minOf(chunkHeader.size - chunkHeaderFill, message.size - offset)
                    message.copyInto(chunkHeader, chunkHeaderFill, offset, offset + take)
                    chunkHeaderFill += take
                    offset += take
                    if (chunkHeaderFill == chunkHeader.size) startChunk()
                    continue
                }
                if (dataLeft > 0) {
                    val target = checkNotNull(buffer)
                    val take = minOf(dataLeft, message.size - offset)
                    message.copyInto(target, bufferFill, offset, offset + take)
                    bufferFill += take
                    dataLeft -= take
                    offset += take
                } else if (padLeft > 0) {
                    val take = minOf(padLeft, message.size - offset)
                    padLeft -= take
                    offset += take
                }
                if (dataLeft == 0 && padLeft == 0 && inChunkBody) endChunk()
            }
        }

        private fun startChunk() {
            val header = AttachmentFetchCodec.decodeChunkHeader(chunkHeader, frameLength)
            val head = first
            if (head == null) {
                if (header.chunkIndex != 0) throw MalformedAttachmentFetchException("first chunk is not chunk 0")
                if (header.status == AttachmentFetchStatus.FOUND) {
                    // checked before any allocation for the data
                    if (header.totalLength > limit) throw TooLargeSignal()
                    buffer = ByteArray(header.totalLength)
                }
                first = header
            } else if (header.status != head.status ||
                header.chunkCount != head.chunkCount ||
                header.totalLength != head.totalLength ||
                header.classIndex != head.classIndex ||
                header.chunkIndex != expectedIndex
            ) {
                throw MalformedAttachmentFetchException("chunk sequence broken")
            }
            dataLeft =
                if (header.status == AttachmentFetchStatus.FOUND) {
                    AttachmentTransferClass.dataLength(header.totalLength, header.chunkCount, header.chunkIndex)
                } else {
                    0
                }
            padLeft = frameLength - AnonymousAttachmentLimits.FRAME_HEADER - dataLeft
            if (padLeft < 0) throw MalformedAttachmentFetchException("chunk data exceeds its class")
            inChunkBody = true
            if (dataLeft == 0 && padLeft == 0) endChunk()
        }

        private fun endChunk() {
            inChunkBody = false
            frameHeaderFill = 0
            chunkHeaderFill = 0
            expectedIndex++
            val head = checkNotNull(first)
            if (expectedIndex < head.chunkCount) return
            finished =
                when (head.status) {
                    AttachmentFetchStatus.FOUND -> {
                        val bytes = checkNotNull(buffer)
                        if (bufferFill != bytes.size || !RemoteContentVerifier.blockMatchesCid(cid, bytes)) {
                            throw MalformedAttachmentFetchException("blob does not match its CID")
                        }
                        AttachmentFetchResult.Found(bytes)
                    }
                    AttachmentFetchStatus.NOT_FOUND -> AttachmentFetchResult.NotFound
                    AttachmentFetchStatus.RATE_LIMITED -> unavailable(AttachmentFetchFailure.RATE_LIMITED)
                    AttachmentFetchStatus.TOO_LARGE -> unavailable(AttachmentFetchFailure.TOO_LARGE)
                    AttachmentFetchStatus.MALFORMED -> unavailable(AttachmentFetchFailure.CLOSED)
                }
            buffer = null
        }

        fun finish(outcome: AttachmentFetchResult) {
            if (!done.compareAndSet(false, true)) return
            cleanup()
            try {
                offLoop.execute { result.complete(outcome) }
            } catch (e: RejectedExecutionException) {
                result.complete(outcome)
            }
        }

        /** Idempotent: closes the stream (also one that is still being opened) and the timers. */
        fun cleanup() {
            done.set(true)
            running -= this
            deadlineTimer?.cancel()
            gapTimer?.cancel()
            channel?.let { runCatching { it.close() } }
            // a stream that is still being opened is closed as soon as it exists (the connect itself is bounded)
            connectFuture?.thenAccept { ch -> runCatching { ch.close() } }
            synchronized(lock) { buffer = null }
        }
    }

    /** Thrown inside the reader when the first header announces more than allowed; [Fetch] maps it via its result. */
    private class TooLargeSignal : MalformedAttachmentFetchException("too large")

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        running.toList().forEach { it.finish(unavailable(AttachmentFetchFailure.CLOSED)) }
        runCatching { scheduler.close() }
        ownPool?.shutdown()
    }

    private companion object {
        fun defaultOffLoop(): java.util.concurrent.ExecutorService =
            Executors.newCachedThreadPool { r ->
                Thread(r, "lapis-net-attachment-client-complete").apply {
                    isDaemon =
                        true
                }
            }
    }
}
