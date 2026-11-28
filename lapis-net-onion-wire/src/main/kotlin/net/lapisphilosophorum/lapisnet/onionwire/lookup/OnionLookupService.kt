package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.onion.LookupBatchResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupOperation
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupSizeClass
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onion.RelayAction
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReferenceArray
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private val logger = KotlinLogging.logger {}

/**
 * Relay-side bounds of the LOOKUP role (wave V0.10.0-J2). Q8 does not name these values; they bound what anonymous
 * clients can make the relay do (operator liability, resources). See docs/anonymity.adoc, "Lookups through circuits".
 */
data class OnionLookupServiceConfig(
    /** Deadline of the relay's own lookup (DHT walk plus Bitswap fetch, or the IPNS walk). */
    val lookupTimeout: Duration = 20.seconds,
    /** Lookups running at the same time; more are answered RATE_LIMITED. */
    val maxInFlight: Int = 8,
    val negativeCacheEntries: Int = 4096,
    val negativeCacheTtl: Duration = 5.minutes,
    /**
     * Lookups of ONE key per [attemptWindow], over all clients, that ended without content (NOT_FOUND, TIMEOUT or
     * content that does not verify); a key at the limit is answered NOT_FOUND without a lookup. A lookup that FOUND
     * the key clears its count and sets its found mark ([foundMarkTtl]); misses during the mark do not count, so a key
     * that exists can not be pushed into NOT_FOUND by asking it often.
     */
    val attemptsPerKeyPerWindow: Int = 2,
    val attemptWindow: Duration = 10.minutes,
    /**
     * How long a key stays marked as "found here" after this relay last FOUND it. While the mark lasts, a lookup of
     * that key that ends without content (NOT_FOUND, TIMEOUT, content that does not verify) is answered TIMEOUT,
     * counts as no miss and writes no negative entry, and it extends the mark by this duration. Reason: a second
     * lookup of an existing block can miss for reasons that say nothing about the block - its only holder went
     * offline, or it is at its re-send limit (`BitswapResendLimits` in lapis-net-storage). Before fix wave F6 this
     * was the normal case: Nabu's Bitswap responder never resent a block to a peer it already sent it to (a per-peer
     * LRU without expiry); since F6 the holder resends within bounds. Without the mark, anyone could turn an existing
     * key into a cached NOT_FOUND with three requests (security audit of wave J2, round 2); with it the client gets
     * TIMEOUT and asks its next relay. Only a verified FOUND sets the mark, so a missing key never gets one.
     */
    val foundMarkTtl: Duration = 30.minutes,
    /** Bytes of answer (counted by size class) per minute over all clients; more is answered RATE_LIMITED. */
    val bytesPerMinuteGlobal: Long = 8L * 1024 * 1024,
    /** Pacing: at most this many fragments per [tick], so a 184-cell answer never floods the link queue (256 cells). */
    val fragmentsPerTick: Int = 8,
    val tick: Duration = 50.milliseconds,
    /** No answer leaves earlier than this after the request arrived (also a cache hit or an error). */
    val minAnswerDelay: Duration = 1500.milliseconds,
    val answerDelayJitter: Duration = 1000.milliseconds,
) {
    init {
        require(lookupTimeout.isPositive() && maxInFlight > 0) { "lookup timeout and in-flight limit must be positive" }
        require(negativeCacheEntries > 0 && negativeCacheTtl.isPositive()) { "negative cache bounds must be positive" }
        require(attemptsPerKeyPerWindow > 0 && attemptWindow.isPositive()) { "attempt limit must be positive" }
        require(foundMarkTtl.isPositive()) { "the found mark must last a positive time" }
        require(bytesPerMinuteGlobal >= LookupSizeClass.size(LookupSizeClass.COUNT - 1)) {
            "the byte budget must allow at least one answer of the largest class"
        }
        require(fragmentsPerTick > 0 && tick.isPositive()) { "pacing must be positive" }
        require(
            !minAnswerDelay.isNegative() && !answerDelayJitter.isNegative(),
        ) { "answer delays must not be negative" }
    }
}

/** Coarse counters of an [OnionLookupService] (no keys, no circuits). */
data class LookupServiceStats(
    val requests: Long,
    val sinkCalls: Long,
    val found: Long,
    val notFound: Long,
    val negativeHits: Long,
    val attemptLimited: Long,
    val invalidContent: Long,
    val malformed: Long,
    val rateLimited: Long,
    val tooLarge: Long,
    val timeouts: Long,
    val fragmentsSent: Long,
    /** Lookups without content of a key marked as found here, answered TIMEOUT instead of counting as a miss. */
    val foundMarkShielded: Long = 0,
    /** Version-2 batches (wave Q16) and the items in them. */
    val batches: Long = 0,
    val batchItems: Long = 0,
)

/**
 * The host side of the LOOKUP role (wave V0.10.0-J2). For each [RelayAction.DeliverLookupRequest], in this order:
 * key shape check (only raw/SHA-256 CIDs and canonical Ed25519 `/ipns/` keys; nothing else is ever looked up),
 * negative cache, attempt limit per key (misses only), byte budget not spent, in-flight limit, the sink on the bounded lookup pool, validation of what the
 * sink returned (a block must hash to its CID, a record must be signed by the name's key: the relay never forwards
 * unverified content), byte budget, then the answer: the fragments of the smallest size class, paced at
 * [OnionLookupServiceConfig.fragmentsPerTick] per tick and never before the minimum answer delay.
 *
 * Caches and limits are keyed by SHA-256 of operation and key, never by the key itself. There is deliberately no
 * positive cache: the relay keeps no content of anonymous clients. Logging: counters and coarse reasons on debug
 * only, never a CID, IPNS name, link or circuit.
 */
internal class OnionLookupService(
    private val sink: OnionLookupSink,
    private val config: OnionLookupServiceConfig,
    /** Sends one fragment backwards on the circuit (the relay's `replyLookupFragment`). */
    private val reply: (Long, ByteArray) -> Unit,
    /** Runs a task after a delay in milliseconds; `false` if the scheduler is closed. */
    private val schedule: (Long, Runnable) -> Boolean,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    /** Test seam: replaces the bounded lookup pool. */
    executor: Executor? = null,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val inFlight = Semaphore(config.maxInFlight)
    private val ownPool: ThreadPoolExecutor? =
        if (executor == null) {
            val n = AtomicInteger()
            ThreadPoolExecutor(
                config.maxInFlight,
                config.maxInFlight,
                30,
                TimeUnit.SECONDS,
                SynchronousQueue(),
                ThreadFactory { r ->
                    Thread(r, "lapis-net-onion-lookup-${n.incrementAndGet()}").apply { isDaemon = true }
                },
                ThreadPoolExecutor.AbortPolicy(),
            ).apply { allowCoreThreadTimeOut(true) }
        } else {
            null
        }
    private val pool: Executor = executor ?: checkNotNull(ownPool)

    private class Expiring(
        val untilMillis: Long,
        /** The answer of a cache hit: NOT_FOUND, or TOO_LARGE for a block the relay already found too large. */
        val status: Byte,
    )

    /** Lookups of one key in the current window that ended without content. */
    private class Misses(
        val windowStart: Long,
        var count: Int,
    )

    private val lock = Any()
    private val negative = boundedMap<Expiring>(config.negativeCacheEntries)
    private val misses = boundedMap<Misses>(config.negativeCacheEntries)

    /** Keys this relay FOUND recently, with the end of their mark (see [OnionLookupServiceConfig.foundMarkTtl]). */
    private val foundMarks = boundedMap<Long>(config.negativeCacheEntries)
    private var byteWindowStart = clock.millis()
    private var bytesInWindow = 0L

    private val requests = AtomicLong()
    private val sinkCalls = AtomicLong()
    private val found = AtomicLong()
    private val notFound = AtomicLong()
    private val negativeHits = AtomicLong()
    private val attemptLimited = AtomicLong()
    private val invalidContent = AtomicLong()
    private val malformed = AtomicLong()
    private val rateLimited = AtomicLong()
    private val tooLarge = AtomicLong()
    private val timeouts = AtomicLong()
    private val fragmentsSent = AtomicLong()
    private val foundMarkShielded = AtomicLong()
    private val batches = AtomicLong()
    private val batchItems = AtomicLong()

    fun statsForTest(): LookupServiceStats =
        LookupServiceStats(
            requests.get(),
            sinkCalls.get(),
            found.get(),
            notFound.get(),
            negativeHits.get(),
            attemptLimited.get(),
            invalidContent.get(),
            malformed.get(),
            rateLimited.get(),
            tooLarge.get(),
            timeouts.get(),
            fragmentsSent.get(),
            foundMarkShielded.get(),
            batches.get(),
            batchItems.get(),
        )

    /** Result of the admission checks of one key (shape, negative cache, attempt limit, byte budget). */
    private sealed interface Admission {
        /** Answered without a lookup. */
        class Immediate(
            val status: Byte,
        ) : Admission

        /** Admitted: the sink has to run. */
        class Run(
            val cid: io.ipfs.cid.Cid?,
            val cacheKey: ByteBuffer,
        ) : Admission
    }

    /** Entry point; never blocks (the sink runs on the pool, the answer on the scheduler). */
    fun onRequest(action: RelayAction.DeliverLookupRequest) {
        val receivedAt = clock.millis()
        requests.incrementAndGet()
        val handle = action.circuitHandle
        val requestId = action.requestId

        fun answer(status: Byte) = sendPaced(handle, requestId, status, ByteArray(0), receivedAt)
        if (closed.get()) return
        val key = action.key
        val admission =
            when (val adm = admit(action.op, key, receivedAt)) {
                is Admission.Immediate -> return answer(adm.status)
                is Admission.Run -> adm
            }
        if (!inFlight.tryAcquire()) {
            rateLimited.incrementAndGet()
            logger.debug { "lookup refused: in-flight limit" }
            return answer(LookupStatus.RATE_LIMITED)
        }
        val task =
            Runnable {
                try {
                    run(action.op, key, admission.cid, admission.cacheKey, handle, requestId, receivedAt)
                } finally {
                    inFlight.release()
                }
            }
        try {
            pool.execute(task)
        } catch (e: RejectedExecutionException) {
            inFlight.release()
            rateLimited.incrementAndGet()
            answer(LookupStatus.RATE_LIMITED)
        }
    }

    /**
     * Batch entry point (wave Q16, LOOKUP version 2); never blocks. Every item goes through the same admission as a
     * single lookup, in the same order, and counts against the in-flight limit on its own (the excess is answered
     * RATE_LIMITED per item). The whole answer leaves no earlier than the minimum delay (plus jitter) after the batch
     * arrived and only when the slowest item is done, so the timing of one item does not show.
     */
    fun onBatch(action: RelayAction.DeliverLookupBatch) {
        val receivedAt = clock.millis()
        val keys = action.keys
        val n = keys.size
        requests.addAndGet(n.toLong())
        batches.incrementAndGet()
        batchItems.addAndGet(n.toLong())
        if (closed.get()) return
        val handle = action.circuitHandle
        val requestId = action.requestId
        val results = AtomicReferenceArray<Pair<Byte, ByteArray>>(n)
        val remaining = AtomicInteger(n)

        fun complete(
            index: Int,
            result: Pair<Byte, ByteArray>,
        ) {
            if (!results.compareAndSet(index, null, result)) return
            if (remaining.decrementAndGet() == 0) {
                sendPacedBatch(handle, requestId, List(n) { checkNotNull(results.get(it)) }, receivedAt)
            }
        }

        val empty = ByteArray(0)
        for (i in 0 until n) {
            val key = keys[i]
            when (val adm = admit(action.op, key, receivedAt)) {
                is Admission.Immediate -> complete(i, adm.status to empty)
                is Admission.Run -> {
                    if (!inFlight.tryAcquire()) {
                        rateLimited.incrementAndGet()
                        logger.debug { "lookup refused: in-flight limit" }
                        complete(i, LookupStatus.RATE_LIMITED to empty)
                        continue
                    }
                    val task =
                        Runnable {
                            val result =
                                try {
                                    if (closed.get()) {
                                        null
                                    } else {
                                        lookupOne(
                                            action.op,
                                            key,
                                            adm.cid,
                                            adm.cacheKey,
                                            receivedAt,
                                        )
                                    }
                                } catch (e: RuntimeException) {
                                    logger.debug { "lookup failed: ${e.javaClass.simpleName}" }
                                    LookupStatus.TIMEOUT to empty
                                } finally {
                                    inFlight.release()
                                }
                            if (result != null) complete(i, result)
                        }
                    try {
                        pool.execute(task)
                    } catch (e: RejectedExecutionException) {
                        inFlight.release()
                        rateLimited.incrementAndGet()
                        complete(i, LookupStatus.RATE_LIMITED to empty)
                    }
                }
            }
        }
    }

    /** Shape check, negative cache, attempt limit and byte budget of one key, in this order (counters included). */
    private fun admit(
        op: LookupOperation,
        key: ByteArray,
        receivedAt: Long,
    ): Admission {
        val cid =
            when (op) {
                LookupOperation.GET_BLOCK -> RemoteContentVerifier.parseRawSha256Cid(key)
                LookupOperation.GET_IPNS_RECORD -> null
            }
        val shapeOk =
            when (op) {
                LookupOperation.GET_BLOCK -> cid != null
                LookupOperation.GET_IPNS_RECORD -> RemoteContentVerifier.isIpnsRoutingKey(key)
            }
        if (!shapeOk) {
            malformed.incrementAndGet()
            logger.debug { "lookup refused: malformed key" }
            return Admission.Immediate(LookupStatus.MALFORMED)
        }
        val cacheKey = cacheKeyOf(op, key)
        var negativeStatus: Byte = LookupStatus.NOT_FOUND
        val admitted =
            synchronized(lock) {
                val neg = negative[cacheKey]
                if (neg != null) {
                    if (neg.untilMillis > receivedAt) {
                        negativeStatus = neg.status
                        return@synchronized ADMIT_NEGATIVE
                    }
                    negative.remove(cacheKey)
                }
                // only lookups that ended without content count (see attemptsPerKeyPerWindow); the refusal writes
                // no negative entry of its own, so it never outlives the misses that caused it
                val m = misses[cacheKey]
                if (m != null && inWindow(m, receivedAt) && m.count >= config.attemptsPerKeyPerWindow) {
                    return@synchronized ADMIT_ATTEMPTS
                }
                // the byte budget is spent: no new download until the window turns (oversized blocks count too)
                if (budgetExhausted(receivedAt)) return@synchronized ADMIT_BUDGET
                ADMIT_OK
            }
        return when (admitted) {
            ADMIT_NEGATIVE -> {
                negativeHits.incrementAndGet()
                if (negativeStatus == LookupStatus.TOO_LARGE) tooLarge.incrementAndGet() else notFound.incrementAndGet()
                Admission.Immediate(negativeStatus)
            }
            ADMIT_ATTEMPTS -> {
                attemptLimited.incrementAndGet()
                notFound.incrementAndGet()
                logger.debug { "lookup refused: attempt limit" }
                Admission.Immediate(LookupStatus.NOT_FOUND)
            }
            ADMIT_BUDGET -> {
                rateLimited.incrementAndGet()
                logger.debug { "lookup refused: byte budget" }
                Admission.Immediate(LookupStatus.RATE_LIMITED)
            }
            else -> Admission.Run(cid, cacheKey)
        }
    }

    private fun run(
        op: LookupOperation,
        key: ByteArray,
        cid: io.ipfs.cid.Cid?,
        cacheKey: ByteBuffer,
        handle: Long,
        requestId: Int,
        receivedAt: Long,
    ) {
        if (closed.get()) return
        val (status, content) = lookupOne(op, key, cid, cacheKey, receivedAt)
        sendPaced(handle, requestId, status, content, receivedAt)
    }

    /** The sink call and the validation of what it returned; the status and content to answer. */
    private fun lookupOne(
        op: LookupOperation,
        key: ByteArray,
        cid: io.ipfs.cid.Cid?,
        cacheKey: ByteBuffer,
        receivedAt: Long,
    ): Pair<Byte, ByteArray> {
        sinkCalls.incrementAndGet()
        val timeout = config.lookupTimeout.toJavaDuration()
        val outcome =
            try {
                when (op) {
                    LookupOperation.GET_BLOCK ->
                        sink.fetchBlock(
                            checkNotNull(cid),
                            LookupSizeClass.MAX_CONTENT,
                            timeout,
                        )
                    LookupOperation.GET_IPNS_RECORD -> sink.resolveIpnsRecord(key.copyOf(), timeout)
                }
            } catch (e: RuntimeException) {
                logger.debug { "lookup sink failed: ${e.javaClass.simpleName}" }
                LookupOutcome.NotFound
            }
        val (status, content) =
            when (outcome) {
                is LookupOutcome.Found -> {
                    val bytes = outcome.bytes
                    val valid =
                        bytes.size <= LookupSizeClass.MAX_CONTENT &&
                            when (op) {
                                LookupOperation.GET_BLOCK ->
                                    RemoteContentVerifier.blockMatchesCid(
                                        checkNotNull(cid),
                                        bytes,
                                    )
                                LookupOperation.GET_IPNS_RECORD ->
                                    RemoteContentVerifier.ipnsRecordValid(key, bytes, clock.instant())
                            }
                    when {
                        bytes.size > LookupSizeClass.MAX_CONTENT -> {
                            tooLarge.incrementAndGet()
                            chargeReceived(bytes.size.toLong())
                            rememberNegative(cacheKey, LookupStatus.TOO_LARGE)
                            LookupStatus.TOO_LARGE to ByteArray(0)
                        }
                        !valid -> {
                            invalidContent.incrementAndGet()
                            logger.debug { "lookup answer dropped: content does not verify" }
                            chargeReceived(bytes.size.toLong())
                            if (shieldedByFoundMark(cacheKey)) {
                                LookupStatus.TIMEOUT to ByteArray(0)
                            } else {
                                notFound.incrementAndGet()
                                recordMiss(cacheKey, receivedAt)
                                rememberNegative(cacheKey, LookupStatus.NOT_FOUND)
                                LookupStatus.NOT_FOUND to ByteArray(0)
                            }
                        }
                        !takeBudget(bytes.size) -> {
                            rateLimited.incrementAndGet()
                            logger.debug { "lookup refused: byte budget" }
                            LookupStatus.RATE_LIMITED to ByteArray(0)
                        }
                        else -> {
                            found.incrementAndGet()
                            markFound(cacheKey)
                            LookupStatus.FOUND to bytes
                        }
                    }
                }
                LookupOutcome.NotFound ->
                    if (shieldedByFoundMark(cacheKey)) {
                        timeouts.incrementAndGet()
                        LookupStatus.TIMEOUT to ByteArray(0)
                    } else {
                        notFound.incrementAndGet()
                        recordMiss(cacheKey, receivedAt)
                        rememberNegative(cacheKey, LookupStatus.NOT_FOUND)
                        LookupStatus.NOT_FOUND to ByteArray(0)
                    }
                LookupOutcome.Timeout -> {
                    timeouts.incrementAndGet()
                    if (!shieldedByFoundMark(cacheKey)) recordMiss(cacheKey, receivedAt)
                    LookupStatus.TIMEOUT to ByteArray(0)
                }
                is LookupOutcome.TooLarge -> {
                    tooLarge.incrementAndGet()
                    // the download already happened: it counts against the byte budget, and the block is not
                    // fetched again for this key while the negative entry lasts (its size never changes)
                    chargeReceived(outcome.receivedBytes)
                    rememberNegative(cacheKey, LookupStatus.TOO_LARGE)
                    LookupStatus.TOO_LARGE to ByteArray(0)
                }
            }
        return status to content
    }

    private fun rememberNegative(
        cacheKey: ByteBuffer,
        status: Byte,
    ) {
        synchronized(lock) {
            negative[cacheKey] = Expiring(clock.millis() + config.negativeCacheTtl.inWholeMilliseconds, status)
        }
    }

    private fun inWindow(
        m: Misses,
        now: Long,
    ): Boolean = now >= m.windowStart && now - m.windowStart < config.attemptWindow.inWholeMilliseconds

    /** Counts a lookup that ended without content; the window starts at the request of the first miss. */
    private fun recordMiss(
        cacheKey: ByteBuffer,
        receivedAt: Long,
    ) {
        synchronized(lock) {
            val m = misses[cacheKey]
            if (m == null || !inWindow(m, receivedAt)) {
                misses[cacheKey] = Misses(receivedAt, 1)
            } else {
                m.count++
            }
        }
    }

    /** A verified FOUND: clears the key's misses and (re)starts its found mark. */
    private fun markFound(cacheKey: ByteBuffer) {
        synchronized(lock) {
            misses.remove(cacheKey)
            negative.remove(cacheKey)
            foundMarks[cacheKey] = clock.millis() + config.foundMarkTtl.inWholeMilliseconds
        }
    }

    /**
     * For a lookup that ended without content: `true` if the key carries a live found mark. The lookup then counts as
     * no miss and writes no negative entry, and the mark is extended (the holder's refusal to resend lasts as long as
     * the relay keeps asking). An expired mark is removed.
     */
    private fun shieldedByFoundMark(cacheKey: ByteBuffer): Boolean {
        val shielded =
            synchronized(lock) {
                val now = clock.millis()
                val until = foundMarks[cacheKey]
                when {
                    until == null -> false
                    until <= now -> {
                        foundMarks.remove(cacheKey)
                        false
                    }
                    else -> {
                        foundMarks[cacheKey] = now + config.foundMarkTtl.inWholeMilliseconds
                        true
                    }
                }
            }
        if (shielded) {
            foundMarkShielded.incrementAndGet()
            logger.debug { "lookup without content of a key found here: answered TIMEOUT, no miss" }
        }
        return shielded
    }

    /** Caller holds [lock]. Turns the per-minute window and tells whether the budget is spent. */
    private fun budgetExhausted(now: Long): Boolean {
        turnByteWindow(now)
        return bytesInWindow >= config.bytesPerMinuteGlobal
    }

    /** Caller holds [lock]. */
    private fun turnByteWindow(now: Long) {
        if (now - byteWindowStart >= 60_000L || now < byteWindowStart) {
            byteWindowStart = now
            bytesInWindow = 0
        }
    }

    /**
     * Charges bytes the relay downloaded without answering them (an oversized block, content that does not verify)
     * against the budget. Always charged, even beyond the budget: further lookups are then refused until the window
     * turns, so rotating through large blocks costs the relay at most about one budget per minute plus what the
     * lookups in flight bring in.
     */
    private fun chargeReceived(bytes: Long) {
        if (bytes <= 0) return
        synchronized(lock) {
            turnByteWindow(clock.millis())
            bytesInWindow = (bytesInWindow + bytes).coerceAtMost(Long.MAX_VALUE / 2)
        }
    }

    /** Counts the padded size of the answer's class against the global per-minute budget. */
    private fun takeBudget(contentLength: Int): Boolean {
        val classIndex = LookupSizeClass.classFor(contentLength) ?: return false
        val cost = LookupSizeClass.size(classIndex).toLong()
        synchronized(lock) {
            turnByteWindow(clock.millis())
            if (bytesInWindow + cost > config.bytesPerMinuteGlobal) return false
            bytesInWindow += cost
            return true
        }
    }

    private fun sendPaced(
        handle: Long,
        requestId: Int,
        status: Byte,
        content: ByteArray,
        receivedAt: Long,
    ) {
        if (closed.get()) return
        val fragments = LookupResponseBody.encodeAnswer(requestId, status, content, random)
        val jitter =
            config.answerDelayJitter.inWholeMilliseconds.let { if (it <= 0) 0L else random.nextLong(it + 1) }
        val due = receivedAt + config.minAnswerDelay.inWholeMilliseconds + jitter
        val delay = (due - clock.millis()).coerceAtLeast(0)
        if (!schedule(delay) { sendBatch(handle, fragments, 0) }) {
            logger.debug { "lookup answer dropped: scheduler closed" }
        }
    }

    /** The fragments of all items, in order, paced over all of them; never before the minimum delay (plus jitter). */
    private fun sendPacedBatch(
        handle: Long,
        requestId: Int,
        answers: List<Pair<Byte, ByteArray>>,
        receivedAt: Long,
    ) {
        if (closed.get()) return
        val fragments = LookupBatchResponseBody.encodeBatch(requestId, answers, random)
        val jitter =
            config.answerDelayJitter.inWholeMilliseconds.let { if (it <= 0) 0L else random.nextLong(it + 1) }
        val due = receivedAt + config.minAnswerDelay.inWholeMilliseconds + jitter
        val delay = (due - clock.millis()).coerceAtLeast(0)
        if (!schedule(delay) { sendBatch(handle, fragments, 0) }) {
            logger.debug { "lookup answer dropped: scheduler closed" }
        }
    }

    private fun sendBatch(
        handle: Long,
        fragments: List<ByteArray>,
        from: Int,
    ) {
        if (closed.get()) return
        val end = minOf(from + config.fragmentsPerTick, fragments.size)
        for (i in from until end) {
            reply(handle, fragments[i])
            fragmentsSent.incrementAndGet()
        }
        if (end < fragments.size) {
            schedule(config.tick.inWholeMilliseconds) { sendBatch(handle, fragments, end) }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        ownPool?.shutdownNow()
        synchronized(lock) {
            negative.clear()
            misses.clear()
            foundMarks.clear()
        }
    }

    private companion object {
        const val ADMIT_OK = 0
        const val ADMIT_NEGATIVE = 1
        const val ADMIT_ATTEMPTS = 2
        const val ADMIT_BUDGET = 3

        fun cacheKeyOf(
            op: LookupOperation,
            key: ByteArray,
        ): ByteBuffer {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(op.code.toByte())
            digest.update(key)
            return ByteBuffer.wrap(digest.digest())
        }

        fun <V> boundedMap(capacity: Int): LinkedHashMap<ByteBuffer, V> =
            object : LinkedHashMap<ByteBuffer, V>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteBuffer, V>): Boolean =
                    size > capacity
            }
    }
}
