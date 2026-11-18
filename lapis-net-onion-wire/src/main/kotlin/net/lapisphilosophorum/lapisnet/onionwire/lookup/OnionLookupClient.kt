@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LookupOperation
import net.lapisphilosophorum.lapisnet.onion.LookupRequestBody
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupSizeClass
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onionwire.CircuitAdmissionException
import net.lapisphilosophorum.lapisnet.onionwire.OnionCircuitFactory
import net.lapisphilosophorum.lapisnet.onionwire.OnionClientCircuit
import net.lapisphilosophorum.lapisnet.onionwire.OnionPathProvider
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.WarmCircuitPool
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/** Client-side bounds of lookups through circuits (wave V0.10.0-J2). */
data class OnionLookupClientConfig(
    val buildTimeout: Duration = 20.seconds,
    /** From sending the request to the last fragment (the relay waits at least 1.5 s and looks up for up to 20 s). */
    val answerTimeout: Duration = 45.seconds,
    /** Relays tried for one lookup (a failure, a refusal or a manipulated answer moves on to the next). */
    val maxAttempts: Int = 2,
    /** Lookups waiting behind the one that runs; the oldest is dropped beyond this. */
    val maxQueued: Int = 32,
    val negativeTtl: Duration = 10.minutes,
    val negativeCacheEntries: Int = 1024,
    /** Backoff of a relay after a failed exchange: 30 s, doubling up to 8 min. */
    val failureBackoffBase: Duration = 30.seconds,
    val failureBackoffMaxShift: Int = 4,
    /** Backoff of a relay that destroyed the circuit before answering or answered DISABLED: 30 min doubling to 24 h. */
    val unsupportedBackoffBase: Duration = 30.minutes,
    val unsupportedBackoffMax: Duration = 24.hours,
    /** Backoff of a relay whose answer did not verify. */
    val manipulationBackoff: Duration = 24.hours,
    /**
     * A circuit destroyed by the network sooner than this after the request was sent, before any answer fragment, counts
     * as a relay without the LOOKUP role (an older relay destroys at once; an honest one never answers before its
     * minimum delay of 1.5 s). A later destroy only counts as a failure.
     */
    val legacyDestroyWindow: Duration = 1500.milliseconds,
) {
    init {
        require(buildTimeout.isPositive() && answerTimeout.isPositive()) { "timeouts must be positive" }
        require(maxAttempts > 0 && maxQueued > 0 && negativeCacheEntries > 0) { "limits must be positive" }
        require(negativeTtl.isPositive() && failureBackoffBase.isPositive() && failureBackoffMaxShift in 0..20) {
            "backoff must be positive"
        }
        require(unsupportedBackoffBase.isPositive() && unsupportedBackoffMax >= unsupportedBackoffBase) {
            "unsupported backoff inconsistent"
        }
        require(manipulationBackoff.isPositive()) { "manipulation backoff must be positive" }
        require(legacyDestroyWindow.isPositive()) { "legacy destroy window must be positive" }
    }
}

/** Outcome of a lookup through a circuit. */
sealed interface LookupResult {
    class Found(
        bytes: ByteArray,
    ) : LookupResult {
        private val stored = bytes.copyOf()
        val bytes: ByteArray get() = stored.copyOf()

        override fun toString(): String = "Found(length=${stored.size})"
    }

    data object NotFound : LookupResult

    data class Unavailable(
        val reason: LookupFailure,
    ) : LookupResult
}

enum class LookupFailure {
    /** No LOOKUP relay is usable (none known, or all in backoff). */
    NO_RELAY,

    /** The circuit policy refused the build (rate, pool, lockdown, no policy) or the queue dropped the lookup. */
    ADMISSION,
    TIMEOUT,

    /** The relay answered with a definitive refusal (too large, malformed key, rate limited). */
    REFUSED,

    /** The relay's answer did not verify (wrong block, invalid record, broken fragments). */
    MANIPULATED,
    CLOSED,
}

/** Coarse counters of an [OnionLookupClient] (no keys, no relays). */
data class LookupClientStats(
    val requested: Long,
    val circuitsBuilt: Long,
    val found: Long,
    val notFound: Long,
    val negativeHits: Long,
    val manipulated: Long,
    val legacySuspected: Long,
    val disabled: Long,
    val failed: Long,
    val dropped: Long,
    val deduplicated: Long,
)

/**
 * Client side of lookups through circuits (wave V0.10.0-J2): content blocks and IPNS records are fetched through ONE
 * circuit per request (purpose [CircuitPurpose.LOOKUP]) whose last hop is a LOOKUP relay; the circuit is closed after the
 * answer, nothing is reused. At most one lookup runs at a time (the governor allows one lookup circuit and two builds
 * per minute), identical keys are merged, at most [OnionLookupClientConfig.maxQueued] wait.
 *
 * Every answer is verified here (block against its CID, record against the name's key): a relay that lies is put on a
 * 24-hour backoff and the next relay is asked. A circuit destroyed by the network within
 * [OnionLookupClientConfig.legacyDestroyWindow] of the request and before the first answer fragment presumably ends at
 * a relay older than this wave (it does not know the command); that relay gets a backoff from 30 minutes up to 24 hours,
 * as one that answers DISABLED. A later destroy is a plain failure; a lost guard link or a local close is no verdict
 * about the relay at all, and neither is the end of the callers' deadline (the relay may still be looking up honestly).
 * NOT_FOUND is believed (one relay can withhold an answer; see docs/anonymity.adoc) and kept
 * in a negative cache. Fail closed: there is no path to content other than [OnionCircuitFactory.build] with the circuit
 * policy installed; without one, without relays or in lockdown the result is [LookupResult.Unavailable].
 *
 * Futures complete on [offLoop] (the link manager's pool), never on an event loop.
 */
@ExperimentalOnionApi
class OnionLookupClient internal constructor(
    private val factory: OnionCircuitFactory,
    private val paths: OnionPathProvider,
    private val lookupRelays: () -> List<OnionRelayDescriptor>,
    private val config: OnionLookupClientConfig = OnionLookupClientConfig(),
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    private val prebuilt: ((CircuitPurpose) -> WarmCircuitPool.Prebuilt?)? = null,
    /** Runs a task off the event loop; `false` if rejected (then a daemon thread of the common pool is used). */
    private val offLoop: (Runnable) -> Boolean = {
        CompletableFuture.runAsync(it)
        true
    },
) : AutoCloseable,
    LookupBackend {
    private class Job(
        val op: LookupOperation,
        val key: ByteArray,
        val cacheKey: ByteBuffer,
        deadlineMillis: Long,
        val result: CompletableFuture<LookupResult> = CompletableFuture(),
    ) {
        /** The latest deadline of all callers merged into this job (raised under the client lock, read anywhere). */
        @Volatile var deadlineMillis: Long = deadlineMillis
    }

    /** What an attempt says about the relay: [NONE] is no verdict (the cause was not the relay). */
    private enum class Kind { NONE, FAILURE, UNSUPPORTED, MANIPULATION }

    private class Backoff(
        val failures: Int,
        val unsupported: Int,
        val untilMillis: Long,
    )

    /** What one exchange with one relay ended in. */
    private sealed interface Attempt {
        class Done(
            val result: LookupResult,
        ) : Attempt

        class Next(
            val kind: Kind,
            val reason: LookupFailure,
        ) : Attempt

        class Stop(
            val reason: LookupFailure,
        ) : Attempt
    }

    private val lock = Any()
    private val queue = ArrayDeque<Job>()
    private val byKey = HashMap<ByteBuffer, Job>()
    private var running: Job? = null
    private val negative =
        object : LinkedHashMap<ByteBuffer, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteBuffer, Long>): Boolean =
                size > config.negativeCacheEntries
        }
    private val backoff = ConcurrentHashMap<Secp256k1PublicKey, Backoff>()
    private val open = ConcurrentHashMap.newKeySet<OnionClientCircuit>()

    @Volatile private var closed = false

    @Volatile internal var onClosed: (() -> Unit)? = null

    private val requested = AtomicLong()
    private val circuitsBuilt = AtomicLong()
    private val found = AtomicLong()
    private val notFound = AtomicLong()
    private val negativeHits = AtomicLong()
    private val manipulated = AtomicLong()
    private val legacySuspected = AtomicLong()
    private val disabled = AtomicLong()
    private val failed = AtomicLong()
    private val dropped = AtomicLong()
    private val deduplicated = AtomicLong()

    fun statsForTest(): LookupClientStats =
        LookupClientStats(
            requested.get(),
            circuitsBuilt.get(),
            found.get(),
            notFound.get(),
            negativeHits.get(),
            manipulated.get(),
            legacySuspected.get(),
            disabled.get(),
            failed.get(),
            dropped.get(),
            deduplicated.get(),
        )

    /** Circuits currently open for lookups (leak checks). */
    fun openCircuits(): Int = open.size

    /** `true` while [relay] is on a backoff (tests). */
    internal fun inBackoff(relay: Secp256k1PublicKey): Boolean = (backoff[relay]?.untilMillis ?: 0L) > clock.millis()

    /** Fetches the raw block [cid] (CIDv1, raw, SHA-256 only). Never throws. */
    override fun fetchBlock(
        cid: Cid,
        timeout: Duration,
    ): CompletableFuture<LookupResult> {
        val key =
            RemoteContentVerifier.rawSha256CidBytes(cid) ?: return done(LookupResult.Unavailable(LookupFailure.REFUSED))
        return submit(LookupOperation.GET_BLOCK, key, timeout)
    }

    /** Fetches the raw IPNS record behind [routingKey] (`/ipns/<Ed25519 multihash>`). Never throws. */
    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): CompletableFuture<LookupResult> {
        if (!RemoteContentVerifier.isIpnsRoutingKey(
                routingKey,
            )
        ) {
            return done(LookupResult.Unavailable(LookupFailure.REFUSED))
        }
        return submit(LookupOperation.GET_IPNS_RECORD, routingKey.copyOf(), timeout)
    }

    private fun done(r: LookupResult): CompletableFuture<LookupResult> = CompletableFuture.completedFuture(r)

    private fun submit(
        op: LookupOperation,
        key: ByteArray,
        timeout: Duration,
    ): CompletableFuture<LookupResult> {
        requested.incrementAndGet()
        if (closed) return done(LookupResult.Unavailable(LookupFailure.CLOSED))
        if (!timeout.isPositive()) return done(LookupResult.Unavailable(LookupFailure.TIMEOUT))
        val now = clock.millis()
        val cacheKey = cacheKeyOf(op, key)
        var evicted: Job? = null
        var start = false
        val job: Job =
            synchronized(lock) {
                val neg = negative[cacheKey]
                if (neg != null && neg > now) {
                    negativeHits.incrementAndGet()
                    return done(LookupResult.NotFound)
                }
                if (neg != null) negative.remove(cacheKey)
                val existing = byKey[cacheKey]
                if (existing != null) {
                    deduplicated.incrementAndGet()
                    // the job runs as long as its most patient caller; each caller keeps its own timeout below
                    existing.deadlineMillis = maxOf(existing.deadlineMillis, now + timeout.inWholeMilliseconds)
                    existing
                } else {
                    val j = Job(op, key, cacheKey, now + timeout.inWholeMilliseconds)
                    byKey[cacheKey] = j
                    if (running == null) {
                        running = j
                        start = true
                    } else {
                        if (queue.size >= config.maxQueued) {
                            evicted = queue.removeFirst()
                            evicted?.let { byKey.remove(it.cacheKey) }
                        }
                        queue.addLast(j)
                    }
                    j
                }
            }
        evicted?.let {
            dropped.incrementAndGet()
            completeOff(it.result, LookupResult.Unavailable(LookupFailure.ADMISSION))
        }
        if (start) runJob(job)
        // every caller gets its own view with its own deadline; the shared future stays untouched
        return job.result
            .copy()
            .completeOnTimeout(
                LookupResult.Unavailable(LookupFailure.TIMEOUT),
                timeout.inWholeMilliseconds,
                TimeUnit.MILLISECONDS,
            )
    }

    private fun completeOff(
        f: CompletableFuture<LookupResult>,
        r: LookupResult,
    ) {
        val task = Runnable { f.complete(r) }
        if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
    }

    private fun runJob(job: Job) {
        if (closed) return finish(job, LookupResult.Unavailable(LookupFailure.CLOSED))
        if (clock.millis() >= job.deadlineMillis) return finish(job, LookupResult.Unavailable(LookupFailure.TIMEOUT))
        if (factory.policy == null) {
            // fail closed: never a circuit without the anonymity-mode policy (governor, path length, guards)
            return finish(job, LookupResult.Unavailable(LookupFailure.ADMISSION))
        }
        val now = clock.millis()
        val candidates =
            try {
                lookupRelays()
                    .filter { (backoff[it.identity]?.untilMillis ?: 0L) <= now }
                    .distinctBy { it.identity }
                    .shuffled(random)
                    .take(config.maxAttempts)
            } catch (e: RuntimeException) {
                emptyList()
            }
        val warm = runCatching { prebuilt?.invoke(CircuitPurpose.LOOKUP) }.getOrNull()
        val warmUsable =
            warm != null && !warm.circuit.isClosed && (backoff[warm.lastHop.identity]?.untilMillis ?: 0L) <= now
        if (warm != null && !warmUsable) runCatching { warm.circuit.close() }
        val slots = ArrayList<Slot>()
        if (warmUsable) slots += Slot(checkNotNull(warm).lastHop, warm)
        candidates
            .filter { d -> slots.none { it.relay.identity == d.identity } }
            .forEach { slots += Slot(it, null) }
        val limited = slots.take(config.maxAttempts)
        if (limited.isEmpty()) return finish(job, LookupResult.Unavailable(LookupFailure.NO_RELAY))
        attemptFrom(job, limited, 0, LookupFailure.NO_RELAY)
    }

    /** One relay to try: through a warm circuit that already ends there, or through a new build. */
    private class Slot(
        val relay: OnionRelayDescriptor,
        val warm: WarmCircuitPool.Prebuilt?,
    )

    private val offLoopExecutor =
        java.util.concurrent.Executor { task ->
            if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
        }

    private fun attemptFrom(
        job: Job,
        slots: List<Slot>,
        index: Int,
        lastReason: LookupFailure,
    ) {
        if (closed) {
            slots.drop(index).forEach { s -> s.warm?.let { runCatching { it.circuit.close() } } }
            return finish(job, LookupResult.Unavailable(LookupFailure.CLOSED))
        }
        if (index >= slots.size) return finish(job, LookupResult.Unavailable(lastReason))
        if (clock.millis() >= job.deadlineMillis) {
            // a warm circuit that is not used any more must not stay open
            slots.drop(index).forEach { s -> s.warm?.let { runCatching { it.circuit.close() } } }
            return finish(job, LookupResult.Unavailable(LookupFailure.TIMEOUT))
        }
        val slot = slots[index]
        val relay = slot.relay
        val circuitFuture: CompletableFuture<OnionClientCircuit> =
            if (slot.warm != null) {
                CompletableFuture.completedFuture(slot.warm.circuit)
            } else {
                try {
                    factory.build(
                        paths.pathEndingAt(relay, CircuitPurpose.LOOKUP),
                        config.buildTimeout,
                        CircuitPurpose.LOOKUP,
                    )
                } catch (e: RuntimeException) {
                    CompletableFuture.failedFuture(e)
                }
            }
        circuitFuture
            .handle { circuit, error ->
                if (error != null || circuit == null) {
                    val cause = generateSequence(error) { it.cause }.firstOrNull { it is CircuitAdmissionException }
                    if (cause != null) {
                        CompletableFuture.completedFuture<Attempt>(Attempt.Stop(LookupFailure.ADMISSION))
                    } else {
                        CompletableFuture.completedFuture<Attempt>(Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT))
                    }
                } else {
                    circuitsBuilt.incrementAndGet()
                    exchange(circuit, job)
                }
            }.thenCompose { it }
            .exceptionally { Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT) }
            .thenAcceptAsync({ attempt ->
                when (attempt) {
                    is Attempt.Done -> {
                        backoff.remove(relay.identity)
                        finish(job, attempt.result)
                    }
                    is Attempt.Stop -> {
                        slots.drop(index + 1).forEach { s -> s.warm?.let { runCatching { it.circuit.close() } } }
                        finish(job, LookupResult.Unavailable(attempt.reason))
                    }
                    is Attempt.Next -> {
                        if (!closed && attempt.kind != Kind.NONE) penalise(relay.identity, attempt.kind)
                        attemptFrom(job, slots, index + 1, attempt.reason)
                    }
                }
            }, offLoopExecutor)
    }

    private fun penalise(
        relay: Secp256k1PublicKey,
        kind: Kind,
    ) {
        val now = clock.millis()
        backoff.compute(relay) { _, old ->
            val failures = old?.failures ?: 0
            val unsupported = old?.unsupported ?: 0
            when (kind) {
                Kind.FAILURE -> {
                    val f = failures + 1
                    val shift = minOf(f - 1, config.failureBackoffMaxShift)
                    Backoff(f, unsupported, now + (config.failureBackoffBase.inWholeMilliseconds shl shift))
                }
                Kind.UNSUPPORTED -> {
                    val u = unsupported + 1
                    val delay =
                        minOf(
                            config.unsupportedBackoffMax.inWholeMilliseconds,
                            config.unsupportedBackoffBase.inWholeMilliseconds shl minOf(u - 1, MAX_UNSUPPORTED_SHIFT),
                        )
                    Backoff(failures, u, now + delay)
                }
                Kind.MANIPULATION ->
                    Backoff(
                        failures,
                        unsupported,
                        now + config.manipulationBackoff.inWholeMilliseconds,
                    )
                Kind.NONE -> old
            }
        }
    }

    /** One request on [circuit], then the circuit is closed whatever happens. */
    private fun exchange(
        circuit: OnionClientCircuit,
        job: Job,
    ): CompletableFuture<Attempt> {
        open += circuit
        if (closed) {
            open -= circuit
            circuit.close()
            return CompletableFuture.completedFuture(Attempt.Stop(LookupFailure.CLOSED))
        }
        if (clock.millis() >= job.deadlineMillis) {
            // the build outlasted the callers (e.g. a delayed admission): no request, no verdict about the relay
            open -= circuit
            circuit.close()
            return CompletableFuture.completedFuture(Attempt.Stop(LookupFailure.TIMEOUT))
        }
        val requestId = random.nextInt(256)
        val answer = CompletableFuture<Attempt>()
        val assembler = Assembler(requestId)
        circuit.onInbound = { msg ->
            // circuit callback (event loop): only reassembly here; verification runs off the loop
            val outcome = assembler.accept(msg)
            if (outcome != null) answer.complete(outcome)
        }
        val sentAt = AtomicLong(Long.MAX_VALUE)
        circuit.onClosed = {
            answer.complete(closedOutcome(circuit, assembler.started, clock.millis() - sentAt.get()))
        }
        val body = LookupRequestBody.encode(requestId, job.op, job.key, random)
        sentAt.set(clock.millis())
        if (!circuit.send(RelayMessage(RelayCommand.LOOKUP_REQUEST, 0, body))) {
            open -= circuit
            circuit.close()
            // the link or this side refused the cell: nothing reached the relay, no verdict about it
            return CompletableFuture.completedFuture(Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT))
        }
        armDeadline(job, answer)
        return answer
            .completeOnTimeout(
                // the relay had the full answer time and stayed silent
                Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT),
                config.answerTimeout.inWholeMilliseconds,
                TimeUnit.MILLISECONDS,
            ).thenApplyAsync({ a ->
                circuit.onClosed = {}
                open -= circuit
                circuit.close()
                if (a is Attempt.Done && a.result is AnswerFound) verify(job, (a.result as AnswerFound).content) else a
            }, offLoopExecutor)
    }

    /**
     * The callers' deadline ends [answer] without a verdict about the relay (it may still be looking up honestly); it is
     * re-armed while a merged caller raises the deadline.
     */
    private fun armDeadline(
        job: Job,
        answer: CompletableFuture<Attempt>,
    ) {
        if (answer.isDone) return
        val remaining = job.deadlineMillis - clock.millis()
        if (remaining <= 0) {
            answer.complete(Attempt.Stop(LookupFailure.TIMEOUT))
            return
        }
        CompletableFuture
            .delayedExecutor(remaining, TimeUnit.MILLISECONDS)
            .execute { armDeadline(job, answer) }
    }

    /**
     * What a circuit that went away before its answer was complete says about the last hop. The cause and the time
     * since the request are all there is (the destroy reason is not passed up): only a DESTROY from the network
     * shortly after the request and before any answer fragment looks like a relay without the LOOKUP role.
     */
    private fun closedOutcome(
        circuit: OnionClientCircuit,
        started: Boolean,
        sinceSentMillis: Long,
    ): Attempt =
        when {
            // this client is closing: no verdict about the relay
            closed -> Attempt.Stop(LookupFailure.CLOSED)
            // the guard link broke or this side closed: the last hop is not at fault
            circuit.closeCause != OnionClientCircuit.CloseCause.NETWORK_DESTROY ->
                Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT)
            !started && sinceSentMillis in 0 until config.legacyDestroyWindow.inWholeMilliseconds -> {
                legacySuspected.incrementAndGet()
                Attempt.Next(Kind.UNSUPPORTED, LookupFailure.REFUSED)
            }
            else -> Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT)
        }

    /** Internal carrier of an unverified FOUND answer between the assembler and [verify]. */
    private class AnswerFound(
        val content: ByteArray,
    ) : LookupResult

    private fun verify(
        job: Job,
        content: ByteArray,
    ): Attempt {
        val ok =
            when (job.op) {
                LookupOperation.GET_BLOCK ->
                    RemoteContentVerifier
                        .parseRawSha256Cid(job.key)
                        ?.let { RemoteContentVerifier.blockMatchesCid(it, content) } == true
                LookupOperation.GET_IPNS_RECORD ->
                    RemoteContentVerifier.ipnsRecordValid(
                        job.key,
                        content,
                        clock.instant(),
                    )
            }
        if (!ok) {
            manipulated.incrementAndGet()
            logger.debug { "lookup answer rejected: content does not verify" }
            return Attempt.Next(Kind.MANIPULATION, LookupFailure.MANIPULATED)
        }
        return Attempt.Done(LookupResult.Found(content))
    }

    /** Strict reassembly of one answer; any deviation is a manipulation. Not thread-safe (one circuit, one loop). */
    private inner class Assembler(
        private val requestId: Int,
    ) {
        @Volatile var started = false
            private set
        private var buffer: ByteArray? = null
        private var fragCount = 0
        private var next = 0
        private var status: Byte = 0
        private var length = 0
        private var finished = false

        fun accept(msg: RelayMessage): Attempt? {
            if (finished) return null
            started = true
            val result = acceptInternal(msg)
            if (result != null) finished = true
            return result
        }

        private fun broken(): Attempt {
            manipulated.incrementAndGet()
            buffer = null
            return Attempt.Next(Kind.MANIPULATION, LookupFailure.MANIPULATED)
        }

        private fun acceptInternal(msg: RelayMessage): Attempt? {
            if (msg.command != RelayCommand.LOOKUP_RESPONSE) return broken()
            val data = msg.data
            val header =
                try {
                    LookupResponseBody.decodeFragmentHeader(data)
                } catch (e: CellFormatException) {
                    return broken()
                }
            if (header.requestId != requestId || header.fragIndex != next) return broken()
            if (next == 0) {
                val answer =
                    try {
                        LookupResponseBody.decodeAnswerHeader(data, header.fragCount)
                    } catch (e: CellFormatException) {
                        return broken()
                    }
                fragCount = header.fragCount
                status = answer.status
                length = answer.length
                // allocated only now, after the header was checked: at most one class of payload
                buffer = ByteArray(fragCount * LookupResponseBody.FRAGMENT_DATA)
            } else if (header.fragCount != fragCount) {
                return broken()
            }
            val buf = buffer ?: return broken()
            data.copyInto(
                buf,
                next * LookupResponseBody.FRAGMENT_DATA,
                LookupResponseBody.HEADER,
                LookupResponseBody.BODY_SIZE,
            )
            next++
            if (next < fragCount) return null
            buffer = null
            return when (status) {
                LookupStatus.FOUND ->
                    Attempt.Done(
                        AnswerFound(
                            buf.copyOfRange(
                                LookupSizeClass.ANSWER_HEADER,
                                LookupSizeClass.ANSWER_HEADER + length,
                            ),
                        ),
                    )
                LookupStatus.NOT_FOUND -> Attempt.Done(LookupResult.NotFound)
                LookupStatus.DISABLED, LookupStatus.UNSUPPORTED_VERSION, LookupStatus.UNSUPPORTED_OPERATION -> {
                    disabled.incrementAndGet()
                    Attempt.Next(Kind.UNSUPPORTED, LookupFailure.REFUSED)
                }
                LookupStatus.RATE_LIMITED, LookupStatus.TIMEOUT -> Attempt.Next(Kind.FAILURE, LookupFailure.REFUSED)
                // the client checked the key shape before sending (fetchBlock / resolveIpnsRecord), so MALFORMED
                // is a provable lie of the exit relay: 24-hour backoff and the next relay is asked
                LookupStatus.MALFORMED -> {
                    manipulated.incrementAndGet()
                    Attempt.Next(Kind.MANIPULATION, LookupFailure.MANIPULATED)
                }
                // the client can not check the size; another relay is asked, so one exit can not end the lookup
                LookupStatus.TOO_LARGE -> Attempt.Next(Kind.FAILURE, LookupFailure.REFUSED)
                // an unknown status: a deviation like any other
                else -> broken()
            }
        }
    }

    private fun finish(
        job: Job,
        result: LookupResult,
    ) {
        when (result) {
            is LookupResult.Found -> found.incrementAndGet()
            LookupResult.NotFound -> notFound.incrementAndGet()
            else -> failed.incrementAndGet()
        }
        val next: Job?
        synchronized(lock) {
            if (result == LookupResult.NotFound) {
                negative[job.cacheKey] = clock.millis() + config.negativeTtl.inWholeMilliseconds
            }
            byKey.remove(job.cacheKey, job)
            next = if (closed) null else queue.removeFirstOrNull()
            running = next
        }
        completeOff(job.result, result)
        if (next != null) {
            val task = Runnable { runJob(next) }
            if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        val pending =
            synchronized(lock) {
                val all = queue.toList()
                queue.clear()
                byKey.clear()
                negative.clear()
                all
            }
        pending.forEach { completeOff(it.result, LookupResult.Unavailable(LookupFailure.CLOSED)) }
        open.toList().forEach { runCatching { it.close() } }
        open.clear()
        runCatching { onClosed?.invoke() }
        logger.debug { "lookup client closed" }
    }

    private companion object {
        const val MAX_UNSUPPORTED_SHIFT = 10

        fun cacheKeyOf(
            op: LookupOperation,
            key: ByteArray,
        ): ByteBuffer {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(op.code.toByte())
            digest.update(key)
            return ByteBuffer.wrap(digest.digest())
        }
    }
}
