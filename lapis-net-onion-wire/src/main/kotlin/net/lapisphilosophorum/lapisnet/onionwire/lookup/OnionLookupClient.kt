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
import net.lapisphilosophorum.lapisnet.onion.OnionRelayLimits
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

/** The number of lookups a relay accepts on one circuit (`OnionRelayLimits.lookupRequestsPerCircuit`). */
internal val RELAY_LOOKUP_REQUESTS_PER_CIRCUIT: Int = OnionRelayLimits().lookupRequestsPerCircuit

/**
 * What a lookup is for (wave V0.10.0-J3). A circuit only ever carries lookups of ONE context, so the exit relay can not
 * link, say, a timeline post with a mailbox blob. [TIMELINE] lookups may share a circuit (up to
 * [OnionLookupClientConfig.requestsPerCircuitTimeline]); [MAILBOX] and [IPNS] always get a circuit of their own.
 */
enum class LookupContext { TIMELINE, MAILBOX, IPNS }

/** Client-side bounds of lookups through circuits (waves V0.10.0-J2 and J3). */
data class OnionLookupClientConfig(
    val buildTimeout: Duration = 20.seconds,
    /** From sending the request to the last fragment (the relay waits at least 1.5 s and looks up for up to 20 s). */
    val answerTimeout: Duration = 45.seconds,
    /**
     * Relays tried for one lookup, for all kinds of error together: a failure, a refusal, a manipulated answer and the
     * NOT_FOUND cross-check each use one attempt.
     */
    val maxAttempts: Int = 2,
    /** Lookups waiting behind the one that runs; the oldest is dropped beyond this. */
    val maxQueued: Int = 32,
    /** How long a NOT_FOUND confirmed by two relays is kept. */
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
     * minimum delay of 1.5 s). A later destroy only counts as a failure. Never applied to a reused circuit (its relay
     * has demonstrably answered a lookup already).
     */
    val legacyDestroyWindow: Duration = 1500.milliseconds,
    /**
     * Wave V0.10.0-J3 (Q15, confirmed by the user (2026-11-22); deviates from the earlier Q8 "1 by the client"): requests
     * on one TIMELINE circuit, sequential, one outstanding. Never more than the relay allows (4).
     */
    val requestsPerCircuitTimeline: Int = 4,
    /**
     * A reused circuit takes no new request once it is older than this minus [answerTimeout] and [buildTimeout] (the
     * relays close every circuit after 10 minutes; the answer must arrive before that). It is closed instead.
     */
    val circuitReuseMaxAge: Duration = 10.minutes,
    /** Negative TTL when NOT_FOUND could not be cross-checked at a second relay. */
    val negativeTtlUnconfirmed: Duration = 2.minutes,
    /** Of [maxQueued], at most this many TIMELINE lookups wait (the others keep room); capped at [maxQueued]. */
    val maxQueuedTimeline: Int = 24,
    /**
     * Pause before a lookup tries again when the governor answered POOL_FULL or RATE_LIMITED (the node's own circuits
     * fill the pool, or failed builds put it on a backoff, e.g. right after the start). The lookup keeps waiting this
     * way until its deadline; no attempt is used.
     */
    val admissionPause: Duration = 500.milliseconds,
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
        require(requestsPerCircuitTimeline in 1..RELAY_LOOKUP_REQUESTS_PER_CIRCUIT) {
            "requests per timeline circuit must be within the relay's limit"
        }
        require(circuitReuseMaxAge.isPositive()) { "circuit reuse age must be positive" }
        require(negativeTtlUnconfirmed.isPositive() && negativeTtlUnconfirmed <= negativeTtl) {
            "the unconfirmed negative TTL must be positive and at most the confirmed one"
        }
        require(maxQueuedTimeline > 0) { "the timeline queue bound must be positive" }
        require(admissionPause.isPositive()) { "the admission pause must be positive" }
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

    /**
     * Not found. [confirmed] is `true` when two different relays answered NOT_FOUND (wave V0.10.0-J3); `false` when
     * only one did and the cross-check at a second relay was not possible or did not end in an answer.
     */
    data class NotFound(
        val confirmed: Boolean,
    ) : LookupResult

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
    /** NOT_FOUND confirmed by two relays. */
    val notFound: Long,
    val negativeHits: Long,
    val manipulated: Long,
    val legacySuspected: Long,
    val disabled: Long,
    val failed: Long,
    val dropped: Long,
    val deduplicated: Long,
    /** NOT_FOUND from one relay only (cross-check impossible or without an answer). */
    val notFoundUnconfirmed: Long = 0,
    /** Answers that did not verify (the same number as [manipulated]). */
    val rejected: Long = 0,
    /** Requests sent on a circuit that had carried an earlier request. */
    val circuitsReused: Long = 0,
    /** Cross-checks of a NOT_FOUND started at a second relay. */
    val crossChecks: Long = 0,
    /** A second relay delivered what the first had answered NOT_FOUND for (no penalty for the first). */
    val notFoundContradicted: Long = 0,
    /** Pauses because the governor refused for now (pool full, rate limit or backoff); no attempt was counted. */
    val admissionPauses: Long = 0,
)

/**
 * Lookup counters for the node status (wave V0.10.0-J3): numbers only, no identities.
 *
 * [requested] counts every caller request that reached the queue logic, including those answered from the negative
 * cache and those merged into a running lookup; each lookup that ends counts exactly once in [found], [notFound]
 * (confirmed by two relays), [notFoundUnconfirmed] (one relay) or [failed] (unavailable, dropped, closed). So
 * `requested = found + notFound + notFoundUnconfirmed + failed + negative-cache hits + merged + in flight`.
 * [rejected] counts answers that did not verify (a lookup with a rejected answer may still end found).
 */
data class LookupStatusCounters(
    val requested: Long,
    val found: Long,
    val notFound: Long,
    val notFoundUnconfirmed: Long,
    val failed: Long,
    val rejected: Long,
    val relaysKnown: Int,
    val relaysAvailable: Int,
    val relaysOnBackoff: Int,
) {
    companion object {
        val ZERO = LookupStatusCounters(0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

/**
 * Client side of lookups through circuits (waves V0.10.0-J2 and J3): content blocks and IPNS records are fetched
 * through circuits of purpose [CircuitPurpose.LOOKUP] whose last hop is a LOOKUP relay. At most one lookup runs at a
 * time (the governor allows one lookup circuit and two builds per minute), identical keys of the same [LookupContext]
 * are merged, at most [OnionLookupClientConfig.maxQueued] wait (of them at most
 * [OnionLookupClientConfig.maxQueuedTimeline] timeline lookups; a full timeline queue drops its oldest timeline lookup,
 * never one of another context).
 *
 * **Circuit reuse (J3).** A circuit carries lookups of one context only. A [LookupContext.TIMELINE] circuit is kept
 * after a verified answer for the next queued lookup iff that one is a TIMELINE lookup too, its deadline has not passed,
 * it has not been answered NOT_FOUND by this exit, the circuit carried fewer than
 * [OnionLookupClientConfig.requestsPerCircuitTimeline] requests and is young enough
 * ([OnionLookupClientConfig.circuitReuseMaxAge]). Otherwise it is closed at once: there is no idle hold, because a held
 * circuit would block the single lookup slot of the governor for every other context. [LookupContext.MAILBOX] and
 * [LookupContext.IPNS] lookups use one circuit per request. The exit relay can link the lookups it carried on one
 * circuit (up to four timeline posts); see docs/anonymity.adoc.
 *
 * **Verification.** Every answer is verified here (block against its CID, record against the name's key) on every
 * request, also on a reused circuit: a relay that lies is put on a 24-hour backoff, its circuit is closed and the next
 * relay is asked. A circuit destroyed by the network within [OnionLookupClientConfig.legacyDestroyWindow] of the first
 * request and before the first answer fragment presumably ends at a relay older than wave J2; that relay gets a backoff
 * from 30 minutes up to 24 hours, as one that answers DISABLED. A later destroy, or any destroy of a reused circuit, is
 * a plain failure; a lost guard link or a local close is no verdict about the relay at all, and neither is the end of
 * the callers' deadline (the relay may still be looking up honestly).
 *
 * **NOT_FOUND (J3).** One relay's NOT_FOUND is cross-checked at a second relay (a different exit, through a new
 * circuit) as long as an attempt is left: two NOT_FOUND give [LookupResult.NotFound] with `confirmed = true` (negative
 * cache [OnionLookupClientConfig.negativeTtl]); a cross-check that is impossible or ends without an answer gives
 * `confirmed = false` (negative cache [OnionLookupClientConfig.negativeTtlUnconfirmed]). A NOT_FOUND contradicted by a
 * second relay is not penalised (it is not provably a lie). Fail closed: there is no path to content other than
 * [OnionCircuitFactory.build] with the circuit policy installed; without one, without relays or in lockdown the result
 * is [LookupResult.Unavailable].
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
    /** The relays counted for [statusCounters] (side-effect free); defaults to [lookupRelays]. */
    private val relayCensus: (() -> List<OnionRelayDescriptor>)? = null,
) : AutoCloseable,
    LookupBackend {
    private class Job(
        val op: LookupOperation,
        val key: ByteArray,
        val cacheKey: ByteBuffer,
        val context: LookupContext,
        deadlineMillis: Long,
        val result: CompletableFuture<LookupResult> = CompletableFuture(),
    ) {
        /** The latest deadline of all callers merged into this job (raised under the client lock, read anywhere). */
        @Volatile var deadlineMillis: Long = deadlineMillis

        /** Exit relays that already answered NOT_FOUND for this job (the cross-check goes elsewhere). */
        val excludedExits: MutableSet<Secp256k1PublicKey> = ConcurrentHashMap.newKeySet()

        @Volatile var notFoundCount: Int = 0

        /** Attempts begun, for all kinds of error together (bounded by [OnionLookupClientConfig.maxAttempts]). */
        @Volatile var attemptsUsed: Int = 0

        @Volatile var lastReason: LookupFailure = LookupFailure.NO_RELAY
    }

    /** A circuit that may carry further lookups of its [context]. Only the running job touches it. */
    private class ReusableCircuit(
        val circuit: OnionClientCircuit,
        val exit: OnionRelayDescriptor,
        val context: LookupContext,
        val openedAtMillis: Long,
    ) {
        @Volatile var requestsSent: Int = 0
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

        /**
         * The governor refused for now (POOL_FULL: the node's own circuits fill the pool; RATE_LIMITED: the build budget
         * or the backoff after failed builds): try again shortly, no attempt used, no verdict about a relay.
         */
        data object Pause : Attempt
    }

    /** An [Attempt] plus the circuit when it is still open after a verified answer (a candidate for reuse). */
    private class Outcome(
        val attempt: Attempt,
        val keep: ReusableCircuit?,
    )

    private class NegativeEntry(
        val untilMillis: Long,
        val confirmed: Boolean,
    )

    private val lock = Any()
    private val queue = ArrayDeque<Job>()
    private val byKey = HashMap<ByteBuffer, Job>()
    private var running: Job? = null

    /** The circuit kept for the next (already chosen) TIMELINE job; at most one (the governor allows one). */
    private var current: ReusableCircuit? = null
    private val negative =
        object : LinkedHashMap<ByteBuffer, NegativeEntry>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteBuffer, NegativeEntry>): Boolean =
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
    private val notFoundUnconfirmed = AtomicLong()
    private val negativeHits = AtomicLong()
    private val manipulated = AtomicLong()
    private val legacySuspected = AtomicLong()
    private val disabled = AtomicLong()
    private val failed = AtomicLong()
    private val dropped = AtomicLong()
    private val deduplicated = AtomicLong()
    private val circuitsReused = AtomicLong()
    private val crossChecks = AtomicLong()
    private val notFoundContradicted = AtomicLong()
    private val admissionPauses = AtomicLong()

    fun statsForTest(): LookupClientStats =
        LookupClientStats(
            requested = requested.get(),
            circuitsBuilt = circuitsBuilt.get(),
            found = found.get(),
            notFound = notFound.get(),
            negativeHits = negativeHits.get(),
            manipulated = manipulated.get(),
            legacySuspected = legacySuspected.get(),
            disabled = disabled.get(),
            failed = failed.get(),
            dropped = dropped.get(),
            deduplicated = deduplicated.get(),
            notFoundUnconfirmed = notFoundUnconfirmed.get(),
            rejected = manipulated.get(),
            circuitsReused = circuitsReused.get(),
            crossChecks = crossChecks.get(),
            notFoundContradicted = notFoundContradicted.get(),
            admissionPauses = admissionPauses.get(),
        )

    /** The counters of the node status (see [LookupStatusCounters]); never throws, contains no identities. */
    fun statusCounters(): LookupStatusCounters {
        val now = clock.millis()
        val relays =
            runCatching { (relayCensus ?: lookupRelays)().distinctBy { it.identity } }.getOrDefault(emptyList())
        val onBackoff = relays.count { (backoff[it.identity]?.untilMillis ?: 0L) > now }
        return LookupStatusCounters(
            requested = requested.get(),
            found = found.get(),
            notFound = notFound.get(),
            notFoundUnconfirmed = notFoundUnconfirmed.get(),
            failed = failed.get(),
            rejected = manipulated.get(),
            relaysKnown = relays.size,
            relaysAvailable = relays.size - onBackoff,
            relaysOnBackoff = onBackoff,
        )
    }

    /** Circuits currently open for lookups (leak checks). */
    fun openCircuits(): Int = open.size

    /** `true` while [relay] is on a backoff (tests). */
    internal fun inBackoff(relay: Secp256k1PublicKey): Boolean = (backoff[relay]?.untilMillis ?: 0L) > clock.millis()

    /**
     * Fetches the raw block [cid] (CIDv1, raw, SHA-256 only) as a [LookupContext.MAILBOX] lookup: one request per
     * circuit (the conservative default). Never throws.
     */
    override fun fetchBlock(
        cid: Cid,
        timeout: Duration,
    ): CompletableFuture<LookupResult> = fetchBlock(cid, timeout, LookupContext.MAILBOX)

    /** Fetches the raw block [cid] in [context]. Never throws. */
    override fun fetchBlock(
        cid: Cid,
        timeout: Duration,
        context: LookupContext,
    ): CompletableFuture<LookupResult> {
        val key =
            RemoteContentVerifier.rawSha256CidBytes(cid) ?: return done(LookupResult.Unavailable(LookupFailure.REFUSED))
        return submit(LookupOperation.GET_BLOCK, key, timeout, context)
    }

    /**
     * Fetches the raw IPNS record behind [routingKey] (`/ipns/<Ed25519 multihash>`), always as a [LookupContext.IPNS]
     * lookup on a circuit of its own. Never throws.
     */
    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): CompletableFuture<LookupResult> {
        if (!RemoteContentVerifier.isIpnsRoutingKey(routingKey)) {
            return done(LookupResult.Unavailable(LookupFailure.REFUSED))
        }
        return submit(LookupOperation.GET_IPNS_RECORD, routingKey.copyOf(), timeout, LookupContext.IPNS)
    }

    private fun done(r: LookupResult): CompletableFuture<LookupResult> = CompletableFuture.completedFuture(r)

    private fun requestLimit(context: LookupContext): Int =
        if (context == LookupContext.TIMELINE) config.requestsPerCircuitTimeline else 1

    private fun submit(
        op: LookupOperation,
        key: ByteArray,
        timeout: Duration,
        context: LookupContext,
    ): CompletableFuture<LookupResult> {
        requested.incrementAndGet()
        if (closed) {
            failed.incrementAndGet()
            return done(LookupResult.Unavailable(LookupFailure.CLOSED))
        }
        if (!timeout.isPositive()) {
            failed.incrementAndGet()
            return done(LookupResult.Unavailable(LookupFailure.TIMEOUT))
        }
        val now = clock.millis()
        val cacheKey = cacheKeyOf(op, key, context)
        val evicted = ArrayList<Job>(2)
        var start = false
        val job: Job =
            synchronized(lock) {
                val neg = negative[cacheKey]
                if (neg != null && neg.untilMillis > now) {
                    negativeHits.incrementAndGet()
                    return done(LookupResult.NotFound(neg.confirmed))
                }
                if (neg != null) negative.remove(cacheKey)
                val existing = byKey[cacheKey]
                if (existing != null) {
                    deduplicated.incrementAndGet()
                    // the job runs as long as its most patient caller; each caller keeps its own timeout below
                    existing.deadlineMillis = maxOf(existing.deadlineMillis, now + timeout.inWholeMilliseconds)
                    existing
                } else {
                    val j = Job(op, key, cacheKey, context, now + timeout.inWholeMilliseconds)
                    byKey[cacheKey] = j
                    if (running == null) {
                        running = j
                        start = true
                    } else {
                        if (context == LookupContext.TIMELINE) {
                            val bound = minOf(config.maxQueuedTimeline, config.maxQueued)
                            if (queue.count { it.context == LookupContext.TIMELINE } >= bound) {
                                val oldest = queue.first { it.context == LookupContext.TIMELINE }
                                queue.remove(oldest)
                                evicted += oldest
                            }
                        }
                        if (queue.size >= config.maxQueued) evicted += queue.removeFirst()
                        evicted.forEach { byKey.remove(it.cacheKey) }
                        queue.addLast(j)
                    }
                    j
                }
            }
        evicted.forEach {
            dropped.incrementAndGet()
            failed.incrementAndGet()
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

    private val offLoopExecutor =
        java.util.concurrent.Executor { task ->
            if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
        }

    /** Closes [rc] and forgets it (idempotent). */
    private fun discard(rc: ReusableCircuit?) {
        if (rc == null) return
        rc.circuit.onClosed = {}
        rc.circuit.onInbound = {}
        open -= rc.circuit
        runCatching { rc.circuit.close() }
    }

    private fun discardWarm(warm: WarmCircuitPool.Prebuilt?) {
        if (warm != null) runCatching { warm.circuit.close() }
    }

    /** Requests a circuit of this age or older take no new request (the answer must arrive before the relay drops it). */
    private val reuseAgeLimitMillis: Long =
        (
            config.circuitReuseMaxAge.inWholeMilliseconds - config.answerTimeout.inWholeMilliseconds -
                config.buildTimeout.inWholeMilliseconds
        ).coerceAtLeast(0)

    /** May [rc] carry the next request of [job]? (No blocking calls; used under [lock].) */
    private fun reusableFor(
        rc: ReusableCircuit,
        job: Job,
        now: Long,
    ): Boolean =
        rc.context == LookupContext.TIMELINE &&
            job.context == LookupContext.TIMELINE &&
            rc.requestsSent < requestLimit(rc.context) &&
            now - rc.openedAtMillis < reuseAgeLimitMillis &&
            !rc.circuit.isClosed &&
            rc.exit.identity !in job.excludedExits &&
            (backoff[rc.exit.identity]?.untilMillis ?: 0L) <= now &&
            now < job.deadlineMillis

    /** The outcome when [job] can not go on: unconfirmed NOT_FOUND if a relay answered so, otherwise [reason]. */
    private fun exhausted(
        job: Job,
        reason: LookupFailure,
    ): LookupResult =
        if (job.notFoundCount > 0 && reason != LookupFailure.CLOSED) {
            LookupResult.NotFound(confirmed = false)
        } else {
            LookupResult.Unavailable(reason)
        }

    private fun runJob(job: Job) {
        val reused = synchronized(lock) { current.also { current = null } }
        if (closed) {
            discard(reused)
            return finish(job, LookupResult.Unavailable(LookupFailure.CLOSED))
        }
        if (clock.millis() >= job.deadlineMillis) {
            discard(reused)
            return finish(job, exhausted(job, LookupFailure.TIMEOUT))
        }
        if (factory.policy == null) {
            // fail closed: never a circuit without the anonymity-mode policy (governor, path length, guards)
            discard(reused)
            return finish(job, LookupResult.Unavailable(LookupFailure.ADMISSION))
        }
        val now = clock.millis()
        if (reused != null) {
            if (synchronized(lock) { reusableFor(reused, job, now) }) {
                circuitsReused.incrementAndGet()
                startAttempt(job, reused.exit, CompletableFuture.completedFuture(reused))
                return
            }
            discard(reused)
        }
        val warm = runCatching { prebuilt?.invoke(CircuitPurpose.LOOKUP) }.getOrNull()
        val warmUsable =
            warm != null &&
                !warm.circuit.isClosed &&
                warm.lastHop.identity !in job.excludedExits &&
                (backoff[warm.lastHop.identity]?.untilMillis ?: 0L) <= now
        if (warm != null && warmUsable) {
            circuitsBuilt.incrementAndGet()
            val rc = ReusableCircuit(warm.circuit, warm.lastHop, job.context, minOf(warm.builtAtMillis, now))
            startAttempt(job, warm.lastHop, CompletableFuture.completedFuture(rc))
            return
        }
        discardWarm(warm)
        val relay =
            try {
                lookupRelays()
                    .filter { (backoff[it.identity]?.untilMillis ?: 0L) <= now && it.identity !in job.excludedExits }
                    .distinctBy { it.identity }
                    .shuffled(random)
                    .firstOrNull()
            } catch (e: RuntimeException) {
                null
            } ?: run {
                logger.debug { "lookup ended: no usable lookup relay" }
                return finish(job, exhausted(job, job.lastReason))
            }
        val openedAt = clock.millis()
        val built: CompletableFuture<ReusableCircuit> =
            try {
                factory
                    .build(paths.pathEndingAt(relay, CircuitPurpose.LOOKUP), config.buildTimeout, CircuitPurpose.LOOKUP)
                    .thenApply { c ->
                        circuitsBuilt.incrementAndGet()
                        ReusableCircuit(c, relay, job.context, openedAt)
                    }
            } catch (e: RuntimeException) {
                CompletableFuture.failedFuture(e)
            }
        startAttempt(job, relay, built)
    }

    private fun startAttempt(
        job: Job,
        relay: OnionRelayDescriptor,
        circuitFuture: CompletableFuture<ReusableCircuit>,
    ) {
        job.attemptsUsed++
        if (job.notFoundCount > 0) crossChecks.incrementAndGet()
        circuitFuture
            .handle { rc, error ->
                if (error != null || rc == null) {
                    val cause =
                        generateSequence(error) { it.cause }.firstOrNull { it is CircuitAdmissionException }
                            as CircuitAdmissionException?
                    if (cause?.kind in TRANSIENT_ADMISSION) {
                        // transient: right after the start the node's own circuits (introduction points, publications,
                        // warm pool) can fill the pool, and failed builds put the governor on a backoff; the lookup
                        // waits within its deadline. LOCKED and PATH_TOO_SHORT still end it at once (fail closed).
                        CompletableFuture.completedFuture(Outcome(Attempt.Pause, null))
                    } else if (cause != null) {
                        logger.debug { "lookup circuit refused by the circuit policy: ${cause.kind}" }
                        CompletableFuture.completedFuture(Outcome(Attempt.Stop(LookupFailure.ADMISSION), null))
                    } else {
                        CompletableFuture.completedFuture(
                            Outcome(Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT), null),
                        )
                    }
                } else {
                    exchange(rc, job)
                }
            }.thenCompose { it }
            .exceptionally { Outcome(Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT), null) }
            .thenAcceptAsync({ outcome -> afterAttempt(job, relay, outcome) }, offLoopExecutor)
    }

    /** What happens after one attempt: finish, retry (another relay) or cross-check, and whether the circuit is kept. */
    private fun afterAttempt(
        job: Job,
        relay: OnionRelayDescriptor,
        outcome: Outcome,
    ) {
        var result: LookupResult? = null
        var retry = false
        when (val a = outcome.attempt) {
            is Attempt.Done -> {
                backoff.remove(relay.identity)
                when (val r = a.result) {
                    is LookupResult.NotFound -> {
                        job.notFoundCount++
                        job.excludedExits += relay.identity
                        when {
                            job.notFoundCount >= 2 -> result = LookupResult.NotFound(confirmed = true)
                            job.attemptsUsed < config.maxAttempts && !closed -> retry = true
                            else -> result = LookupResult.NotFound(confirmed = false)
                        }
                    }
                    is LookupResult.Found -> {
                        // the first relay's NOT_FOUND was contradicted: no penalty (a Bitswap gap, a provider walk)
                        if (job.notFoundCount > 0) notFoundContradicted.incrementAndGet()
                        result = r
                    }
                    else -> result = r
                }
            }
            is Attempt.Stop -> result = exhausted(job, a.reason)
            is Attempt.Pause -> {
                // no relay was involved: the attempt is given back and the same job tries again after a pause
                job.attemptsUsed--
                if (job.notFoundCount > 0) crossChecks.decrementAndGet()
                admissionPauses.incrementAndGet()
                if (closed) {
                    result = LookupResult.Unavailable(LookupFailure.CLOSED)
                } else {
                    discard(outcome.keep)
                    CompletableFuture
                        .delayedExecutor(config.admissionPause.inWholeMilliseconds, TimeUnit.MILLISECONDS)
                        .execute { offLoopExecutor.execute { runJob(job) } }
                    return
                }
            }
            is Attempt.Next -> {
                if (!closed && a.kind != Kind.NONE) penalise(relay.identity, a.kind)
                job.lastReason = a.reason
                if (job.attemptsUsed < config.maxAttempts &&
                    !closed
                ) {
                    retry = true
                } else {
                    result = exhausted(job, a.reason)
                }
            }
        }
        if (result != null) {
            finish(job, result, outcome.keep)
        } else {
            check(retry)
            discard(outcome.keep)
            // the same job goes on at once (it stays the running job): a retry or the NOT_FOUND cross-check
            val task = Runnable { runJob(job) }
            if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
        }
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

    /**
     * One request on [rc]. The circuit stays open only after a verified answer (FOUND or NOT_FOUND); in every other case
     * (manipulation, timeout, refusal, destroy, deadline) it is closed here.
     */
    private fun exchange(
        rc: ReusableCircuit,
        job: Job,
    ): CompletableFuture<Outcome> {
        val circuit = rc.circuit
        open += circuit
        if (closed) {
            discard(rc)
            return CompletableFuture.completedFuture(Outcome(Attempt.Stop(LookupFailure.CLOSED), null))
        }
        if (clock.millis() >= job.deadlineMillis) {
            // the build outlasted the callers (e.g. a delayed admission): no request, no verdict about the relay
            discard(rc)
            return CompletableFuture.completedFuture(Outcome(Attempt.Stop(LookupFailure.TIMEOUT), null))
        }
        if (rc.requestsSent >= requestLimit(rc.context) || rc.context != job.context) {
            // never more requests than the relay allows, never two contexts on one circuit: close, never send
            discard(rc)
            return CompletableFuture.completedFuture(Outcome(Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT), null))
        }
        rc.requestsSent++
        val reused = rc.requestsSent > 1
        val requestId = random.nextInt(256)
        val answer = CompletableFuture<Attempt>()
        // a fresh assembler per request; the previous one finished with its last fragment before this request
        val assembler = Assembler(requestId)
        circuit.onInbound = { msg ->
            // circuit callback (event loop): only reassembly here; verification runs off the loop
            val outcome = assembler.accept(msg)
            if (outcome != null) answer.complete(outcome)
        }
        val sentAt = AtomicLong(Long.MAX_VALUE)
        circuit.onClosed = {
            answer.complete(closedOutcome(circuit, assembler.started, clock.millis() - sentAt.get(), reused))
        }
        val body = LookupRequestBody.encode(requestId, job.op, job.key, random)
        sentAt.set(clock.millis())
        check(rc.requestsSent <= requestLimit(rc.context)) { "lookup request limit per circuit exceeded" }
        if (circuit.isClosed || !circuit.send(RelayMessage(RelayCommand.LOOKUP_REQUEST, 0, body))) {
            discard(rc)
            // the link or this side refused the cell: nothing reached the relay, no verdict about it
            return CompletableFuture.completedFuture(Outcome(Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT), null))
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
                circuit.onInbound = {}
                val verified =
                    if (a is Attempt.Done &&
                        a.result is AnswerFound
                    ) {
                        verify(job, a.result.content)
                    } else {
                        a
                    }
                if (verified is Attempt.Done && !closed && !circuit.isClosed) {
                    Outcome(verified, rc)
                } else {
                    discard(rc)
                    Outcome(verified, null)
                }
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
     * shortly after the FIRST request of a circuit and before any answer fragment looks like a relay without the LOOKUP
     * role. On a reused circuit the relay has answered a lookup already, so a destroy there is a plain failure.
     */
    private fun closedOutcome(
        circuit: OnionClientCircuit,
        started: Boolean,
        sinceSentMillis: Long,
        reused: Boolean,
    ): Attempt =
        when {
            // this client is closing: no verdict about the relay
            closed -> Attempt.Stop(LookupFailure.CLOSED)
            // the guard link broke or this side closed: the last hop is not at fault
            circuit.closeCause != OnionClientCircuit.CloseCause.NETWORK_DESTROY ->
                Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT)
            !reused && !started && sinceSentMillis in 0 until config.legacyDestroyWindow.inWholeMilliseconds -> {
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
            // a fragment of an older request on a reused circuit is a deviation like any other
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
                // one relay's NOT_FOUND; the client decides whether it is confirmed (cross-check)
                LookupStatus.NOT_FOUND -> Attempt.Done(LookupResult.NotFound(confirmed = false))
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
        keep: ReusableCircuit? = null,
    ) {
        when (result) {
            is LookupResult.Found -> found.incrementAndGet()
            is LookupResult.NotFound ->
                if (result.confirmed) notFound.incrementAndGet() else notFoundUnconfirmed.incrementAndGet()
            else -> failed.incrementAndGet()
        }
        val next: Job?
        var kept = false
        synchronized(lock) {
            if (result is LookupResult.NotFound) {
                val now = clock.millis()
                val existing = negative[job.cacheKey]
                // an unconfirmed result never overrides a confirmed entry that is still valid
                if (!(existing != null && existing.confirmed && !result.confirmed && existing.untilMillis > now)) {
                    val ttl = if (result.confirmed) config.negativeTtl else config.negativeTtlUnconfirmed
                    negative[job.cacheKey] = NegativeEntry(now + ttl.inWholeMilliseconds, result.confirmed)
                }
            }
            byKey.remove(job.cacheKey, job)
            next = if (closed) null else queue.removeFirstOrNull()
            running = next
            // reuse only for a TIMELINE lookup that is already queued; otherwise the circuit is closed at once
            if (keep != null && next != null && reusableFor(keep, next, clock.millis())) {
                current = keep
                kept = true
            }
        }
        if (!kept) discard(keep)
        completeOff(job.result, result)
        if (next != null) {
            val task = Runnable { runJob(next) }
            if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        val (pending, held) =
            synchronized(lock) {
                val all = queue.toList()
                queue.clear()
                byKey.clear()
                negative.clear()
                val c = current
                current = null
                all to c
            }
        pending.forEach {
            failed.incrementAndGet()
            completeOff(it.result, LookupResult.Unavailable(LookupFailure.CLOSED))
        }
        discard(held)
        open.toList().forEach { runCatching { it.close() } }
        open.clear()
        runCatching { onClosed?.invoke() }
        logger.debug { "lookup client closed" }
    }

    private companion object {
        const val MAX_UNSUPPORTED_SHIFT = 10

        /** Governor refusals that pass: the lookup pauses instead of failing. */
        val TRANSIENT_ADMISSION =
            setOf(CircuitAdmissionException.Kind.POOL_FULL, CircuitAdmissionException.Kind.RATE_LIMITED)

        fun cacheKeyOf(
            op: LookupOperation,
            key: ByteArray,
            context: LookupContext,
        ): ByteBuffer {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(op.code.toByte())
            // two contexts asking for the same key are never merged (merging would couple them)
            digest.update(context.ordinal.toByte())
            digest.update(key)
            return ByteBuffer.wrap(digest.digest())
        }
    }
}
