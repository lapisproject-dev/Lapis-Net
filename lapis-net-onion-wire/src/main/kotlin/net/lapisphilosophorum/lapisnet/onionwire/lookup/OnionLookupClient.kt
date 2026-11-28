@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LookupBatchRequestBody
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

/** The number of lookup items (keys over all requests) a relay accepts on one circuit (wave Q16). */
internal val RELAY_LOOKUP_ITEMS_PER_CIRCUIT: Int = OnionRelayLimits().lookupItemsPerCircuit

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
    /**
     * Wave Q16 (LOOKUP version 2; provisional, not measured in a pilot): the most TIMELINE block lookups sent to one exit
     * in ONE request. 1 switches batching off (every lookup is a version-1 request, as before Q16). A group of one is
     * always sent as a version-1 request.
     */
    val batchItemsTimeline: Int = 4,
    /**
     * Wave Q16: the most distinct keys one TIMELINE circuit carries for its exit relay, over all its requests (the
     * linkability budget; with 4 it is what Q15 allowed). At least [batchItemsTimeline], at most what a relay accepts.
     */
    val itemsPerCircuitTimeline: Int = 4,
    /** Wave Q16: how long an exit that answered UNSUPPORTED_VERSION to a batch is sent version-1 requests only (memory only). */
    val v1OnlyMemoTtl: Duration = 6.hours,
    val v1OnlyMemoEntries: Int = 1024,
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
        require(batchItemsTimeline in 1..LookupBatchRequestBody.MAX_ITEMS) { "batch size out of range" }
        require(itemsPerCircuitTimeline in batchItemsTimeline..RELAY_LOOKUP_ITEMS_PER_CIRCUIT) {
            "items per timeline circuit must be within [batch size, the relay's item limit]"
        }
        require(v1OnlyMemoTtl.isPositive() && v1OnlyMemoEntries > 0) { "the version-1-only memo must be positive" }
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
    /** Version-2 requests (batches) sent, and the keys in them (wave Q16). */
    val batchesSent: Long = 0,
    val batchItemsSent: Long = 0,
    /** Batches answered UNSUPPORTED_VERSION: the group went on as version-1 requests, without penalty. */
    val v1Fallbacks: Long = 0,
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

        /** Exits that refused this job for now (rate limit, timeout, too large, disabled): tried again elsewhere. */
        val avoidExits: MutableSet<Secp256k1PublicKey> = ConcurrentHashMap.newKeySet()
    }

    /** A circuit that may carry further lookups of its [context]. Only the running job touches it. */
    private class ReusableCircuit(
        val circuit: OnionClientCircuit,
        val exit: OnionRelayDescriptor,
        val context: LookupContext,
        val openedAtMillis: Long,
    ) {
        @Volatile var requestsSent: Int = 0

        /** The keys this exit has seen on this circuit (the linkability budget of wave Q16). Guarded by the client lock. */
        val seen: MutableSet<ByteBuffer> = HashSet()
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

        /** The attempt was a batch; its own continuation settles every job (wave Q16). */
        data object Handled : Attempt
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

    /** Jobs of a finished batch that go on before the queue (wave Q16); not counted against the queue bounds. */
    private val retryHead = ArrayDeque<Job>()

    /** Exits known to answer version-1 only, with the end of the memo. Memory only, bounded. */
    private val v1OnlyExits =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > config.v1OnlyMemoEntries
        }

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
    private val batchesSent = AtomicLong()
    private val batchItemsSent = AtomicLong()
    private val v1Fallbacks = AtomicLong()

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
            batchesSent = batchesSent.get(),
            batchItemsSent = batchItemsSent.get(),
            v1Fallbacks = v1Fallbacks.get(),
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
            (job.cacheKey in rc.seen || rc.seen.size < config.itemsPerCircuitTimeline) &&
            now - rc.openedAtMillis < reuseAgeLimitMillis &&
            !rc.circuit.isClosed &&
            rc.exit.identity !in job.excludedExits &&
            rc.exit.identity !in job.avoidExits &&
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
                warm.lastHop.identity !in job.avoidExits &&
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
                    .filter {
                        (backoff[it.identity]?.untilMillis ?: 0L) <= now &&
                            it.identity !in job.excludedExits &&
                            it.identity !in job.avoidExits
                    }.distinctBy { it.identity }
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
                    exchangeOrBatch(rc, job, relay)
                }
            }.thenCompose { it }
            .exceptionally { Outcome(Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT), null) }
            .thenAcceptAsync({ outcome -> afterAttempt(job, relay, outcome) }, offLoopExecutor)
    }

    /** What a job does next after one attempt: a [result], or a retry (the job goes on at another relay). */
    private class Decision(
        val result: LookupResult?,
        val retry: Boolean,
    )

    /** The verdict about one job after one attempt at [relay]. No pause here (see [afterAttempt]). */
    private fun decide(
        job: Job,
        relay: OnionRelayDescriptor,
        a: Attempt,
    ): Decision {
        var result: LookupResult? = null
        var retry = false
        when (a) {
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
            is Attempt.Pause, is Attempt.Handled -> error("not a verdict")
        }
        return Decision(result, retry)
    }

    /** What happens after one attempt: finish, retry (another relay) or cross-check, and whether the circuit is kept. */
    private fun afterAttempt(
        job: Job,
        relay: OnionRelayDescriptor,
        outcome: Outcome,
    ) {
        when (outcome.attempt) {
            is Attempt.Handled -> return
            is Attempt.Pause -> {
                // no relay was involved: the attempt is given back and the same job tries again after a pause
                job.attemptsUsed--
                if (job.notFoundCount > 0) crossChecks.decrementAndGet()
                admissionPauses.incrementAndGet()
                if (closed) {
                    finish(job, LookupResult.Unavailable(LookupFailure.CLOSED), outcome.keep)
                } else {
                    discard(outcome.keep)
                    CompletableFuture
                        .delayedExecutor(config.admissionPause.inWholeMilliseconds, TimeUnit.MILLISECONDS)
                        .execute { offLoopExecutor.execute { runJob(job) } }
                }
                return
            }
            else -> Unit
        }
        val d = decide(job, relay, outcome.attempt)
        val result = d.result
        if (result != null) {
            finish(job, result, outcome.keep)
        } else {
            check(d.retry)
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
        if (rc.requestsSent >= requestLimit(rc.context) ||
            rc.context != job.context ||
            synchronized(lock) { job.cacheKey !in rc.seen && rc.seen.size >= config.itemsPerCircuitTimeline }
        ) {
            // never more requests than the relay allows, never two contexts on one circuit: close, never send
            discard(rc)
            return CompletableFuture.completedFuture(Outcome(Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT), null))
        }
        rc.requestsSent++
        synchronized(lock) { rc.seen += job.cacheKey }
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
    ) = armDeadline({ job.deadlineMillis }, answer, Attempt.Stop(LookupFailure.TIMEOUT))

    private fun <T> armDeadline(
        deadline: () -> Long,
        answer: CompletableFuture<T>,
        expired: T,
    ) {
        if (answer.isDone) return
        val remaining = deadline() - clock.millis()
        if (remaining <= 0) {
            answer.complete(expired)
            return
        }
        CompletableFuture
            .delayedExecutor(remaining, TimeUnit.MILLISECONDS)
            .execute { armDeadline(deadline, answer, expired) }
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

    // ---------------------------------------------------------------------------------------------------------------
    // Wave Q16: batches (LOOKUP version 2)
    // ---------------------------------------------------------------------------------------------------------------

    /** What a batch exchange ended in, before the per-job verdicts. */
    private sealed interface BatchEnd {
        /** The complete, still unverified answer. */
        class Raw(
            val items: List<BatchAssembler.Item>,
        ) : BatchEnd

        /** The answers after verification: one [Attempt] per job, in group order. */
        class Items(
            val attempts: List<Attempt>,
            /** The one verdict about the relay, applied after the per-item verdicts (a verified item must not clear it). */
            val penalty: Kind? = null,
        ) : BatchEnd

        /** The exit does not know version 2 (it answered UNSUPPORTED_VERSION in the version-1 framing). */
        data object V1Only : BatchEnd

        /** One verdict for the whole batch (a failure, a refusal of the whole batch, a manipulation, a deadline, closed). */
        class Whole(
            val attempt: Attempt,
        ) : BatchEnd
    }

    private class BatchResult(
        val end: BatchEnd,
        val keep: ReusableCircuit?,
    )

    private fun v1OnlyKnown(
        exit: Secp256k1PublicKey,
        now: Long,
    ): Boolean =
        synchronized(lock) {
            val until = v1OnlyExits[exit] ?: return@synchronized false
            if (until <= now) {
                v1OnlyExits.remove(exit)
                false
            } else {
                true
            }
        }

    /**
     * Sends [job] alone as a version-1 request, or together with waiting TIMELINE block lookups as one version-2 batch.
     * Only TIMELINE block lookups are batched (MAILBOX and IPNS keep a circuit each), only to an exit that is not
     * known to be version-1 only, only up to the batch size and the keys this circuit may still show its exit. A group
     * of one is always a version-1 request.
     */
    private fun exchangeOrBatch(
        rc: ReusableCircuit,
        job: Job,
        relay: OnionRelayDescriptor,
    ): CompletableFuture<Outcome> {
        val members = gatherMembers(rc, job)
        if (members.isEmpty()) return exchange(rc, job)
        val group = ArrayList<Job>(members.size + 1)
        group += job
        group += members
        exchangeBatch(rc, group)
            .exceptionally { BatchResult(BatchEnd.Whole(Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT)), null) }
            .thenAcceptAsync({ r ->
                try {
                    afterBatch(group, relay, r)
                } catch (e: RuntimeException) {
                    logger.debug { "lookup batch failed: ${e.javaClass.simpleName}" }
                    discard(r.keep)
                    group.forEach { j -> settleMember(j, LookupResult.Unavailable(LookupFailure.TIMEOUT)) }
                }
            }, offLoopExecutor)
        return CompletableFuture.completedFuture(Outcome(Attempt.Handled, null))
    }

    /** Takes the jobs that join [job] in a batch to [rc]'s exit out of the retry list and the queue. */
    private fun gatherMembers(
        rc: ReusableCircuit,
        job: Job,
    ): List<Job> {
        if (config.batchItemsTimeline <= 1 || closed) return emptyList()
        if (job.context != LookupContext.TIMELINE || job.op != LookupOperation.GET_BLOCK) return emptyList()
        if (rc.context != LookupContext.TIMELINE) return emptyList()
        val now = clock.millis()
        val exit = rc.exit.identity
        return synchronized(lock) {
            if (v1OnlyKnown(exit, now) || rc.requestsSent >= requestLimit(rc.context) || job.cacheKey in rc.seen) {
                return@synchronized emptyList()
            }
            val cap = minOf(config.batchItemsTimeline, config.itemsPerCircuitTimeline - rc.seen.size)
            if (cap < 2) return@synchronized emptyList()
            val picked = ArrayList<Job>(cap - 1)

            fun eligible(m: Job): Boolean =
                m.context == LookupContext.TIMELINE &&
                    m.op == LookupOperation.GET_BLOCK &&
                    now < m.deadlineMillis &&
                    exit !in m.excludedExits &&
                    exit !in m.avoidExits &&
                    m.attemptsUsed < config.maxAttempts

            for (source in listOf(retryHead, queue)) {
                val it = source.iterator()
                while (it.hasNext() && picked.size < cap - 1) {
                    val m = it.next()
                    if (eligible(m)) {
                        it.remove()
                        picked += m
                    }
                }
            }
            picked.forEach { m ->
                m.attemptsUsed++
                if (m.notFoundCount > 0) crossChecks.incrementAndGet()
            }
            picked
        }
    }

    /** One version-2 request for [group] on [rc]; the circuit stays open only after verified answers or a version-1 fallback. */
    private fun exchangeBatch(
        rc: ReusableCircuit,
        group: List<Job>,
    ): CompletableFuture<BatchResult> {
        val circuit = rc.circuit
        open += circuit

        fun whole(a: Attempt) = CompletableFuture.completedFuture(BatchResult(BatchEnd.Whole(a), null))
        if (closed) {
            discard(rc)
            return whole(Attempt.Stop(LookupFailure.CLOSED))
        }
        if (clock.millis() >= group.maxOf { it.deadlineMillis }) {
            discard(rc)
            return whole(Attempt.Stop(LookupFailure.TIMEOUT))
        }
        if (rc.requestsSent >= requestLimit(rc.context) ||
            group.any { it.context != rc.context } ||
            synchronized(lock) {
                rc.seen.size + group.count { it.cacheKey !in rc.seen } > config.itemsPerCircuitTimeline
            }
        ) {
            // never more than the relay allows, never two contexts on one circuit: close, never send
            discard(rc)
            return whole(Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT))
        }
        rc.requestsSent++
        synchronized(lock) { rc.seen += group.map { it.cacheKey } }
        batchesSent.incrementAndGet()
        batchItemsSent.addAndGet(group.size.toLong())
        val reused = rc.requestsSent > 1
        val requestId = random.nextInt(256)
        val answer = CompletableFuture<BatchEnd>()
        val assembler = BatchAssembler(requestId, group.size)
        circuit.onInbound = { msg ->
            // circuit callback (event loop): only reassembly here; verification runs off the loop
            when (val r = assembler.accept(msg)) {
                null -> Unit
                is BatchAssembler.Result.Complete -> answer.complete(BatchEnd.Raw(r.items))
                BatchAssembler.Result.V1Only -> answer.complete(BatchEnd.V1Only)
                BatchAssembler.Result.WholeRefused ->
                    answer.complete(BatchEnd.Whole(Attempt.Next(Kind.FAILURE, LookupFailure.REFUSED)))
                BatchAssembler.Result.Broken -> {
                    manipulated.incrementAndGet()
                    answer.complete(BatchEnd.Whole(Attempt.Next(Kind.MANIPULATION, LookupFailure.MANIPULATED)))
                }
            }
        }
        val sentAt = AtomicLong(Long.MAX_VALUE)
        circuit.onClosed = {
            answer.complete(
                BatchEnd.Whole(closedOutcome(circuit, assembler.started, clock.millis() - sentAt.get(), reused)),
            )
        }
        val body = LookupBatchRequestBody.encode(requestId, group[0].op, group.map { it.key }, random)
        sentAt.set(clock.millis())
        check(rc.requestsSent <= requestLimit(rc.context)) { "lookup request limit per circuit exceeded" }
        if (circuit.isClosed || !circuit.send(RelayMessage(RelayCommand.LOOKUP_REQUEST, 0, body))) {
            discard(rc)
            // the link or this side refused the cell: nothing reached the relay, no verdict about it
            return whole(Attempt.Next(Kind.NONE, LookupFailure.TIMEOUT))
        }
        armDeadline({ group.maxOf { it.deadlineMillis } }, answer, BatchEnd.Whole(Attempt.Stop(LookupFailure.TIMEOUT)))
        // the relay answers all items together, after its slowest lookup and paced: allow for the extra fragments
        val timeoutMillis =
            config.answerTimeout.inWholeMilliseconds + (group.size - 1) * BATCH_PACING_ALLOWANCE_MILLIS
        return answer
            .completeOnTimeout(
                BatchEnd.Whole(Attempt.Next(Kind.FAILURE, LookupFailure.TIMEOUT)),
                timeoutMillis,
                TimeUnit.MILLISECONDS,
            ).thenApplyAsync({ end ->
                circuit.onClosed = {}
                circuit.onInbound = {}
                val alive = { !closed && !circuit.isClosed }
                when (val processed = if (end is BatchEnd.Raw) verifyItems(group, rc, end.items) else end) {
                    is BatchEnd.Items -> {
                        if (alive() && processed.attempts.none { it is Attempt.Next && it.kind == Kind.MANIPULATION }) {
                            BatchResult(processed, rc)
                        } else {
                            discard(rc)
                            BatchResult(processed, null)
                        }
                    }
                    BatchEnd.V1Only ->
                        if (alive()) {
                            BatchResult(processed, rc)
                        } else {
                            discard(rc)
                            BatchResult(processed, null)
                        }
                    else -> {
                        discard(rc)
                        BatchResult(processed, null)
                    }
                }
            }, offLoopExecutor)
    }

    /**
     * Every FOUND item is verified on its own (block against its CID, record against the name's key). A MALFORMED
     * answer to a key the client had checked is a provable lie. If any item is manipulated the relay is put on the
     * long backoff once, verified FOUND items are still taken (the hash proves them), and every other item uses its
     * attempt without a verdict. Without manipulation, items the relay refused go to another exit; if it refused
     * all of them, the relay is penalised once.
     */
    private fun verifyItems(
        group: List<Job>,
        rc: ReusableCircuit,
        items: List<BatchAssembler.Item>,
    ): BatchEnd {
        val exit = rc.exit.identity
        val raw =
            items.mapIndexed { i, item ->
                when (item.status) {
                    LookupStatus.FOUND -> verify(group[i], item.content)
                    LookupStatus.NOT_FOUND -> Attempt.Done(LookupResult.NotFound(confirmed = false))
                    LookupStatus.DISABLED, LookupStatus.UNSUPPORTED_VERSION, LookupStatus.UNSUPPORTED_OPERATION -> {
                        disabled.incrementAndGet()
                        Attempt.Next(Kind.UNSUPPORTED, LookupFailure.REFUSED)
                    }
                    LookupStatus.MALFORMED -> {
                        manipulated.incrementAndGet()
                        Attempt.Next(Kind.MANIPULATION, LookupFailure.MANIPULATED)
                    }
                    else -> Attempt.Next(Kind.FAILURE, LookupFailure.REFUSED)
                }
            }
        val manipulation = raw.any { it is Attempt.Next && it.kind == Kind.MANIPULATION }
        if (manipulation) {
            return BatchEnd.Items(
                raw.map { a ->
                    if (a is Attempt.Done && a.result is LookupResult.Found) {
                        a
                    } else {
                        Attempt.Next(Kind.NONE, LookupFailure.MANIPULATED)
                    }
                },
                Kind.MANIPULATION,
            )
        }
        val refused = raw.filter { it is Attempt.Next }
        var penalty: Kind? = null
        if (refused.isNotEmpty()) {
            if (refused.size == raw.size) {
                penalty =
                    if (refused.any {
                            (it as Attempt.Next).kind == Kind.UNSUPPORTED
                        }
                    ) {
                        Kind.UNSUPPORTED
                    } else {
                        Kind.FAILURE
                    }
            }
            group.forEachIndexed { i, j -> if (raw[i] is Attempt.Next) j.avoidExits += exit }
        }
        return BatchEnd.Items(
            raw.map { a -> if (a is Attempt.Next) Attempt.Next(Kind.NONE, LookupFailure.REFUSED) else a },
            penalty,
        )
    }

    /** Settles a job without moving the queue on (a batch member; the lead job's [finish] does that). */
    private fun settleMember(
        job: Job,
        result: LookupResult,
    ) {
        countResult(result)
        synchronized(lock) { recordResultLocked(job, result) }
        completeOff(job.result, result)
    }

    /** What happens after a batch: every job gets its verdict; the lead job moves the queue on or retries. */
    private fun afterBatch(
        group: List<Job>,
        relay: OnionRelayDescriptor,
        result: BatchResult,
    ) {
        val lead = group[0]
        val members = group.drop(1)
        val end = result.end
        if (end is BatchEnd.V1Only) {
            // an older relay: no verdict, no penalty; the group goes on as version-1 requests, on this circuit if it lives
            synchronized(
                lock,
            ) { v1OnlyExits[relay.identity] = clock.millis() + config.v1OnlyMemoTtl.inWholeMilliseconds }
            v1Fallbacks.incrementAndGet()
            group.forEach { j ->
                j.attemptsUsed--
                if (j.notFoundCount > 0) crossChecks.decrementAndGet()
            }
            synchronized(lock) { retryHead.addAll(0, members) }
            val kept = result.keep
            if (kept != null) {
                startAttempt(lead, relay, CompletableFuture.completedFuture(kept))
            } else {
                val task = Runnable { runJob(lead) }
                if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
            }
            return
        }
        val attempts: List<Attempt> =
            when (end) {
                is BatchEnd.Items -> end.attempts
                is BatchEnd.Whole -> {
                    val a = end.attempt
                    // one verdict about the relay for the whole batch, not one per item
                    if (a is Attempt.Next && a.kind != Kind.NONE && !closed) penalise(relay.identity, a.kind)
                    val each: Attempt = if (a is Attempt.Next) Attempt.Next(Kind.NONE, a.reason) else a
                    group.map { each }
                }
                else -> error("unexpected batch end")
            }
        val decisions = group.indices.map { decide(group[it], relay, attempts[it]) }
        if (end is BatchEnd.Items) {
            val penalty = end.penalty
            if (penalty != null && !closed) penalise(relay.identity, penalty)
        }
        val retries = ArrayList<Job>()
        for (i in 1 until group.size) {
            val r = decisions[i].result
            if (r != null) settleMember(group[i], r) else retries += group[i]
        }
        if (retries.isNotEmpty()) synchronized(lock) { retryHead.addAll(retries) }
        val leadResult = decisions[0].result
        if (leadResult != null) {
            finish(lead, leadResult, result.keep)
        } else {
            discard(result.keep)
            val task = Runnable { runJob(lead) }
            if (!runCatching { offLoop(task) }.getOrDefault(false)) CompletableFuture.runAsync(task)
        }
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
        countResult(result)
        val next: Job?
        var kept = false
        synchronized(lock) {
            recordResultLocked(job, result)
            next = if (closed) null else retryHead.removeFirstOrNull() ?: queue.removeFirstOrNull()
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

    private fun countResult(result: LookupResult) {
        when (result) {
            is LookupResult.Found -> found.incrementAndGet()
            is LookupResult.NotFound ->
                if (result.confirmed) notFound.incrementAndGet() else notFoundUnconfirmed.incrementAndGet()
            else -> failed.incrementAndGet()
        }
    }

    /** Caller holds [lock]: the negative cache entry of a NOT_FOUND result, and the job leaves the merge table. */
    private fun recordResultLocked(
        job: Job,
        result: LookupResult,
    ) {
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
    }

    override fun close() {
        if (closed) return
        closed = true
        val (pending, held) =
            synchronized(lock) {
                val all = retryHead.toList() + queue.toList()
                retryHead.clear()
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

        /** Pacing time of one largest-class item at the relay (184 fragments, 8 per 50 ms), rounded up. */
        const val BATCH_PACING_ALLOWANCE_MILLIS = 1200L

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
