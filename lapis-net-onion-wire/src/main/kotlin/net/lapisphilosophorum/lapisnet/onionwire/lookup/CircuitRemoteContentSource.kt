@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockState
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockView
import net.lapisphilosophorum.lapisnet.storage.RemoteContentSource
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import java.time.Duration
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.time.toKotlinDuration

/** What [CircuitRemoteContentSource] needs of an [OnionLookupClient] (a seam for tests). */
internal interface LookupBackend {
    fun fetchBlock(
        cid: Cid,
        timeout: kotlin.time.Duration,
    ): java.util.concurrent.CompletableFuture<LookupResult>

    /** Wave V0.10.0-J3: a lookup in [context]; the default ignores the context (older test fakes). */
    fun fetchBlock(
        cid: Cid,
        timeout: kotlin.time.Duration,
        context: LookupContext,
    ): java.util.concurrent.CompletableFuture<LookupResult> = fetchBlock(cid, timeout)

    fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: kotlin.time.Duration,
    ): java.util.concurrent.CompletableFuture<LookupResult>
}

/**
 * The [RemoteContentSource] of a node in anonymity mode (waves V0.10.0-J2 and J3): a miss of the local stores becomes a
 * lookup through a circuit ([OnionLookupClient]).
 *
 * - The blocking calls ([fetchBlock], [resolveIpnsRecord]) wait for the answer and must never run on an event loop. A
 *   blocking [fetchBlock] is a [LookupContext.MAILBOX] lookup (a circuit of its own; no production caller exists in
 *   wave J3), an IPNS record always an [LookupContext.IPNS] one.
 * - [blockState] never blocks: it answers from a small LRU cache of verified blocks (entries and bytes bounded), from
 *   the set of running background lookups and from a bounded memo of recent outcomes (a confirmed NOT_FOUND for
 *   [notFoundMemo], an unconfirmed one or a failed lookup for [unavailableMemo]; a lookup that reached no relay, was
 *   dropped by the queue or ended by a close is not remembered); with `schedule` a miss starts one background
 *   [LookupContext.TIMELINE] lookup (merged with an identical one by the client's queue). The memo stores states only,
 *   never content.
 *
 * IPNS records are never cached (freshness first).
 */
class CircuitRemoteContentSource internal constructor(
    private val client: LookupBackend,
    private val cacheEntries: Int = 64,
    private val cacheBytes: Long = 8L * 1024 * 1024,
    private val backgroundTimeout: Duration = Duration.ofSeconds(90),
    private val memoEntries: Int = 1024,
    private val notFoundMemo: Duration = Duration.ofMinutes(10),
    private val unavailableMemo: Duration = Duration.ofMinutes(2),
    /** Monotonic clock of the memo (tests move it). */
    private val nanoClock: () -> Long = System::nanoTime,
) : RemoteContentSource,
    AutoCloseable {
    init {
        require(cacheEntries > 0 && cacheBytes > 0 && memoEntries > 0) { "cache bounds must be positive" }
        require(!notFoundMemo.isNegative && !unavailableMemo.isNegative) { "memo durations must not be negative" }
    }

    private class Memo(
        val state: RemoteBlockState,
        val untilNanos: Long,
    )

    private val lock = Any()
    private var bytesHeld = 0L
    private val cache =
        object : LinkedHashMap<Cid, ByteArray>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Cid, ByteArray>): Boolean = false
        }
    private val pendingBackground = HashSet<Cid>()
    private val memo =
        object : LinkedHashMap<Cid, Memo>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Cid, Memo>): Boolean = size > memoEntries
        }

    @Volatile private var closed = false

    /** Entries and bytes currently cached (tests). */
    internal fun cacheStatsForTest(): Pair<Int, Long> = synchronized(lock) { cache.size to bytesHeld }

    /** Entries currently in the outcome memo (tests). */
    internal fun memoSizeForTest(): Int = synchronized(lock) { memo.size }

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray? {
        if (closed) return null
        cached(cid)?.let { return it.takeIf { b -> b.size <= maxBytes } }
        val result =
            await(client.fetchBlock(cid, timeout.toKotlinDuration(), LookupContext.MAILBOX), timeout) ?: return null
        val bytes = (result as? LookupResult.Found)?.bytes ?: return null
        // the client verified it already; checked again because this cache feeds blockState
        if (bytes.size > maxBytes || !RemoteContentVerifier.blockMatchesCid(cid, bytes)) return null
        remember(cid, bytes)
        return bytes
    }

    override fun resolveIpnsRecord(
        name: ByteArray,
        timeout: Duration,
    ): ByteArray? {
        if (closed) return null
        val result = await(client.resolveIpnsRecord(name, timeout.toKotlinDuration()), timeout) ?: return null
        return (result as? LookupResult.Found)?.bytes
    }

    override fun blockIfCached(cid: Cid): ByteArray? = blockState(cid, schedule = true).bytes

    override fun blockState(
        cid: Cid,
        schedule: Boolean,
    ): RemoteBlockView {
        if (closed) return RemoteBlockView.NONE
        val known = known(cid)
        if (known != null || !schedule) return known ?: RemoteBlockView.NONE
        val start = synchronized(lock) { pendingBackground.add(cid) }
        if (!start) return RemoteBlockView(RemoteBlockState.FETCHING, null, newlyScheduled = false)
        val future =
            runCatching { client.fetchBlock(cid, backgroundTimeout.toKotlinDuration(), LookupContext.TIMELINE) }
                .getOrElse {
                    java.util.concurrent.CompletableFuture
                        .completedFuture(null)
                }
        future.whenComplete { r, _ -> backgroundDone(cid, r) }
        // a negative-cache hit completes at once: report what is known now
        val now = known(cid)
        return RemoteBlockView(now?.state ?: RemoteBlockState.FETCHING, now?.bytes, newlyScheduled = true)
    }

    /** The cache, a running lookup or a still-valid memo entry; `null` when nothing is known. */
    private fun known(cid: Cid): RemoteBlockView? =
        synchronized(lock) {
            cache[cid]?.let { return@synchronized RemoteBlockView(RemoteBlockState.CACHED, it, newlyScheduled = false) }
            if (cid in pendingBackground) {
                return@synchronized RemoteBlockView(RemoteBlockState.FETCHING, null, newlyScheduled = false)
            }
            val m = memo[cid] ?: return@synchronized null
            if (m.untilNanos - nanoClock() > 0) {
                RemoteBlockView(m.state, null, newlyScheduled = false)
            } else {
                memo.remove(cid)
                null
            }
        }

    private fun backgroundDone(
        cid: Cid,
        r: LookupResult?,
    ) {
        val bytes = (r as? LookupResult.Found)?.bytes
        val verified = bytes != null && !closed && RemoteContentVerifier.blockMatchesCid(cid, bytes)
        if (verified) remember(cid, checkNotNull(bytes))
        synchronized(lock) {
            pendingBackground.remove(cid)
            if (closed) return@synchronized
            when {
                verified -> memo.remove(cid)
                r is LookupResult.NotFound && r.confirmed ->
                    memo[cid] = Memo(RemoteBlockState.NOT_FOUND, nanoClock() + notFoundMemo.toNanos())
                // no lookup reached a relay (none usable yet, queue dropped it, closing): nothing is known about the
                // block, so nothing is remembered and the next request asks again (e.g. right after the start)
                r is LookupResult.Unavailable && r.reason in NOT_REMEMBERED -> memo.remove(cid)
                else -> memo[cid] = Memo(RemoteBlockState.UNAVAILABLE, nanoClock() + unavailableMemo.toNanos())
            }
        }
    }

    private fun cached(cid: Cid): ByteArray? = synchronized(lock) { cache[cid]?.copyOf() }

    private fun remember(
        cid: Cid,
        bytes: ByteArray,
    ) {
        if (bytes.size > cacheBytes) return
        synchronized(lock) {
            cache.remove(cid)?.let { bytesHeld -= it.size }
            cache[cid] = bytes.copyOf()
            bytesHeld += bytes.size
            val it = cache.entries.iterator()
            while ((cache.size > cacheEntries || bytesHeld > cacheBytes) && it.hasNext()) {
                val eldest = it.next()
                bytesHeld -= eldest.value.size
                it.remove()
            }
        }
    }

    private fun <T> await(
        future: java.util.concurrent.CompletableFuture<T>,
        timeout: Duration,
    ): T? =
        try {
            future.get(timeout.toMillis().coerceAtLeast(1), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            null
        } catch (e: ExecutionException) {
            null
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }

    private companion object {
        /** Failures that say nothing about the block: not kept in the memo. */
        val NOT_REMEMBERED = setOf(LookupFailure.NO_RELAY, LookupFailure.ADMISSION, LookupFailure.CLOSED)
    }

    override fun close() {
        closed = true
        synchronized(lock) {
            cache.clear()
            bytesHeld = 0
            pendingBackground.clear()
            memo.clear()
        }
    }
}
