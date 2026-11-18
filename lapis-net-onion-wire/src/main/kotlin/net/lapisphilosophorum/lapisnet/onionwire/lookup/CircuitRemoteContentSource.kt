@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
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

    fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: kotlin.time.Duration,
    ): java.util.concurrent.CompletableFuture<LookupResult>
}

/**
 * The [RemoteContentSource] of a node in anonymity mode (wave V0.10.0-J2): every miss of the local stores becomes a
 * lookup through a circuit ([OnionLookupClient]). Blocking calls ([fetchBlock], [resolveIpnsRecord]) wait for the
 * answer and must never run on an event loop. Verified blocks are kept in a small LRU cache (entries and bytes
 * bounded), so that [blockIfCached] can answer without blocking; IPNS records are never cached (freshness first).
 * [blockIfCached] on a miss schedules one background fetch (merged with an identical one by the client's queue).
 */
class CircuitRemoteContentSource internal constructor(
    private val client: LookupBackend,
    private val cacheEntries: Int = 64,
    private val cacheBytes: Long = 8L * 1024 * 1024,
    private val backgroundTimeout: Duration = Duration.ofSeconds(90),
) : RemoteContentSource,
    AutoCloseable {
    init {
        require(cacheEntries > 0 && cacheBytes > 0) { "cache bounds must be positive" }
    }

    private val lock = Any()
    private var bytesHeld = 0L
    private val cache =
        object : LinkedHashMap<Cid, ByteArray>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Cid, ByteArray>): Boolean = false
        }
    private val pendingBackground = HashSet<Cid>()

    @Volatile private var closed = false

    /** Entries and bytes currently cached (tests). */
    internal fun cacheStatsForTest(): Pair<Int, Long> = synchronized(lock) { cache.size to bytesHeld }

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray? {
        if (closed) return null
        cached(cid)?.let { return it.takeIf { b -> b.size <= maxBytes } }
        val result = await(client.fetchBlock(cid, timeout.toKotlinDuration()), timeout) ?: return null
        val bytes = (result as? LookupResult.Found)?.bytes ?: return null
        // the client verified it already; checked again because this cache feeds blockIfCached
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

    override fun blockIfCached(cid: Cid): ByteArray? {
        if (closed) return null
        cached(cid)?.let { return it }
        val start = synchronized(lock) { pendingBackground.add(cid) }
        if (start) {
            client.fetchBlock(cid, backgroundTimeout.toKotlinDuration()).whenComplete { r, _ ->
                synchronized(lock) { pendingBackground.remove(cid) }
                val bytes = (r as? LookupResult.Found)?.bytes
                if (bytes != null && !closed && RemoteContentVerifier.blockMatchesCid(cid, bytes)) remember(cid, bytes)
            }
        }
        return null
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

    override fun close() {
        closed = true
        synchronized(lock) {
            cache.clear()
            bytesHeld = 0
            pendingBackground.clear()
        }
    }
}
