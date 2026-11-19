package net.lapisphilosophorum.lapisnet.storage

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import org.peergos.Want
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * Fix wave F6: the bounds of [BitswapResendPolicy], i.e. how often this node, as a HOLDER, sends a block again that
 * it already sent to the same peer. Provisional numbers (like the other DoS bounds of this module).
 *
 * - [minInterval]: the same (peer, want) pair is answered again at most once per interval. Equal to the requester's
 *   re-send period, so a well-behaved requester is answered on its first re-send.
 * - [perPeerPerMinute] / [perPeerBurst]: a token bucket per requesting peer over all of its re-sends.
 * - [globalPerMinute] / [globalBurst]: one token bucket over all peers.
 * - [maxTrackedPairs] / [maxTrackedPeers]: LRU bounds of the state; an evicted entry starts afresh.
 */
internal data class BitswapResendLimits(
    val minInterval: Duration = Duration.ofSeconds(5),
    val perPeerPerMinute: Int = 60,
    val perPeerBurst: Int = 20,
    val globalPerMinute: Int = 1200,
    val globalBurst: Int = 200,
    val maxTrackedPairs: Int = 16_384,
    val maxTrackedPeers: Int = 1_024,
) {
    init {
        require(!minInterval.isNegative && !minInterval.isZero) { "minInterval must be positive" }
        require(perPeerPerMinute > 0) { "perPeerPerMinute must be positive" }
        require(perPeerBurst > 0) { "perPeerBurst must be positive" }
        require(perPeerBurst <= perPeerPerMinute) { "perPeerBurst must not exceed perPeerPerMinute" }
        require(globalPerMinute > 0) { "globalPerMinute must be positive" }
        require(globalBurst > 0) { "globalBurst must be positive" }
        require(globalBurst <= globalPerMinute) { "globalBurst must not exceed globalPerMinute" }
        require(maxTrackedPairs > 0) { "maxTrackedPairs must be positive" }
        require(maxTrackedPeers > 0) { "maxTrackedPeers must be positive" }
    }
}

/** What [BitswapResendPolicy.decide] says about one re-send. */
internal enum class ResendDecision { ALLOWED, DENIED_INTERVAL, DENIED_PEER_LIMIT, DENIED_GLOBAL_LIMIT }

/** Counters of [BitswapResendPolicy] (numbers only, for tests and diagnostics). */
internal class ResendStats(
    val allowed: Long,
    val deniedInterval: Long,
    val deniedPeer: Long,
    val deniedGlobal: Long,
) {
    override fun toString(): String =
        "allowed=$allowed deniedInterval=$deniedInterval deniedPeer=$deniedPeer deniedGlobal=$deniedGlobal"
}

/**
 * Fix wave F6: decides whether this node re-sends a block to a peer that it already sent the block to.
 *
 * Nabu's responder never does: after it sent a block to a peer it remembers (peer, want) in an LRU without expiry and
 * silently skips every later WANT_BLOCK for it (see [RefreshableBitswapEngine]). This policy replaces "never" with
 * "at most once per [BitswapResendLimits.minInterval] per pair, within a per-peer and a global token bucket". A first
 * send is NOT counted here - it stays Nabu's unchanged behaviour.
 *
 * State: pair stamps keyed by SHA-256 over the length-prefixed peer ID, CID and auth (no raw CID kept, a new digest
 * per call), a token bucket per peer and one global bucket - all LRU-bounded, all under one lock, O(1) per call.
 * [clock] returns nanoseconds; time that runs backwards counts as no time (it never adds tokens or ages a stamp).
 * Nothing about a CID or peer is logged.
 */
internal class BitswapResendPolicy(
    private val limits: BitswapResendLimits,
    private val clock: () -> Long,
) {
    private class Bucket(
        var tokens: Double,
        var last: Long,
    )

    private val lock = Any()
    private val minIntervalNanos = limits.minInterval.toNanos()

    private val stamps =
        object : LinkedHashMap<ByteBuffer, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteBuffer, Long>): Boolean =
                size > limits.maxTrackedPairs
        }

    private val peerBuckets =
        object : LinkedHashMap<PeerId, Bucket>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, Bucket>): Boolean =
                size > limits.maxTrackedPeers
        }

    private var global: Bucket? = null

    private val allowed = AtomicLong()
    private val deniedInterval = AtomicLong()
    private val deniedPeer = AtomicLong()
    private val deniedGlobal = AtomicLong()

    /** Only for a want this engine already sent to [peer] (it is in Nabu's `recentBlocksSent`). */
    fun decide(
        peer: PeerId,
        want: Want,
    ): ResendDecision {
        val key = pairKey(peer, want)
        val decision =
            synchronized(lock) {
                val now = clock()
                val stamp = stamps[key]
                if (stamp != null && now - stamp < minIntervalNanos) return@synchronized ResendDecision.DENIED_INTERVAL
                val peerBucket =
                    peerBuckets[peer] ?: Bucket(limits.perPeerBurst.toDouble(), now).also { peerBuckets[peer] = it }
                refill(peerBucket, now, limits.perPeerPerMinute, limits.perPeerBurst)
                if (peerBucket.tokens < 1.0) return@synchronized ResendDecision.DENIED_PEER_LIMIT
                val globalBucket = global ?: Bucket(limits.globalBurst.toDouble(), now).also { global = it }
                refill(globalBucket, now, limits.globalPerMinute, limits.globalBurst)
                if (globalBucket.tokens < 1.0) return@synchronized ResendDecision.DENIED_GLOBAL_LIMIT
                peerBucket.tokens -= 1.0
                globalBucket.tokens -= 1.0
                stamps[key] = now
                ResendDecision.ALLOWED
            }
        when (decision) {
            ResendDecision.ALLOWED -> allowed.incrementAndGet()
            ResendDecision.DENIED_INTERVAL -> deniedInterval.incrementAndGet()
            ResendDecision.DENIED_PEER_LIMIT -> deniedPeer.incrementAndGet()
            ResendDecision.DENIED_GLOBAL_LIMIT -> deniedGlobal.incrementAndGet()
        }
        if (decision != ResendDecision.ALLOWED) logger.debug { "bitswap resend denied: ${stats()}" }
        return decision
    }

    fun stats(): ResendStats = ResendStats(allowed.get(), deniedInterval.get(), deniedPeer.get(), deniedGlobal.get())

    internal fun trackedPairsForTest(): Int = synchronized(lock) { stamps.size }

    internal fun trackedPeersForTest(): Int = synchronized(lock) { peerBuckets.size }

    private fun refill(
        bucket: Bucket,
        now: Long,
        perMinute: Int,
        burst: Int,
    ) {
        val elapsed = now - bucket.last
        if (elapsed <= 0) return // no time passed, or the clock went backwards: no tokens, keep the later stamp
        bucket.tokens = minOf(burst.toDouble(), bucket.tokens + elapsed.toDouble() * perMinute / NANOS_PER_MINUTE)
        bucket.last = now
    }

    private fun pairKey(
        peer: PeerId,
        want: Want,
    ): ByteBuffer {
        val digest = MessageDigest.getInstance("SHA-256")
        lengthPrefixed(digest, peer.bytes)
        lengthPrefixed(digest, want.cid.toBytes())
        lengthPrefixed(digest, want.authHex.orElse("").toByteArray(Charsets.UTF_8))
        lengthPrefixed(digest, byteArrayOf(if (want.authHex.isPresent) 1 else 0))
        return ByteBuffer.wrap(digest.digest())
    }

    private fun lengthPrefixed(
        digest: MessageDigest,
        bytes: ByteArray,
    ) {
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
        digest.update(bytes)
    }

    private companion object {
        const val NANOS_PER_MINUTE = 60_000_000_000.0
    }
}
