package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.etc.util.netty.TotalTimeoutHandler
import io.libp2p.protocol.ProtocolHandler
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.ReferenceCountUtil
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.net.InetAddress
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/** Limits of the serving side (wave V0.10.0-J1b, assumptions Q12). */
data class RelayDirectoryServeLimits(
    val perPeerRequests: Int = 2,
    val perPeerWindow: Duration = Duration.ofMinutes(10),
    val globalPerMinute: Int = 30,
    val maxConcurrentStreams: Int = 4,
    /** Streams at once from one remote address (IPv4 address, IPv6 /64), since peer ids cost nothing. */
    val maxConcurrentPerAddress: Int = 2,
    val maxTrackedPeers: Int = 1024,
    val cacheRebuildInterval: Duration = Duration.ofSeconds(30),
    val streamTimeout: Duration = Duration.ofSeconds(15),
    /** The 5-byte request must be complete this long after the stream was admitted, or the stream is reset. */
    val requestTimeout: Duration = Duration.ofSeconds(5),
) {
    init {
        require(
            perPeerRequests > 0 &&
                globalPerMinute > 0 &&
                maxConcurrentStreams > 0 &&
                maxConcurrentPerAddress > 0 &&
                maxTrackedPeers > 0 &&
                !requestTimeout.isNegative &&
                !requestTimeout.isZero,
        ) {
            "invalid serve limits"
        }
    }
}

/**
 * The key of the per-address concurrency limit: the IPv4 address, or the /64 prefix of an IPv6 address (one host
 * gets a whole /64 cheaply), of the first `ip4`/`ip6` component of [address]; `"unknown"` without one (all such
 * streams share one key, fail-closed). Never logged.
 */
internal fun remoteAddressKey(address: Multiaddr?): String {
    val ip = address?.filterComponents(Protocol.IP4, Protocol.IP6)?.firstOrNull() ?: return "unknown"
    return if (ip.protocol == Protocol.IP6) {
        val bytes = runCatching { InetAddress.getByName(ip.stringValue).address }.getOrNull() ?: return "unknown"
        "ip6:" + bytes.copyOf(8).joinToString("") { "%02x".format(it) }
    } else {
        "ip4:" + ip.stringValue
    }
}

/** A lazily refilled token bucket: [capacity] tokens, one token back every [refillMillis]. Not thread-safe on its own. */
internal class RefillBucket(
    private val capacity: Int,
    private val refillMillis: Long,
    startMillis: Long,
) {
    private var tokens = capacity.toDouble()
    private var last = startMillis

    /** `true` when [tryAcquire] at [nowMillis] would succeed; takes nothing. */
    fun canAcquire(nowMillis: Long): Boolean {
        val elapsed = (nowMillis - last).coerceAtLeast(0)
        return minOf(capacity.toDouble(), tokens + elapsed.toDouble() / refillMillis) >= 1.0
    }

    fun tryAcquire(nowMillis: Long): Boolean {
        val elapsed = (nowMillis - last).coerceAtLeast(0)
        tokens = minOf(capacity.toDouble(), tokens + elapsed.toDouble() / refillMillis)
        last = nowMillis
        if (tokens >= 1.0) {
            tokens -= 1.0
            return true
        }
        return false
    }
}

/**
 * Admission of snapshot requests: at most [RelayDirectoryServeLimits.maxConcurrentStreams] at once, at most
 * [RelayDirectoryServeLimits.maxConcurrentPerAddress] of them from one remote address ([remoteAddressKey]; peer ids
 * cost nothing, so a per-peer-id concurrency limit would not help), per remote peer id
 * [RelayDirectoryServeLimits.perPeerRequests] per [RelayDirectoryServeLimits.perPeerWindow] (an LRU of
 * [RelayDirectoryServeLimits.maxTrackedPeers] buckets; weak on its own, since a node in anonymity mode has a fresh
 * peer id per run) and [RelayDirectoryServeLimits.globalPerMinute] in total. A refused request takes no token from any
 * bucket (both are checked before either is taken). Thread-safe.
 */
internal class RelayDirectoryServeLimiter(
    private val limits: RelayDirectoryServeLimits,
    private val clock: Clock,
) {
    private val concurrent = AtomicInteger(0)
    private val global = RefillBucket(limits.globalPerMinute, 60_000L / limits.globalPerMinute, clock.millis())
    private val perPeer =
        object : LinkedHashMap<PeerId, RefillBucket>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, RefillBucket>): Boolean =
                size > limits.maxTrackedPeers
        }

    /** Streams in flight per address key; at most [RelayDirectoryServeLimits.maxConcurrentStreams] entries. */
    private val perAddress = HashMap<String, Int>()

    /**
     * `true` and one concurrency slot taken (give it back with [release] and the same [address]), or `false` and
     * nothing taken. A `null` [address] skips the per-address limit (tests of the other limits).
     */
    fun tryAcquire(
        peer: PeerId,
        address: String? = null,
    ): Boolean {
        if (concurrent.incrementAndGet() > limits.maxConcurrentStreams) {
            concurrent.decrementAndGet()
            return false
        }
        val now = clock.millis()
        val admitted =
            synchronized(this) {
                val fromAddress = address?.let { perAddress[it] } ?: 0
                if (address != null && fromAddress >= limits.maxConcurrentPerAddress) return@synchronized false
                val bucket =
                    perPeer.getOrPut(peer) {
                        RefillBucket(
                            limits.perPeerRequests,
                            limits.perPeerWindow.toMillis() / limits.perPeerRequests,
                            now,
                        )
                    }
                if (!bucket.canAcquire(now) || !global.canAcquire(now)) return@synchronized false
                bucket.tryAcquire(now)
                global.tryAcquire(now)
                if (address != null) perAddress[address] = fromAddress + 1
                true
            }
        if (!admitted) concurrent.decrementAndGet()
        return admitted
    }

    fun release(address: String? = null) {
        if (address != null) {
            synchronized(this) {
                val left = (perAddress[address] ?: 1) - 1
                if (left <= 0) perAddress.remove(address) else perAddress[address] = left
            }
        }
        concurrent.decrementAndGet()
    }

    fun inFlight(): Int = concurrent.get()
}

/**
 * The serving side of `/lapis/onion-relay-directory/1.0.0` (wave V0.10.0-J1b): answers one request per stream with a
 * snapshot of the relay descriptors this node holds, each with the relay's peer record when it is usable, so that a
 * node in anonymity mode learns relays (and where to reach its guard) without waiting for gossip republication.
 *
 * Registered on every node in normal mode that runs the onion wire (assumption Q10), never in anonymity mode. The
 * answer comes from a cached, fully encoded snapshot that is rebuilt at most every
 * [RelayDirectoryServeLimits.cacheRebuildInterval] (no CPU work per request beyond the limits), with a random choice
 * ([SecureRandom]) of [OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES] descriptors when there are more. A request over
 * the limits, a malformed request, a request not complete within [RelayDirectoryServeLimits.requestTimeout], or a
 * second request on the same stream closes the stream without an answer. The concurrency slot is given back as soon as
 * the answer has been flushed (or the stream closes), not only when the reader closes the stream or the total timeout
 * ends it: a reader that never closes holds a stream, but no slot (security audit of wave J1b). Streams that linger
 * after their answer are bounded by the global rate times [RelayDirectoryServeLimits.streamTimeout]. Logs counters
 * only, never a peer id or address.
 */
class OnionRelayDirectoryServer(
    private val index: OnionRelayDescriptorIndex,
    private val records: (Secp256k1PublicKey, Long) -> PeerRecord?,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    private val limits: RelayDirectoryServeLimits = RelayDirectoryServeLimits(),
) : AutoCloseable {
    internal val limiter = RelayDirectoryServeLimiter(limits, clock)
    private val closed = AtomicBoolean(false)
    private val cacheLock = Any()
    private var cached: ByteArray? = null
    private var cachedAtMillis = Long.MIN_VALUE
    private val rebuilds = AtomicLong(0)
    private val served = AtomicLong(0)
    private val refused = AtomicLong(0)

    val binding: StrictProtocolBinding<Unit> = Binding(Handler())

    /** How often the snapshot was encoded (tests: the cache bound). */
    val rebuildCount: Long get() = rebuilds.get()

    val servedCount: Long get() = served.get()

    val refusedCount: Long get() = refused.get()

    /** The current encoded snapshot, rebuilt when older than the cache interval. */
    internal fun snapshotBytes(): ByteArray =
        synchronized(cacheLock) {
            val now = clock.millis()
            val current = cached
            if (current != null && now - cachedAtMillis < limits.cacheRebuildInterval.toMillis()) return current
            val fresh = buildSnapshot(now / 1000)
            cached = fresh
            cachedAtMillis = now
            rebuilds.incrementAndGet()
            fresh
        }

    private fun buildSnapshot(nowEpochSecond: Long): ByteArray {
        val all = index.snapshot(nowEpochSecond).toMutableList()
        if (all.size > OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES) {
            // Fisher-Yates prefix with a SecureRandom: an unpredictable choice, so no fixed subset is always omitted
            for (i in 0 until OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES) {
                val j = i + random.nextInt(all.size - i)
                val t = all[i]
                all[i] = all[j]
                all[j] = t
            }
        }
        val chosen = all.take(OnionRelayDirectoryCodec.MAX_SNAPSHOT_ENTRIES)
        return OnionRelayDirectoryCodec.encodeResponse(chosen.map { it to usableRecord(it, nowEpochSecond) })
    }

    private fun usableRecord(
        d: OnionRelayDescriptor,
        nowEpochSecond: Long,
    ): ByteArray? {
        val record = runCatching { records(d.identity, nowEpochSecond) }.getOrNull() ?: return null
        if (record.notValidAfterEpochSecond < nowEpochSecond) return null
        if (record.identity != d.identity || record.peerId != d.peerId) return null
        if (record.directAddresses.isEmpty()) return null
        val bytes = PeerRecordCodec.encode(record)
        return bytes.takeIf { it.size <= OnionRelayDirectoryCodec.MAX_SNAPSHOT_RECORD_BYTES }
    }

    override fun close() {
        closed.set(true)
    }

    // ProtocolHandler(initiatorTrafficLimit, responderTrafficLimit): the first bounds what a RESPONDER stream accepts
    // from the initiator (checked against the bytecode of jvm-libp2p 1.3.5); one request plus one byte
    private inner class Handler :
        ProtocolHandler<Unit>((OnionRelayDirectoryCodec.REQUEST_SIZE + 1).toLong(), Long.MAX_VALUE) {
        override fun initProtocolStream(stream: Stream) {
            stream.pushHandler(TotalTimeoutHandler(limits.streamTimeout))
        }

        override fun onStartInitiator(stream: Stream): CompletableFuture<Unit> {
            // this binding only serves; the client side lives in OnionRelayDirectoryClient
            stream.reset()
            return CompletableFuture.completedFuture(Unit)
        }

        override fun onStartResponder(stream: Stream): CompletableFuture<Unit> {
            val peer = runCatching { stream.remotePeerId() }.getOrNull()
            val address = remoteAddressKey(runCatching { stream.connection.remoteAddress() }.getOrNull())
            if (closed.get() || peer == null || !limiter.tryAcquire(peer, address)) {
                refused.incrementAndGet()
                logger.debug { "relay directory request refused (total ${refused.get()})" }
                stream.reset()
                return CompletableFuture.completedFuture(Unit)
            }
            val released = AtomicBoolean(false)
            val releaseSlot = { if (released.compareAndSet(false, true)) limiter.release(address) }
            stream.closeFuture().whenComplete { _, _ -> releaseSlot() }
            stream.pushHandler(RequestReader(stream, releaseSlot))
            return CompletableFuture.completedFuture(Unit)
        }
    }

    /** Reads exactly one request; anything else (wrong bytes, more bytes, a second request) closes the stream. */
    private inner class RequestReader(
        private val stream: Stream,
        private val onAnswerFlushed: () -> Unit,
    ) : ChannelInboundHandlerAdapter() {
        private val buffer = ByteArray(OnionRelayDirectoryCodec.REQUEST_SIZE)
        private var filled = 0

        @Volatile private var answered = false

        override fun handlerAdded(ctx: ChannelHandlerContext) {
            // a stream that never sends its request must not hold a slot until the total timeout
            ctx.executor().schedule(
                Runnable {
                    if (!answered) {
                        refused.incrementAndGet()
                        logger.debug { "relay directory request refused: not complete in time" }
                        stream.reset()
                    }
                },
                limits.requestTimeout.toMillis(),
                TimeUnit.MILLISECONDS,
            )
        }

        override fun channelRead(
            ctx: ChannelHandlerContext,
            msg: Any,
        ) {
            try {
                val buf = msg as? ByteBuf ?: return
                val n = buf.readableBytes()
                if (answered || filled + n > buffer.size) {
                    logger.debug {
                        "relay directory request refused: unexpected bytes (answered=$answered filled=$filled n=$n)"
                    }
                    refused.incrementAndGet()
                    stream.reset()
                    return
                }
                buf.readBytes(buffer, filled, n)
                filled += n
                if (filled < buffer.size) return
                if (!OnionRelayDirectoryCodec.isValidRequest(buffer)) {
                    logger.debug { "relay directory request refused: malformed" }
                    refused.incrementAndGet()
                    stream.reset()
                    return
                }
                answered = true
                val response = snapshotBytes()
                ctx
                    .channel()
                    .writeAndFlush(Unpooled.wrappedBuffer(response))
                    .addListener { onAnswerFlushed() }
                served.incrementAndGet()
                // no close here: the reader decides completion from the length fields and closes the stream itself
                // (an early close can drop the queued answer on some muxers); the total timeout cleans up a reader that
                // never does. The concurrency slot is given back once the answer is flushed (onAnswerFlushed).
                logger.debug { "relay directory snapshot served (${response.size} bytes, total ${served.get()})" }
            } catch (e: RuntimeException) {
                logger.debug { "relay directory request failed: ${e.javaClass.simpleName}" }
                stream.reset()
            } finally {
                ReferenceCountUtil.release(msg)
            }
        }

        @Deprecated("Deprecated in Java")
        override fun exceptionCaught(
            ctx: ChannelHandlerContext,
            cause: Throwable,
        ) {
            ctx.close()
        }
    }

    private class Binding(
        handler: ProtocolHandler<Unit>,
    ) : StrictProtocolBinding<Unit>(ONION_RELAY_DIRECTORY_PROTOCOL_ID, handler)

    companion object {
        /** A server answering from [index] and the peer records of [peerDirectory]. */
        fun of(
            index: OnionRelayDescriptorIndex,
            peerDirectory: PeerDirectoryGossip,
            clock: Clock = Clock.systemUTC(),
        ): OnionRelayDirectoryServer =
            OnionRelayDirectoryServer(index, { id, now -> peerDirectory.lookup(id, now) }, clock)
    }
}
