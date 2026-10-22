package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import net.lapisphilosophorum.lapisnet.directory.MultiaddrHygiene
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCodec
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.LinkId
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

/** Lazily refilled token bucket (burst = rate), per link. */
internal class CellRateLimiter(
    private val perSecond: Int,
    private val clock: Clock,
) {
    private var tokens = perSecond.toDouble()
    private var last = clock.millis()

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clock.millis()
        tokens = minOf(perSecond.toDouble(), tokens + (now - last).coerceAtLeast(0) * perSecond / 1000.0)
        last = now
        if (tokens >= 1.0) {
            tokens -= 1.0
            return true
        }
        return false
    }
}

/**
 * Per-key counter with an upper bound. Acquire (increment + cap check) and release (decrement + removal at zero) are each
 * one atomic map operation, so a counter that is about to be removed can never be handed out again (no orphaned counter,
 * no way past the cap by churning).
 */
internal class PeerLinkCounter<K : Any> {
    private val counts = ConcurrentHashMap<K, Int>()

    fun tryAcquire(
        key: K,
        max: Int,
    ): Boolean {
        var acquired = false
        counts.compute(key) { _, c ->
            val n = c ?: 0
            if (n < max) {
                acquired = true
                n + 1
            } else {
                c
            }
        }
        return acquired
    }

    fun release(key: K) {
        counts.computeIfPresent(key) { _, c -> if (c <= 1) null else c - 1 }
    }

    fun count(key: K): Int = counts[key] ?: 0

    fun size(): Int = counts.size
}

/** One open link (a libp2p stream to a neighbour). The remote [peer] comes from the Noise-authenticated connection,
 * never from payload data. It is internal bookkeeping and must never reach a log. */
internal class OnionLink(
    override val linkId: LinkId,
    val peer: PeerId,
    val inbound: Boolean,
    val stream: Stream,
    limiter: CellRateLimiter,
) : OnionLinkHandle {
    val id: LinkId get() = linkId
    val rate: CellRateLimiter = limiter
    val pending = AtomicInteger(0)
    val ready = CompletableFuture<Unit>()

    @Volatile var ctx: ChannelHandlerContext? = null

    @Volatile var sawCell = false

    /** Millis of admission or of the last cell that was processed on an existing circuit (or created one); PADDING and cells for unknown circuits are not activity. */
    @Volatile var lastUsefulMillis: Long = 0
    val ended = AtomicBoolean(false)

    fun attach(c: ChannelHandlerContext) {
        ctx = c
        ready.complete(Unit)
    }
}

/** Receives every cell that arrives on a link; returns `true` if it consumed the cell. First claim wins. */
internal fun interface CellSink {
    fun onCell(
        link: LinkId,
        cell: Cell,
    ): Boolean
}

/**
 * Owns all links of the onion layer: admission (hard link cap reserved with a CAS before a stream is accepted, a cap per
 * remote peer), reuse of links (an inbound link may carry an extend towards the same peer), de-duplication of concurrent
 * dials, per-link cell rate limit and write backpressure (an overfull write queue closes the link: nothing is ever buffered
 * without bound). Blocking work (dial) runs on a small bounded pool, never on a Netty event loop. Link ids are random.
 */
internal class OnionLinkManager(
    private val config: OnionWireConfig,
    private val node: LapisNode?,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val links = ConcurrentHashMap<Long, OnionLink>()
    private val slots = AtomicInteger(0)
    private val inboundSlots = AtomicInteger(0)
    private val inboundByPeer = PeerLinkCounter<PeerId>()
    private val dials = ConcurrentHashMap<PeerId, CompletableFuture<LinkId>>()
    private val sinks = CopyOnWriteArrayList<CellSink>()
    private val closedFlag = AtomicBoolean(false)

    private val closedSinks = CopyOnWriteArrayList<(LinkId) -> Unit>()

    /** Tells whether the relay holds circuits on a link; set by the relay service. Without it, no link counts as busy. */
    @Volatile var hasCircuits: (LinkId) -> Boolean = { false }

    /** `true` if a circuit with this circuit id exists on the link; only cells for existing circuits count as activity. */
    @Volatile var circuitKnown: (LinkId, Int) -> Boolean = { _, _ -> false }

    /** Inbound streams are only admitted in relay mode (the handler is registered on the host only then, this is a second guard). */
    @Volatile var acceptInbound: Boolean = false

    private val threadCounter = AtomicInteger()
    private val dialExecutor =
        ThreadPoolExecutor(
            config.dialThreads,
            config.dialThreads,
            30,
            TimeUnit.SECONDS,
            LinkedBlockingQueue(config.maxQueuedDials),
            ThreadFactory {
                Thread(it, "lapis-net-onion-dial-${threadCounter.incrementAndGet()}").also { t ->
                    t.isDaemon =
                        true
                }
            },
        ).also { it.allowCoreThreadTimeOut(true) }
    private val timer =
        ScheduledThreadPoolExecutor(1) { Thread(it, "lapis-net-onion-timer").also { t -> t.isDaemon = true } }
            .also { it.removeOnCancelPolicy = true }

    val protocolHandler = OnionProtocolHandler(this, config)
    val binding = OnionProtocolBinding(protocolHandler)

    /** [priority] sinks (client circuits) are asked before the catch-all relay sink. */
    fun addSink(
        sink: CellSink,
        priority: Boolean = false,
    ) {
        if (priority) sinks.add(0, sink) else sinks.add(sink)
    }

    fun addClosedSink(sink: (LinkId) -> Unit) {
        closedSinks += sink
    }

    fun linkCount(): Int = links.size

    internal fun pendingDialCount(): Int = dials.size

    internal fun reservedSlots(): Int = slots.get()

    internal fun inboundPeerEntries(): Int = inboundByPeer.size()

    /** Submits blocking [task] to the bounded pool; `false` if the pool is saturated or closed. */
    fun submit(task: Runnable): Boolean =
        try {
            dialExecutor.execute(task)
            true
        } catch (e: RejectedExecutionException) {
            false
        }

    fun schedule(
        delayMillis: Long,
        task: Runnable,
    ): java.util.concurrent.ScheduledFuture<*>? =
        try {
            timer.schedule(task, delayMillis, TimeUnit.MILLISECONDS)
        } catch (e: RejectedExecutionException) {
            null
        }

    // ---- admission ---------------------------------------------------------------------------------

    private fun reserveSlot(inbound: Boolean): Boolean {
        if (inbound) {
            // inbound links may never take the slots reserved for outbound (EXTEND) links
            val inboundMax = config.maxLinks - config.reservedOutboundLinks
            while (true) {
                val c = inboundSlots.get()
                if (c >= inboundMax) return false
                if (inboundSlots.compareAndSet(c, c + 1)) break
            }
        }
        while (true) {
            val c = slots.get()
            if (c >= config.maxLinks) {
                if (inbound) inboundSlots.decrementAndGet()
                return false
            }
            if (slots.compareAndSet(c, c + 1)) return true
        }
    }

    fun admit(
        stream: Stream,
        inbound: Boolean,
    ): OnionLink? {
        if (closedFlag.get() || (inbound && !acceptInbound)) return null
        val peer = stream.remotePeerId()
        if (inbound) {
            // increment and cap check are one atomic step per peer (see PeerLinkCounter)
            if (!inboundByPeer.tryAcquire(peer, config.maxInboundLinksPerPeer)) {
                logger.debug { "inbound onion link refused: per-peer cap" }
                return null
            }
        }
        if (!reserveSlot(inbound)) {
            if (inbound) releasePeer(peer)
            logger.debug { "onion link refused: link cap" }
            return null
        }
        var id: LinkId
        var link: OnionLink
        do {
            id = LinkId(random.nextLong())
            link = OnionLink(id, peer, inbound, stream, CellRateLimiter(config.cellsPerSecondPerLink, clock))
            link.lastUsefulMillis = clock.millis()
        } while (id.value == 0L || links.putIfAbsent(id.value, link) != null)
        if (closedFlag.get()) {
            // close() raced with admission and may have missed this link
            close(id)
            return null
        }
        if (inbound) {
            val deadline = config.linkHandshakeTimeout.inWholeMilliseconds
            schedule(deadline) {
                if (!link.sawCell) {
                    logger.debug { "inbound onion link closed: no cell within the handshake window" }
                    close(link.id)
                }
            }
            scheduleIdleCheck(link)
        }
        return link
    }

    /** Closes an inbound link that carries no circuit and saw no cell on an existing circuit for the circuit-less idle timeout. */
    private fun scheduleIdleCheck(link: OnionLink) {
        val timeout = config.inboundIdleWithoutCircuitTimeout.inWholeMilliseconds
        schedule(timeout) {
            if (link.ended.get()) return@schedule
            val idleFor = clock.millis() - link.lastUsefulMillis
            if (!hasCircuits(link.id) && idleFor >= timeout) {
                logger.debug { "inbound onion link closed: no circuit and no useful cell" }
                close(link.id)
            } else {
                scheduleIdleCheck(link)
            }
        }
    }

    private fun releasePeer(peer: PeerId) = inboundByPeer.release(peer)

    // ---- inbound -----------------------------------------------------------------------------------

    fun onInboundBytes(
        link: OnionLink,
        bytes: ByteArray,
    ) {
        link.sawCell = true
        if (!link.rate.tryAcquire()) {
            logger.debug { "onion link closed: cell rate limit" }
            close(link.id)
            return
        }
        val cell =
            try {
                CellCodec.decode(bytes)
            } catch (e: CellFormatException) {
                logger.debug { "onion link closed: malformed cell" }
                close(link.id)
                return
            }
        // Activity = a cell for a circuit that exists (checked before processing, DESTROY removes it) or an accepted CREATE
        // (checked after). Cells for unknown circuits, PADDING included, never keep a circuit-less link alive.
        val checkBefore = cell.command != CellCommand.PADDING && cell.command != CellCommand.CREATE
        val knownBefore = checkBefore && circuitKnown(link.id, cell.circuitId)
        try {
            for (sink in sinks) {
                if (sink.onCell(link.id, cell)) break
            }
            if (knownBefore || (cell.command == CellCommand.CREATE && circuitKnown(link.id, cell.circuitId))) {
                link.lastUsefulMillis = clock.millis()
            }
        } catch (e: RuntimeException) {
            logger.debug { "onion cell handler failed: ${e.javaClass.simpleName}" }
            close(link.id)
        }
    }

    // ---- outbound ----------------------------------------------------------------------------------

    /** Writes [cell]; `false` if the link is gone, not ready or its write queue overflowed (the link is then closed). */
    fun send(
        linkId: LinkId,
        cell: Cell,
    ): Boolean {
        val link = links[linkId.value] ?: return false
        val ctx = link.ctx ?: return false
        if (link.ended.get()) return false
        if (link.pending.incrementAndGet() > config.maxQueuedCellsPerLink) {
            link.pending.decrementAndGet()
            logger.debug { "onion link closed: write queue overflow" }
            close(linkId)
            return false
        }
        ctx
            .writeAndFlush(Unpooled.wrappedBuffer(CellCodec.encode(cell)))
            .addListener {
                link.pending.decrementAndGet()
                if (!it.isSuccess) close(linkId)
            }
        return true
    }

    /** Test seam: writes raw bytes to a link, bypassing cell encoding and all queue accounting. */
    internal fun writeRawForTest(
        linkId: LinkId,
        bytes: ByteArray,
    ): Boolean {
        val ctx = links[linkId.value]?.ctx ?: return false
        ctx.writeAndFlush(Unpooled.wrappedBuffer(bytes))
        return true
    }

    fun close(linkId: LinkId) {
        val link = links[linkId.value] ?: return
        linkEnded(link)
        runCatching { link.stream.reset() }
    }

    /** Idempotent cleanup of all bookkeeping of [link] and notification of the relay. */
    fun linkEnded(link: OnionLink) {
        if (!link.ended.compareAndSet(false, true)) return
        links.remove(link.id.value, link)
        slots.decrementAndGet()
        if (link.inbound) {
            inboundSlots.decrementAndGet()
            releasePeer(link.peer)
        }
        link.ready.completeExceptionally(IllegalStateException("link closed"))
        for (sink in closedSinks) {
            try {
                sink(link.id)
            } catch (e: RuntimeException) {
                logger.debug { "link closed handler failed: ${e.javaClass.simpleName}" }
            }
        }
    }

    private fun existingLinkTo(peer: PeerId): OnionLink? =
        links.values.filter { it.peer == peer && !it.ended.get() && it.ctx != null }.minByOrNull { it.inbound }

    /**
     * An open link to [peer] (reusing an existing one in either direction), or a new one. Concurrent requests for one peer
     * share a single dial. Addresses pass [MultiaddrHygiene] (and an already live connection needs none).
     */
    fun linkTo(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ): CompletableFuture<LinkId> {
        existingLinkTo(peer)?.let { return CompletableFuture.completedFuture(it.id) }
        val lan = node ?: return CompletableFuture.failedFuture(IllegalStateException("no node"))
        if (closedFlag.get()) return CompletableFuture.failedFuture(IllegalStateException("closed"))
        val fresh = CompletableFuture<LinkId>()
        val prior = dials.putIfAbsent(peer, fresh)
        if (prior != null) return prior
        if (dials.size > config.maxPendingDials) {
            dials.remove(peer, fresh)
            fresh.completeExceptionally(IllegalStateException("too many pending dials"))
            return fresh
        }
        val accepted =
            submit {
                var linkId: LinkId? = null
                var failure: Exception? = null
                try {
                    val timeout = java.time.Duration.ofMillis(config.extendTimeout.inWholeMilliseconds)
                    val safe = addresses.filterNot { MultiaddrHygiene.isBlockedPrivateOrLocal(it) }
                    val connection =
                        lan.liveConnectionTo(peer)
                            ?: run {
                                check(safe.isNotEmpty()) { "no address to dial" }
                                lan.connect(PeerInfo(peer, safe), timeout)
                            }
                    val handle =
                        connection.muxerSession().createStream(binding).controller.get(
                            config.extendTimeout.inWholeMilliseconds,
                            TimeUnit.MILLISECONDS,
                        )
                    linkId = handle.linkId.takeIf { it.value != 0L }
                } catch (e: Exception) {
                    failure = e
                }
                // bookkeeping first, then the result: a waiter that sees the outcome also sees a clean table
                dials.remove(peer, fresh)
                when {
                    failure != null -> fresh.completeExceptionally(failure)
                    linkId == null -> fresh.completeExceptionally(IllegalStateException("link refused"))
                    else -> fresh.complete(linkId)
                }
            }
        if (!accepted) {
            dials.remove(peer, fresh)
            fresh.completeExceptionally(IllegalStateException("dial queue full"))
        }
        return fresh
    }

    override fun close() {
        if (!closedFlag.compareAndSet(false, true)) return
        for (link in links.values.toList()) close(link.id)
        dials.values.forEach { it.completeExceptionally(IllegalStateException("closed")) }
        dials.clear()
        sinks.clear()
        closedSinks.clear()
        dialExecutor.shutdownNow()
        timer.shutdownNow()
    }
}
