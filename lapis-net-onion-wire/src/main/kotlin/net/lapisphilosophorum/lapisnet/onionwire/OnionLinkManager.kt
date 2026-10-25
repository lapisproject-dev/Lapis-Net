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
import java.util.Arrays
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

    /** Set (once) as soon as this link's id may have been given to a caller; a link claimed this way is never closed by the dial tie-break. */
    val handedOut = AtomicBoolean(false)

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

    /** Local peer id for the deterministic tie-break; null without a node (unit use). */
    private val localPeer: PeerId? = node?.peerId

    /** Test seam (null in production): runs between admission and attaching the Netty handler of a link. */
    @Volatile internal var beforeAttachForTest: ((OnionLink) -> Unit)? = null

    /** Test seam (null in production): runs on the dial thread after the stream is open, before the tie-break. */
    @Volatile internal var beforeDialResultForTest: ((PeerId) -> Unit)? = null

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

    /**
     * The egress shaper of anonymity mode (wave V0.10.0-H), or `null` (normal mode, relay nodes, padding off): then every
     * cell is written at once. Installed and removed by `OnionWire`.
     */
    @Volatile internal var egress: EgressShaper? = null

    /** Test seam (null in production): sees every cell as it is handed to the link, with the time. */
    @Volatile internal var egressTapForTest: ((LinkId, Cell) -> Unit)? = null

    internal fun maxQueuedCells(): Int = config.maxQueuedCellsPerLink

    /** Cells written to [linkId] and not yet flushed by Netty. */
    internal fun pendingCells(linkId: LinkId): Int = links[linkId.value]?.pending?.get() ?: 0

    /**
     * Sends [cell]: through the egress shaper if one is installed (the cell then leaves at the next slice boundary),
     * otherwise written at once. `false` if the link is gone, not ready or a write queue overflowed (the link is then closed).
     */
    fun send(
        linkId: LinkId,
        cell: Cell,
    ): Boolean {
        val link = links[linkId.value] ?: return false
        if (link.ctx == null || link.ended.get()) return false
        val shaper = egress ?: return writeNow(linkId, cell)
        if (shaper.enqueue(linkId, cell)) return true
        logger.debug { "onion link closed: egress queue overflow" }
        close(linkId)
        return false
    }

    /** Writes [cell]; `false` if the link is gone, not ready or its write queue overflowed (the link is then closed). */
    internal fun writeNow(
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
        egressTapForTest?.invoke(linkId, cell)
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
        egress?.linkClosed(link.id)
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

    /** Compares peer ids by their raw bytes, unsigned: the same answer on both sides. */
    internal fun lowerPeer(
        a: PeerId,
        b: PeerId,
    ): PeerId = if (Arrays.compareUnsigned(a.bytes, b.bytes) <= 0) a else b

    /**
     * `true` if [link] was opened by the side with the lower peer id: the canonical link of a pair. Without a local peer
     * id, or with equal ids, no link is canonical (no tie-break).
     */
    internal fun isCanonical(link: OnionLink): Boolean {
        val me = localPeer ?: return false
        if (me == link.peer) return false
        val opener = if (link.inbound) link.peer else me
        return lowerPeer(me, link.peer) == opener
    }

    /**
     * Best open or opening link to [peer]: canonical first, then attached (ctx != null), then outbound. Includes links that
     * are admitted (and counted) but not yet attached, so counting and reuse see the same entry.
     */
    private fun existingLinkTo(peer: PeerId): OnionLink? =
        links.values
            .filter { it.peer == peer && !it.ended.get() }
            .minWithOrNull(compareBy<OnionLink>({ !isCanonical(it) }, { it.ctx == null }, { it.inbound }))

    /**
     * Future of [link]'s id once it is ready; marks the link as handed out. Completion is normally handed to the dial pool
     * (callers run blocking or synchronized work in their callbacks), but when that pool is saturated or closed it is done
     * inline, which may be a Netty event-loop thread: callbacks must therefore not block. A link that ends before it is ready fails the future; there is deliberately no silent re-dial. Inbound waits
     * are bounded by the handshake timer, outbound ones by the dial timeout.
     */
    private fun whenReady(link: OnionLink): CompletableFuture<LinkId> {
        link.handedOut.set(true)
        val ready = link.ready
        if (ready.isDone && !ready.isCompletedExceptionally) return CompletableFuture.completedFuture(link.id)
        val out = CompletableFuture<LinkId>()
        ready.whenComplete { _, e ->
            val finish = Runnable { if (e != null) out.completeExceptionally(e) else out.complete(link.id) }
            if (!submit(finish)) finish.run()
        }
        return out
    }

    /**
     * An open link to [peer] (reusing an existing one in either direction), or a new one. Concurrent requests for one peer
     * share a single dial. Addresses pass [MultiaddrHygiene] (and an already live connection needs none).
     */
    fun linkTo(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ): CompletableFuture<LinkId> {
        existingLinkTo(peer)?.let { return whenReady(it) }
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
                runCatching { beforeDialResultForTest?.invoke(peer) }
                // Tie-break for simultaneous dials: if the canonical link of the pair is already there and ours is not, and
                // ours was never handed out, close ours and complete the waiters with the canonical one. A link that was
                // already handed out is never closed from outside; the idle check retires it once its circuits are gone.
                var redirect: CompletableFuture<LinkId>? = null
                if (failure == null && linkId != null) {
                    val mine = links[linkId.value]
                    val winner = existingLinkTo(peer)
                    if (mine != null &&
                        winner != null &&
                        winner !== mine &&
                        isCanonical(winner) &&
                        !isCanonical(mine) &&
                        !hasCircuits(mine.id) &&
                        mine.handedOut.compareAndSet(false, true)
                    ) {
                        close(mine.id)
                        redirect = whenReady(winner)
                    }
                }
                // bookkeeping first, then the result: a waiter that sees the outcome also sees a clean table
                dials.remove(peer, fresh)
                when {
                    failure != null -> fresh.completeExceptionally(failure)
                    linkId == null -> fresh.completeExceptionally(IllegalStateException("link refused"))
                    redirect != null ->
                        redirect.whenComplete { id, e ->
                            if (e != null) fresh.completeExceptionally(e) else fresh.complete(id)
                        }
                    else -> {
                        links[linkId.value]?.handedOut?.set(true)
                        fresh.complete(linkId)
                    }
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
        runCatching { egress?.closeAndFlush() }
        for (link in links.values.toList()) close(link.id)
        dials.values.forEach { it.completeExceptionally(IllegalStateException("closed")) }
        dials.clear()
        sinks.clear()
        closedSinks.clear()
        dialExecutor.shutdownNow()
        timer.shutdownNow()
    }
}
