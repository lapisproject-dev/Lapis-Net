package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig
import java.time.Clock
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val logger = KotlinLogging.logger {}

/** A pending timer entry that can be cancelled. */
internal fun interface Cancellable {
    fun cancel()
}

/** Seam over the single timer thread of the link manager, so that tests drive time by hand. */
internal fun interface SliceTimer {
    fun schedule(
        delayMillis: Long,
        task: Runnable,
    ): Cancellable?

    companion object {
        fun of(links: OnionLinkManager): SliceTimer =
            SliceTimer { delay, task ->
                val f: ScheduledFuture<*>? = links.schedule(delay, task)
                f?.let { future -> Cancellable { future.cancel(false) } }
            }
    }
}

/**
 * Shapes the outgoing cells of an anonymity-mode node into time slices (wave V0.10.0-H). Cells are not written when they
 * are produced but queued per link and handed to the link at the next boundary of a slice of
 * [TrafficPaddingConfig.sliceMillis] (so a send waits at most one slice). A link that carried real cells owes
 * [TrafficPaddingConfig.burstTailSlices] further slices with one cell each (cover, via [tailSink]), so the end of a burst
 * is not visible at slice resolution. Per boundary at most `maxQueuedNetty - pending` cells go to a link, so a long
 * transfer never overflows the link's write queue.
 *
 * Only an anonymity-mode node installs a shaper, and such a node never relays for others (the modes exclude each other),
 * so every cell it shapes is one of its own. There is exactly one pending timer entry and only while there is queued
 * data or a tail owed: no steady-rate timer runs on an idle node, and no thread is created.
 *
 * Lock order: a circuit lock may be held while [enqueue] takes the queue lock; the queue lock is never held while calling
 * into a circuit, the link or the sink. [flushLock] serialises boundaries and [closeAndFlush]; nothing that holds a
 * circuit lock ever takes it.
 */
internal class EgressShaper(
    private val config: TrafficPaddingConfig,
    private val write: (LinkId, Cell) -> Boolean,
    private val pendingOf: (LinkId) -> Int,
    private val timer: SliceTimer,
    private val clock: Clock,
    private val maxQueuedNetty: Int,
    private val perLinkCap: Int = DEFAULT_PER_LINK_CAP,
    private val totalCap: Int = DEFAULT_TOTAL_CAP,
) : AutoCloseable {
    init {
        require(perLinkCap >= LARGEST_FRAME_CELLS) { "perLinkCap must hold the largest frame class" }
        require(totalCap >= perLinkCap) { "totalCap must be at least perLinkCap" }
        require(maxQueuedNetty > 0) { "maxQueuedNetty must be positive" }
    }

    /** Called at a boundary (outside the queue lock) for every link that owes tail cells. */
    @Volatile var tailSink: ((LinkId, Int) -> Unit)? = null

    private val lock = Any()
    private val flushLock = ReentrantLock()
    private val queues = LinkedHashMap<Long, ArrayDeque<Cell>>()
    private val ids = HashMap<Long, LinkId>()
    private val tailOwed = HashMap<Long, Int>()
    private var total = 0
    private var pending: Cancellable? = null
    private var inBoundary = false
    private var closed = false

    /** Queues [cell]; `false` if a cap is reached (the caller treats that like a write queue overflow). */
    fun enqueue(
        link: LinkId,
        cell: Cell,
    ): Boolean {
        val direct: Boolean
        var drainNow = false
        synchronized(lock) {
            direct = closed
            if (!direct) {
                val q = queues.getOrPut(link.value) { ArrayDeque() }
                if (q.size >= perLinkCap || total >= totalCap) {
                    if (q.isEmpty()) queues.remove(link.value)
                    return false
                }
                q.addLast(cell)
                ids[link.value] = link
                total++
                // real traffic opens a burst tail; cover cells (see asCover) never do
                if (!COVER.get()) tailOwed[link.value] = config.burstTailSlices
                drainNow = !ensureScheduledLocked()
            }
        }
        // after the shaper was closed everything goes straight to the link (a DESTROY must still leave)
        if (direct) return write(link, cell)
        // the timer is gone (shutdown): never leave cells behind
        if (drainNow) closeAndFlush()
        return true
    }

    /** Drops everything queued for [link] (the link ended). */
    fun linkClosed(link: LinkId) {
        synchronized(lock) {
            queues.remove(link.value)?.let { total -= it.size }
            ids.remove(link.value)
            tailOwed.remove(link.value)
        }
    }

    fun queuedCells(): Int = synchronized(lock) { total }

    /** `true` while a timer entry is outstanding (leak checks). */
    fun timerPending(): Boolean = synchronized(lock) { pending != null }

    /** Makes sure one timer entry is outstanding; `false` if the timer refused (it has been shut down). */
    private fun ensureScheduledLocked(): Boolean {
        if (closed || pending != null || inBoundary) return true
        val slice = config.sliceMillis
        val delay = slice - Math.floorMod(clock.millis(), slice)
        val handle = timer.schedule(delay) { boundary() } ?: return false
        pending = handle
        return true
    }

    private fun boundary() {
        flushLock.withLock {
            synchronized(lock) {
                if (closed) return
                pending = null
                inBoundary = true
            }
            try {
                val owing = ArrayList<LinkId>(2)
                synchronized(lock) {
                    for ((k, owed) in tailOwed.entries.toList()) {
                        val q = queues[k]
                        // a slice that carries real cells is itself part of the burst; only empty slices owe a tail cell
                        if (q != null && q.isNotEmpty()) continue
                        if (owed > 0) ids[k]?.let { owing += it }
                        if (owed <= 1) tailOwed.remove(k) else tailOwed[k] = owed - 1
                    }
                }
                val sink = tailSink
                if (sink != null) {
                    for (l in owing) {
                        try {
                            sink(l, 1)
                        } catch (e: RuntimeException) {
                            logger.debug { "tail cover failed: ${e.javaClass.simpleName}" }
                        }
                    }
                }
                flushQuota()
            } finally {
                var drain = false
                synchronized(lock) {
                    inBoundary = false
                    if (!closed && (total > 0 || tailOwed.isNotEmpty())) drain = !ensureScheduledLocked()
                }
                if (drain) closeAndFlush()
            }
        }
    }

    /** Takes up to the per-link quota out of every queue under the lock, writes outside it. */
    private fun flushQuota() {
        val batches = ArrayList<Pair<LinkId, List<Cell>>>()
        synchronized(lock) {
            for ((k, q) in queues) {
                if (q.isEmpty()) continue
                val id = ids[k] ?: continue
                val quota = (maxQueuedNetty - pendingOf(id)).coerceAtLeast(0)
                val n = minOf(quota, q.size)
                if (n == 0) continue
                val taken = ArrayList<Cell>(n)
                repeat(n) { taken += q.removeFirst() }
                total -= n
                batches += id to taken
            }
            queues.entries.removeIf { it.value.isEmpty() }
        }
        for ((id, cells) in batches) {
            for (c in cells) {
                if (!write(id, c)) {
                    linkClosed(id)
                    break
                }
            }
        }
    }

    /** Writes everything that is queued now, in order, and stops shaping: later cells go straight to the link. Idempotent. */
    fun closeAndFlush() {
        flushLock.withLock {
            val cancel: Cancellable?
            val batches = ArrayList<Pair<LinkId, List<Cell>>>()
            synchronized(lock) {
                if (closed) return
                closed = true
                cancel = pending
                pending = null
                for ((k, q) in queues) {
                    val id = ids[k] ?: continue
                    if (q.isNotEmpty()) batches += id to q.toList()
                }
                queues.clear()
                ids.clear()
                tailOwed.clear()
                total = 0
            }
            cancel?.cancel()
            for ((id, cells) in batches) {
                for (c in cells) if (!write(id, c)) break
            }
        }
    }

    override fun close() = closeAndFlush()

    companion object {
        private val COVER = ThreadLocal.withInitial { false }

        /** Runs [block] so that cells it enqueues are cover: they do not open a burst tail. */
        inline fun <T> asCover(block: () -> T): T {
            val prev = coverFlag().get()
            coverFlag().set(true)
            try {
                return block()
            } finally {
                coverFlag().set(prev)
            }
        }

        @PublishedApi internal fun coverFlag(): ThreadLocal<Boolean> = COVER

        /** The chunk count of the largest mail frame class (1153). */
        const val LARGEST_FRAME_CELLS = 1153

        /** Concurrent senders on the one guard link (the mail transport runs two delivery threads, plus DM and signals). */
        const val CONCURRENT_LARGE_FRAMES = 4

        /**
         * Room for [CONCURRENT_LARGE_FRAMES] largest frames at once plus slack: all circuits of an anonymity node share
         * one guard link, and a queue overflow closes that link (and with it every circuit), so the cap must not be
         * reachable by ordinary concurrent sends. A cell is about 1 KiB, so the worst case is about 5 MiB per link.
         */
        const val DEFAULT_PER_LINK_CAP = CONCURRENT_LARGE_FRAMES * LARGEST_FRAME_CELLS + 256
        const val DEFAULT_TOTAL_CAP = 4 * DEFAULT_PER_LINK_CAP
    }
}
