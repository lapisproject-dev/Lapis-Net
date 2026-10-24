package net.lapisphilosophorum.lapisnet.mailonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * The sender's online retry queue for mail bundles that do not fit a sealed mailbox item (wave V0.10.0-F2). No relay
 * stores anything: the sender keeps the bundle in memory and tries the stream delivery again every [intervalMillis] plus
 * or minus up to [jitterMillis] until it is acknowledged or its lifetime ends. It works only while sender AND recipient
 * are online at the same time, and the queue is lost on restart (both documented limits).
 *
 * Bounds: [maxEntries] in total, [maxPerRecipient] per recipient and [maxTotalBytes] of bundle data; when one is hit the
 * oldest entries are dropped and counted. The attempt itself is a callback installed by the transport; attempts run one
 * at a time on the queue's own thread. Nothing here is ever logged beyond counters.
 */
class OnionMailRetryQueue(
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    private val intervalMillis: Long = 600_000L,
    private val jitterMillis: Long = 120_000L,
    tickMillis: Long = 5_000L,
    private val maxEntries: Int = MAX_ENTRIES,
    private val maxPerRecipient: Int = MAX_PER_RECIPIENT,
    private val maxTotalBytes: Long = MAX_TOTAL_BYTES,
) : AutoCloseable {
    private class Entry(
        val seq: Long,
        val recipient: Secp256k1PublicKey,
        val bundle: ByteArray,
        val notValidAfterEpochSecond: Long,
        @Volatile var nextDueMillis: Long,
    )

    private val lock = Any()
    private val entries = ArrayList<Entry>()
    private val seq = AtomicLong(0)
    private val dropped = AtomicLong(0)
    private val delivered = AtomicLong(0)
    private val closed = AtomicBoolean(false)
    private val running = AtomicBoolean(false)

    @Volatile private var attempt: ((Secp256k1PublicKey, ByteArray) -> Boolean)? = null
    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "lapis-net-mail-onion-retry").apply { isDaemon = true }
        }

    init {
        scheduler.scheduleWithFixedDelay({ runCatching { tick() } }, tickMillis, tickMillis, TimeUnit.MILLISECONDS)
    }

    /** Installs the delivery attempt (once, by the transport): returns whether the bundle was acknowledged. */
    fun start(attempt: (recipient: Secp256k1PublicKey, bundle: ByteArray) -> Boolean) {
        check(this.attempt == null) { "the retry queue is already started" }
        this.attempt = attempt
    }

    /** Entries waiting for delivery or expiry. */
    fun pendingCount(): Int = synchronized(lock) { entries.size }

    /** Bundle bytes currently held. */
    fun pendingBytes(): Long = synchronized(lock) { entries.sumOf { it.bundle.size.toLong() } }

    /** Entries dropped because a bound was reached. */
    fun droppedCount(): Long = dropped.get()

    /** Bundles acknowledged by a retry. */
    fun deliveredCount(): Long = delivered.get()

    /** Queues [bundle]; its first retry is due after [firstDelayMillis]. */
    fun add(
        recipient: Secp256k1PublicKey,
        bundle: ByteArray,
        notValidAfterEpochSecond: Long,
        firstDelayMillis: Long = intervalMillis,
    ) {
        if (closed.get() || bundle.size > maxTotalBytes) return
        synchronized(lock) {
            val own = entries.filter { it.recipient == recipient }
            if (own.size >= maxPerRecipient) evict(own.minBy { it.seq })
            while (entries.size >= maxEntries) evict(entries.minBy { it.seq })
            var total = entries.sumOf { it.bundle.size.toLong() } + bundle.size
            while (total > maxTotalBytes && entries.isNotEmpty()) {
                val oldest = entries.minBy { it.seq }
                total -= oldest.bundle.size
                evict(oldest)
            }
            entries +=
                Entry(
                    seq.incrementAndGet(),
                    recipient,
                    bundle.copyOf(),
                    notValidAfterEpochSecond,
                    clock.millis() + firstDelayMillis,
                )
        }
    }

    private fun evict(e: Entry) {
        entries.remove(e)
        e.bundle.fill(0)
        dropped.incrementAndGet()
    }

    private fun jittered(): Long =
        intervalMillis + (if (jitterMillis > 0) random.nextLong(-jitterMillis, jitterMillis + 1) else 0L)

    private fun tick() {
        val doAttempt = attempt ?: return
        if (closed.get() || !running.compareAndSet(false, true)) return
        try {
            val nowMillis = clock.millis()
            val nowSeconds = nowMillis / 1000
            val due: List<Entry>
            synchronized(lock) {
                entries.removeAll { e -> (e.notValidAfterEpochSecond < nowSeconds).also { if (it) e.bundle.fill(0) } }
                due = entries.filter { it.nextDueMillis <= nowMillis }.sortedBy { it.nextDueMillis }.take(1)
            }
            for (e in due) {
                if (closed.get()) return
                // a copy: a concurrent eviction zeroes the stored bundle and must not corrupt a send in progress
                val copy = e.bundle.copyOf()
                val ok =
                    try {
                        doAttempt(e.recipient, copy)
                    } catch (ex: RuntimeException) {
                        logger.debug { "mail retry attempt failed (${ex.javaClass.simpleName})" }
                        false
                    } finally {
                        copy.fill(0)
                    }
                if (ok) {
                    delivered.incrementAndGet()
                    synchronized(lock) {
                        if (entries.remove(e)) e.bundle.fill(0)
                    }
                } else {
                    e.nextDueMillis = clock.millis() + jittered()
                }
            }
        } finally {
            running.set(false)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        scheduler.shutdownNow()
        synchronized(lock) {
            entries.forEach { it.bundle.fill(0) }
            entries.clear()
        }
    }

    override fun toString(): String = "OnionMailRetryQueue(REDACTED)"

    companion object {
        const val MAX_ENTRIES = 32
        const val MAX_PER_RECIPIENT = 4
        const val MAX_TOTAL_BYTES = 16L * 1024 * 1024
    }
}
