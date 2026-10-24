package net.lapisphilosophorum.lapisnet.dmonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.dm.SealedMailboxItemCodec
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * The sender's side of the anonymity-mode offline mailbox (wave V0.10.0-F1): keeps the already encrypted envelopes that
 * could not be delivered online and announces them again and again until their lifetime ends, because a recipient who
 * is offline now can only receive an item that is announced AFTER it comes back. This is the honest limit of the design:
 * offline delivery works only while the sender keeps announcing (it was the same with the direct mailbox pointers).
 *
 * Every announcement seals the envelope afresh (new ephemeral key), so announcements cannot be linked by their bytes;
 * the recipient's duplicate suppression absorbs the repeats. At most [itemsPerCircuit] items travel through one circuit.
 * The queue lives in memory only (lost on restart, documented) and is bounded: [maxEntries] in total and
 * [maxPerRecipient] per recipient; when full the oldest entry is dropped and counted.
 *
 * Timing: first announcement at once, then every [intervalMillis] plus or minus up to [jitterMillis]; a failed
 * announcement is retried after [retryMillis]. Defaults (10 min, 2 min, 60 s) are assumptions awaiting confirmation.
 */
class AnonymousMailboxRedelivery(
    private val port: OnionDmRuntimePort,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    private val intervalMillis: Long = 600_000L,
    private val jitterMillis: Long = 120_000L,
    private val retryMillis: Long = 60_000L,
    tickMillis: Long = 5_000L,
    private val maxEntries: Int = MAX_ENTRIES,
    private val maxPerRecipient: Int = MAX_PER_RECIPIENT,
    private val itemsPerCircuit: Int = ITEMS_PER_CIRCUIT,
) : AutoCloseable {
    private class Entry(
        val seq: Long,
        val recipient: Secp256k1PublicKey,
        val sealingKey: X25519PublicKey,
        val envelopeBytes: ByteArray,
        val notValidAfterEpochSecond: Long,
        @Volatile var nextDueMillis: Long,
    )

    private val lock = Any()
    private val entries = ArrayList<Entry>()
    private val seq = AtomicLong(0)
    private val dropped = AtomicLong(0)
    private val announcements = AtomicLong(0)
    private val inFlight = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "lapis-net-dm-onion-redelivery").apply { isDaemon = true }
        }

    init {
        scheduler.scheduleWithFixedDelay({ runCatching { tick() } }, tickMillis, tickMillis, TimeUnit.MILLISECONDS)
    }

    /** Entries currently waiting for their lifetime to end. */
    fun pendingCount(): Int = synchronized(lock) { entries.size }

    /** Entries dropped because a bound was reached (tests, diagnostics). */
    fun droppedCount(): Long = dropped.get()

    /** Items handed to circuits successfully so far (tests, diagnostics). */
    fun announcementCount(): Long = announcements.get()

    /** Queues [envelopeBytes] for announcement and triggers the first announcement at once. */
    fun add(
        recipient: Secp256k1PublicKey,
        sealingKey: X25519PublicKey,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        if (closed.get()) return
        synchronized(lock) {
            if (entries.any { it.recipient == recipient && it.envelopeBytes.contentEquals(envelopeBytes) }) return
            val own = entries.filter { it.recipient == recipient }
            if (own.size >= maxPerRecipient) {
                entries.remove(own.minBy { it.seq })
                dropped.incrementAndGet()
            }
            if (entries.size >= maxEntries) {
                entries.remove(entries.minBy { it.seq })
                dropped.incrementAndGet()
            }
            entries +=
                Entry(
                    seq.incrementAndGet(),
                    recipient,
                    sealingKey,
                    envelopeBytes.copyOf(),
                    notValidAfterEpochSecond,
                    0L,
                )
        }
        try {
            scheduler.execute { runCatching { tick() } }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            // closed concurrently
        }
    }

    private fun jittered(): Long =
        intervalMillis + (if (jitterMillis > 0) random.nextLong(-jitterMillis, jitterMillis + 1) else 0L)

    private fun tick() {
        if (closed.get() || !port.ready()) return
        val nowMillis = clock.millis()
        val nowSeconds = nowMillis / 1000
        val due: List<Entry>
        synchronized(lock) {
            entries.removeAll { it.notValidAfterEpochSecond < nowSeconds }
            due = entries.filter { it.nextDueMillis <= nowMillis }.sortedBy { it.nextDueMillis }.take(itemsPerCircuit)
        }
        if (due.isEmpty() || !inFlight.compareAndSet(false, true)) return
        val items = ArrayList<ByteArray>(due.size)
        val sealedFor = ArrayList<Entry>(due.size)
        for (e in due) {
            try {
                items += SealedMailboxItemCodec.seal(e.envelopeBytes, e.sealingKey, e.notValidAfterEpochSecond, random)
                sealedFor += e
            } catch (ex: RuntimeException) {
                logger.debug { "dropping an unsealable mailbox entry (${ex.javaClass.simpleName})" }
                synchronized(lock) { entries.remove(e) }
            }
        }
        if (items.isEmpty()) {
            inFlight.set(false)
            return
        }
        val future =
            try {
                port.publishMailboxItems(items)
            } catch (ex: RuntimeException) {
                inFlight.set(false)
                sealedFor.forEach { it.nextDueMillis = clock.millis() + retryMillis }
                return
            }
        future.whenComplete { ok, error ->
            inFlight.set(false)
            val later = clock.millis()
            if (error == null && ok == true) {
                announcements.addAndGet(sealedFor.size.toLong())
                sealedFor.forEach { it.nextDueMillis = later + jittered() }
            } else {
                sealedFor.forEach { it.nextDueMillis = later + retryMillis }
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        scheduler.shutdownNow()
        synchronized(lock) {
            entries.forEach { it.envelopeBytes.fill(0) }
            entries.clear()
        }
    }

    companion object {
        const val MAX_ENTRIES = 256
        const val MAX_PER_RECIPIENT = 32
        const val ITEMS_PER_CIRCUIT = 4
    }
}
