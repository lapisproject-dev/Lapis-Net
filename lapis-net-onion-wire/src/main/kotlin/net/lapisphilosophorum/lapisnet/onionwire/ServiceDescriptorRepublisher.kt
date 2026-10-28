package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryRepublishSchedule
import net.lapisphilosophorum.lapisnet.directory.PublicationRateGuard
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Hands the service descriptors of an `OnionServiceHost` to a [DirectoryPublicationChannel] and makes sure they are
 * not lost: the host publishes a descriptor only on change and once per hour, and a publication that is lost (circuit
 * or acknowledgement failure) or that happens before a receiver subscribed to the gossip topic would otherwise be
 * missing for up to an hour.
 *
 * - Only the newest descriptor (highest sequence number) counts. A newer one cancels everything open for the older
 *   one; an older or equal one is ignored.
 * - At most one send is in flight. [submit] never blocks (the host calls it under its session lock).
 * - A failed first send is retried along [failureBackoff] and then given up on (the host's next descriptor heals it).
 * - The [schedule] is planned ONCE per lifetime, after the first success after the start. Later descriptors (hourly
 *   republication, change of the introduction points) get their first send and failure retries only; they do not
 *   restart the schedule, so no recurring burst pattern appears. Slots that are still open continue with the newest
 *   descriptor.
 * - At the slots a FRESH VERSION of the same content is sent when [refresh] is set: the host re-signs the descriptor
 *   with a higher sequence number (same introduction points and keys, new signature). A byte-identical repeat is
 *   ignored (not forwarded) by every node that already holds it, so it only reaches direct gossip neighbours of the
 *   announcing relay; a new version passes every receiver's pre-check, is valid and is forwarded over several hops. The
 *   senders' [versionGuard] (4 per minute) limits the refresh versions to stay below the receivers' 6 per minute per
 *   author; genuine descriptors (change, hourly) are always sent and only count against the same budget, so there is no
 *   hard guarantee when many genuine changes happen within one minute (refreshes are skipped then, a receiver may drop
 *   the surplus version as rate limited). If the guard is empty,
 *   [refresh] reports that nothing can be refreshed or [refresh] is not set, the same descriptor is sent again as
 *   before (helps the direct neighbours only).
 * - Lock order: the host's session lock is taken BEFORE this monitor ([submit] runs under it). [refresh] takes the
 *   session lock, so it is never called while holding this monitor.
 * - Failure retries and repeats are capped at [maxEarlySendsPerHour]; repeats stop [retryReserve] sends earlier, so a
 *   failed first send of a new descriptor can always still be retried. An expired descriptor is never sent.
 * - After [close] [submit] is a no-op and nothing remains scheduled.
 */
internal class ServiceDescriptorRepublisher(
    private val channel: DirectoryPublicationChannel,
    private val scheduler: (delayMillis: Long, task: () -> Unit) -> Future<*>?,
    private val clockMillis: () -> Long,
    private val schedule: DirectoryRepublishSchedule = DirectoryRepublishSchedule(),
    private val failureBackoff: List<Duration> = listOf(5.seconds, 15.seconds, 45.seconds, 2.minutes, 5.minutes),
    private val maxEarlySendsPerHour: Int = 12,
    private val retryReserve: Int = 4,
    /** Asks the host for a fresh version; returns whether one was produced (and handed to [submit]). */
    private val refresh: (() -> Boolean)? = null,
    /** Sender-side limit for new versions of this descriptor, below the receivers' per-author rate. */
    private val versionGuard: PublicationRateGuard? = null,
) : AutoCloseable {
    private var current: OnionServiceDescriptor? = null
    private var generation = 0L
    private var closed = false
    private var inFlight = false
    private var failures = 0
    private var firstSent = false // the current descriptor was sent successfully at least once
    private var scheduleDone = false // the repeat schedule was planned (once per lifetime)
    private val slots = ArrayDeque<Long>()
    private var timerFuture: Future<*>? = null
    private val extraSends = ArrayDeque<Long>()
    private val refreshing = ThreadLocal.withInitial { false } // set while this thread runs [refresh]
    private var refreshAccepted = false // a fresh version arrived through [submit] during [refresh]

    /** Number of sends handed to the channel (tests). */
    @Volatile var sends: Int = 0
        private set

    /** Registers [descriptor] for publication. Never blocks. */
    fun submit(descriptor: OnionServiceDescriptor) {
        val gen: Long
        val fresh = refreshing.get()
        synchronized(this) {
            if (closed) return
            val cur = current
            if (cur != null && descriptor.sequenceNumber <= cur.sequenceNumber) return
            if (descriptor.notValidAfterEpochSecond * 1000 < clockMillis()) return
            current = descriptor
            generation++
            failures = 0
            if (fresh) {
                refreshAccepted = true // the lifetime's schedule goes on; a failed send of this version is no restart
            } else {
                firstSent = false
            }
            cancelTimer()
            if (inFlight) {
                if (!fresh) versionGuard?.tryAcquire()
                return // the completion of the running send picks up the newer descriptor
            }
            inFlight = true
            gen = generation
        }
        // a genuine new descriptor (change, hourly) is essential and always sent, but counts against the version budget
        if (!fresh) versionGuard?.tryAcquire()
        dispatch(descriptor, gen)
    }

    private fun dispatch(
        descriptor: OnionServiceDescriptor,
        gen: Long,
    ) {
        synchronized(this) { sends++ }
        val future =
            try {
                channel.publishServiceDescriptor(descriptor)
            } catch (e: RuntimeException) {
                CompletableFuture.failedFuture(e)
            }
        future.whenComplete { ok, error ->
            if (error != null || ok != true) logger.debug { "service descriptor publication failed" }
            onResult(gen, error == null && ok == true)
        }
    }

    private fun onResult(
        gen: Long,
        ok: Boolean,
    ) {
        var next: OnionServiceDescriptor? = null
        var nextGen = 0L
        synchronized(this) {
            inFlight = false
            if (closed) return
            if (gen != generation) {
                val cur = current ?: return
                inFlight = true
                next = cur
                nextGen = generation
            } else if (ok) {
                firstSent = true
                if (!scheduleDone) {
                    scheduleDone = true
                    slots.addAll(schedule.plan(clockMillis()).toList())
                }
                failures = 0
                scheduleNextSlot(gen)
            } else if (firstSent) {
                scheduleNextSlot(gen) // the remaining slots are the retries
            } else {
                failures++
                if (failures <= failureBackoff.size) {
                    scheduleTimer(clockMillis() + failureBackoff[failures - 1].inWholeMilliseconds, gen)
                } else {
                    logger.debug { "service descriptor early publication given up" }
                }
            }
        }
        next?.let { dispatch(it, nextGen) }
    }

    private fun onTimer(gen: Long) {
        val send: OnionServiceDescriptor
        val useRefresh: Boolean
        synchronized(this) {
            if (closed || gen != generation) return
            timerFuture = null
            val d = current ?: return
            val now = clockMillis()
            val isRetry = !firstSent // a failed first send of this descriptor, not an optional repeat
            if (!isRetry) {
                // merge every slot that is due by now (suspend, clock jump) into this one send
                if (slots.isNotEmpty()) slots.removeFirst()
                while (slots.isNotEmpty() && slots.first() <= now) slots.removeFirst()
            }
            if (d.notValidAfterEpochSecond * 1000 < now) {
                slots.clear()
                return
            }
            if (inFlight) {
                scheduleNextSlot(gen)
                return
            }
            while (extraSends.isNotEmpty() && now - extraSends.first() >= HOUR_MILLIS) extraSends.removeFirst()
            val limit = if (isRetry) maxEarlySendsPerHour else maxOf(0, maxEarlySendsPerHour - retryReserve)
            if (extraSends.size >= limit) {
                if (!isRetry) slots.clear()
                logger.debug { "service descriptor early publication capped" }
                return
            }
            extraSends.addLast(now)
            useRefresh = !isRetry && refresh != null
            if (useRefresh) {
                refreshAccepted = false
                send = d
            } else {
                inFlight = true
                send = d
            }
        }
        if (useRefresh) {
            // outside of the monitor: refresh takes the host's session lock, which is held while it calls submit
            // peek first, take the token only for a version that was really produced
            if (versionGuard != null && versionGuard.nextAllowedAtMillis() > clockMillis()) {
                logger.debug { "service descriptor refresh skipped: rate guard" }
            } else if (runRefresh()) {
                versionGuard?.tryAcquire()
                return // the new version went out through submit
            }
            val repeat: OnionServiceDescriptor
            synchronized(this) {
                if (closed || gen != generation) return // a newer descriptor took over meanwhile
                if (inFlight) {
                    scheduleNextSlot(gen)
                    return
                }
                inFlight = true
                repeat = current ?: return
            }
            dispatch(repeat, gen)
            return
        }
        dispatch(send, gen)
    }

    /** Runs [refresh] with the fresh-version marker set; `true` if a new version was accepted by [submit]. */
    private fun runRefresh(): Boolean {
        val r = refresh ?: return false
        refreshing.set(true)
        val produced =
            try {
                r()
            } catch (e: RuntimeException) {
                logger.debug { "service descriptor refresh failed: ${e.javaClass.simpleName}" }
                false
            } finally {
                refreshing.set(false)
            }
        return produced && synchronized(this) { refreshAccepted.also { refreshAccepted = false } }
    }

    private fun scheduleNextSlot(gen: Long) {
        if (slots.isNotEmpty()) scheduleTimer(slots.first(), gen)
    }

    private fun scheduleTimer(
        atMillis: Long,
        gen: Long,
    ) {
        cancelTimer()
        timerFuture = scheduler(maxOf(0L, atMillis - clockMillis())) { onTimer(gen) }
    }

    private fun cancelTimer() {
        timerFuture?.cancel(false)
        timerFuture = null
    }

    override fun close() {
        synchronized(this) {
            if (closed) return
            closed = true
            cancelTimer()
            current = null
            slots.clear()
        }
    }

    private companion object {
        const val HOUR_MILLIS = 3_600_000L
    }
}
