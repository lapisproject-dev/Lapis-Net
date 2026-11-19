package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** A send gave up waiting for its turn in the per-peer outbound lane ([OutboundLanes.awaitTurn] timed out). */
internal class DmLaneWaitTimeoutException : DmSessionException("timed out waiting for earlier sends to the same peer")

/**
 * Per-peer FIFO "send lanes" of [DmSessionManager]: they keep envelopes for one peer on the wire in ratchet order while
 * the network I/O itself runs WITHOUT the peer's stripe lock (two-phase send, see `docs/architecture.adoc`).
 *
 * Phase A of a send (under the stripe lock) calls [reserve] in the same critical section as the ratchet `encrypt`, so
 * ticket order equals ratchet order. Phase B (no stripe lock held) calls [awaitTurn], does the dial/write, deposit or
 * anonymous delivery, then [release] in a `finally` block.
 *
 * Lock order: stripe lock (optional, outermost) -> the [lanes] map's bin lock -> a lane's own [Lane.lock] (innermost).
 * Nothing is called back, and no I/O happens, while a lane lock is held.
 *
 * Memory: a lane exists only while it has at least one ticket and is removed as soon as it is empty. Lanes are created
 * only by outbound sends (local calls, or the re-send after an authenticated rejection), never by inbound data. Per lane
 * at most [maxQueuedPerPeer] tickets, at most [maxActiveLanes] lanes in total.
 */
internal class OutboundLanes(
    @Volatile internal var maxQueuedPerPeer: Int,
    @Volatile internal var maxActiveLanes: Int,
) {
    internal class Ticket internal constructor(
        val peer: Secp256k1PublicKey,
        internal val lane: Lane,
        internal val seq: Long,
    )

    /** Result of [awaitTurn]. [previousDialFailed]: an online attempt to the same peer that was ahead of this ticket
     * (reserved earlier and still running when this ticket was queued) failed. */
    internal class HeadState(
        val previousDialFailed: Boolean,
    )

    internal class Lane {
        val lock = ReentrantLock()
        val turn: Condition = lock.newCondition()
        val queue = ArrayDeque<Ticket>()
        var nextSeq = 0L

        /** Every ticket with `seq < failedBefore` was already queued when an online attempt ahead of it failed. */
        var failedBefore = -1L
    }

    private val lanes = ConcurrentHashMap<Secp256k1PublicKey, Lane>()

    @Volatile
    private var closed = false

    /**
     * Appends a ticket for [peer]. Called inside the peer's stripe lock, BEFORE the ratchet step, so a full lane never
     * consumes a ratchet step. Never blocks on another thread's I/O (map bin lock and lane lock only).
     *
     * @throws DmSessionException if the lane is full, too many lanes are active, or the lanes were closed.
     */
    fun reserve(peer: Secp256k1PublicKey): Ticket {
        var ticket: Ticket? = null
        var failure: String? = null
        lanes.compute(peer) { _, existing ->
            if (closed) {
                failure = STOPPED
                return@compute existing
            }
            if (existing == null && lanes.size >= maxActiveLanes) {
                failure = "too many peers with queued outbound sends"
                return@compute null
            }
            val lane = existing ?: Lane()
            lane.lock.withLock {
                if (lane.queue.size >= maxQueuedPerPeer) {
                    failure = "too many queued sends to the same peer"
                } else {
                    val t = Ticket(peer, lane, lane.nextSeq++)
                    lane.queue.addLast(t)
                    ticket = t
                }
            }
            if (lane.queue.isEmpty()) null else lane
        }
        failure?.let { throw DmSessionException(it) }
        return checkNotNull(ticket)
    }

    /**
     * Waits until [ticket] is the head of its lane. Called WITHOUT any stripe lock. Interruptible and bounded by
     * [timeout]. On timeout, interrupt or [close] the ticket is removed (the next ticket gets its turn) and a
     * [DmSessionException] is thrown; on interrupt the thread's interrupt flag is restored.
     */
    fun awaitTurn(
        ticket: Ticket,
        timeout: Duration,
    ): HeadState {
        val lane = ticket.lane
        var failure: DmSessionException? = null
        lane.lock.withLock {
            var remaining = timeout.toNanos()
            while (true) {
                if (closed) {
                    failure = DmSessionException(STOPPED)
                    break
                }
                if (lane.queue.firstOrNull() === ticket) {
                    return HeadState(previousDialFailed = ticket.seq < lane.failedBefore)
                }
                if (remaining <= 0L) {
                    failure = DmLaneWaitTimeoutException()
                    break
                }
                try {
                    remaining = lane.turn.awaitNanos(remaining)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    failure = DmSessionException("interrupted waiting for earlier sends to the same peer", e)
                    break
                }
            }
            lane.queue.remove(ticket)
            lane.turn.signalAll()
        }
        removeIfEmpty(ticket.peer, lane)
        throw checkNotNull(failure)
    }

    /**
     * Removes [ticket] wherever it is (idempotent) and wakes the waiters. [onlineAttemptFailed] marks every ticket
     * already queued behind it as "previous dial failed" (single flight, see [HeadState]). Called in a `finally`.
     */
    fun release(
        ticket: Ticket,
        onlineAttemptFailed: Boolean = false,
    ) {
        val lane = ticket.lane
        lane.lock.withLock {
            val wasQueued = lane.queue.remove(ticket)
            if (wasQueued && onlineAttemptFailed) lane.failedBefore = maxOf(lane.failedBefore, lane.nextSeq)
            lane.turn.signalAll()
        }
        removeIfEmpty(ticket.peer, lane)
    }

    /** Stops the lanes: every waiter wakes up and fails, every later [reserve] fails. */
    fun close() {
        closed = true
        lanes.values.forEach { lane -> lane.lock.withLock { lane.turn.signalAll() } }
    }

    private fun removeIfEmpty(
        peer: Secp256k1PublicKey,
        lane: Lane,
    ) {
        lanes.compute(peer) { _, current ->
            if (current !== lane) return@compute current
            val empty = lane.lock.withLock { lane.queue.isEmpty() }
            if (empty) null else lane
        }
    }

    internal fun queuedForTest(peer: Secp256k1PublicKey): Int =
        lanes[peer]?.let { it.lock.withLock { it.queue.size } } ?: 0

    internal fun laneCountForTest(): Int = lanes.size

    internal fun laneOfForTest(peer: Secp256k1PublicKey): Lane? = lanes[peer]

    /** Invariant check for tests: every lane in the map is non-empty. */
    internal fun allLanesNonEmptyForTest(): Boolean = lanes.values.all { it.lock.withLock { it.queue.isNotEmpty() } }

    private companion object {
        const val STOPPED = "dm session manager stopped"
    }
}
