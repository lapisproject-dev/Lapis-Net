package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val logger = KotlinLogging.logger {}

/**
 * Delivers decrypted inbound messages to their listeners per peer, in ratchet order, WITHOUT the peer's stripe lock.
 *
 * [DmSessionManager] decrypts, persists and marks an inbound message under the sender's stripe lock and, still under
 * that lock, [enqueue]s the listener notification. Because the lock serializes the decrypts of one peer, the queue
 * order of a peer equals its decrypt (ratchet) order. After releasing the lock the receiving thread calls [deliver]:
 * if no other thread is draining that peer's queue it becomes the drainer and runs the queued tasks FIFO on its own
 * thread up to and including its own, then hands the rest over to their (waiting) callers; otherwise it waits until
 * its own task has run. So a slow listener delays only later deliveries of the SAME peer, never phase A of a send,
 * rejection handling, or any traffic of other peers on the same stripe, and no thread runs more than the tasks queued
 * ahead of its own (plus those it owes from reentrant calls).
 *
 * **Bound.** A ticket is only ever created after a successful AEAD decrypt, i.e. for an authenticated sender, and every
 * ticket belongs to a caller that waits for it in [deliver] (the one exception, a reentrant call, belongs to the
 * draining thread itself). The number of queued tickets is therefore bounded by the number of threads that deliver
 * inbound envelopes, not by the number of identities an attacker can mint; an empty peer queue is removed at once, so
 * the map holds at most one entry per peer with a delivery in progress (same reasoning as `peerLockStripes`: no
 * structure keyed on an untrusted, unbounded claim).
 *
 * **Lock order.** Stripe lock, then the map's bin lock (only inside [enqueue], briefly). [deliver] runs with no stripe
 * lock held. Tasks (listeners) and I/O never run under the map's bin lock - all queue state is changed only inside
 * [ConcurrentHashMap.compute] and the task runs outside it.
 *
 * **Reentrancy.** A task that synchronously causes another inbound delivery from the same peer on the draining thread
 * (e.g. a listener feeding an envelope back in) gets an immediate return from [deliver]; the new task runs after the
 * current one, on the same thread (the thread owes it and keeps draining until it ran). A listener must not synchronously feed inbound envelopes of a DIFFERENT peer whose
 * listener in turn does the same for this peer: like nested stripe locks before, two drainers would wait on each other.
 */
internal class InboundDeliveryQueue {
    internal class Ticket internal constructor(
        internal val peer: Secp256k1PublicKey,
        internal val task: () -> Unit,
    ) {
        private val lock = ReentrantLock()
        private val changed = lock.newCondition()

        @Volatile private var done = false

        /** Bumped when the drainer gave up after an [Error]: a waiting caller re-checks whether it must drain. */
        @Volatile private var handoffs = 0

        internal val isDone: Boolean get() = done

        internal fun markDone() {
            lock.withLock {
                done = true
                changed.signalAll()
            }
        }

        internal fun handoff() {
            lock.withLock {
                handoffs++
                changed.signalAll()
            }
        }

        /** Waits (uninterruptibly, like the stripe lock before) until done or a hand-off; returns true if done. The
         * interrupt flag of the caller is preserved. */
        internal fun awaitDoneOrHandoff(seenHandoffs: Int): Boolean =
            lock.withLock {
                while (!done && handoffs == seenHandoffs) changed.awaitUninterruptibly()
                done
            }

        internal fun handoffCount(): Int = handoffs
    }

    private class PeerQueue {
        val tickets = ArrayDeque<Ticket>()
        var drainer: Thread? = null
    }

    private val queues = ConcurrentHashMap<Secp256k1PublicKey, PeerQueue>()

    /**
     * MUST be called under [peer]'s stripe lock: that fixes delivery order = decrypt (ratchet) order. Never runs
     * [task]; the caller passes the returned ticket to [deliver] after releasing the lock.
     */
    fun enqueue(
        peer: Secp256k1PublicKey,
        task: () -> Unit,
    ): Ticket {
        val ticket = Ticket(peer, task)
        queues.compute(peer) { _, existing -> (existing ?: PeerQueue()).also { it.tickets.addLast(ticket) } }
        return ticket
    }

    /**
     * MUST be called WITHOUT any stripe lock. Runs [ticket]'s peer's queued tasks FIFO on the calling thread if no
     * other thread is draining that peer, up to and including [ticket]'s own task; otherwise waits until [ticket] has
     * run. A reentrant call from a task of the same peer on the draining thread returns at once (the ticket runs after
     * the current task, still on this thread).
     */
    fun deliver(ticket: Ticket) {
        val me = Thread.currentThread()
        while (!ticket.isDone) {
            val seenHandoffs = ticket.handoffCount()
            var role = Role.WAIT
            queues.compute(ticket.peer) { _, queue ->
                when {
                    // No queue: the ticket already ran (it is marked done before its queue can be removed).
                    queue == null -> role = Role.DONE
                    queue.drainer == null -> {
                        queue.drainer = me
                        role = Role.DRAIN
                    }
                    queue.drainer === me -> role = Role.REENTRANT
                }
                queue
            }
            when (role) {
                Role.DONE -> return
                Role.REENTRANT -> {
                    // This thread owes the ticket: its outer drain keeps going until the ticket has run.
                    owed.get() += ticket
                    return
                }
                Role.DRAIN -> drain(ticket)
                Role.WAIT -> if (ticket.awaitDoneOrHandoff(seenHandoffs)) return
            }
        }
    }

    private enum class Role { DRAIN, WAIT, REENTRANT, DONE }

    /** Tickets whose reentrant [deliver] returned at once on this thread; drained before this thread lets go. */
    private val owed = ThreadLocal.withInitial { ArrayList<Ticket>() }

    /**
     * Runs the peer's tasks FIFO until [own] (and every ticket this thread owes for that peer) has run, then drops the
     * drainer role in the same step that checks the queue. Tasks still queued then belong to other callers, which are
     * woken (hand-off) and drain their own: a drainer never runs an unbounded stream of later deliveries, so a Netty
     * thread is held at most for the tasks queued ahead of its own.
     */
    private fun drain(own: Ticket) {
        val peer = own.peer
        val owedHere = owed.get()
        try {
            while (true) {
                var next: Ticket? = null
                var wake: List<Ticket> = emptyList()
                queues.compute(peer) { _, queue ->
                    if (queue == null) return@compute null
                    val mustContinue = !own.isDone || owedHere.any { it.peer == peer && !it.isDone }
                    if (mustContinue && queue.tickets.isNotEmpty()) {
                        next = queue.tickets.removeFirst()
                        queue
                    } else {
                        // Under the bin lock: drop the role together with the emptiness check (no stranded ticket).
                        queue.drainer = null
                        wake = queue.tickets.toList()
                        if (queue.tickets.isEmpty()) null else queue
                    }
                }
                wake.forEach { it.handoff() }
                val ticket = next ?: return
                try {
                    ticket.task()
                } catch (e: RuntimeException) {
                    logger.warn(e) { "inbound delivery task threw - later deliveries of this peer still run" }
                } catch (e: Error) {
                    ticket.markDone()
                    abandonDrainer(peer)
                    throw e
                } finally {
                    ticket.markDone()
                }
            }
        } finally {
            owedHere.removeIf { it.isDone }
        }
    }

    /** After an [Error] in a task: drop the drainer role and wake every waiting caller, one of which takes over. */
    private fun abandonDrainer(peer: Secp256k1PublicKey) {
        var waiting: List<Ticket> = emptyList()
        queues.compute(peer) { _, queue ->
            if (queue == null) return@compute null
            queue.drainer = null
            waiting = queue.tickets.toList()
            if (queue.tickets.isEmpty()) null else queue
        }
        waiting.forEach { it.handoff() }
    }

    /** Test seam: how many peers currently have a queue entry (0 once every delivery has drained). */
    internal fun queuedPeerCountForTest(): Int = queues.size
}
