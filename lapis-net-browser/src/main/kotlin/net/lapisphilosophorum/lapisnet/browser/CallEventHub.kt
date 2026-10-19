package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import net.lapisphilosophorum.lapisnet.call.CallEvent
import net.lapisphilosophorum.lapisnet.call.CallId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/** An INVITE from a quarantined sender that `lapis-net-call` silently dropped; shown to the user as
 * a muted history line, never as something they can act on. */
data class BlockedCallAttempt(
    val callId: CallId,
    val peer: Secp256k1PublicKey,
    val atEpochSecond: Long,
)

/**
 * V0.8.7b - fans the single `CallManager` listener stream out to any number of SSE subscribers.
 *
 * **Exactly one** listener is registered on the [CallRemote] (in `init`): `CallManager` has no
 * `removeCallListener`, so registering one per SSE connection would leak a listener per page load.
 * The hub lives as long as the [BrowserServer].
 *
 * **The listener runs on the call state thread and must never block it.** [onEvent] therefore only
 * maps the event, does a non-suspending `trySend` per subscriber (a subscriber whose buffer is full is
 * closed - it reconnects and re-reads `/status` - instead of being waited for) and appends to a
 * bounded lock-free ring of [BlockedCallAttempt]s. No I/O, no `synchronized`, no per-event info logging.
 *
 * **Quarantine:** an `IncomingCall(quarantined = true)` with [autoRejectQuarantined] is mapped to a
 * `blocked` UI event and recorded - and, deliberately, this class never calls the remote for it: the
 * acceptance policy is not bypassed by a browser click on a call that was silently dropped.
 */
class CallEventHub(
    remote: CallRemote,
    private val autoRejectQuarantined: Boolean,
    private val clockSeconds: () -> Long = { Instant.now().epochSecond },
    private val maxSubscribers: Int = 4,
    private val subscriberBuffer: Int = 64,
    private val maxBlockedEntries: Int = 64,
) {
    /** A live SSE subscription; [close] is idempotent and returns the slot exactly once. */
    sealed interface Subscription : AutoCloseable {
        val events: ReceiveChannel<CallUiEvent>
    }

    private inner class SubscriptionImpl : Subscription {
        val channel = Channel<CallUiEvent>(subscriberBuffer)
        private val closed = AtomicBoolean(false)
        override val events: ReceiveChannel<CallUiEvent> get() = channel

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            subscribers.remove(this)
            channel.close()
            slots.release()
        }
    }

    private val slots = Semaphore(maxSubscribers)
    private val subscribers = CopyOnWriteArraySet<SubscriptionImpl>()
    private val blockedRing = ConcurrentLinkedDeque<BlockedCallAttempt>()
    private val blockedIds = ConcurrentHashMap<CallId, Boolean>()
    private val blockedSize = AtomicInteger(0)
    private val listenerNanosMax = AtomicLong(0)

    init {
        remote.addCallListener(::onEvent)
    }

    /** Takes a subscriber slot, or returns `null` (the route answers 429) when all are in use. */
    fun trySubscribe(): Subscription? {
        if (!slots.tryAcquire()) return null
        val subscription = SubscriptionImpl()
        subscribers.add(subscription)
        return subscription
    }

    fun blockedAttempts(): List<BlockedCallAttempt> = blockedRing.toList()

    fun isBlocked(callId: CallId): Boolean = blockedIds.containsKey(callId)

    internal fun subscriberCountForTesting(): Int = subscribers.size

    internal fun listenerInvocationNanosMaxForTesting(): Long = listenerNanosMax.get()

    private fun onEvent(event: CallEvent) {
        val started = System.nanoTime()
        try {
            val ui = map(event)
            for (subscriber in subscribers) {
                if (!subscriber.channel.trySend(ui).isSuccess) {
                    // Full (slow reader) or already closed: drop the subscriber, never wait for it.
                    subscriber.close()
                }
            }
        } catch (e: Exception) {
            logger.warn(e) { "call event hub failed to dispatch an event" }
        } finally {
            val elapsed = System.nanoTime() - started
            listenerNanosMax.accumulateAndGet(elapsed) { a, b -> maxOf(a, b) }
        }
    }

    private fun map(event: CallEvent): CallUiEvent {
        val id = event.callId.bytes.toHexString()
        val peer = event.peer.bytes.toHexString()
        val fp = event.peer.fingerprint()
        return when (event) {
            is CallEvent.IncomingCall ->
                if (event.quarantined && autoRejectQuarantined) {
                    recordBlocked(BlockedCallAttempt(event.callId, event.peer, clockSeconds()))
                    CallUiEvent("blocked", id, peer, fp)
                } else {
                    CallUiEvent("incoming", id, peer, fp, unaccepted = event.quarantined)
                }
            is CallEvent.OutgoingRinging -> CallUiEvent("ringing", id, peer, fp)
            is CallEvent.Connecting -> CallUiEvent("connecting", id, peer, fp)
            is CallEvent.Active -> CallUiEvent("active", id, peer, fp)
            is CallEvent.Ended -> CallUiEvent("ended", id, peer, fp, reason = event.reason.name)
        }
    }

    private fun recordBlocked(attempt: BlockedCallAttempt) {
        blockedRing.addLast(attempt)
        blockedIds[attempt.callId] = true
        blockedSize.incrementAndGet()
        while (blockedSize.get() > maxBlockedEntries) {
            val oldest = blockedRing.pollFirst() ?: break
            blockedIds.remove(oldest.callId)
            blockedSize.decrementAndGet()
        }
    }
}
