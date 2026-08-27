package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import java.time.Instant
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

private val logger = KotlinLogging.logger {}

/**
 * The sender-side periodic re-announcer for V0.8.5's offline mailbox pointers - this wave's
 * genuinely novel mechanism, not mirrored from any prior sub-wave's precedent.
 *
 * **Why this exists at all - a gap `MailboxGossip` being purely reactive (subscribe once, wait for
 * gossip) would leave open.** [GossipPubSub.subscribe]'s own doc comment establishes that GossipSub
 * has ZERO message replay/history: a node that publishes while a peer isn't yet subscribed never
 * redelivers that message to a later-joining subscriber. The defining "genuinely offline" scenario
 * this wave targets - a recipient's node that is not even RUNNING at the moment the sender deposits
 * a pointer - means the pointer's original publish is published while the recipient's mailbox topic
 * subscription does not exist yet; GossipSub will NEVER deliver that specific publish to a
 * subsequently-starting subscriber, no matter how long the recipient later stays subscribed.
 *
 * This class closes that gap the only way available without relying on GossipSub's internal
 * mcache/IHAVE timing (which would be fragile and undocumented): the sender does not publish a
 * pointer once and forget it - [DmSessionManager.sendOffline] hands it to this scheduler via
 * [track], which re-publishes the SAME pointer bytes on a fixed interval for as long as its TTL
 * has not expired. A recipient's node that starts up later and subscribes to its own mailbox topic
 * receives the pointer on the NEXT scheduled re-publish, through completely ordinary, already-
 * proven GossipSub delivery.
 *
 * **This is the fuller explanation behind this wave's "sender must remain reachable, or at least
 * periodically online" caveat - stronger than "reachable to serve the eventual Bitswap fetch".**
 * The sender must be ALIVE FOR POINTER REDELIVERY, which is the ONLY way the pointer's existence is
 * ever discoverable by a recipient who missed the original publish - not merely a nice-to-have for
 * serving one Bitswap request. If the sender's node is not online again before the pointer's TTL
 * expires, the recipient can never learn the pointer exists at all, regardless of whether the
 * underlying blob would still have been fetchable. See `docs/roadmap.adoc`'s and
 * `docs/architecture.adoc`'s V0.8.5 sections - this is this wave's most important caveat, stated
 * there without hedging.
 *
 * **In-memory-only, process-local, best-effort tracking - lost on restart, an accepted, documented
 * limitation, the same scope cut `DmSessionManager`'s own `liveSessionCache`/every other in-memory
 * index in this codebase already carries.** A sender that restarts mid-TTL-window simply stops
 * re-announcing pointers it sent before the restart; the durable blob and the already-published
 * pointer remain valid and fetchable if a recipient happened to see an earlier publish, but no
 * further re-announcement occurs for those specific pointers. Restarting `sendOffline` for the same
 * message (a fresh deposit) is the caller's remedy, exactly like every other in-memory-only
 * structure in this codebase.
 */
class MailboxRedeliveryScheduler private constructor(
    private val pubsub: GossipPubSub,
    private val redeliverIntervalSeconds: Long,
) {
    private data class Pending(
        val recipient: Secp256k1PublicKey,
        val pointerBytes: ByteArray,
        val notValidAfterEpochSecond: Long,
    )

    /** Bounded, LRU-evicting - mirrors `DmSessionManager.MAX_LIVE_SESSIONS`'s "generous headroom,
     * provisional magnitude" framing. */
    private val pending =
        object : LinkedHashMap<MailboxPointerContentId, Pending>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<MailboxPointerContentId, Pending>): Boolean =
                size > MAX_PENDING_OUTBOUND_MAILBOX_SENDS
        }

    private val executor: ScheduledExecutorService by lazy {
        ScheduledThreadPoolExecutor(1) { r -> Thread(r, "lapis-net-dm-mailbox-redeliver").apply { isDaemon = true } }
            .also { it.removeOnCancelPolicy = true }
    }
    private var scheduledTask: ScheduledFuture<*>? = null

    /** Registers a just-announced pointer for periodic re-announcement. Called by
     * [DmSessionManager.sendOffline] strictly BEFORE the first live publish - security audit round 2
     * minor finding: a `pubsub.publish` failure after the pointer/blob were already durably persisted
     * must not also skip registering re-announcement, the ONLY way an offline recipient ever learns a
     * pointer exists at all (see this class's own doc comment). This scheduler never performs the
     * FIRST announce itself, that stays synchronous inside `sendOffline` - `track` only registers this
     * pointer for scheduler's OWN later, periodic re-publishes, matching this codebase's established
     * "persist then publish, publish strictly last" invariant (track is a cheap, no-I/O map write, not
     * a publish). */
    @Synchronized
    fun track(
        recipient: Secp256k1PublicKey,
        pointer: MailboxPointer,
        pointerBytes: ByteArray,
    ) {
        pending[MailboxPointerContentId(pointer.contentId())] =
            Pending(recipient, pointerBytes, pointer.notValidAfterEpochSecond)
    }

    /**
     * Security audit round 1 minor finding fixed here: `pubsub.publish` used to run INSIDE this
     * `@Synchronized` critical section, with no per-entry `try`/`catch` - a single publish that threw
     * (e.g. `GossipPubSubException` from `GossipPubSub.publish`'s own `awaitOrWrap` timeout, not the
     * `NoPeersForOutboundMessageException` case that method already swallows internally) aborted the
     * REST of the pass at the same position on every subsequent tick, since [pending]'s iteration
     * order is stable across ticks - permanently starving every pointer ordered after the failing
     * one of re-announcement, the ONLY mechanism by which an offline recipient ever learns a pointer
     * exists at all. Separately, holding this monitor for up to
     * [MAX_PENDING_OUTBOUND_MAILBOX_SENDS] publishes (each up to a 10s timeout) blocked [track],
     * which [DmSessionManager.sendOffline] calls while already holding a per-peer stripe lock.
     *
     * Fixed by snapshotting the due entries under the lock (cheap, no I/O), then publishing OUTSIDE
     * it with each publish independently `try`/`caught` - a single failing publish is logged and
     * skipped, every other entry still gets its chance this tick, and [track] is never blocked
     * behind an in-flight publish.
     */
    private fun redeliverDue(nowEpochSecond: Long) {
        val due = mutableListOf<Pair<MailboxPointerContentId, Pending>>()
        synchronized(this) {
            val iterator = pending.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                if (entry.value.notValidAfterEpochSecond < nowEpochSecond) {
                    // TTL passed - stop re-announcing. MailboxPointerIndex.evictExpired reclaims the
                    // RECEIVING side independently.
                    iterator.remove()
                    continue
                }
                due.add(entry.key to entry.value)
            }
        }
        due.forEach { (_, entry) ->
            try {
                pubsub.publish(MailboxTopics.forRecipient(entry.recipient), entry.pointerBytes)
            } catch (e: RuntimeException) {
                logger.warn(e) {
                    "failed to re-announce a mailbox pointer for recipient ${entry.recipient.fingerprint()} - " +
                        "leaving it tracked, will retry on the next redelivery tick"
                }
            }
        }
    }

    private fun start() {
        scheduledTask =
            executor.scheduleWithFixedDelay(
                { runCatching { redeliverDue(Instant.now().epochSecond) } },
                redeliverIntervalSeconds,
                redeliverIntervalSeconds,
                TimeUnit.SECONDS,
            )
    }

    /** Cancels the periodic re-announce task and shuts down this scheduler's background executor.
     * Idempotent. Pointers still tracked at the moment of `stop()` are simply dropped - no final
     * flush is attempted. */
    fun stop() {
        scheduledTask?.cancel(false)
        executor.shutdownNow()
    }

    companion object {
        /** Mirrors `net.lapisphilosophorum.lapisnet.directory.PeerPresenceAnnouncer`'s own
         * minimum-republish-interval default exactly - same "generous heartbeat, not derived from
         * pilot data" framing. */
        const val DEFAULT_REDELIVER_INTERVAL_SECONDS = 300L

        /** Mirrors `DmSessionManager.MAX_LIVE_SESSIONS`. */
        const val MAX_PENDING_OUTBOUND_MAILBOX_SENDS = 4_096

        fun attach(
            pubsub: GossipPubSub,
            redeliverIntervalSeconds: Long = DEFAULT_REDELIVER_INTERVAL_SECONDS,
        ): MailboxRedeliveryScheduler = MailboxRedeliveryScheduler(pubsub, redeliverIntervalSeconds).also { it.start() }
    }
}
