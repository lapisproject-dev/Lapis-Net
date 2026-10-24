package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Clock

private val logger = KotlinLogging.logger {}

/** The single, shared GossipSub topic of sealed anonymity-mode mailbox items (wave V0.10.0-F1). */
const val ANONYMOUS_MAILBOX_GOSSIP_TOPIC = "LapisNet:anonymous-mailbox:v1"

/**
 * Gossip wiring of the shared anonymous mailbox topic. Items are announced by relays (the last hop of a
 * MAILBOX_PUBLISH circuit) and are sealed boxes of exactly [ITEM_SIZE] bytes that this class never opens.
 *
 * The validator order is deliberate and cheap-first: exact size (REJECT), the message author must be a relay
 * with a current [OnionRelayDescriptor] (IGNORE, so a not-yet-synced forwarder is not penalised), duplicates by
 * SHA-256 (IGNORE, and they do not use the budget), then the per-author and global rate budget (IGNORE on excess,
 * never REJECT). Nothing is logged except aggregate debug lines: no peer ids, no bytes.
 *
 * [consumer], when set, receives every item that passed validation (it runs on the gossip thread: the consumer
 * must hand work to a bounded executor and return at once).
 */
class AnonymousMailboxGossip private constructor(
    private val pubsub: GossipPubSub,
    private val subscription: PubsubSubscription,
) {
    @Volatile
    var consumer: ((ByteArray) -> Unit)? = null

    /** Announces [itemBytes] (a relay only). The size is re-checked; nothing else about the item is. */
    fun publish(itemBytes: ByteArray) {
        require(itemBytes.size == ITEM_SIZE) { "mailbox item has the wrong size" }
        pubsub.publish(ANONYMOUS_MAILBOX_GOSSIP_TOPIC, itemBytes)
    }

    fun stop() {
        consumer = null
        subscription.unsubscribe()
    }

    companion object {
        /** Matches `SealedMailboxItemCodec.SEALED_ITEM_BYTES` in lapis-net-dm (asserted by a test in dm-onion). */
        const val ITEM_SIZE = 5_728
        const val DEFAULT_PER_AUTHOR_PER_MINUTE = 10
        const val DEFAULT_GLOBAL_PER_MINUTE = 120
        const val MAX_TRACKED_AUTHOR_BUCKETS = 1024
        const val MAX_REMEMBERED_ITEMS = 4096

        fun attach(
            pubsub: GossipPubSub,
            relays: OnionRelayDescriptorIndex,
            clock: Clock = Clock.systemUTC(),
            perAuthorPerMinute: Int = DEFAULT_PER_AUTHOR_PER_MINUTE,
            globalPerMinute: Int = DEFAULT_GLOBAL_PER_MINUTE,
        ): AnonymousMailboxGossip {
            val validator = Validator(relays, clock, perAuthorPerMinute, globalPerMinute)
            var self: AnonymousMailboxGossip? = null
            val sub =
                pubsub.subscribe(ANONYMOUS_MAILBOX_GOSSIP_TOPIC) { bytes, from ->
                    val result = validator.validate(bytes, from)
                    if (result == ValidationResult.Valid) {
                        try {
                            self?.consumer?.invoke(bytes)
                        } catch (e: RuntimeException) {
                            logger.debug { "mailbox consumer failed (${e::class.simpleName})" }
                        }
                    }
                    result
                }
            return AnonymousMailboxGossip(pubsub, sub).also { self = it }
        }
    }

    /** The gossip validator, a separate class so tests drive it without a network. */
    internal class Validator(
        private val relays: OnionRelayDescriptorIndex,
        private val clock: Clock,
        private val perAuthorPerMinute: Int,
        globalPerMinute: Int,
    ) {
        private val global = MinuteBucket(globalPerMinute, clock)
        private val perAuthor =
            object : LinkedHashMap<PeerId, MinuteBucket>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, MinuteBucket>): Boolean =
                    size > MAX_TRACKED_AUTHOR_BUCKETS
            }
        private val seen =
            object : LinkedHashMap<ByteBuffer, Boolean>(16, 0.75f, false) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteBuffer, Boolean>): Boolean =
                    size > MAX_REMEMBERED_ITEMS
            }

        fun validate(
            bytes: ByteArray,
            from: PeerId,
        ): ValidationResult {
            if (bytes.size != ITEM_SIZE) return ValidationResult.Invalid
            val now = clock.millis() / 1000
            if (relays.byPeerId(from, now) == null) {
                logger.debug { "mailbox item ignored: author is not a known relay" }
                return ValidationResult.Ignore
            }
            val digest = ByteBuffer.wrap(MessageDigest.getInstance("SHA-256").digest(bytes))
            // check and reserve atomically so a concurrent duplicate cannot spend budget twice
            if (synchronized(seen) { seen.putIfAbsent(digest, true) } != null) return ValidationResult.Ignore
            val bucket =
                synchronized(perAuthor) { perAuthor.getOrPut(from) { MinuteBucket(perAuthorPerMinute, clock) } }
            if (!bucket.tryAcquire() || !global.tryAcquire()) {
                synchronized(seen) { seen.remove(digest) }
                logger.debug { "mailbox item ignored: rate limit" }
                return ValidationResult.Ignore
            }
            return ValidationResult.Valid
        }
    }
}
