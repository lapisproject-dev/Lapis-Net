package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import java.time.Clock

private val logger = KotlinLogging.logger {}

/** Dedicated GossipSub topic of [AnonymousPeerRecord]s. Nodes that do not know it simply never subscribe. */
const val ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC = "LapisNet:anonymous-peer-record-gossip:v1"

/**
 * Gossip wiring of [AnonymousPeerRecord]s (wave V0.10.0-D) on a topic of its own, so that v0.12.0 nodes ignore it.
 * Validator order, as in [OnionServiceDescriptorGossip]: exact size BEFORE decoding, decode, cheap index pre-check
 * (duplicates, replays and stale records are IGNOREd without touching any rate budget), then three rate limits (per
 * author identity, per forwarding peer, global; excess is IGNORE so an honest forwarder is never penalised) guarding
 * the expensive signature verification, then full verification and indexing. Invalid records are rejected. Log lines
 * carry a reason class only: never bytes, keys, identities, addresses or the sending peer.
 *
 * **[announce] from the own node publishes under the node's libp2p key** (the gossip envelope carries the sender's
 * peer ID, and in the current design that peer ID IS the identity key). A node in anonymity mode must therefore not
 * announce directly: it hands the record to a circuit (`DirectoryPublicationChannel`), and the *relay* that
 * receives it announces. See docs/anonymity.adoc.
 *
 * Attach to EVERY node, anonymous or not: senders must be able to resolve anonymous recipients.
 */
class AnonymousPeerRecordGossip private constructor(
    private val pubsub: GossipPubSub,
    private val index: AnonymousPeerRecordIndex,
    private val subscription: PubsubSubscription,
    private val clock: Clock,
) {
    /**
     * Verifies [record], indexes it and publishes it on the topic. Returns the index outcome; a record that does not
     * verify, or is stale, is never published. A repeated call with the same record publishes again.
     */
    fun announce(record: AnonymousPeerRecord): AnonymousIngestOutcome {
        val now = clock.millis() / 1000
        val outcome = index.add(record, now)
        // A duplicate is published again on purpose: "retrying the same announce is safe" is the contract of every
        // gossip class here (the first publication may have found no mesh peer yet). Stale or invalid records never go out.
        if (outcome == AnonymousIngestOutcome.ACCEPTED || outcome == AnonymousIngestOutcome.DUPLICATE) {
            pubsub.publish(ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC, AnonymousPeerRecordCodec.encode(record))
        }
        return outcome
    }

    /**
     * Like [announce], but only returns once the record was handed to at least one mesh peer: while the mesh has no peer
     * for the topic it publishes again every [interval] until [timeout] has passed. Throws [IllegalStateException] if the
     * record was never delivered (or [announce]'s outcome is neither ACCEPTED nor DUPLICATE). For the revocation of an
     * anonymous record, whose "sent" state must not be persisted before somebody actually received it.
     */
    fun announceDelivered(
        record: AnonymousPeerRecord,
        timeout: java.time.Duration = java.time.Duration.ofSeconds(15),
        interval: java.time.Duration = java.time.Duration.ofMillis(500),
    ): AnonymousIngestOutcome {
        val deadline = System.nanoTime() + timeout.toNanos()
        while (true) {
            val now = clock.millis() / 1000
            val outcome = index.add(record, now)
            check(outcome == AnonymousIngestOutcome.ACCEPTED || outcome == AnonymousIngestOutcome.DUPLICATE) {
                "record not accepted"
            }
            if (pubsub.publishReporting(ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC, AnonymousPeerRecordCodec.encode(record))) {
                return outcome
            }
            check(System.nanoTime() < deadline) { "no mesh peer received the record" }
            Thread.sleep(interval.toMillis())
        }
    }

    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        const val DEFAULT_PER_AUTHOR_PER_MINUTE = 6
        const val DEFAULT_PER_PEER_PER_MINUTE = 12
        const val DEFAULT_GLOBAL_PER_MINUTE = 60
        const val MAX_TRACKED_BUCKETS = 1024

        fun attach(
            pubsub: GossipPubSub,
            index: AnonymousPeerRecordIndex,
            clock: Clock = Clock.systemUTC(),
            perAuthorPerMinute: Int = DEFAULT_PER_AUTHOR_PER_MINUTE,
            perPeerPerMinute: Int = DEFAULT_PER_PEER_PER_MINUTE,
            globalPerMinute: Int = DEFAULT_GLOBAL_PER_MINUTE,
        ): AnonymousPeerRecordGossip {
            val validator = Validator(index, clock, perAuthorPerMinute, perPeerPerMinute, globalPerMinute)
            val sub =
                pubsub.subscribe(
                    ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC,
                ) { bytes, from -> validator.validate(from, bytes) }
            return AnonymousPeerRecordGossip(pubsub, index, sub, clock)
        }
    }

    internal class Validator(
        private val index: AnonymousPeerRecordIndex,
        private val clock: Clock,
        private val perAuthorPerMinute: Int,
        private val perPeerPerMinute: Int,
        globalPerMinute: Int,
    ) {
        private val global = MinuteBucket(globalPerMinute, clock)
        private val perPeer = lru<PeerId>()
        private val perAuthor = lru<Secp256k1PublicKey>()

        private fun <K> lru() =
            object : LinkedHashMap<K, MinuteBucket>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, MinuteBucket>): Boolean =
                    size > MAX_TRACKED_BUCKETS
            }

        fun validate(
            from: PeerId,
            bytes: ByteArray,
        ): ValidationResult {
            if (bytes.size != AnonymousPeerRecordCodec.ENCODED_SIZE) return ValidationResult.Invalid
            val record =
                try {
                    AnonymousPeerRecordCodec.decode(bytes)
                } catch (e: MalformedAnonymousPeerRecordException) {
                    logger.debug { "anonymous peer record rejected: malformed" }
                    return ValidationResult.Invalid
                }
            val now = clock.millis() / 1000
            if (index.precheck(record, now) != null) return ValidationResult.Ignore
            val authorBucket =
                synchronized(
                    perAuthor,
                ) { perAuthor.getOrPut(record.identity) { MinuteBucket(perAuthorPerMinute, clock) } }
            val peerBucket = synchronized(perPeer) { perPeer.getOrPut(from) { MinuteBucket(perPeerPerMinute, clock) } }
            if (!authorBucket.tryAcquire() || !peerBucket.tryAcquire() || !global.tryAcquire()) {
                logger.debug { "anonymous peer record ignored: rate limit" }
                return ValidationResult.Ignore
            }
            return when (index.add(record, now)) {
                AnonymousIngestOutcome.ACCEPTED -> ValidationResult.Valid
                AnonymousIngestOutcome.INVALID -> {
                    logger.debug { "anonymous peer record rejected: invalid" }
                    ValidationResult.Invalid
                }
                AnonymousIngestOutcome.EXPIRED,
                AnonymousIngestOutcome.DUPLICATE,
                AnonymousIngestOutcome.REPLAYED_OR_STALE,
                AnonymousIngestOutcome.CAPACITY,
                -> ValidationResult.Ignore
            }
        }
    }
}
