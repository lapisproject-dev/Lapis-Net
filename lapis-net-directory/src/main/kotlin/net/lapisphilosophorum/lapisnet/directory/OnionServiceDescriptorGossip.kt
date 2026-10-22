package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import java.time.Clock

private val logger = KotlinLogging.logger {}

/** Dedicated GossipSub topic of onion service descriptors. */
const val ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC = "LapisNet:onion-service-descriptor-gossip:v1"

/**
 * Gossip wiring of [OnionServiceDescriptor]s (wave V0.10.0-C). Validator order: size bounds BEFORE decoding,
 * decode, cheap index pre-check (duplicates, replays and stale descriptors are IGNOREd without touching any
 * rate budget), then three rate limits - per service key (author), per forwarding peer, global - whose excess
 * is IGNORE (an honest forwarder is never penalised), which only guard the expensive signature verification;
 * then full verification and indexing. Invalid descriptors are rejected. Only aggregate debug counters are
 * logged: no peer IDs, service keys, addresses or bytes.
 *
 * Announcing from the node itself shows the node's IP (as gossip peer) together with the onion address to its
 * gossip neighbours; publishing through circuits is wave D. See docs/anonymity.adoc.
 */
class OnionServiceDescriptorGossip private constructor(
    private val pubsub: GossipPubSub,
    private val index: OnionServiceDescriptorIndex,
    private val subscription: PubsubSubscription,
    private val clock: Clock,
) {
    fun announce(d: OnionServiceDescriptor) {
        val now = clock.millis() / 1000
        require(OnionServiceDescriptor.verify(d, now)) { "refusing to announce a descriptor that does not verify" }
        index.add(d, now)
        pubsub.publish(ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC, OnionServiceDescriptorCodec.encode(d))
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
            index: OnionServiceDescriptorIndex,
            clock: Clock = Clock.systemUTC(),
            perAuthorPerMinute: Int = DEFAULT_PER_AUTHOR_PER_MINUTE,
            perPeerPerMinute: Int = DEFAULT_PER_PEER_PER_MINUTE,
            globalPerMinute: Int = DEFAULT_GLOBAL_PER_MINUTE,
        ): OnionServiceDescriptorGossip {
            val validator = Validator(index, clock, perAuthorPerMinute, perPeerPerMinute, globalPerMinute)
            val sub =
                pubsub.subscribe(
                    ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC,
                ) { bytes, from -> validator.validate(bytes, from) }
            return OnionServiceDescriptorGossip(pubsub, index, sub, clock)
        }
    }

    internal class Validator(
        private val index: OnionServiceDescriptorIndex,
        private val clock: Clock,
        private val perAuthorPerMinute: Int,
        private val perPeerPerMinute: Int,
        globalPerMinute: Int,
    ) {
        private val global = MinuteBucket(globalPerMinute, clock)
        private val perPeer = lru<PeerId>()
        private val perAuthor = lru<Ed25519PublicKey>()

        private fun <K> lru() =
            object : LinkedHashMap<K, MinuteBucket>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, MinuteBucket>): Boolean =
                    size > MAX_TRACKED_BUCKETS
            }

        fun validate(
            bytes: ByteArray,
            from: PeerId,
        ): ValidationResult {
            if (bytes.size < OnionServiceDescriptorCodec.FIXED_SIZE + OnionServiceDescriptorCodec.ENTRY_SIZE ||
                bytes.size > OnionServiceDescriptorCodec.MAX_ENCODED_SIZE
            ) {
                return ValidationResult.Invalid
            }
            val descriptor =
                try {
                    OnionServiceDescriptorCodec.decode(bytes)
                } catch (e: CellFormatException) {
                    logger.debug { "onion service descriptor rejected: malformed" }
                    return ValidationResult.Invalid
                }
            val now = clock.millis() / 1000
            if (index.precheck(descriptor, now) != null) return ValidationResult.Ignore
            val authorBucket =
                synchronized(
                    perAuthor,
                ) { perAuthor.getOrPut(descriptor.serviceKey) { MinuteBucket(perAuthorPerMinute, clock) } }
            val peerBucket = synchronized(perPeer) { perPeer.getOrPut(from) { MinuteBucket(perPeerPerMinute, clock) } }
            if (!authorBucket.tryAcquire() || !peerBucket.tryAcquire() || !global.tryAcquire()) {
                logger.debug { "onion service descriptor ignored: rate limit" }
                return ValidationResult.Ignore
            }
            return when (index.add(descriptor, now)) {
                DescriptorIngestOutcome.ACCEPTED -> ValidationResult.Valid
                DescriptorIngestOutcome.INVALID -> {
                    logger.debug { "onion service descriptor rejected: invalid" }
                    ValidationResult.Invalid
                }
                DescriptorIngestOutcome.EXPIRED,
                DescriptorIngestOutcome.DUPLICATE,
                DescriptorIngestOutcome.REPLAYED_OR_STALE,
                DescriptorIngestOutcome.CAPACITY,
                -> ValidationResult.Ignore
            }
        }
    }
}
