package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import java.time.Clock

private val logger = KotlinLogging.logger {}

/** Dedicated GossipSub topic of relay descriptors (distinct from the signing domain tag). */
const val ONION_RELAY_DESCRIPTOR_GOSSIP_TOPIC = "LapisNet:onion-relay-descriptor-gossip:v1"

/** Simple lazily refilled token bucket, burst equal to the per-minute rate. */
internal class MinuteBucket(
    private val perMinute: Int,
    private val clock: Clock,
) {
    private var tokens = perMinute.toDouble()
    private var last = clock.millis()

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clock.millis()
        tokens = minOf(perMinute.toDouble(), tokens + (now - last).coerceAtLeast(0) * perMinute / 60_000.0)
        last = now
        if (tokens >= 1.0) {
            tokens -= 1.0
            return true
        }
        return false
    }
}

/**
 * Gossip wiring of [OnionRelayDescriptor]s. The validator order is deliberate: size check BEFORE
 * decoding, then decode and a cheap index pre-check (duplicates, replays and stale descriptors are IGNOREd without
 * touching the rate budget), then the per-author and the global rate limit (excess is IGNORE, never REJECT, so an
 * honest forwarder is not penalised) which only guards the expensive signature verification, then full verification and indexing. Invalid descriptors are
 * rejected; replays, duplicates and capacity refusals are ignored. Only aggregate debug counters are
 * logged: no peer IDs, no identities, no bytes (stricter than the sibling gossip classes).
 */
class OnionRelayDescriptorGossip private constructor(
    private val pubsub: GossipPubSub,
    private val index: OnionRelayDescriptorIndex,
    private val subscription: PubsubSubscription,
    private val clock: Clock,
) {
    /** Publishes an own descriptor after local verification and indexing it (publish last). */
    fun announce(d: OnionRelayDescriptor) {
        val now = clock.millis() / 1000
        require(OnionRelayDescriptor.verify(d, now)) { "refusing to announce a descriptor that does not verify" }
        index.add(d, now)
        pubsub.publish(ONION_RELAY_DESCRIPTOR_GOSSIP_TOPIC, OnionRelayDescriptorCodec.encode(d))
    }

    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        const val DEFAULT_PER_PEER_PER_MINUTE = 6
        const val DEFAULT_GLOBAL_PER_MINUTE = 60
        const val MAX_TRACKED_PEER_BUCKETS = 1024

        fun attach(
            pubsub: GossipPubSub,
            index: OnionRelayDescriptorIndex,
            clock: Clock = Clock.systemUTC(),
            perPeerPerMinute: Int = DEFAULT_PER_PEER_PER_MINUTE,
            globalPerMinute: Int = DEFAULT_GLOBAL_PER_MINUTE,
        ): OnionRelayDescriptorGossip {
            val validator = Validator(index, clock, perPeerPerMinute, globalPerMinute)
            val sub =
                pubsub.subscribe(ONION_RELAY_DESCRIPTOR_GOSSIP_TOPIC) { bytes, from ->
                    validator.validate(bytes, from)
                }
            return OnionRelayDescriptorGossip(pubsub, index, sub, clock)
        }
    }

    /** The gossip validator, a separate class so tests drive it without a network. */
    internal class Validator(
        private val index: OnionRelayDescriptorIndex,
        private val clock: Clock,
        private val perPeerPerMinute: Int,
        globalPerMinute: Int,
    ) {
        private val global = MinuteBucket(globalPerMinute, clock)
        private val perPeer =
            object : LinkedHashMap<PeerId, MinuteBucket>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, MinuteBucket>): Boolean =
                    size > MAX_TRACKED_PEER_BUCKETS
            }

        fun validate(
            bytes: ByteArray,
            from: PeerId,
        ): ValidationResult {
            if (bytes.size != OnionRelayDescriptorCodec.ENCODED_SIZE) return ValidationResult.Invalid
            val descriptor =
                try {
                    OnionRelayDescriptorCodec.decode(bytes)
                } catch (e: MalformedOnionRelayDescriptorException) {
                    logger.debug { "onion descriptor rejected: malformed" }
                    return ValidationResult.Invalid
                }
            val now = clock.millis() / 1000
            // Replays, duplicates and stale descriptors cost no signature check and must not use up the rate budget,
            // otherwise republished honest descriptors would starve genuinely new ones.
            if (index.precheck(descriptor, now) != null) return ValidationResult.Ignore
            val bucket = synchronized(perPeer) { perPeer.getOrPut(from) { MinuteBucket(perPeerPerMinute, clock) } }
            if (!bucket.tryAcquire() || !global.tryAcquire()) {
                logger.debug { "onion descriptor ignored: rate limit" }
                return ValidationResult.Ignore
            }
            return when (index.add(descriptor, now)) {
                DescriptorIngestOutcome.ACCEPTED -> ValidationResult.Valid
                DescriptorIngestOutcome.INVALID -> {
                    logger.debug { "onion descriptor rejected: invalid" }
                    ValidationResult.Invalid
                }
                // expired may just be clock skew of an honest forwarder: never penalise it
                DescriptorIngestOutcome.EXPIRED,
                DescriptorIngestOutcome.DUPLICATE,
                DescriptorIngestOutcome.REPLAYED_OR_STALE,
                DescriptorIngestOutcome.CAPACITY,
                -> ValidationResult.Ignore
            }
        }
    }
}
