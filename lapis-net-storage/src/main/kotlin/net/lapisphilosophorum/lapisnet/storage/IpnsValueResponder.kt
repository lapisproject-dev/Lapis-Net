package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import org.peergos.PeerAddresses
import org.peergos.protocol.dht.pb.Dht
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * Answers `PUT_VALUE` and `GET_VALUE` for [LapisKademliaEngine] (V0.9.13), in place of Nabu's
 * handlers (see [IpnsRecordCodec] and [EmptyRecordStore] for why those are not used).
 *
 * Inbound `PUT_VALUE` is accepted only if, in this order: the key names an Ed25519 publisher, the
 * request's Noise-authenticated [source] IS that publisher, the source is within its rate limit, and
 * the record validates ([IpnsRecordCodec.validate]) and supersedes what is held. The first two are
 * free, the third costs one map access - all three run before the signature check. "Source is the
 * publisher" means nobody can relay or flood somebody else's record into this store, and a source can
 * only ever occupy a record slot under its own name.
 */
internal class IpnsValueResponder(
    private val store: BoundedIpnsRecordStore,
    private val limits: DhtLimits,
    private val closestPeers: (ByteArray, Int) -> List<PeerAddresses>,
    private val clock: () -> Instant = Instant::now,
    private val nanoClock: () -> Long = System::nanoTime,
) {
    private val putsAccepted = AtomicLong()
    private val putsRejected = AtomicLong()
    private val getsAnswered = AtomicLong()

    val ipnsPutsAccepted: Long get() = putsAccepted.get()
    val ipnsPutsRejected: Long get() = putsRejected.get()
    val ipnsGetsAnswered: Long get() = getsAnswered.get()

    private class Bucket(
        var tokens: Double,
        var lastNanos: Long,
    )

    private val buckets =
        object : LinkedHashMap<PeerId, Bucket>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PeerId, Bucket>): Boolean =
                size > limits.valueRateTrackerCapacity
        }

    /** How many source peers the rate limiter currently remembers (tests; bounded by [DhtLimits.valueRateTrackerCapacity]). */
    internal fun trackedSources(): Int = synchronized(buckets) { buckets.size }

    /** Token bucket of [DhtLimits.maxValuePutsPerSourcePerMinute] tokens, refilled evenly over a minute. */
    private fun tryTake(source: PeerId): Boolean =
        synchronized(buckets) {
            val now = nanoClock()
            val capacity = limits.maxValuePutsPerSourcePerMinute.toDouble()
            val bucket = buckets.getOrPut(source) { Bucket(capacity, now) }
            val elapsed = (now - bucket.lastNanos).coerceAtLeast(0)
            bucket.tokens = minOf(capacity, bucket.tokens + elapsed * capacity / NANOS_PER_MINUTE)
            bucket.lastNanos = now
            if (bucket.tokens < 1.0) return@synchronized false
            bucket.tokens -= 1.0
            true
        }

    /** Echoes the request on [stream] if the record was accepted; writes nothing otherwise. */
    fun handlePut(
        msg: Dht.Message,
        source: PeerId,
        stream: Stream,
    ) {
        val key = msg.key.toByteArray()
        val publisher = parseIpnsKey(key)
        val accepted =
            publisher != null &&
                publisher == source &&
                tryTake(source) &&
                msg.hasRecord() &&
                msg.record.key == msg.key &&
                acceptRecord(key, msg.record.value.toByteArray())
        if (accepted) {
            putsAccepted.incrementAndGet()
            stream.writeAndFlush(msg)
        } else {
            putsRejected.incrementAndGet()
            logger.debug { "rejected an inbound IPNS PUT_VALUE" }
        }
    }

    private fun acceptRecord(
        key: ByteArray,
        raw: ByteArray,
    ): Boolean {
        val now = clock()
        val validated = IpnsRecordCodec.validate(key, raw, now, limits) ?: return false
        return store.putIfNewer(validated, now)
    }

    /** Answers with the held record (if any) and the closest peers this node knows. */
    fun handleGet(
        msg: Dht.Message,
        stream: Stream,
    ) {
        val key = msg.key.toByteArray()
        val publisher = parseIpnsKey(key) ?: return
        val held = store.get(publisher, clock())
        val reply =
            Dht.Message
                .newBuilder()
                .setType(Dht.Message.MessageType.GET_VALUE)
                .setKey(msg.key)
        if (held != null) {
            reply.setRecord(
                Dht.Record
                    .newBuilder()
                    .setKey(msg.key)
                    .setValue(ByteString.copyFrom(held.raw))
                    .build(),
            )
        }
        reply.addAllCloserPeers(closestPeers(key, limits.maxCloserPeersPerResponse).map { it.toProtobuf() })
        getsAnswered.incrementAndGet()
        stream.writeAndFlush(reply.build())
    }

    private companion object {
        const val NANOS_PER_MINUTE = 60_000_000_000.0
    }
}
