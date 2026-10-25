package net.lapisphilosophorum.lapisnet.dmonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dm.AnonymousDmTarget
import net.lapisphilosophorum.lapisnet.dm.AnonymousDmTransport
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousFailure
import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.nio.ByteBuffer
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val logger = KotlinLogging.logger {}

/**
 * [AnonymousDmTransport] over onion circuits (wave V0.10.0-F1).
 *
 * [resolve] looks the recipient up in the local directory only (never the DHT) and answers with ONE refusal code for every
 * way a recipient can be unreachable anonymously (unknown, direct mode, no DM service, no prekey bundle), without a silent
 * fallback to the direct path. [deliverOnline] reaches the recipient's onion service through the runtime and speaks
 * [DmCircuitFraming]: one envelope frame, wait for the constant acknowledgement. [depositOffline] hands the SAME encrypted
 * envelope to [AnonymousMailboxRedelivery].
 *
 * The sender keeps at most [maxStreams] open streams (default 2, they share the circuit pool with directory
 * publication), one per onion address, idle at most [idleMillis] (60 s); a failed exchange closes its stream and the next
 * send builds a new circuit. A new onion address always gets a new circuit. Nothing here logs an address, key or id.
 */
class OnionDmTransport(
    private val port: OnionDmRuntimePort,
    private val bundleLookup: (Secp256k1PublicKey) -> PrekeyBundle?,
    private val redelivery: AnonymousMailboxRedelivery,
    private val clock: Clock = Clock.systemUTC(),
    private val connectTimeout: Duration = Duration.ofSeconds(25),
    private val maxStreams: Int = MAX_STREAMS,
    private val idleMillis: Long = IDLE_MILLIS,
    sweepMillis: Long = 5_000L,
) : AnonymousDmTransport {
    private class Entry(
        val key: ByteBuffer,
        val channel: FrameChannel,
        val reader: DmFrameReader,
    ) {
        val lock = ReentrantLock()

        @Volatile var pendingAck: CompletableFuture<Boolean>? = null

        @Volatile var lastUsedMillis: Long = 0L

        @Volatile var dead = false
    }

    private val closed = AtomicBoolean(false)
    private val cacheLock = Any()
    private val cache = LinkedHashMap<ByteBuffer, Entry>()
    private var connecting = 0
    private val sweeper: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "lapis-net-dm-onion-streams").apply { isDaemon = true }
        }

    init {
        sweeper.scheduleWithFixedDelay({ runCatching { sweepIdle() } }, sweepMillis, sweepMillis, TimeUnit.MILLISECONDS)
    }

    /** Open cached streams (leak checks). */
    fun openStreams(): Int = synchronized(cacheLock) { cache.size }

    private fun fail(failure: DmAnonymousFailure): Nothing = throw DmAnonymousDeliveryException(failure)

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget {
        if (closed.get() || !port.ready()) fail(DmAnonymousFailure.ANONYMITY_NOT_READY)
        val reachability =
            try {
                port.resolveIdentity(recipient)
            } catch (e: RuntimeException) {
                unreachable()
            }
        val bundle = bundleLookup(recipient) ?: unreachable()
        return when (reachability) {
            is DirectoryReachability.Hidden -> {
                if (AnonymousCapability.DM !in reachability.record.capabilities) unreachable()
                AnonymousDmTarget(recipient, bundle.x25519IdentityKey, reachability.descriptor, online = true)
            }
            is DirectoryReachability.HiddenDescriptorMissing -> {
                if (AnonymousCapability.DM !in reachability.record.capabilities) unreachable()
                AnonymousDmTarget(recipient, bundle.x25519IdentityKey, null, online = false)
            }
            // direct-mode, revoked and unknown recipients are all the same answer, and there is no fallback
            is DirectoryReachability.Direct,
            DirectoryReachability.Revoked,
            DirectoryReachability.Unknown,
            -> unreachable()
        }
    }

    private fun unreachable(): Nothing {
        runCatching { port.recordRecipientUnreachable() }
        fail(DmAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY)
    }

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        if (closed.get()) return false
        val descriptor = target.handle as? OnionServiceDescriptor ?: return false
        if (envelopeBytes.isEmpty() || envelopeBytes.size > DmEnvelopeCodec.MAX_ENVELOPE_BYTES) return false
        val entry = acquire(descriptor, deadline) ?: return false
        val ok =
            try {
                entry.lock.withLock { exchange(entry, envelopeBytes, deadline) }
            } catch (e: RuntimeException) {
                false
            }
        if (!ok) drop(entry)
        return ok
    }

    private fun acquire(
        descriptor: OnionServiceDescriptor,
        deadline: Instant,
    ): Entry? {
        val key = ByteBuffer.wrap(descriptor.serviceKey.bytes)
        synchronized(cacheLock) {
            val existing = cache[key]
            if (existing != null && !existing.dead && !existing.channel.isClosed) {
                existing.lastUsedMillis = clock.millis()
                return existing
            }
            existing?.let {
                cache.remove(key)
                it.dead = true
                runCatching { it.channel.close() }
            }
            if (cache.size + connecting >= maxStreams) {
                // make room by closing the least recently used stream that is not in use right now
                val victim = cache.values.filter { !it.lock.isLocked }.minByOrNull { it.lastUsedMillis } ?: return null
                cache.remove(victim.key)
                victim.dead = true
                runCatching { victim.channel.close() }
            }
            connecting++
        }
        var channel: FrameChannel? = null
        var pendingConnect: java.util.concurrent.CompletableFuture<FrameChannel>? = null
        try {
            val remaining = Duration.between(clock.instant(), deadline)
            val timeout = minOf(connectTimeout, remaining)
            if (timeout.isNegative || timeout.isZero) return null
            val future = port.connect(descriptor, timeout)
            pendingConnect = future
            channel = future.get(timeout.toMillis() + 1000, TimeUnit.MILLISECONDS)
        } catch (e: ExecutionException) {
            logger.debug { "DM stream could not be opened (${rootName(e)})" }
        } catch (e: TimeoutException) {
            logger.debug { "DM stream could not be opened (timeout)" }
        } catch (e: RuntimeException) {
            logger.debug { "DM stream could not be opened (${e.javaClass.simpleName})" }
        } finally {
            synchronized(cacheLock) { connecting-- }
            if (channel == null) {
                // The connect future was abandoned (timeout, failure, interrupt). If it still completes
                // successfully later, close that stream and its circuit instead of leaking them outside
                // the cache and maxStreams.
                pendingConnect?.whenComplete { ch, _ -> if (ch != null) runCatching { ch.close() } }
            }
        }
        val opened = channel ?: return null
        val entry = Entry(key, opened, DmFrameReader(DmCircuitFraming.TYPE_ACK, clock::millis))
        entry.lastUsedMillis = clock.millis()
        opened.onReceive { chunk ->
            try {
                entry.reader.feed(chunk) { _, _ -> entry.pendingAck?.complete(true) }
            } catch (e: DmFramingException) {
                entry.pendingAck?.complete(false)
                drop(entry)
            }
        }
        opened.onClose {
            entry.dead = true
            entry.pendingAck?.complete(false)
            synchronized(cacheLock) { if (cache[key] === entry) cache.remove(key) }
        }
        synchronized(cacheLock) {
            if (closed.get()) {
                entry.dead = true
                runCatching { opened.close() }
                return null
            }
            val raced = cache[key]
            if (raced != null && !raced.dead && !raced.channel.isClosed) {
                // another caller opened a stream for this address meanwhile: keep it, close ours
                entry.dead = true
                runCatching { opened.close() }
                raced.lastUsedMillis = clock.millis()
                return raced
            }
            cache[key] = entry
        }
        return entry
    }

    private fun rootName(e: Throwable): String = generateSequence<Throwable>(e) { it.cause }.last().javaClass.simpleName

    private fun exchange(
        entry: Entry,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        if (entry.dead || entry.channel.isClosed) return false
        val ack = CompletableFuture<Boolean>()
        entry.pendingAck = ack
        val maxPayload = entry.channel.maxPayload
        val frame =
            if (port.paddingEnabled) {
                if (envelopeBytes.size > DmEnvelopeCodec.MAX_ENVELOPE_BYTES) return false
                DmCircuitFraming.paddedEnvelopeFrame(envelopeBytes, maxPayload)
            } else {
                DmCircuitFraming.envelopeFrame(envelopeBytes)
            }
        for (chunk in DmCircuitFraming.chunks(frame, maxPayload)) {
            if (!entry.channel.send(chunk)) return false
        }
        val remaining = Duration.between(clock.instant(), deadline).toMillis()
        if (remaining <= 0) return false
        return try {
            val ok = ack.get(remaining, TimeUnit.MILLISECONDS)
            entry.lastUsedMillis = clock.millis()
            ok
        } catch (e: TimeoutException) {
            false
        } catch (e: ExecutionException) {
            false
        } finally {
            entry.pendingAck = null
        }
    }

    private fun drop(entry: Entry) {
        entry.dead = true
        synchronized(cacheLock) { if (cache[entry.key] === entry) cache.remove(entry.key) }
        runCatching { entry.channel.close() }
    }

    private fun sweepIdle() {
        val now = clock.millis()
        val stale = synchronized(cacheLock) { cache.values.filter { now - it.lastUsedMillis >= idleMillis } }
        for (e in stale) {
            if (e.lock.tryLock()) {
                try {
                    drop(e)
                } finally {
                    e.lock.unlock()
                }
            }
        }
    }

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        if (closed.get()) return
        redelivery.add(target.recipient, target.sealingKey, envelopeBytes, notValidAfterEpochSecond)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        sweeper.shutdownNow()
        val all = synchronized(cacheLock) { cache.values.toList().also { cache.clear() } }
        all.forEach {
            it.dead = true
            it.pendingAck?.complete(false)
            runCatching { it.channel.close() }
        }
        redelivery.close()
    }

    companion object {
        const val MAX_STREAMS = 2
        const val IDLE_MILLIS = 60_000L
    }
}
