package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryTransitionPlan
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishBody
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Publishes the directory presence of a node in anonymity mode (wave V0.10.0-D): an [AnonymousPeerRecord] pointing at
 * the node's onion service, and its prekey bundle (reduced to as many one-time prekeys as fit one publish message),
 * both through [channel] - in production the circuit-based `OnionDirectoryPublisher`. The service descriptor itself
 * is published by the `OnionServiceHost`, whose publisher callback points at the same channel.
 *
 * Mode switch: the first [tick] after [start] asks the [DirectoryModeTransition] whether the previous run was in
 * normal mode. If so, [tombstonePublisher] receives the address-free tombstone [PeerRecord] to send once (gossip and
 * `DirectoryDht.publishTombstone`; that is wired by the caller, it is the one publication from the own node) before
 * the first anonymous record goes out with a higher sequence number. [tombstonePublisher] contract: it MUST throw if
 * the tombstone could not be sent (no mesh peer, DHT failure); the tick is then retried. Returning normally marks the
 * transition as done and it is never repeated. A tombstone is only built after a persisted normal-mode (`OFF`) state. The way back (anonymous to normal) is handled by
 * [DirectoryModeTransition.prepare] with [DirectoryAnonymityMode.OFF] at the next start in normal mode.
 *
 * Refuses a channel that exposes the origin ([DirectoryPublicationChannel.exposesOrigin]) unless [allowDirectChannel]
 * is set (tests only). No fallback to a more revealing channel exists: a failed publication is retried on the next
 * tick. [start], [tick] and [close] are idempotent and thread-safe; after [close] nothing is published and no timer
 * thread remains.
 */
class AnonymousDirectoryPublisher(
    private val identity: DualKeyIdentity,
    private val serviceKey: Ed25519KeyPair,
    private val prekeyStore: PrekeyStore,
    private val channel: DirectoryPublicationChannel,
    modeStore: DirectoryModeStore,
    private val clockMillis: () -> Long = System::currentTimeMillis,
    private val recordTtlSeconds: Long = 3 * 3600L,
    private val republishInterval: Duration = 1.hours,
    private val retryInterval: Duration = 1.minutes,
    private val capabilities: Set<AnonymousCapability> = setOf(AnonymousCapability.DM),
    private val tombstonePublisher: (PeerRecord) -> Unit = {},
    allowDirectChannel: Boolean = false,
    private val publishTimeout: Duration = 60.seconds,
) : AutoCloseable {
    init {
        require(allowDirectChannel || !channel.exposesOrigin) {
            "anonymity mode requires a publication channel that does not expose the origin"
        }
        require(recordTtlSeconds in 1..AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS) { "invalid record ttl" }
    }

    private val transition = DirectoryModeTransition(identity, modeStore, clockMillis)
    private val closed = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private var transitionDone = false
    private var lastPublishedAtMillis: Long? = null
    private var timer: ScheduledThreadPoolExecutor? = null
    private var job: ScheduledFuture<*>? = null

    /** Number of anonymous records handed to the channel successfully (tests). */
    @Volatile var publications: Int = 0
        private set

    /** Starts the periodic tick (every [retryInterval]; a tick only publishes when due). Idempotent. */
    @Synchronized
    fun start() {
        if (closed.get() || !started.compareAndSet(false, true)) return
        val executor =
            ScheduledThreadPoolExecutor(1) {
                Thread(it, "lapis-net-anonymous-directory").also { t ->
                    t.isDaemon = true
                }
            }
        executor.removeOnCancelPolicy = true
        timer = executor
        job =
            executor.scheduleWithFixedDelay(
                {
                    try {
                        tick()
                    } catch (e: RuntimeException) {
                        logger.debug { "anonymous directory tick failed: ${e.javaClass.simpleName}" }
                    }
                },
                0,
                retryInterval.inWholeMilliseconds,
                TimeUnit.MILLISECONDS,
            )
    }

    /**
     * Publishes when due. Blocks until the channel answered (at most [publishTimeout] per object). Returns whether the
     * record is current (published now or still within the republish interval).
     */
    @Synchronized
    fun tick(): Boolean {
        if (closed.get()) return false
        val now = clockMillis()
        if (!transitionDone) {
            when (val plan = transition.prepare(DirectoryAnonymityMode.ON)) {
                DirectoryTransitionPlan.None -> Unit
                is DirectoryTransitionPlan.Tombstone -> tombstonePublisher(plan.record)
                is DirectoryTransitionPlan.Revocation -> Unit
            }
            transitionDone = true
        }
        val last = lastPublishedAtMillis
        if (last != null && now - last < republishInterval.inWholeMilliseconds) return true

        val nowSeconds = now / 1000
        val notValidAfter = nowSeconds + recordTtlSeconds
        val bundle = fittingBundle(notValidAfter, nowSeconds)
        val digest =
            bundle?.let {
                domainSeparatedDigest(
                    "LapisNet:anonymous-prekey-digest:v1",
                    PrekeyBundleCodec.encode(it),
                )
            }
        val record =
            AnonymousPeerRecord.create(
                identity,
                serviceKey,
                capabilities,
                digest,
                transition.nextSequence(DirectoryAnonymityMode.ON),
                notValidAfter,
                nowSeconds,
            )
        if (closed.get()) return false
        val bundleOk = bundle == null || await(channel.publishPrekeyBundle(bundle))
        if (closed.get()) return false
        val recordOk = await(channel.publishAnonymousPeerRecord(record))
        if (bundleOk && recordOk) {
            lastPublishedAtMillis = now
            publications++
            return true
        }
        return false
    }

    private fun await(future: java.util.concurrent.CompletableFuture<Boolean>): Boolean =
        try {
            future.get(publishTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS) == true
        } catch (e: java.util.concurrent.ExecutionException) {
            false
        } catch (e: java.util.concurrent.TimeoutException) {
            future.cancel(true)
            false
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }

    /** A bundle with as many one-time prekeys as fit one publish message, or `null` if even none fits. */
    private fun fittingBundle(
        notValidAfter: Long,
        nowSeconds: Long,
    ): PrekeyBundle? {
        for (n in generateSequence(MAX_ONE_TIME_PREKEYS) { it - 1 }.takeWhile { it >= 0 }) {
            val bundle =
                prekeyStore.publishBundle(
                    identity,
                    notValidAfter,
                    maxOneTimePrekeys = n,
                    nowEpochSecond = nowSeconds,
                )
            if (PrekeyBundleCodec.encode(bundle).size <= DirectoryPublishBody.MAX_OBJECT_SIZE) return bundle
        }
        return null
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        job?.cancel(false)
        timer?.shutdownNow()
        timer = null
        job = null
    }

    private companion object {
        /** (717 - 317) / 36 = 11 one-time prekeys fit; verified by a test against the real codec. */
        const val MAX_ONE_TIME_PREKEYS = 11
    }
}
