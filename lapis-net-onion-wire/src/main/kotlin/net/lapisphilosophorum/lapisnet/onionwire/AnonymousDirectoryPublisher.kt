package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordGossip
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryRepublishSchedule
import net.lapisphilosophorum.lapisnet.directory.DirectoryTransitionPlan
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PublicationRateGuard
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishBody
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.util.concurrent.RejectedExecutionException
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
 * the node's onion service, and its prekey bundle (when it has a [PrekeyStore]) (reduced to as many one-time prekeys as fit one publish message),
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
 *
 * Early republication: GossipSub gives late subscribers no history, so an object published before a receiver
 * subscribed would stay invisible to it until the hourly republication. After the FIRST successful publication the
 * publisher therefore republishes on the short [earlySchedule]. Every republication is a complete NEW version (new
 * bundle sequence, new record sequence): a byte-identical bundle would be declined by receivers and scored against the
 * relaying peer. The number of versions per minute stays below the receivers' per-author rate. Slots that fell due
 * while the process was suspended are merged into one publication. A failed publication is retried along
 * [failureBackoff] and then every [retryInterval].
 */
class AnonymousDirectoryPublisher(
    private val identity: DualKeyIdentity,
    private val serviceKey: Ed25519KeyPair,
    private val prekeyStore: PrekeyStore?,
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
    private val earlySchedule: DirectoryRepublishSchedule = DirectoryRepublishSchedule(),
    maxVersionsPerMinute: Int = 4,
    private val failureBackoff: List<Duration> = listOf(5.seconds, 15.seconds, 45.seconds),
) : AutoCloseable {
    init {
        require(allowDirectChannel || !channel.exposesOrigin) {
            "anonymity mode requires a publication channel that does not expose the origin"
        }
        require(recordTtlSeconds in 1..AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS) { "invalid record ttl" }
        require(maxVersionsPerMinute in 1 until AnonymousPeerRecordGossip.DEFAULT_PER_AUTHOR_PER_MINUTE) {
            "version rate must stay below the receivers' per-author rate"
        }
    }

    private val transition = DirectoryModeTransition(identity, modeStore, clockMillis)
    private val closed = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private var transitionDone = false
    private var lastPublishedAtMillis: Long? = null

    @Volatile private var timer: ScheduledThreadPoolExecutor? = null

    @Volatile private var job: ScheduledFuture<*>? = null
    private val versionGuard = PublicationRateGuard(maxVersionsPerMinute, 60_000L, clockMillis)
    private val pendingEarly = ArrayDeque<Long>()
    private var consecutiveFailures = 0
    private var backoffUntilMillis = 0L

    /** Number of anonymous records handed to the channel successfully (tests). */
    @Volatile var publications: Int = 0
        private set

    /** Number of early (staggered) republications that succeeded (tests). */
    @Volatile var earlyRepublications: Int = 0
        private set

    /** Number of publication attempts, successful or not (tests). */
    @Volatile var attempts: Int = 0
        private set

    /**
     * Starts the tick, scheduled dynamically by [nextDelayMillis] (from 1 s up to [retryInterval], depending on what is
     * due next; a tick only publishes when due). Idempotent.
     */
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
        job = executor.schedule(::runTick, 0, TimeUnit.MILLISECONDS)
    }

    private fun runTick() {
        try {
            tick()
        } catch (e: RuntimeException) {
            logger.debug { "anonymous directory tick failed: ${e.javaClass.simpleName}" }
        }
        reschedule()
    }

    @Synchronized
    private fun reschedule() {
        if (closed.get()) return
        val executor = timer ?: return
        try {
            job = executor.schedule(::runTick, nextDelayMillis(), TimeUnit.MILLISECONDS)
        } catch (e: RejectedExecutionException) {
            return // closed concurrently: no zombie timer
        }
        if (closed.get()) job?.cancel(false)
    }

    /** Delay until the next tick is worth running, within [1 s (or [retryInterval]), [retryInterval]]. */
    @Synchronized
    internal fun nextDelayMillis(): Long {
        val now = clockMillis()
        val last = lastPublishedAtMillis
        var due = if (last == null) now else last + republishInterval.inWholeMilliseconds
        pendingEarly.firstOrNull()?.let { due = minOf(due, it) }
        due = maxOf(due, backoffUntilMillis, versionGuard.nextAllowedAtMillis())
        val cap = retryInterval.inWholeMilliseconds
        return (due - now).coerceIn(minOf(1_000L, cap), cap)
    }

    /**
     * Publishes when due. Blocks until the channel answered (at most [publishTimeout] per object). Returns whether the
     * record is current (published now or still within the republish interval).
     */
    @Synchronized
    fun tick(): Boolean {
        if (closed.get()) {
            pendingEarly.clear()
            return false
        }
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
        val republishDue = last == null || now - last >= republishInterval.inWholeMilliseconds
        val earlyDue = pendingEarly.firstOrNull()?.let { now >= it } == true
        if (!republishDue && !earlyDue) return true
        // a failed publication is retried along the backoff, never in a storm; a rate-limited tick is deferred
        if (now < backoffUntilMillis || !versionGuard.tryAcquire()) return !republishDue

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
        attempts++
        if (bundleOk && recordOk) {
            if (last == null) pendingEarly.addAll(earlySchedule.plan(now).toList())
            if (earlyDue) {
                // merge every slot that is due by now (suspend, clock jump): one publication serves all of them
                while (pendingEarly.isNotEmpty() && pendingEarly.first() <= now) pendingEarly.removeFirst()
                earlyRepublications++
                logger.debug {
                    "anonymous directory early republish $earlyRepublications/${earlySchedule.offsets.size}"
                }
            }
            consecutiveFailures = 0
            backoffUntilMillis = 0L
            lastPublishedAtMillis = now
            publications++
            return true
        }
        consecutiveFailures++
        val delay =
            if (consecutiveFailures <= failureBackoff.size) failureBackoff[consecutiveFailures - 1] else retryInterval
        backoffUntilMillis = now + delay.inWholeMilliseconds
        return !republishDue
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
        // a node without a DM capability (the headless CLI node) has no prekeys and publishes no bundle
        val store = prekeyStore ?: return null
        for (n in generateSequence(MAX_ONE_TIME_PREKEYS) { it - 1 }.takeWhile { it >= 0 }) {
            val bundle =
                store.publishBundle(
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
