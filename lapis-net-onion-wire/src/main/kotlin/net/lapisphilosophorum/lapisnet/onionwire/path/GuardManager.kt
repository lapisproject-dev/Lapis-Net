@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.security.SecureRandom
import java.time.Clock

private val logger = KotlinLogging.logger {}

/** One persisted guard. All times are epoch seconds. */
@ExperimentalOnionApi
data class GuardEntry(
    val identity: Secp256k1PublicKey,
    val chosenAtEpochSecond: Long,
    val expiresAtEpochSecond: Long,
    val consecutiveFailures: Int = 0,
    val firstFailureAtEpochSecond: Long? = null,
    val descriptorMissingSinceEpochSecond: Long? = null,
)

@ExperimentalOnionApi
data class GuardState(
    val primary: GuardEntry? = null,
    val backup: GuardEntry? = null,
    val lastFailureRotationEpochSecond: Long? = null,
) {
    companion object {
        val EMPTY = GuardState()
    }
}

@ExperimentalOnionApi
sealed interface GuardLoad {
    class Loaded(
        val state: GuardState,
    ) : GuardLoad

    /** No file. */
    data object Missing : GuardLoad

    /** A file exists but is damaged, tampered with, belongs to another identity or fails the plausibility checks. */
    data object Invalid : GuardLoad
}

@ExperimentalOnionApi
interface GuardStateStore {
    fun load(): GuardLoad

    fun save(state: GuardState)
}

/** Volatile store for tests. */
@ExperimentalOnionApi
class InMemoryGuardStateStore(
    initial: GuardLoad = GuardLoad.Missing,
) : GuardStateStore {
    @Volatile private var current: GuardLoad = initial

    override fun load(): GuardLoad = current

    override fun save(state: GuardState) {
        current = GuardLoad.Loaded(state)
    }
}

/**
 * Persistent entry guards (wave V0.10.0-E). Two guards (primary and backup) with a lifetime of 30 to 60 days. The first
 * hop of every circuit is the primary guard. A guard is replaced
 *  - when it expires (independent of the failure rate limit),
 *  - after at least [FAILURE_COUNT] consecutive first-hop failures spanning at least [FAILURE_WINDOW_SECONDS], or
 *  - when its relay descriptor has been missing or invalid for at least [MISSING_WINDOW_SECONDS];
 * a replacement because of a failure happens at most once per [FAILURE_ROTATION_MIN_INTERVAL_SECONDS]. Only failures at
 * the FIRST hop count: a failure further along the path must not be usable to force a guard rotation.
 *
 * Reachability fallback (fix wave "rendezvous after guard failover", in memory only, never persisted): a first-hop
 * failure at the primary marks it unreachable. While marked, builds enter through the persisted backup (if its
 * descriptor is known); after a retry delay ([PRIMARY_RETRY_MIN_SECONDS] doubling up to [PRIMARY_RETRY_MAX_SECONDS],
 * +/-20 % jitter) exactly one build probes the primary again. A success at the primary clears the mark, a failure extends
 * the delay. Nothing is rotated and no new guard is chosen: the exposure stays the fixed set {primary, backup}. Only the
 * node's own first-hop link/CREATE results reach this (a failure further along the path counts as a first-hop success),
 * so no remote party can trigger the mark or the probe.
 *
 * Reset rule: a damaged state file always results in new guards (WARN, [onReset]); a missing file only when
 * [missingIsReset] (the previous run was in anonymity mode, so the file should exist). A first start has no file and
 * is silent. Deleting the file can not be prevented, only made visible.
 */
@ExperimentalOnionApi
class GuardManager(
    private val store: GuardStateStore,
    private val random: SecureRandom,
    private val clock: Clock,
    missingIsReset: Boolean = false,
    private val onReset: () -> Unit = {},
) {
    private var state: GuardState

    // in-memory reachability of the primary (see the class comment); never written to the store
    private var markedPrimary: Secp256k1PublicKey? = null
    private var primaryRetryAtMillis = 0L
    private var primaryRetryFailures = 0
    private var probeDeadlineMillis: Long? = null

    init {
        state =
            when (val loaded = store.load()) {
                is GuardLoad.Loaded -> loaded.state
                GuardLoad.Missing -> {
                    if (missingIsReset) reset()
                    GuardState.EMPTY
                }
                GuardLoad.Invalid -> {
                    reset()
                    GuardState.EMPTY
                }
            }
    }

    private fun reset() {
        logger.warn { "guard state invalid, reselected guards" }
        runCatching(onReset)
    }

    private fun now(): Long = clock.millis() / 1000

    @Synchronized
    fun guardCount(): Int = listOfNotNull(state.primary, state.backup).size

    @Synchronized
    fun snapshot(): GuardState = state

    /**
     * The guard descriptor to use as first hop of a build, choosing (and persisting) a new guard with [pick] if none is
     * set; `null` if there is no usable guard right now (none chosen and nothing to pick, or the guard's descriptor is
     * unknown). Same as [firstHop] with `forBuild = true`.
     */
    @Synchronized
    fun primaryUsable(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
    ): OnionRelayDescriptor? = firstHop(candidates, pick, forBuild = true)

    /**
     * The guard to use as first hop, choosing (and persisting) a new guard with [pick] if none is set; `null` if there
     * is no usable guard right now.
     *
     * The primary is used while its descriptor is known and it is not marked unreachable. Its descriptor unknown, or it
     * marked unreachable and the backup's descriptor known: the backup (as Tor does), until the retry delay has passed;
     * then exactly one build ([forBuild] `true`) gets the primary as a probe, every other call keeps getting the backup.
     * A marked primary without a usable backup is still returned (never "no guard" only because of the mark). With
     * [forBuild] `false` (endpoint choice, checks without a build) the probe is never handed out.
     */
    @Synchronized
    fun firstHop(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
        forBuild: Boolean,
    ): OnionRelayDescriptor? = firstHopLocked(candidates, pick, forBuild).descriptor

    /** The answer of [firstHopWithProbe]: the first hop and whether this call took the primary probe. */
    internal class FirstHop(
        val descriptor: OnionRelayDescriptor?,
        val probe: Boolean,
    )

    /** Like [firstHop], and says whether the primary probe was handed out by THIS call (see [releaseProbe]). */
    @Synchronized
    internal fun firstHopWithProbe(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
        forBuild: Boolean,
    ): FirstHop = firstHopLocked(candidates, pick, forBuild)

    private fun firstHopLocked(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
        forBuild: Boolean,
    ): FirstHop {
        maintainLocked(candidates, pick)
        val primary = state.primary
        if (primary == null) {
            val chosen =
                pick(candidates.filter { it.identity != state.backup?.identity }) ?: return FirstHop(null, false)
            state = state.copy(primary = newEntry(chosen))
            fillBackup(candidates, pick)
            save()
            return FirstHop(chosen, false)
        }
        val primaryDescriptor = candidates.firstOrNull { it.identity == primary.identity }
        // The primary's descriptor is unknown (relay offline, descriptor expired): use the backup as first hop meanwhile
        // (as Tor does) instead of building nothing until the primary is rotated out after MISSING_WINDOW_SECONDS.
        val backupDescriptor = state.backup?.let { b -> candidates.firstOrNull { it.identity == b.identity } }
        if (primaryDescriptor == null) return FirstHop(backupDescriptor, false)
        if (!isMarkedLocked() || backupDescriptor == null) return FirstHop(primaryDescriptor, false)
        val now = clock.millis()
        probeDeadlineMillis?.let { deadline ->
            // a probe whose build never reported (refused before a link was tried): counts as a failed probe
            if (now >= deadline) extendMark(now)
        }
        if (forBuild && probeDeadlineMillis == null && now >= primaryRetryAtMillis) {
            probeDeadlineMillis = now + PROBE_TIMEOUT_SECONDS * 1000
            return FirstHop(primaryDescriptor, true)
        }
        return FirstHop(backupDescriptor, false)
    }

    /**
     * The other persisted guard than [excluding] (primary or backup), if its descriptor is among [candidates]; used to
     * enter the network for one circuit whose remotely chosen last hop equals the effective guard. Never a new guard.
     */
    @Synchronized
    fun alternativeGuard(
        excluding: Secp256k1PublicKey,
        candidates: List<OnionRelayDescriptor>,
    ): OnionRelayDescriptor? {
        val other =
            listOfNotNull(state.primary, state.backup).firstOrNull { it.identity != excluding } ?: return null
        return candidates.firstOrNull { it.identity == other.identity }
    }

    /**
     * Hands back a primary probe that [firstHop] gave out for a build that then did not start (path conflict, governor
     * refusal before admission): the probe is free again for the next build and does NOT count as failed, so the retry
     * delay is not extended without a first-hop result. A no-op unless [identity] is the marked primary with a probe
     * outstanding. Only the path selector calls it, and only for the path that actually carries the probe
     * ([OnionPathSelector.releaseUnbuiltPath], matched by reference). A build that merely starts at the primary must
     * never release: while the primary is marked and the backup is the effective guard, a remotely chosen last hop equal
     * to the backup enters through the primary ([alternativeGuard]) WITHOUT the probe, and releasing for its refusal
     * would free the probe of another build still in flight, so the next build would probe the primary a second time.
     */
    @Synchronized
    internal fun releaseProbe(identity: Secp256k1PublicKey) {
        if (isMarkedLocked() && identity == markedPrimary && probeDeadlineMillis != null) probeDeadlineMillis = null
    }

    /** `true` while the persisted primary is marked unreachable (in memory, see the class comment). */
    @Synchronized
    fun isPrimaryMarkedUnreachable(): Boolean = isMarkedLocked()

    /** The primary's identity while it is marked unreachable, else `null`. */
    @Synchronized
    internal fun markedPrimaryIdentity(): Secp256k1PublicKey? = if (isMarkedLocked()) markedPrimary else null

    private fun isMarkedLocked(): Boolean {
        val m = markedPrimary ?: return false
        if (m != state.primary?.identity) {
            // the primary changed (rotation, expiry, reset): the mark belonged to the old one
            clearMark()
            return false
        }
        return true
    }

    private fun clearMark() {
        markedPrimary = null
        primaryRetryAtMillis = 0L
        primaryRetryFailures = 0
        probeDeadlineMillis = null
    }

    private fun extendMark(nowMillis: Long) {
        val base =
            (PRIMARY_RETRY_MIN_SECONDS * 1000L shl primaryRetryFailures.coerceAtMost(MAX_RETRY_SHIFT))
                .coerceAtMost(PRIMARY_RETRY_MAX_SECONDS * 1000L)
        // +/-20 % jitter so that the probes of many nodes do not line up
        val jitter = 1.0 - RETRY_JITTER + 2 * RETRY_JITTER * random.nextDouble()
        primaryRetryAtMillis = nowMillis + (base * jitter).toLong()
        primaryRetryFailures = (primaryRetryFailures + 1).coerceAtMost(MAX_COUNTER)
        probeDeadlineMillis = null
    }

    @Synchronized
    fun recordFirstHopSuccess(identity: Secp256k1PublicKey) {
        var changed = false

        fun ok(e: GuardEntry?): GuardEntry? =
            if (e != null &&
                e.identity == identity &&
                (e.consecutiveFailures != 0 || e.firstFailureAtEpochSecond != null)
            ) {
                changed = true
                e.copy(consecutiveFailures = 0, firstFailureAtEpochSecond = null)
            } else {
                e
            }
        state = state.copy(primary = ok(state.primary), backup = ok(state.backup))
        if (identity == state.primary?.identity) clearMark()
        if (changed) save()
    }

    @Synchronized
    fun recordFirstHopFailure(identity: Secp256k1PublicKey) {
        val now = now()

        fun bump(e: GuardEntry?): GuardEntry? =
            if (e != null && e.identity == identity) {
                e.copy(
                    consecutiveFailures = (e.consecutiveFailures + 1).coerceAtMost(MAX_COUNTER),
                    firstFailureAtEpochSecond = e.firstFailureAtEpochSecond ?: now,
                )
            } else {
                e
            }
        state = state.copy(primary = bump(state.primary), backup = bump(state.backup))
        if (identity == state.primary?.identity) {
            val nowMillis = clock.millis()
            if (!isMarkedLocked()) {
                markedPrimary = identity
                extendMark(nowMillis)
            } else if (probeDeadlineMillis != null || nowMillis >= primaryRetryAtMillis) {
                // the probe failed; builds that were already under way when the mark was set do not extend the delay
                extendMark(nowMillis)
            }
        }
        val p = state.primary
        if (p != null && failedOut(p, now)) rotateFailedPrimary(now, emptyList()) { null }
        save()
    }

    /** Expiry, missing descriptors, promotion of the backup and refilling of the empty slots. */
    @Synchronized
    fun maintain(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor? = { it.randomOrNull(random) },
    ) {
        maintainLocked(candidates, pick)
    }

    private fun maintainLocked(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
    ) {
        val now = now()
        val known = candidates.map { it.identity }.toSet()
        val before = state

        fun track(e: GuardEntry?): GuardEntry? =
            e?.copy(
                descriptorMissingSinceEpochSecond =
                    if (e.identity in known) null else e.descriptorMissingSinceEpochSecond ?: now,
            )
        state = state.copy(primary = track(state.primary), backup = track(state.backup))
        // expiry first (not rate limited), then failure-style replacement of the primary
        state.backup?.let { if (now >= it.expiresAtEpochSecond) state = state.copy(backup = null) }
        state.primary?.let { p ->
            if (now >= p.expiresAtEpochSecond) {
                state = state.copy(primary = state.backup, backup = null)
            } else if (failedOut(p, now)) {
                rotateFailedPrimary(now, candidates, pick)
            }
        }
        state.backup?.let { b ->
            if (b.descriptorMissingSinceEpochSecond?.let { now - it >= MISSING_WINDOW_SECONDS } == true) {
                state = state.copy(backup = null)
            }
        }
        if (state.primary != null) fillBackup(candidates, pick)
        if (state != before) save()
    }

    private fun failedOut(
        e: GuardEntry,
        now: Long,
    ): Boolean {
        val failures =
            e.consecutiveFailures >= FAILURE_COUNT &&
                e.firstFailureAtEpochSecond?.let { now - it >= FAILURE_WINDOW_SECONDS } == true
        val missing = e.descriptorMissingSinceEpochSecond?.let { now - it >= MISSING_WINDOW_SECONDS } == true
        return failures || missing
    }

    private fun rotateFailedPrimary(
        now: Long,
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
    ) {
        val last = state.lastFailureRotationEpochSecond
        if (last != null && now - last < FAILURE_ROTATION_MIN_INTERVAL_SECONDS) return
        state = state.copy(primary = state.backup, backup = null, lastFailureRotationEpochSecond = now)
        if (state.primary != null) fillBackup(candidates, pick)
    }

    private fun fillBackup(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
    ) {
        if (state.backup != null || state.primary == null || candidates.isEmpty()) return
        val chosen = pick(candidates.filter { it.identity != state.primary?.identity }) ?: return
        state = state.copy(backup = newEntry(chosen))
    }

    private fun newEntry(d: OnionRelayDescriptor): GuardEntry {
        val now = now()
        val span = MAX_LIFETIME_SECONDS - MIN_LIFETIME_SECONDS
        // unbiased: SecureRandom.nextLong(bound)
        val lifetime = MIN_LIFETIME_SECONDS + random.nextLong(span + 1)
        return GuardEntry(d.identity, now, now + lifetime)
    }

    private fun save() {
        try {
            store.save(state)
        } catch (e: java.io.IOException) {
            logger.warn { "guard state could not be saved (${e.javaClass.simpleName})" }
        } catch (e: RuntimeException) {
            logger.warn { "guard state could not be saved (${e.javaClass.simpleName})" }
        }
    }

    companion object {
        const val MIN_LIFETIME_SECONDS = 30L * 86_400
        const val MAX_LIFETIME_SECONDS = 60L * 86_400
        const val FAILURE_COUNT = 3
        const val FAILURE_WINDOW_SECONDS = 24L * 3600
        const val MISSING_WINDOW_SECONDS = 72L * 3600
        const val FAILURE_ROTATION_MIN_INTERVAL_SECONDS = 24L * 3600

        /** First retry delay of a primary marked unreachable; doubles per failed probe up to [PRIMARY_RETRY_MAX_SECONDS]. */
        const val PRIMARY_RETRY_MIN_SECONDS = 30L
        const val PRIMARY_RETRY_MAX_SECONDS = 600L

        /** A probe that never reports a first-hop result (refused before a link was tried) counts as failed after this. */
        const val PROBE_TIMEOUT_SECONDS = 60L
        private const val RETRY_JITTER = 0.2
        private const val MAX_RETRY_SHIFT = 10
        private const val MAX_COUNTER = 1_000_000
    }
}

private fun <T> List<T>.randomOrNull(random: SecureRandom): T? = if (isEmpty()) null else this[random.nextInt(size)]
