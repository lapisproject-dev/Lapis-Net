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
     * The guard descriptor to use as first hop, choosing (and persisting) a new guard with [pick] if none is set; `null`
     * if there is no usable guard right now (none chosen and nothing to pick, or the guard's descriptor is unknown).
     */
    @Synchronized
    fun primaryUsable(
        candidates: List<OnionRelayDescriptor>,
        pick: (List<OnionRelayDescriptor>) -> OnionRelayDescriptor?,
    ): OnionRelayDescriptor? {
        maintainLocked(candidates, pick)
        val primary = state.primary
        if (primary == null) {
            val chosen = pick(candidates.filter { it.identity != state.backup?.identity }) ?: return null
            state = state.copy(primary = newEntry(chosen))
            fillBackup(candidates, pick)
            save()
            return chosen
        }
        candidates.firstOrNull { it.identity == primary.identity }?.let { return it }
        // The primary's descriptor is unknown (relay offline, descriptor expired): use the backup as first hop meanwhile
        // (as Tor does) instead of building nothing until the primary is rotated out after MISSING_WINDOW_SECONDS.
        val backup = state.backup ?: return null
        return candidates.firstOrNull { it.identity == backup.identity }
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
        private const val MAX_COUNTER = 1_000_000
    }
}

private fun <T> List<T>.randomOrNull(random: SecureRandom): T? = if (isEmpty()) null else this[random.nextInt(size)]
