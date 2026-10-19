package net.lapisphilosophorum.lapisnet.networking.relay

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/**
 * Orders relay candidates best-first. Implemented outside this module (the Madli module supplies
 * a reliability-based one) so `lapis-net-networking` stays free of any dependency on reputation
 * code. **A ranker is advisory, never a gate:** [RelayAutoSelector] keeps every input candidate
 * the ranker omitted (appended in input order) and discards anything the ranker invents.
 */
fun interface RelayCandidateRanker {
    fun rank(candidates: List<PeerInfo>): List<PeerInfo>

    companion object {
        /** Keeps the directory's order. */
        val UNRANKED = RelayCandidateRanker { it }
    }
}

/** The slice of [RelayReservationClient] the selector needs - an interface so the selection logic
 * is testable without real relays. */
internal interface RelaySlots {
    fun reserve(relay: PeerInfo): RelayReservation

    fun reservations(): List<RelayReservation>

    fun holdsReservationWith(relay: PeerId): Boolean

    fun release(relay: PeerId)
}

/** What one selection pass did. */
data class AutoRelayPassResult(
    /** Relays newly reserved in this pass. */
    val reserved: List<PeerId>,
    /** Relays whose reservation attempt failed in this pass. */
    val failed: List<PeerId>,
    /** Number of live reservations held at the end of the pass. */
    val held: Int,
)

/**
 * Keeps a node that sits behind NAT reachable by holding [AutoRelayConfig.targetRelayCount] relay
 * reservations, picked from directory candidates and ordered by an optional
 * [RelayCandidateRanker]. Runs only when explicitly started
 * ([net.lapisphilosophorum.lapisnet.networking.LapisNode.startAutoRelay], and then only for
 * [NodeReachability.PRIVATE]).
 *
 * Design points:
 *  - **Bounded work.** Unusable entries (self, held, in backoff, duplicate, unsafe) are filtered first, then at most
 *    [AutoRelayConfig.candidateLimit] remain before any ranking or dialling, a pass makes at most [AutoRelayConfig.maxAttemptsPerPass] attempts, and
 *    failures are remembered (capped) for [AutoRelayConfig.failureBackoff].
 *  - **Stability.** A working relay is never swapped out because another one ranks higher; the
 *    selector only fills gaps.
 *  - **Diversity.** Candidates on a source address (host) not yet used by a held relay come first,
 *    so two reservations do not silently share one machine.
 *  - **Untrusted input.** Candidate addresses come from a gossiped directory. Non-public IP
 *    literals and all DNS-form addresses are dropped unless [AutoRelayConfig.allowNonPublicCandidateAddresses].
 *  - **Never throws.** Every candidate and the ranker are guarded; a failing pass is logged.
 */
class RelayAutoSelector internal constructor(
    private val client: RelaySlots,
    private val config: AutoRelayConfig,
    private val candidates: () -> List<PeerInfo>,
    private val ranker: RelayCandidateRanker,
    private val selfPeerId: PeerId,
    private val clock: () -> Instant = Instant::now,
    private val schedulerFactory: () -> ScheduledExecutorService = {
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "lapis-relay-autoselect").apply { isDaemon = true }
        }
    },
) {
    private val backoff = LinkedHashMap<PeerId, Instant>()
    private val running = AtomicBoolean(false)
    private val stopped = AtomicBoolean(false)

    private val lifecycleLock = Any()

    @Volatile
    private var scheduler: ScheduledExecutorService? = null

    /** Starts the periodic pass (first pass immediately). Idempotent; a no-op after [stop]. */
    fun start() {
        synchronized(lifecycleLock) {
            if (stopped.get() || !running.compareAndSet(false, true)) return
            val executor = schedulerFactory()
            scheduler = executor
            executor.scheduleWithFixedDelay(
                { runCatching { runSelectionPass() }.onFailure { logger.warn(it) { "relay selection pass failed" } } },
                0,
                config.reselectInterval.toMillis(),
                TimeUnit.MILLISECONDS,
            )
        }
    }

    /** Stops the periodic pass and releases the thread. Idempotent. Reservations already taken
     * stay with the [RelayReservationClient] (which is stopped by the node). */
    fun stop() {
        synchronized(lifecycleLock) {
            if (!stopped.compareAndSet(false, true)) return
            scheduler?.shutdownNow()
            scheduler = null
        }
    }

    /** Whether the periodic pass has been started and not stopped. */
    fun isRunning(): Boolean = running.get() && !stopped.get()

    /** One selection pass - see the class doc. Serialised, so a manual call cannot interleave with
     * the scheduled one. */
    @Synchronized
    internal fun runSelectionPass(): AutoRelayPassResult {
        val now = clock()
        // 1. Forget reservations that lapsed without being renewed.
        // A relay whose reservation lapsed is backed off like a failed one: it did not renew.
        client.reservations().filterNot { client.holdsReservationWith(it.relay) }.forEach {
            client.release(it.relay)
            remember(it.relay, now)
        }
        val heldNow = client.reservations()
        val heldIds = heldNow.map { it.relay }.toSet()
        var held = heldIds.size
        if (held >= config.targetRelayCount) return AutoRelayPassResult(emptyList(), emptyList(), held)

        backoff.entries.removeIf { !it.value.isAfter(now) }

        // 2. Candidates, bounded BEFORE anything else touches them.
        val pool = collectCandidates(heldIds, now)
        if (pool.isEmpty()) return AutoRelayPassResult(emptyList(), emptyList(), held)

        // 3. Rank (advisory), 4. diversify.
        val ordered = diversify(safeRank(pool), heldNow.flatMap { it.relayAddresses }.mapNotNull(::sourceKeyOf).toSet())

        // 5. Attempt, bounded.
        val reserved = ArrayList<PeerId>()
        val failed = ArrayList<PeerId>()
        var attempts = 0
        for (candidate in ordered) {
            if (held >= config.targetRelayCount || attempts >= config.maxAttemptsPerPass) break
            attempts++
            try {
                client.reserve(candidate)
                reserved += candidate.peerId
                held++
            } catch (e: Exception) {
                failed += candidate.peerId
                remember(candidate.peerId, now)
                logger.debug { "automatic relay reservation on ${candidate.peerId} failed: ${e.message}" }
            }
        }
        if (reserved.isNotEmpty() || failed.isNotEmpty()) {
            logger.info { "relay selection pass: reserved=${reserved.size} failed=${failed.size} held=$held" }
        }
        return AutoRelayPassResult(reserved, failed, held)
    }

    private fun collectCandidates(
        heldIds: Set<PeerId>,
        now: Instant,
    ): List<PeerInfo> {
        val raw =
            try {
                candidates()
            } catch (e: Exception) {
                logger.warn(e) { "relay candidate source failed" }
                return emptyList()
            }
        val seen = HashSet<PeerId>()
        // The cheap in-memory filters (self, held, backoff, sanitise, dedup) run BEFORE the cap, so
        // entries that cannot be dialled anyway never use up a place among the candidateLimit. The
        // cap still bounds ranking and dialling; the raw input scanned is bounded separately.
        return raw
            .asSequence()
            .take((config.candidateLimit.toLong() * RAW_SCAN_FACTOR).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            .filter { it.peerId != selfPeerId && it.peerId !in heldIds && backoff[it.peerId]?.isAfter(now) != true }
            .mapNotNull(::sanitise)
            .filter { seen.add(it.peerId) }
            .take(config.candidateLimit)
            .toList()
    }

    /** Drops unusable / unsafe addresses; `null` when none remain. */
    private fun sanitise(info: PeerInfo): PeerInfo? {
        val usable =
            info.addresses.filter { address ->
                !address.has(Protocol.P2PCIRCUIT) && (config.allowNonPublicCandidateAddresses || isAcceptable(address))
            }
        if (usable.isEmpty()) return null
        return if (usable.size == info.addresses.size) info else PeerInfo(info.peerId, usable)
    }

    /**
     * Literal IP components must all be globally routable. DNS-form components (`/dns`, `/dns4`,
     * `/dns6`, `/dnsaddr`) are rejected outright: the libp2p dialer would resolve them later
     * without any check, so a name such as `localtest.me`, `10.0.0.1.nip.io` or a rebinding
     * attacker domain would turn a gossiped directory entry into an internal-network dial
     * (SSRF / port-scan primitive) - the same rule `PeerAddressSanitizer` applies in the DHT layer.
     */
    private fun isAcceptable(address: Multiaddr): Boolean {
        if (address.hasAny(Protocol.DNS, Protocol.DNS4, Protocol.DNS6, Protocol.DNSADDR)) return false
        val literals = ReachabilityHeuristic.literalAddressesOf(address)
        if (literals.isEmpty()) return false
        return literals.all { ReachabilityHeuristic.isPubliclyRoutable(it) }
    }

    private fun safeRank(pool: List<PeerInfo>): List<PeerInfo> {
        val byId = pool.associateBy { it.peerId }
        val ranked =
            try {
                ranker.rank(pool)
            } catch (e: Exception) {
                logger.warn(e) { "relay candidate ranker failed - using directory order" }
                return pool
            }
        val result = LinkedHashMap<PeerId, PeerInfo>()
        var foreign = 0
        for (entry in ranked) {
            val known = byId[entry.peerId]
            // Only candidates we passed in; always OUR sanitised copy, never the ranker's.
            if (known == null) foreign++ else result.putIfAbsent(known.peerId, known)
        }
        if (foreign > 0) logger.warn { "relay candidate ranker returned $foreign unknown candidates - discarded" }
        // A ranker is advisory: anything it left out keeps its place at the end.
        pool.forEach { result.putIfAbsent(it.peerId, it) }
        return result.values.toList()
    }

    private fun diversify(
        ranked: List<PeerInfo>,
        usedKeys: Set<String>,
    ): List<PeerInfo> {
        val taken = HashSet(usedKeys)
        val diverse = ArrayList<PeerInfo>()
        val rest = ArrayList<PeerInfo>()
        for (candidate in ranked) {
            val keys = candidate.addresses.mapNotNull(::sourceKeyOf).toSet()
            if (keys.isEmpty() || keys.none { it in taken }) {
                diverse += candidate
                taken += keys
            } else {
                rest += candidate
            }
        }
        return diverse + rest
    }

    private fun sourceKeyOf(address: Multiaddr): String? = reservationSourceKey(address)

    private fun remember(
        peer: PeerId,
        now: Instant,
    ) {
        if (config.failureBackoff.isZero) return
        if (backoff.size >= config.maxBackoffEntries && !backoff.containsKey(peer)) {
            // Evict the entry that would expire first.
            backoff.entries.minByOrNull { it.value }?.let { backoff.remove(it.key) }
        }
        backoff[peer] = now.plus(config.failureBackoff)
    }
}

/** How many raw directory entries are scanned per kept candidate; bounds work on a hostile directory. */
private const val RAW_SCAN_FACTOR = 64
