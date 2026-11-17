@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.directory.MultiaddrHygiene
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDirectoryClient
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.RelayDirectoryFetchResult
import net.lapisphilosophorum.lapisnet.directory.RelayDirectorySnapshotIngest
import net.lapisphilosophorum.lapisnet.directory.directAddresses
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.confinement.ConnectionConfinement
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardManager
import net.lapisphilosophorum.lapisnet.onionwire.path.OnionPathSelector
import net.lapisphilosophorum.lapisnet.onionwire.path.PathConflictException
import net.lapisphilosophorum.lapisnet.onionwire.path.PathSelectionResult
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/** Connection state of a confined node (wave V0.10.0-J1b). */
enum class ConfinementState(
    val wire: String,
) {
    /** No usable relay view or no live guard connection: the bootstrap peers are allowed and contacted. */
    BOOTSTRAPPING("bootstrapping"),

    /** Only the two guards are connected. */
    GUARDS_ONLY("guards-only"),
}

/**
 * What the connection controller of a confined node needs from the network (wave V0.10.0-J1b). Public only as a test
 * seam of [AnonymityRuntime.start]; production uses the [LapisNode] of the onion wire.
 */
@ExperimentalOnionApi
interface ConfinedNetwork {
    fun isConnected(peer: PeerId): Boolean

    /** Dials [peer] at [addresses] and waits for the connection; throws on failure or refusal. */
    fun dial(
        peer: PeerId,
        addresses: List<Multiaddr>,
    )

    /** A snapshot fetch over the existing connection to [peer]; [RelayDirectoryFetchResult.Failed] without one. */
    fun fetch(peer: PeerId): CompletableFuture<RelayDirectoryFetchResult>

    fun closeOutside(allowed: Set<PeerId>)
}

/** [ConfinedNetwork] over a real [LapisNode] (dials go through [LapisNode.connect], so the confinement applies). */
internal class LapisNodeConfinedNetwork(
    private val node: LapisNode,
    private val client: OnionRelayDirectoryClient = OnionRelayDirectoryClient(),
    private val dialTimeout: java.time.Duration = java.time.Duration.ofSeconds(10),
) : ConfinedNetwork {
    override fun isConnected(peer: PeerId): Boolean = node.liveConnectionTo(peer) != null

    override fun dial(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ) {
        node.connect(PeerInfo(peer, addresses), dialTimeout)
    }

    override fun fetch(peer: PeerId): CompletableFuture<RelayDirectoryFetchResult> {
        val connection =
            node.liveConnectionTo(peer) ?: return CompletableFuture.completedFuture(RelayDirectoryFetchResult.Failed)
        return client.fetch(connection)
    }

    override fun closeOutside(allowed: Set<PeerId>) {
        node.closeConnectionsOutside(allowed)
    }
}

/**
 * Keeps a node in anonymity mode connected ONLY to its guards (wave V0.10.0-J1b), with the bootstrap peers allowed and
 * contacted only while the node lacks a usable relay view or a live guard connection.
 *
 * Per [tick] (every 30 s +/- 3 s from the supervisor, and after every snapshot):
 *  1. the guards' peer ids (from their current descriptors) become the allowed guard set;
 *  2. both guards are dialled when not connected (addresses from their verified peer records);
 *  3. `ready` = a full path can be selected (a check without a build) and `guardLink` = a live guard connection;
 *  4. in [ConfinementState.BOOTSTRAPPING] the bootstrap peers are allowed, dialled with backoff (5 s, 15 s, 45 s, then
 *     60 s) and asked for snapshots (at most [MAX_BOOTSTRAP_FETCH_SOURCES] random ones, one per source and
 *     [SOURCE_FETCH_INTERVAL_MILLIS], at most [MAX_FETCHES_PER_HOUR] fetches per hour in total);
 *  5. each guard is asked once after it is connected and then every 3 h +/- 20 %;
 *  6. `ready && guardLink`: [ConfinementState.GUARDS_ONLY], the bootstrap peers are no longer allowed and every
 *     connection outside {primary, backup} is closed (a bootstrap peer that is a guard stays). Losing that state for
 *     [HYSTERESIS_TICKS] consecutive ticks returns to bootstrapping (no close-and-reconnect loop).
 *
 * [relayViewReady] is the gate of a NEW guard choice: snapshots from at least `min(2, configured sources)` distinct
 * sources, or [VIEW_SETTLE_MILLIS] after the first answer once every configured source is SETTLED. A source is settled
 * when it delivered a snapshot, answered [RelayDirectoryFetchResult.Unsupported], was blocked by the ingest, or could
 * not be dialled [UNREACHABLE_AFTER_DIAL_FAILURES] times in a row. A source that is reachable but whose fetch failed
 * after the connection stood ([RelayDirectoryFetchResult.Failed], [RelayDirectoryFetchResult.Malformed],
 * [RelayDirectoryFetchResult.Timeout], e.g. because its server refused the stream over its limits) keeps the gate closed
 * and is asked again after [FETCH_RETRY_BACKOFF_MILLIS] (5 s, 15 s, 45 s, then 60 s, within the hourly budget) instead
 * of [SOURCE_FETCH_INTERVAL_MILLIS]: otherwise one hostile source that answers at once, plus a second source whose
 * server is kept busy for two minutes, would decide the guard choice alone (security audit of wave J1b). Once open, the
 * gate stays open. With a single configured source the first guard choice trusts that source (assumption Q14): logged
 * once as `single-directory-source`, shown in the status.
 *
 * Gossip fallback: when EVERY configured bootstrap peer answered [RelayDirectoryFetchResult.Unsupported] (old v0.12.0
 * nodes serve no snapshots) before any snapshot arrived, the gate opens [VIEW_SETTLE_MILLIS] after the last of them
 * did, and the guard choice uses the view gossip built meanwhile, as in wave J1a (no provenance: gossip is not a
 * source). Logged once as `gossip-only-relay-view`, shown in the status. A bootstrap peer that is never reached does
 * not count as unsupported, so with one of those the gate stays closed (fail-closed). A snapshot that arrives later
 * (e.g. from a newer guard) does not restart the settle window: the earlier of both moments counts, so a gate that
 * has opened stays open.
 *
 * Without any configured bootstrap peer a confined node (no listener, no mDNS, no persisted descriptors) can not reach
 * any relay: logged once as `no-bootstrap-peers` at construction and shown in the status; it stays bootstrapping.
 *
 * All state changes run on one worker thread; the counters are readable from anywhere. Logs carry no peer id.
 */
internal class AnonymousConnectionController(
    private val confinement: ConnectionConfinement,
    bootstrap: List<Multiaddr>,
    private val guards: GuardManager,
    private val selector: OnionPathSelector,
    private val descriptors: OnionRelayDescriptorIndex,
    private val peerRecords: (Secp256k1PublicKey, Long) -> PeerRecord?,
    private val network: ConfinedNetwork,
    private val ingest: RelayDirectorySnapshotIngest,
    private val clock: Clock,
    private val random: SecureRandom,
    executor: Executor? = null,
    private val onRelayViewChanged: () -> Unit = {},
) : AutoCloseable {
    private class Bootstrap(
        val peer: PeerId,
        val addresses: List<Multiaddr>,
    ) {
        var failures = 0
        var nextDialAtMillis = 0L
        var fetchFailures = 0

        /** Set while the source has not yet delivered a snapshot and its last fetch failed; cleared by an Ok. */
        var nextFetchRetryAtMillis: Long? = null
    }

    private val ownExecutor: ExecutorService? =
        if (executor == null) {
            ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, LinkedBlockingQueue(64)) {
                Thread(it, "lapis-net-anonymity-confinement").also { t -> t.isDaemon = true }
            }.also { it.allowCoreThreadTimeOut(true) }
        } else {
            null
        }
    private val worker: Executor = executor ?: ownExecutor!!
    private val bootstraps: List<Bootstrap> =
        bootstrap
            .mapNotNull { a ->
                val peer = runCatching { a.getPeerId() }.getOrNull() ?: return@mapNotNull null
                Bootstrap(peer, listOf(Multiaddr(a.components.filter { it.protocol != Protocol.P2P })))
            }.distinctBy { it.peer }
    private val configuredSources = bootstraps.size
    private val closed = AtomicBoolean(false)
    private val pending = AtomicBoolean(false)

    // worker-thread state
    private var unhealthyStreak = 0
    private val lastFetchAt = HashMap<PeerId, Long>()
    private val fetchTimes = ArrayDeque<Long>()
    private val inFlight = HashSet<PeerId>()
    private val unsupported = HashSet<PeerId>()
    private val responded = LinkedHashSet<PeerId>()
    private val guardNextFetchAt = HashMap<PeerId, Long>()
    private var singleSourceLogged = false

    @Volatile private var currentState = ConfinementState.BOOTSTRAPPING

    @Volatile private var respondedCount = 0

    @Volatile private var firstResponseAtMillis: Long? = null

    /** When the last configured source turned out not to serve snapshots (no snapshot yet); see the class comment. */
    @Volatile private var gossipOnlySinceMillis: Long? = null

    /** Every configured source is settled (class comment); recomputed on the worker after each dial and fetch. */
    @Volatile private var sourcesSettled = false

    /** Latched: a gate that has opened stays open (also when a source becomes unsettled again later). */
    @Volatile private var gateOpened = false

    @Volatile private var guardConnectionCount = 0
    private val fetchCount = AtomicLong(0)
    private val rejectedEntries = AtomicLong(0)

    init {
        confinement.setBootstrapPeers(bootstraps.map { it.peer }.toSet())
        confinement.setBootstrapAllowed(true)
        if (configuredSources == 0) {
            logger.warn {
                "anonymity mode: no bootstrap peer configured; the node can reach no relay and stays bootstrapping " +
                    "(no-bootstrap-peers)"
            }
        }
    }

    fun state(): ConfinementState = currentState

    fun guardConnections(): Int = guardConnectionCount

    fun snapshotFetches(): Long = fetchCount.get()

    fun snapshotRejectedEntries(): Long = rejectedEntries.get()

    /** `true` when the first guard choice relies on one configured directory source (assumption Q14). */
    fun singleDirectorySource(): Boolean = configuredSources == 1

    /** `true` when no bootstrap peer is configured: the confined node can reach no relay (see the class comment). */
    fun noBootstrapPeers(): Boolean = configuredSources == 0

    /** `true` while the guard choice relies on the gossip view only (no source serves snapshots; class comment). */
    fun gossipOnlyRelayView(): Boolean = gossipOnlySinceMillis != null && firstResponseAtMillis == null

    /** The gate of a NEW guard choice (see the class comment). */
    fun relayViewReady(): Boolean {
        if (gateOpened) return true
        val required = minOf(MIN_SOURCES, configuredSources).coerceAtLeast(1)
        if (respondedCount >= required) {
            gateOpened = true
            return true
        }
        // the settle fallback needs an answer (Ok/Unsupported/blocked/unreachable) from EVERY configured source: a
        // source that is reachable but failed keeps the gate closed (security audit of wave J1b, see the class comment)
        if (!sourcesSettled) return false
        // the earlier of both moments: a first snapshot that arrives after the gossip fallback has started
        // must not restart the settle window (the gate that already opened would close again)
        val first = firstResponseAtMillis
        val gossip = gossipOnlySinceMillis
        val since =
            when {
                first != null && gossip != null -> minOf(first, gossip)
                else -> first ?: gossip ?: return false
            }
        if (clock.millis() - since < VIEW_SETTLE_MILLIS) return false
        gateOpened = true
        return true
    }

    /** Worker thread only: recomputes [sourcesSettled] (see the class comment). */
    private fun updateSourcesSettled() {
        sourcesSettled =
            bootstraps.isNotEmpty() &&
            bootstraps.all { b ->
                b.peer in responded ||
                    b.peer in unsupported ||
                    ingest.isBlocked(b.peer) ||
                    (b.failures >= UNREACHABLE_AFTER_DIAL_FAILURES && !network.isConnected(b.peer))
            }
    }

    /** Asks for one step on the worker; coalesces requests that arrive while one is queued. */
    fun tick() {
        if (closed.get()) return
        if (!pending.compareAndSet(false, true)) return
        try {
            worker.execute {
                pending.set(false)
                if (!closed.get()) {
                    try {
                        step()
                    } catch (e: RuntimeException) {
                        logger.debug { "confinement step failed: ${e.javaClass.simpleName}" }
                    }
                }
            }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            pending.set(false)
        }
    }

    private fun step() {
        val now = clock.millis()
        val nowSec = now / 1000
        val state = guards.snapshot()
        val guardIds = listOfNotNull(state.primary?.identity, state.backup?.identity)
        val guardDescriptors = guardIds.mapNotNull { descriptors.current(it, nowSec) }
        val guardPeers = guardDescriptors.map { it.peerId }.toSet()
        confinement.setGuardPeers(guardPeers)
        updateSourcesSettled()
        for (d in guardDescriptors) {
            if (network.isConnected(d.peerId)) continue
            val addresses =
                peerRecords(d.identity, nowSec)
                    ?.takeIf { it.peerId == d.peerId }
                    ?.directAddresses
                    ?.filterNot { MultiaddrHygiene.isBlockedPrivateOrLocal(it) }
                    .orEmpty()
            if (addresses.isEmpty()) continue
            runCatching { network.dial(d.peerId, addresses) }
                .onFailure { logger.debug { "guard dial failed: ${it.javaClass.simpleName}" } }
        }
        val connectedGuards = guardPeers.filter { network.isConnected(it) }
        guardConnectionCount = connectedGuards.size
        // evaluated every step (never short-circuited): with the gate open this check is what chooses the guards
        val ready = pathReady()
        val healthy = ready && connectedGuards.isNotEmpty()
        unhealthyStreak = if (healthy) 0 else unhealthyStreak + 1
        when (currentState) {
            ConfinementState.BOOTSTRAPPING ->
                if (healthy) {
                    currentState = ConfinementState.GUARDS_ONLY
                    confinement.setBootstrapAllowed(false)
                    network.closeOutside(guardPeers)
                    logger.info { "anonymity mode: connected to guards only" }
                }
            ConfinementState.GUARDS_ONLY ->
                if (unhealthyStreak >= HYSTERESIS_TICKS) {
                    currentState = ConfinementState.BOOTSTRAPPING
                    logger.info { "anonymity mode: no usable guard connection, contacting bootstrap peers again" }
                }
        }
        if (currentState == ConfinementState.BOOTSTRAPPING) {
            confinement.setBootstrapAllowed(true)
            dialBootstraps(now)
            fetchFromBootstraps(now)
        } else {
            network.closeOutside(guardPeers)
        }
        for (peer in connectedGuards) {
            val next = guardNextFetchAt[peer]
            if (next == null || now >= next) {
                // scheduled BEFORE the fetch starts: its result may run the next step before startFetch returns
                guardNextFetchAt[peer] = now + jittered(GUARD_REFRESH_MILLIS)
                if (!startFetch(peer, now)) {
                    if (next == null) guardNextFetchAt.remove(peer) else guardNextFetchAt[peer] = next
                }
            }
        }
        // the path check may just have chosen the guards (gate open): connect them without waiting for the next tick
        val after = guards.snapshot()
        if (listOfNotNull(after.primary?.identity, after.backup?.identity) != guardIds) tick()
        if (relayViewReady() && configuredSources == 1 && !singleSourceLogged) {
            singleSourceLogged = true
            logger.warn {
                "anonymity mode: the guard choice relies on a single directory source (single-directory-source)"
            }
        }
    }

    private fun pathReady(): Boolean =
        try {
            selector.select(null, forBuild = false) is PathSelectionResult.Selected
        } catch (e: PathConflictException) {
            false
        }

    private fun dialBootstraps(now: Long) {
        var dials = 0
        for (b in bootstraps) {
            if (dials >= MAX_BOOTSTRAP_DIALS_PER_STEP) break
            if (network.isConnected(b.peer) || now < b.nextDialAtMillis) continue
            dials++
            try {
                network.dial(b.peer, b.addresses)
                b.failures = 0
                b.nextDialAtMillis = 0
            } catch (e: Exception) {
                b.failures++
                b.nextDialAtMillis = clock.millis() + BOOTSTRAP_BACKOFF_MILLIS[(b.failures - 1).coerceAtMost(3)]
                logger.debug { "bootstrap dial failed (${b.failures} in a row): ${e.javaClass.simpleName}" }
            }
        }
        updateSourcesSettled()
    }

    private fun fetchFromBootstraps(now: Long) {
        val due = bootstraps.filter { isDue(it, now) }.shuffled(random)
        val slots = (MAX_BOOTSTRAP_FETCH_SOURCES - inFlight.size).coerceAtLeast(0)
        // checked again per source: a result that completes at once runs a nested step that may have asked it already
        for (b in due.take(slots)) if (isDue(b, now)) startFetch(b.peer, now)
    }

    private fun isDue(
        b: Bootstrap,
        now: Long,
    ): Boolean {
        val p = b.peer
        return p !in unsupported &&
            p !in inFlight &&
            !ingest.isBlocked(p) &&
            network.isConnected(p) &&
            // a source without a snapshot yet whose last fetch failed: retried with backoff, so that it can still
            // answer inside the settle window; otherwise one fetch per interval
            (
                b.nextFetchRetryAtMillis?.let { now >= it }
                    ?: (lastFetchAt[p]?.let { now - it >= SOURCE_FETCH_INTERVAL_MILLIS } != false)
            )
    }

    /** Starts a fetch when the hourly budget allows it; `true` if started. */
    private fun startFetch(
        peer: PeerId,
        now: Long,
    ): Boolean {
        if (peer in inFlight || peer in unsupported) return false
        while (fetchTimes.isNotEmpty() && now - fetchTimes.first() >= HOUR_MILLIS) fetchTimes.removeFirst()
        if (fetchTimes.size >= MAX_FETCHES_PER_HOUR) return false
        fetchTimes.addLast(now)
        lastFetchAt[peer] = now
        inFlight += peer
        fetchCount.incrementAndGet()
        val future =
            try {
                network.fetch(peer)
            } catch (e: RuntimeException) {
                CompletableFuture.completedFuture(RelayDirectoryFetchResult.Failed)
            }
        future.whenComplete { result, _ ->
            val outcome = result ?: RelayDirectoryFetchResult.Failed
            try {
                worker.execute { onFetchResult(peer, outcome) }
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                // closed meanwhile
            }
        }
        return true
    }

    private fun onFetchResult(
        peer: PeerId,
        result: RelayDirectoryFetchResult,
    ) {
        inFlight -= peer
        if (closed.get()) return
        val source = bootstraps.firstOrNull { it.peer == peer }
        when (result) {
            is RelayDirectoryFetchResult.Ok -> {
                source?.fetchFailures = 0
                source?.nextFetchRetryAtMillis = null
                val report = ingest.ingest(peer, result.snapshot)
                rejectedEntries.addAndGet(report.rejected.toLong())
                if (!report.sourceBlocked) {
                    // distinct peer ids: a source that is both bootstrap peer and guard counts once
                    if (responded.add(peer)) respondedCount = responded.size
                    if (firstResponseAtMillis == null) firstResponseAtMillis = clock.millis()
                }
                runCatching(onRelayViewChanged)
            }
            RelayDirectoryFetchResult.Unsupported -> {
                unsupported += peer
                if (firstResponseAtMillis == null &&
                    gossipOnlySinceMillis == null &&
                    bootstraps.isNotEmpty() &&
                    bootstraps.all { it.peer in unsupported }
                ) {
                    gossipOnlySinceMillis = clock.millis()
                    logger.warn {
                        "anonymity mode: no bootstrap peer serves relay directory snapshots; the guard choice will " +
                            "rely on the gossip view (gossip-only-relay-view)"
                    }
                }
            }
            RelayDirectoryFetchResult.Malformed,
            RelayDirectoryFetchResult.Timeout,
            RelayDirectoryFetchResult.Failed,
            ->
                // reachable, but no answer: keeps the gate closed; retried soon while it has delivered nothing yet
                if (source != null && peer !in responded) {
                    source.fetchFailures++
                    source.nextFetchRetryAtMillis =
                        clock.millis() + FETCH_RETRY_BACKOFF_MILLIS[(source.fetchFailures - 1).coerceAtMost(3)]
                }
        }
        updateSourcesSettled()
        logger.debug { "relay directory fetch finished: ${result.javaClass.simpleName}" }
        tick()
    }

    private fun jittered(base: Long): Long = (base * (1.0 - JITTER + 2 * JITTER * random.nextDouble())).toLong()

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        ownExecutor?.shutdownNow()
    }

    companion object {
        const val MIN_SOURCES = 2
        const val VIEW_SETTLE_MILLIS = 120_000L
        const val HYSTERESIS_TICKS = 2
        const val MAX_BOOTSTRAP_FETCH_SOURCES = 4
        const val MAX_BOOTSTRAP_DIALS_PER_STEP = 4
        const val SOURCE_FETCH_INTERVAL_MILLIS = 600_000L
        const val MAX_FETCHES_PER_HOUR = 6
        const val GUARD_REFRESH_MILLIS = 3L * 3_600_000L
        private const val HOUR_MILLIS = 3_600_000L
        private const val JITTER = 0.2
        val BOOTSTRAP_BACKOFF_MILLIS = longArrayOf(5_000L, 15_000L, 45_000L, 60_000L)

        /** Retry of a source whose fetch failed before it ever delivered a snapshot (class comment). */
        val FETCH_RETRY_BACKOFF_MILLIS = longArrayOf(5_000L, 15_000L, 45_000L, 60_000L)

        /** Consecutive failed dials after which a never connected source counts as settled (class comment). */
        const val UNREACHABLE_AFTER_DIAL_FAILURES = 4
    }
}
