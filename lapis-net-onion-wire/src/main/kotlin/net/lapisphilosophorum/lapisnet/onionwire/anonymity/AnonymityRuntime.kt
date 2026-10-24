@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.AnonymousMailboxGossip
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.AnonymousDirectoryPublisher
import net.lapisphilosophorum.lapisnet.onionwire.CircuitAdmissionException
import net.lapisphilosophorum.lapisnet.onionwire.CircuitPolicy
import net.lapisphilosophorum.lapisnet.onionwire.OnionClientCircuit
import net.lapisphilosophorum.lapisnet.onionwire.OnionDirectoryPublisher
import net.lapisphilosophorum.lapisnet.onionwire.OnionMailboxPublisher
import net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousClient
import net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousStream
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceHello
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceHost
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceStreamRouter
import net.lapisphilosophorum.lapisnet.onionwire.OnionWire
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.EncryptedFileGuardStateStore
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardManager
import net.lapisphilosophorum.lapisnet.onionwire.path.InsufficientRelaysException
import net.lapisphilosophorum.lapisnet.onionwire.path.OnionPathSelector
import net.lapisphilosophorum.lapisnet.onionwire.path.PathConflictException
import net.lapisphilosophorum.lapisnet.onionwire.path.RelayNetworkLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.RelayReputation
import net.lapisphilosophorum.lapisnet.onionwire.path.SelectingOnionPathProvider
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Path
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Anonymity mode of a node (wave V0.10.0-E): path selection with persistent guards, the circuit policy, and the
 * circuit-based directory publication of wave D, all started and stopped as one unit.
 *
 * **What it does:** the node publishes its directory presence (anonymous peer record, prekey bundle, service
 * descriptor) ONLY through circuits whose first hop is a persistent guard, and (wave V0.10.0-F1) carries direct messages
 * over rendezvous circuits and sealed mailbox items announced by relays. **What it does NOT do:** mail and call
 * signalling still use direct connections and reveal the IP address; GossipSub, the DHT and fetches still show
 * identity and IP; the libp2p transport key is still the identity key (see docs/anonymity.adoc). Hence
 * [ANONYMITY_INCOMPLETE_WARNING] at every start.
 *
 * Lifecycle: `start` -> running -> [close]. [close] is idempotent, stops new circuit builds first, then closes the
 * publisher, the service host and every remaining circuit (each sends DESTROY), and releases the guard key. A `start`
 * for a data directory whose previous runtime is still stopping waits for that stop; a second `start` for a running
 * directory fails.
 */
@ExperimentalOnionApi
class AnonymityRuntime private constructor(
    private val key: Path,
    private val guards: GuardManager,
    private val guardStore: EncryptedFileGuardStateStore,
    private val governor: CircuitBuildGovernor,
    private val channel: OnionDirectoryPublisher,
    private val host: OnionServiceHost,
    private val anonymousPublisher: AnonymousDirectoryPublisher,
    private val clock: Clock,
    private val lastError: AtomicReference<Pair<AnonymityErrorCode, Long>?>,
    private val wire: OnionWire,
    private val selector: OnionPathSelector,
    private val paths: SelectingOnionPathProvider,
    private val rendezvousClient: OnionRendezvousClient,
    private val mailboxPublisher: OnionMailboxPublisher,
    private val router: OnionServiceStreamRouter,
) : AutoCloseable {
    private val lifecycle = Any()

    @Volatile internal var hostStarted = false
    private val recipientUnreachable = AtomicLong(0)
    private var state = State.RUNNING
    private var maintenance: NodeServiceSupervisor.PeriodicJob? = null
    internal var maintenanceTick: () -> Unit = {}

    private enum class State { RUNNING, STOPPING, STOPPED }

    /** Runs one maintenance round now (the supervisor does this every 30 s); safe to call from any thread. */
    fun maintainNow() = maintenanceTick()

    internal fun attachMaintenance(job: NodeServiceSupervisor.PeriodicJob) {
        maintenance = job
    }

    internal fun stopped(): Boolean = synchronized(lifecycle) { state != State.RUNNING }

    /** A snapshot for the status panel: mode, guard and circuit counts, last error code. */
    fun status(): AnonymityStatus {
        val e = lastError.get()
        return AnonymityStatus(
            mode = "on",
            incomplete = true,
            guards = guards.guardCount(),
            activeCircuits = governor.openCount(),
            lastError = e?.first ?: AnonymityErrorCode.NONE,
            lastErrorAgeSeconds = e?.let { ((clock.millis() - it.second) / 1000).coerceAtLeast(0) },
            recipientUnreachableCount = recipientUnreachable.get(),
        )
    }

    /** The router that dispatches the streams reaching this node's onion service by application (wave V0.10.0-F1). */
    fun serviceRouter(): OnionServiceStreamRouter = router

    /** The shared anonymous mailbox topic; its consumer receives every validated sealed item. */
    fun mailboxGossip(): AnonymousMailboxGossip? = wire.mailboxGossip

    /** `true` while guards exist, the service host is started and nothing is shutting down. */
    fun ready(): Boolean =
        synchronized(lifecycle) { state == State.RUNNING } &&
            hostStarted &&
            !governor.isLocked() &&
            guards.guardCount() > 0

    /**
     * Resolves [identity] over the mixed directory. The directory is built WITHOUT a DHT: a DHT lookup would tell the
     * DHT neighbours, together with this node's IP address, whom it wants to reach.
     */
    fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability =
        wire.anonymousDirectory().resolve(identity)

    /**
     * Opens a rendezvous stream to the onion service described by [descriptor] and sends the HELLO frame for [app].
     * The rendezvous point is a path-selector endpoint; an endpoint that conflicts with the guard is replaced (at most
     * [RENDEZVOUS_ENDPOINT_TRIES] times). Fails with the cause of the underlying build/rendezvous failure; a failed
     * attempt is never retried here, the circuit governor's backoff applies.
     */
    fun connectToService(
        descriptor: OnionServiceDescriptor,
        app: OnionServiceApp,
        timeout: Duration,
    ): CompletableFuture<OnionRendezvousStream> {
        if (!ready()) return CompletableFuture.failedFuture(InsufficientRelaysException())
        val exclude = HashSet<Secp256k1PublicKey>()
        var endpoint: OnionRelayDescriptor? = null
        repeat(RENDEZVOUS_ENDPOINT_TRIES) {
            if (endpoint != null) return@repeat
            val candidate = selector.selectEndpoint(exclude) ?: return@repeat
            try {
                selector.select(candidate, lastHopChosenRemotely = false)
                endpoint = candidate
            } catch (e: PathConflictException) {
                exclude += candidate.identity
            }
        }
        val rendezvousPoint = endpoint ?: return CompletableFuture.failedFuture(InsufficientRelaysException())
        return rendezvousClient
            .connect(descriptor.address(), paths, rendezvousPoint, descriptor, timeout)
            .thenCompose { stream ->
                if (stream.send(OnionServiceHello.encode(app))) {
                    CompletableFuture.completedFuture(stream)
                } else {
                    stream.close()
                    CompletableFuture.failedFuture(IllegalStateException("could not send the service HELLO"))
                }
            }
    }

    /**
     * Hands up to four sealed mailbox items to a relay through one circuit. Completes with `true` only after every item
     * was acknowledged; there is no fallback to announcing from the own node.
     */
    fun publishMailboxItems(items: List<ByteArray>): CompletableFuture<Boolean> = mailboxPublisher.publishItems(items)

    /** Counts a send that found no anonymous way to the recipient; keeps no target and records the coarse code. */
    fun recordRecipientUnreachable() {
        recipientUnreachable.incrementAndGet()
        lastError.set(AnonymityErrorCode.RECIPIENT_UNREACHABLE to clock.millis())
    }

    /** Number of directory objects the publisher handed to circuits successfully (tests). */
    fun publications(): Int = anonymousPublisher.publications

    override fun close() {
        val latch =
            synchronized(lifecycle) {
                if (state != State.RUNNING) return
                state = State.STOPPING
                CountDownLatch(1).also { stopping[key] = it }
            }
        try {
            governor.lockdown()
            maintenance?.cancel()
            runCatching { router.close() }
            runCatching { rendezvousClient.close() }
            runCatching { mailboxPublisher.close() }
            runCatching { anonymousPublisher.close() }
            runCatching { host.close() }
            runCatching { channel.close() }
            for (h in governor.allHandles()) {
                runCatching { (h as OnionClientCircuit).close() }
                governor.onClosed(h)
            }
            runCatching { guardStore.close() }
        } finally {
            synchronized(lifecycle) { state = State.STOPPED }
            running.remove(key)
            stopping.remove(key, latch)
            latch.countDown()
        }
    }

    companion object {
        private val running = ConcurrentHashMap.newKeySet<Path>()
        private val stopping = ConcurrentHashMap<Path, CountDownLatch>()
        private const val INTRO_POINTS = 3
        private const val PUBLISH_CANDIDATES = 3
        private const val RENDEZVOUS_ENDPOINT_TRIES = 3

        /**
         * Starts anonymity mode on [wire], which must have been attached with [DirectoryAnonymityMode.ON].
         *
         * @param tombstonePublisher sends the address-free tombstone of an OFF to ON switch from the own node (once);
         * see [AnonymousDirectoryPublisher] for its contract
         */
        fun start(
            wire: OnionWire,
            identity: DualKeyIdentity,
            homeDir: Path,
            reputation: RelayReputation,
            locator: RelayNetworkLocator,
            modeStore: DirectoryModeStore,
            prekeyStore: PrekeyStore?,
            serviceKey: Ed25519KeyPair,
            tombstonePublisher: (PeerRecord) -> Unit,
            supervisor: NodeServiceSupervisor,
            random: SecureRandom = SecureRandom(),
            clock: Clock = Clock.systemUTC(),
            governor: CircuitBuildGovernor = CircuitBuildGovernor(clock),
            capabilities: Set<AnonymousCapability> = setOf(AnonymousCapability.DM),
        ): AnonymityRuntime {
            require(wire.directoryMode == DirectoryAnonymityMode.ON) { "the onion wire is not in anonymity mode" }
            val key = homeDir.toAbsolutePath().normalize()
            stopping[key]?.await(STOP_WAIT_SECONDS, TimeUnit.SECONDS)
            check(running.add(key)) { "anonymity mode is already running for this data directory" }
            val closers = ArrayList<() -> Unit>()
            try {
                // read BEFORE the publisher persists the new mode: a previous run in anonymity mode must have left guards
                val previousWasOn =
                    DirectoryModeTransition(identity, modeStore).previousMode() == DirectoryAnonymityMode.ON
                val lastError = AtomicReference<Pair<AnonymityErrorCode, Long>?>(null)

                fun record(code: AnonymityErrorCode) {
                    val now = clock.millis()
                    // a lost guard state is the one finding an operator must not miss: later, routine errors do not
                    // hide it for an hour (a successful publication clears it)
                    val current = lastError.get()
                    if (current != null &&
                        current.first == AnonymityErrorCode.GUARD_STATE_RESET &&
                        code != AnonymityErrorCode.GUARD_STATE_RESET &&
                        now - current.second < RESET_STICKY_MILLIS
                    ) {
                        return
                    }
                    lastError.set(code to now)
                }
                val guardStore =
                    EncryptedFileGuardStateStore(key.resolve("onion").resolve("guards.bin"), identity, random, clock)
                closers += { guardStore.close() }
                val guards =
                    GuardManager(guardStore, random, clock, missingIsReset = previousWasOn) {
                        record(AnonymityErrorCode.GUARD_STATE_RESET)
                    }
                val selector =
                    OnionPathSelector(
                        { wire.descriptors.snapshot(clock.millis() / 1000) },
                        identity.secp256k1KeyPair.publicKey,
                        locator,
                        reputation,
                        guards = guards,
                        random = random,
                        clock = clock,
                    )
                val paths = SelectingOnionPathProvider(selector) { record(AnonymityErrorCode.INSUFFICIENT_RELAYS) }
                wire.installCircuitPolicy(
                    CircuitPolicy(
                        governor,
                        firstHopResult = { id, ok ->
                            // a shutdown in progress must neither count failures against a guard nor touch its state file
                            if (!governor.isLocked()) {
                                if (ok) guards.recordFirstHopSuccess(id) else guards.recordFirstHopFailure(id)
                            }
                        },
                        onError = { record(codeOf(it)) },
                    ),
                )

                fun endpoints(count: Int): List<OnionRelayDescriptor> {
                    val picked = ArrayList<OnionRelayDescriptor>(count)
                    val exclude = HashSet<Secp256k1PublicKey>()
                    repeat(count) {
                        val d = selector.selectEndpoint(exclude) ?: return@repeat
                        picked += d
                        exclude += d.identity
                    }
                    if (picked.size < count) record(AnonymityErrorCode.INSUFFICIENT_RELAYS)
                    return picked
                }
                val publisher = wire.experimentalDirectoryPublisher(paths) { endpoints(PUBLISH_CANDIDATES) }
                closers += { publisher.close() }
                val recording = RecordingChannel(publisher) { record(AnonymityErrorCode.PUBLISH_FAILED) }
                val host =
                    wire.experimentalServiceHost(
                        serviceKey,
                        OnionServiceConfig(introPoints = INTRO_POINTS),
                        paths,
                        recording,
                    )
                closers += { host.close() }
                val router = OnionServiceStreamRouter()
                closers += { router.close() }
                host.onConnection = router::route
                val rendezvousClient = wire.experimentalRendezvousClient()
                closers += { rendezvousClient.close() }
                val mailboxPublisher = wire.experimentalMailboxPublisher(paths) { endpoints(PUBLISH_CANDIDATES) }
                closers += { mailboxPublisher.close() }
                val anonymousPublisher =
                    AnonymousDirectoryPublisher(
                        identity,
                        serviceKey,
                        prekeyStore,
                        recording,
                        modeStore,
                        clockMillis = clock::millis,
                        capabilities = capabilities,
                        tombstonePublisher = tombstonePublisher,
                    )
                closers += { anonymousPublisher.close() }
                val runtime =
                    AnonymityRuntime(
                        key,
                        guards,
                        guardStore,
                        governor,
                        publisher,
                        host,
                        anonymousPublisher,
                        clock,
                        lastError,
                        wire,
                        selector,
                        paths,
                        rendezvousClient,
                        mailboxPublisher,
                        router,
                    )

                var publisherStarted = false
                var lastPublications = 0
                val maintenanceLock = Any()
                runtime.maintenanceTick = {
                    synchronized(maintenanceLock) {
                        if (runtime.stopped()) return@synchronized
                        guards.maintain(wire.descriptors.snapshot(clock.millis() / 1000))
                        for (h in governor.expired(clock.instant())) {
                            runCatching { (h as OnionClientCircuit).close() }
                            governor.onClosed(h)
                        }
                        if (!runtime.hostStarted) {
                            val intro = endpoints(INTRO_POINTS)
                            if (intro.size >= INTRO_POINTS) {
                                host.start(intro)
                                runtime.hostStarted = true
                            }
                        }
                        if (runtime.hostStarted && !publisherStarted) {
                            anonymousPublisher.start()
                            publisherStarted = true
                        }
                        val p = anonymousPublisher.publications
                        if (p > lastPublications) {
                            lastPublications = p
                            lastError.set(null)
                        }
                    }
                }
                val job =
                    supervisor.launchPeriodic(
                        "anonymity-maintenance",
                        interval = 30.seconds,
                        jitter = 3.seconds,
                        initialDelay = 1.seconds,
                    ) { runtime.maintenanceTick() }
                runtime.attachMaintenance(job)
                logger.warn { ANONYMITY_INCOMPLETE_WARNING }
                return runtime
            } catch (e: Exception) {
                closers.asReversed().forEach { runCatching(it) }
                running.remove(key)
                throw e
            }
        }

        private const val STOP_WAIT_SECONDS = 30L
        private const val RESET_STICKY_MILLIS = 3_600_000L

        internal fun codeOf(t: Throwable): AnonymityErrorCode =
            when (t) {
                is InsufficientRelaysException, is PathConflictException -> AnonymityErrorCode.INSUFFICIENT_RELAYS
                is CircuitAdmissionException ->
                    when (t.kind) {
                        CircuitAdmissionException.Kind.RATE_LIMITED, CircuitAdmissionException.Kind.POOL_FULL ->
                            AnonymityErrorCode.RATE_LIMITED
                        CircuitAdmissionException.Kind.PATH_TOO_SHORT -> AnonymityErrorCode.INSUFFICIENT_RELAYS
                        CircuitAdmissionException.Kind.LOCKED -> AnonymityErrorCode.NONE
                    }
                else ->
                    if (generateSequence(t) { it.cause }.any { it.message?.contains("timed out") == true }) {
                        AnonymityErrorCode.BUILD_TIMEOUT
                    } else {
                        AnonymityErrorCode.BUILD_FAILED
                    }
            }
    }
}

/** Reports a failed publication (false or exceptional) without changing the result. */
private class RecordingChannel(
    private val delegate: DirectoryPublicationChannel,
    private val onFailure: () -> Unit,
) : DirectoryPublicationChannel {
    override val exposesOrigin: Boolean get() = delegate.exposesOrigin

    private fun watch(f: CompletableFuture<Boolean>): CompletableFuture<Boolean> =
        f.whenComplete { ok, e -> if (e != null || ok != true) onFailure() }

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord) =
        watch(delegate.publishAnonymousPeerRecord(record))

    override fun publishPrekeyBundle(bundle: PrekeyBundle) = watch(delegate.publishPrekeyBundle(bundle))

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor) =
        watch(delegate.publishServiceDescriptor(descriptor))
}
