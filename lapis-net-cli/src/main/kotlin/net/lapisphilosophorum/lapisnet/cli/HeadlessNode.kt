@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeRetirement
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.FileDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.resolveKeystorePassphrase
import net.lapisphilosophorum.lapisnet.madli.CachedVeritasObserverWeight
import net.lapisphilosophorum.lapisnet.madli.DailyRelayReliabilityPublication
import net.lapisphilosophorum.lapisnet.madli.MadliGossip
import net.lapisphilosophorum.lapisnet.madli.MadliRelayRanker
import net.lapisphilosophorum.lapisnet.madli.MadliRelayReliabilityPublisher
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayAutoSelector
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionWire
import net.lapisphilosophorum.lapisnet.onionwire.OnionWireConfig
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityStatus
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.anonymityIncompleteWarning
import net.lapisphilosophorum.lapisnet.onionwire.path.PeerDirectoryRelayNetworkLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.RelayNetworkLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.RelayReputation
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

private val logger = KotlinLogging.logger {}

/** File name of the (encrypted) onion key file inside the node's data directory. */
private const val ONION_KEY_FILE = "onion-relay.onionkeys"

/** File name of the persisted directory publication mode (wave V0.10.0-D/E) inside the node's data directory. */
private const val DIRECTORY_MODE_FILE = "directory-mode.state"

/** Validity of the record a headless node publishes; it is refreshed long before. */
private const val HEADLESS_RECORD_TTL_SECONDS = 24L * 3600

/**
 * The lean long-running node behind `lapisnet node` (V0.9.15): a [LapisNode] with the switches of
 * [NodeWiringOptions] - automatic relay selection (Madli-ranked), the DHT fallback for the peer directory and the
 * publication of relay reliability. **No DM, no mail**: the CLI has no inbox and no session store, so there is no
 * `InboxDhtFetcher` and no outbox consumer here, and the node's own record advertises NO capability (in particular
 * never RELAY: it is not a relay server). Everything background is owned by one [NodeServiceSupervisor] and torn down
 * in reverse start order by [stop], which is idempotent.
 */
internal class HeadlessNode private constructor(
    val node: LapisNode,
    val options: NodeWiringOptions,
    val storage: NabuStorage,
    val directoryDht: DirectoryDht?,
    val onionWire: OnionWire,
    val madliGossip: MadliGossip?,
    val autoRelaySelector: RelayAutoSelector?,
    val relayReliabilityJob: NodeServiceSupervisor.PeriodicJob?,
    val supervisor: NodeServiceSupervisor,
    private val closers: List<() -> Unit>,
    /** Anonymity mode (wave V0.10.0-E); `null` in normal mode. */
    val anonymity: AnonymityRuntime? = null,
) {
    private val stopped = AtomicBoolean(false)

    /** Mode, guard and circuit counts and the last error code; [AnonymityStatus.OFF] in normal mode. */
    fun anonymityStatus(): AnonymityStatus = anonymity?.status() ?: AnonymityStatus.OFF

    /** Idempotent teardown: supervised parts first (publisher, auto-relay, Madli, DHT), then the layers below, the node last. */
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        runCatching { supervisor.stopAll() }
        closers.forEach { runCatching(it) }
        runCatching { node.stop() }
    }

    companion object {
        /**
         * Starts a headless node. Everything attached is rolled back if a later step throws.
         *
         * The `*` parameters are test seams (production passes none): tests need `allowNonPublicCandidateAddresses`
         * for loopback relays and short intervals.
         */
        fun start(
            options: NodeWiringOptions,
            identity: DualKeyIdentity,
            bootstrapPeers: List<Multiaddr>,
            listenAddress: Multiaddr,
            dataDirectory: Path,
            autoRelayConfig: AutoRelayConfig = AutoRelayConfig(),
            directoryDhtLimits: DirectoryDhtLimits = DirectoryDhtLimits(),
            maintenanceInterval: Duration = 60.seconds,
            maintenanceInitialDelay: Duration = 5.seconds,
            selfRecordCheckInterval: Duration = 30.seconds,
            onionWireConfig: OnionWireConfig = OnionWireConfig(relayMode = options.onionRelay),
            onionKeyPassphrase: () -> CharArray? = ::resolveKeystorePassphrase,
            /** Test seam: must return a `RelayNetworkLocator`; typed `Any` so the experimental onion type does not leak to callers. */
            anonymityLocator: ((PeerDirectoryGossip) -> Any)? = null,
        ): HeadlessNode {
            Files.createDirectories(dataDirectory)
            val rollback = mutableListOf<() -> Unit>()
            try {
                val node =
                    LapisNode.create(
                        identity,
                        listenAddress,
                        options.relayConfig(RelayConfig.CLIENT_ONLY.copy(autoRelay = autoRelayConfig)),
                        options.holePunchConfig(),
                    )
                node.start(bootstrapPeers = bootstrapPeers)
                rollback += { runCatching { node.stop() } }
                val storage = NabuStorage.attach(node, dataDirectory)
                rollback += { runCatching { storage.stop() } }
                // GossipPubSub must attach before any connect().
                val pubsub = GossipPubSub.attach(node)
                rollback += { runCatching { pubsub.stop() } }
                val veritas = VeritasGossip.attach(pubsub, storage)
                rollback += { runCatching { veritas.stop() } }
                val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
                rollback += { runCatching { peerDirectory.stop() } }
                val prekeys = PrekeyBundleGossip.attach(pubsub, storage)
                rollback += { runCatching { prekeys.stop() } }

                val supervisor = NodeServiceSupervisor("lapis-cli-node")
                rollback += { supervisor.stopAll() }

                // V0.10.0-B: the descriptor index and its gossip are always attached (bounded, read-mostly); the relay
                // service (key file, protocol handler, descriptor) only with --onion-relay.
                val passphrase = if (onionWireConfig.relayMode) onionKeyPassphrase() else null
                val onionWire =
                    try {
                        OnionWire.attach(
                            node,
                            identity,
                            onionWireConfig,
                            pubsub,
                            peerDirectory,
                            supervisor,
                            dataDirectory.resolve(ONION_KEY_FILE),
                            passphrase,
                            directoryMode =
                                if (options.anonymity == AnonymityMode.ON) {
                                    DirectoryAnonymityMode.ON
                                } else {
                                    DirectoryAnonymityMode.OFF
                                },
                            prekeys = prekeys,
                        )
                    } finally {
                        passphrase?.fill('\u0000')
                    }
                rollback += { runCatching { onionWire.close() } }

                var directoryDht: DirectoryDht? = null
                if (options.dhtFallback) {
                    val dht =
                        DirectoryDht.attach(
                            storage,
                            peerDirectory,
                            prekeys,
                            directoryDhtLimits,
                            onionDescriptorIndex = onionWire.descriptors,
                        )
                    directoryDht = dht
                    supervisor.launchPeriodic(
                        "dht-maintenance",
                        interval = maintenanceInterval,
                        jitter = (maintenanceInterval.inWholeMilliseconds / 6).milliseconds,
                        initialDelay = maintenanceInitialDelay,
                    ) {
                        runCatching { dht.refreshStale() }.onFailure { if (it is InterruptedException) throw it }
                        // find relays without gossip (rate-limited by the DHT limits)
                        runCatching { dht.discoverOnionRelays() }.onFailure { if (it is InterruptedException) throw it }
                    }
                }

                // The persisted publication mode: a start in normal mode retires an anonymous record of an earlier
                // anonymity run (revocation) and persists OFF; the sequence numbers of the own records come from it,
                // so that a later tombstone lies above everything ever published.
                val modeStore = FileDirectoryModeStore(dataDirectory.resolve(DIRECTORY_MODE_FILE))
                val transition = DirectoryModeTransition(identity, modeStore)
                val anonymous = options.anonymity == AnonymityMode.ON
                var sequenceSource: () -> Long = { System.currentTimeMillis() }
                if (!anonymous) {
                    val retired = DirectoryModeRetirement.onNormalStart(transition) { onionWire.announceRevocation(it) }
                    val mode = if (retired) DirectoryAnonymityMode.OFF else DirectoryAnonymityMode.ON
                    sequenceSource = { transition.nextSequence(mode) }
                }

                // The DHT value (one IPNS name per node) is written by this publisher only, so the relay descriptor
                // is handed to it rather than published separately - a second writer would overwrite the peer record.
                val publisher =
                    HeadlessSelfPublisher(
                        identity,
                        node::listenAddresses,
                        peerDirectory,
                        directoryDht,
                        directoryDhtLimits.minRepublishInterval.toKotlinDuration(),
                        descriptorProvider = onionWire::currentDescriptor,
                        // in anonymity mode this class publishes NOTHING itself (the AnonymityRuntime does it through circuits)
                        directoryMode = if (anonymous) DirectoryAnonymityMode.ON else DirectoryAnonymityMode.OFF,
                        sequenceSource = sequenceSource,
                    )
                publisher.tick(includeDht = false)
                supervisor.launchPeriodic(
                    "self-record-republisher",
                    interval = selfRecordCheckInterval,
                    jitter = (selfRecordCheckInterval.inWholeMilliseconds / 10).milliseconds,
                    initialDelay = selfRecordCheckInterval,
                ) { publisher.tick() }

                var madli: MadliGossip? = null
                var selector: RelayAutoSelector? = null
                var publishJob: NodeServiceSupervisor.PeriodicJob? = null
                val ownKey = identity.secp256k1KeyPair.publicKey
                var ranker: MadliRelayRanker? = null
                if (options.autoRelay || options.publishRelayReliability || anonymous) {
                    val gossip = MadliGossip.attach(pubsub, storage)
                    madli = gossip
                    supervisor.register("madli-gossip") { gossip.stop() }
                    if (options.autoRelay || anonymous) {
                        val weights = CachedVeritasObserverWeight.startSupervised(veritas, ownKey, supervisor)
                        ranker = MadliRelayRanker(gossip::currentVectorsForObservedPeer, weights::weightOf)
                    }
                    if (options.autoRelay) {
                        val started = node.startAutoRelay({ peerDirectory.relayCandidates() }, checkNotNull(ranker))
                        selector = started
                        supervisor.register("auto-relay") { started.stop() }
                    }
                    if (options.publishRelayReliability) {
                        val daily =
                            DailyRelayReliabilityPublication(
                                MadliRelayReliabilityPublisher(
                                    gossip,
                                    identity.secp256k1KeyPair,
                                    node::relayReliabilityCounts,
                                    enabled = true,
                                ),
                            )
                        publishJob =
                            supervisor.launchPeriodic(
                                "madli-relay-publisher",
                                interval = 6.hours,
                                jitter = 10.minutes,
                                initialDelay = 1.minutes,
                            ) { daily.runOnce() }
                    }
                }

                // Anonymity mode (wave V0.10.0-E): path selection with persistent guards, circuit policy and the
                // circuit-based directory publication. Nothing is published from this node itself (except the one
                // address-free tombstone of an OFF to ON switch).
                var anonymity: AnonymityRuntime? = null
                if (anonymous) {
                    val relayRanker = checkNotNull(ranker)
                    anonymity =
                        AnonymityRuntime.start(
                            onionWire,
                            identity,
                            dataDirectory,
                            RelayReputation { relayRanker.relayReliability(it) },
                            (anonymityLocator?.invoke(peerDirectory) as RelayNetworkLocator?)
                                ?: PeerDirectoryRelayNetworkLocator(peerDirectory),
                            modeStore,
                            prekeyStore = null,
                            serviceKey = Ed25519KeyPair.generate(),
                            tombstonePublisher = { tombstone ->
                                peerDirectory.announce(tombstone)
                                directoryDht?.publishTombstone(identity, tombstone)
                            },
                            supervisor = supervisor,
                            capabilities = emptySet(),
                            // the headless node has no calls: the call-media exposure text never applies
                            incompleteWarning = anonymityIncompleteWarning(false, options.anonymityPadding),
                            padding = TrafficPaddingConfig.of(options.anonymityPadding),
                        )
                    val started = anonymity
                    rollback += { started.close() }
                    supervisor.register("anonymity") { started.close() }
                }

                // Layers below the supervised parts, stopped in reverse attach order after them.
                val closers =
                    listOf<() -> Unit>(
                        { onionWire.close() },
                        { prekeys.stop() },
                        { peerDirectory.stop() },
                        { veritas.stop() },
                        { pubsub.stop() },
                        { storage.stop() },
                    )
                return HeadlessNode(
                    node,
                    options,
                    storage,
                    directoryDht,
                    onionWire,
                    madli,
                    selector,
                    publishJob,
                    supervisor,
                    closers,
                    anonymity,
                )
            } catch (e: Exception) {
                rollback.asReversed().forEach { runCatching(it) }
                throw e
            }
        }
    }
}

/**
 * Keeps the headless node's own [PeerRecord] current: gossip on start, on changed addresses (a private node learns its
 * `/p2p-circuit` addresses after the reservations) and every few hours; DHT publication (record only, no prekey bundle -
 * there is no DM here) on the same triggers, at most once per [minDhtAttemptInterval]. The capability set is empty.
 */
internal class HeadlessSelfPublisher(
    private val identity: DualKeyIdentity,
    private val addresses: () -> List<Multiaddr>,
    private val peerDirectory: PeerDirectoryGossip,
    private val directoryDht: DirectoryDht?,
    private val minDhtAttemptInterval: Duration,
    private val maxInterval: Duration = 6.hours,
    private val clockMillis: () -> Long = System::currentTimeMillis,
    private val descriptorProvider: () -> OnionRelayDescriptor? = { null },
    /**
     * Wave V0.10.0-D. [DirectoryAnonymityMode.OFF] (default everywhere until wave E) keeps this class unchanged.
     * With [DirectoryAnonymityMode.ON] it publishes nothing itself (no address-bearing record, no DHT value);
     * [anonymousTick] (the circuit-based publisher, wired in wave E) does the publishing instead.
     */
    private val directoryMode: DirectoryAnonymityMode = DirectoryAnonymityMode.OFF,
    private val anonymousTick: (() -> Unit)? = null,
    /**
     * Sequence number of the next address-bearing record. The default is the wall clock (the behaviour before wave
     * V0.10.0-E); the node wires the persisted [net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition] here so
     * that the OFF state is persisted and every later tombstone lies above all published sequence numbers.
     */
    private val sequenceSource: () -> Long = { clockMillis() },
) {
    private var dhtDescriptorSequence: Long? = null

    private var gossipAddresses: Set<String>? = null
    private var gossipAt: Long? = null
    private var dhtAddresses: Set<String>? = null
    private var dhtDoneAt: Long? = null
    private var dhtAttemptAt: Long? = null

    /** Number of DHT publication attempts made (observable for tests). */
    @Volatile var dhtAttempts: Int = 0
        private set

    /** Number of DHT publications acknowledged by at least one peer (observable for tests). */
    @Volatile var dhtPublications: Int = 0
        private set

    /** `true` if nothing happened yet ([since] `null`) or [window] has passed since [since]. */
    private fun elapsed(
        since: Long?,
        now: Long,
        window: Duration,
    ): Boolean = since == null || now - since >= window.inWholeMilliseconds

    @Synchronized
    fun tick(includeDht: Boolean = true) {
        if (directoryMode == DirectoryAnonymityMode.ON) {
            try {
                anonymousTick?.invoke()
            } catch (e: RuntimeException) {
                logger.debug { "anonymous directory tick failed: ${e.javaClass.simpleName}" }
            }
            return
        }
        val now = clockMillis()
        val current = addresses().map { it.toString() }.toSet()
        val descriptor = descriptorProvider()
        val gossipDue = gossipAddresses != current || elapsed(gossipAt, now, maxInterval)
        val dhtDue =
            includeDht &&
                directoryDht != null &&
                (
                    dhtAddresses != current ||
                        elapsed(dhtDoneAt, now, maxInterval) ||
                        descriptor?.sequenceNumber != dhtDescriptorSequence
                ) &&
                elapsed(dhtAttemptAt, now, minDhtAttemptInterval)
        if (!gossipDue && !dhtDue) return
        val nowSeconds = Instant.ofEpochMilli(now).epochSecond
        val record =
            PeerRecord.create(
                identity = identity,
                addresses = addresses(),
                capabilities = emptySet<PeerCapability>(),
                sequenceNumber = sequenceSource(),
                notValidAfterEpochSecond = nowSeconds + HEADLESS_RECORD_TTL_SECONDS,
                nowEpochSecond = nowSeconds,
            )
        if (gossipDue) {
            peerDirectory.announce(record)
            gossipAddresses = current
            gossipAt = now
        }
        if (dhtDue) {
            directoryDht.let { dht ->
                dhtAttemptAt = now
                dhtAttempts++
                try {
                    val result = dht.publishOwn(identity, record, null, onionRelayDescriptor = descriptor)
                    // no acknowledging DHT peer (e.g. empty routing table) = held locally only: retry later
                    if (!result.skippedByRateLimit && result.acknowledged > 0) {
                        dhtAddresses = current
                        dhtDescriptorSequence = descriptor?.sequenceNumber
                        dhtDoneAt = now
                        dhtPublications++
                    }
                } catch (e: Exception) {
                    logger.warn {
                        "publishing the own record to the DHT failed (${e.javaClass.simpleName}); will retry"
                    }
                }
            }
        }
    }
}
