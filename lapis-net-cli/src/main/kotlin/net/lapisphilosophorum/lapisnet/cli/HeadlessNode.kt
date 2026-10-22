package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.resolveKeystorePassphrase
import net.lapisphilosophorum.lapisnet.madli.CachedVeritasObserverWeight
import net.lapisphilosophorum.lapisnet.madli.DailyRelayReliabilityPublication
import net.lapisphilosophorum.lapisnet.madli.MadliGossip
import net.lapisphilosophorum.lapisnet.madli.MadliRelayRanker
import net.lapisphilosophorum.lapisnet.madli.MadliRelayReliabilityPublisher
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayAutoSelector
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.onionwire.OnionWire
import net.lapisphilosophorum.lapisnet.onionwire.OnionWireConfig
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
) {
    private val stopped = AtomicBoolean(false)

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
                if (options.autoRelay || options.publishRelayReliability) {
                    val gossip = MadliGossip.attach(pubsub, storage)
                    madli = gossip
                    supervisor.register("madli-gossip") { gossip.stop() }
                    if (options.autoRelay) {
                        val weights = CachedVeritasObserverWeight.startSupervised(veritas, ownKey, supervisor)
                        val ranker = MadliRelayRanker(gossip::currentVectorsForObservedPeer, weights::weightOf)
                        val started = node.startAutoRelay({ peerDirectory.relayCandidates() }, ranker)
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
                sequenceNumber = now,
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
