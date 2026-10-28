@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion

import io.libp2p.core.ConnectionHandler
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeRetirement
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.onionwire.OnionWire
import net.lapisphilosophorum.lapisnet.onionwire.OnionWireConfig
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.NetworkBucket
import net.lapisphilosophorum.lapisnet.onionwire.path.RelayNetworkLocator
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds

fun awaitCondition(
    timeout: Duration = Duration.ofSeconds(20),
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(50)
    }
    return condition()
}

fun fastConfig(relay: Boolean): OnionWireConfig =
    OnionWireConfig(
        relayMode = relay,
        descriptorInitialRepublishDelay = 1.seconds,
        descriptorRepublishInterval = 3.seconds,
        linkHandshakeTimeout = 2.seconds,
        extendTimeout = 5.seconds,
    )

/** Synthetic, distinct /16 networks per relay: every relay is on loopback, which the real locator can not tell apart. */
class SyntheticLocator : RelayNetworkLocator {
    private val map = ConcurrentHashMap<Secp256k1PublicKey, Set<NetworkBucket>>()

    fun put(
        identity: Secp256k1PublicKey,
        a: Int,
        b: Int,
    ) {
        map[identity] = setOf(NetworkBucket.V4((a shl 8) or b))
    }

    override fun bucketsOf(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): Set<NetworkBucket> = map[identity] ?: setOf(NetworkBucket.Unknown)
}

/** A relay: a normal node with the onion relay stack. */
class RelayHost : AutoCloseable {
    val identity: DualKeyIdentity = DualKeyIdentity.generate()
    val dir: Path = Files.createTempDirectory("dm-onion-relay")
    val node: LapisNode = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
    val storage: NabuStorage = NabuStorage.attach(node, dir.resolve("storage").also { Files.createDirectories(it) })
    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val peerDirectory: PeerDirectoryGossip = PeerDirectoryGossip.attach(pubsub, storage)
    val supervisor = NodeServiceSupervisor("dm-onion-relay")
    val wire: OnionWire =
        OnionWire.attach(
            node,
            identity,
            fastConfig(true),
            pubsub,
            peerDirectory,
            supervisor,
            dir.resolve("relay.onionkeys"),
            null,
        )
    val key: Secp256k1PublicKey get() = identity.secp256k1KeyPair.publicKey

    fun connectTo(other: RelayHost) {
        node.connect(PeerInfo(other.node.peerId, other.node.listenAddresses()))
    }

    override fun close() {
        runCatching { supervisor.stopAll() }
        runCatching { wire.close() }
        runCatching { peerDirectory.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

/** Records the plaintext chunks a DM sender hands to rendezvous streams and the sealed items it hands to circuits. */
class RecordingPort(
    private val delegate: OnionDmRuntimePort,
) : OnionDmRuntimePort by delegate {
    val frames = CopyOnWriteArrayList<ByteArray>()
    val items = CopyOnWriteArrayList<ByteArray>()
    val connectFailures = CopyOnWriteArrayList<String>()

    override fun connect(
        descriptor: net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel> =
        delegate
            .connect(descriptor, timeout)
            .whenComplete { _, e ->
                if (e != null) {
                    val root = generateSequence<Throwable>(e) { it.cause }.toList()
                    connectFailures += root.joinToString(" <- ") { "${it.javaClass.simpleName}:${it.message}" }
                }
            }.thenApply { inner ->
                object : FrameChannel by inner {
                    override fun send(data: ByteArray): Boolean {
                        frames += data.copyOf()
                        return inner.send(data)
                    }
                }
            }

    override fun publishMailboxItems(items: List<ByteArray>): CompletableFuture<Boolean> {
        this.items += items.map { it.copyOf() }
        return delegate.publishMailboxItems(items)
    }
}

/** A node in anonymity mode with the full DM-over-circuits stack. [start] and [stop] can be repeated (a restart). */
class DmOnionNode(
    val relays: List<RelayHost>,
    private val locator: RelayNetworkLocator,
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    val dir: Path = Files.createTempDirectory("dm-onion-node"),
    private val redeliveryIntervalMillis: Long = 3_000L,
    /** The capabilities the node advertises (F2 adds MAIL). */
    private val capabilities: Set<net.lapisphilosophorum.lapisnet.directory.AnonymousCapability> =
        setOf(net.lapisphilosophorum.lapisnet.directory.AnonymousCapability.DM),
    /** V0.10.0-H: padding of this node's anonymity runtime. */
    private val padding: net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig =
        net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig.STANDARD,
) {
    val key: Secp256k1PublicKey get() = identity.secp256k1KeyPair.publicKey
    var serviceKey: Ed25519KeyPair = Ed25519KeyPair.generate()
        private set

    /** Wave I: `true` makes every [start] generate a NEW service key, i.e. a new onion address (as a real restart does). */
    var freshServiceKeyPerStart: Boolean = false
    val prekeys: PrekeyStore = PrekeyStore.create(dir.resolve("prekeys"), identity, oneTimePrekeyCount = 30)
    private val modeStore =
        InMemoryDirectoryModeStore(
            DirectoryModeState(
                DirectoryAnonymityMode.OFF,
                System.currentTimeMillis() - 5000,
            ),
        )
    val connectedPeers: MutableSet<PeerId> = ConcurrentHashMap.newKeySet()
    val publishedTopics = CopyOnWriteArrayList<String>()

    lateinit var node: LapisNode
    lateinit var storage: NabuStorage
    lateinit var pubsub: GossipPubSub
    lateinit var peerDirectory: PeerDirectoryGossip
    lateinit var bundleGossip: PrekeyBundleGossip
    lateinit var supervisor: NodeServiceSupervisor
    lateinit var wire: OnionWire
    lateinit var runtime: AnonymityRuntime
    lateinit var dm: DmSessionManager
    lateinit var port: RecordingPort
    lateinit var redelivery: AnonymousMailboxRedelivery
    lateinit var transport: OnionDmTransport
    lateinit var handler: OnionDmInboundHandler
    lateinit var subscriber: AnonymousMailboxSubscriber
    val sessionDir: Path = dir.resolve("sessions")
    var running = false

    fun start() {
        if (freshServiceKeyPerStart) serviceKey = Ed25519KeyPair.generate()
        node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
        node.addConnectionHandler(
            ConnectionHandler { conn -> connectedPeers += conn.secureSession().remoteId },
        )
        storage = NabuStorage.attach(node, dir.resolve("storage").also { Files.createDirectories(it) })
        pubsub = GossipPubSub.attach(node)
        pubsub.outboundTap = { topic, _ -> publishedTopics += topic }
        peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
        bundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
        supervisor = NodeServiceSupervisor("dm-onion-node")
        wire =
            OnionWire.attach(
                node,
                identity,
                fastConfig(false),
                pubsub,
                peerDirectory,
                supervisor,
                dir.resolve("relay.onionkeys"),
                null,
                Clock.systemUTC(),
                DirectoryAnonymityMode.ON,
                null,
                bundleGossip,
            )
        relays.forEach { node.connect(PeerInfo(it.node.peerId, it.node.listenAddresses())) }
        val descriptors = relays.map { it.wire.currentDescriptor()!! }
        check(
            awaitCondition(Duration.ofSeconds(90)) {
                descriptors.all { wire.descriptors.current(it.identity, Clock.systemUTC().millis() / 1000) != null }
            },
        ) { "relay descriptors did not converge" }
        dm =
            DmSessionManager.attach(
                identity,
                prekeys,
                node,
                peerDirectory,
                bundleGossip,
                null,
                storage,
                pubsub,
                sessionDir,
                "correct horse battery staple".toCharArray(),
                anonymous = true,
            )
        runtime =
            AnonymityRuntime.start(
                wire,
                identity,
                dir,
                { null },
                locator,
                modeStore,
                prekeys,
                serviceKey,
                { t -> peerDirectory.announce(t) },
                supervisor,
                governor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
                capabilities = capabilities,
                padding = padding,
            )
        port = RecordingPort(AnonymityRuntimePort(runtime))
        redelivery =
            AnonymousMailboxRedelivery(
                port,
                intervalMillis = redeliveryIntervalMillis,
                jitterMillis = 0,
                retryMillis = 1_500,
                tickMillis = 200,
            )
        transport = OnionDmTransport(port, { bundleGossip.lookup(it)?.takeIf { b -> b.identity == it } }, redelivery)
        dm.installAnonymousTransport(transport)
        handler = OnionDmInboundHandler(dm.inboundSink())
        runtime.serviceRouter().register(OnionServiceApp.DM, handler::handle)
        subscriber = AnonymousMailboxSubscriber.attach(checkNotNull(runtime.mailboxGossip()), dm.inboundSink())
        onStarted(this)
        running = true
    }

    var normalRunning = false
        private set

    /**
     * Wave I: starts this identity in NORMAL mode (anonymity mode OFF) on the same data directory and mode store, the
     * way a restart without `--anonymity` does it: the anonymous record of the earlier run is retired by a revocation,
     * then an address-bearing peer record is announced. No DM stack and no anonymity runtime. Call [stopNormalMode]
     * before the next [start].
     */
    fun startNormalMode() {
        check(!running && !normalRunning) { "already running" }
        node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
        storage = NabuStorage.attach(node, dir.resolve("storage").also { Files.createDirectories(it) })
        pubsub = GossipPubSub.attach(node)
        peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
        bundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
        supervisor = NodeServiceSupervisor("dm-onion-node-normal")
        wire =
            OnionWire.attach(
                node,
                identity,
                fastConfig(false),
                pubsub,
                peerDirectory,
                supervisor,
                dir.resolve("relay.onionkeys"),
                null,
                Clock.systemUTC(),
                DirectoryAnonymityMode.OFF,
                null,
                bundleGossip,
            )
        relays.forEach { node.connect(PeerInfo(it.node.peerId, it.node.listenAddresses())) }
        val descriptors = relays.map { it.wire.currentDescriptor()!! }
        check(
            awaitCondition(Duration.ofSeconds(90)) {
                descriptors.all { wire.descriptors.current(it.identity, Clock.systemUTC().millis() / 1000) != null }
            },
        ) { "relay descriptors did not converge" }
        val transition = DirectoryModeTransition(identity, modeStore)
        check(DirectoryModeRetirement.onNormalStart(transition) { wire.announceRevocation(it) }) {
            "the revocation could not be sent"
        }
        peerDirectory.announce(
            PeerRecord.create(
                identity,
                node.listenAddresses(),
                setOf(PeerCapability.DM),
                transition.nextSequence(DirectoryAnonymityMode.OFF),
                Clock.systemUTC().millis() / 1000 + 600,
            ),
        )
        normalRunning = true
    }

    fun stopNormalMode() {
        if (!normalRunning) return
        normalRunning = false
        runCatching { supervisor.stopAll() }
        runCatching { wire.close() }
        runCatching { peerDirectory.stop() }
        runCatching { bundleGossip.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }

    /** Hooks for rigs that add services on top of the DM stack (after the DM stack is up / before it is stopped). */
    var onStarted: (DmOnionNode) -> Unit = {}
    var onStopping: (DmOnionNode) -> Unit = {}

    /** Ticks the maintenance until the node published its presence and the service host is up. */
    fun awaitPublished(timeout: Duration = Duration.ofSeconds(200)): Boolean =
        awaitCondition(timeout) {
            runtime.maintainNow()
            runtime.publications() >= 1 && runtime.ready()
        }

    fun stop() {
        if (!running) return
        running = false
        runCatching { onStopping(this) }
        runCatching { transport.close() }
        runCatching { subscriber.close() }
        runCatching { handler.close() }
        runCatching { runtime.close() }
        runCatching { dm.stop() }
        runCatching { supervisor.stopAll() }
        runCatching { wire.close() }
        runCatching { peerDirectory.stop() }
        runCatching { bundleGossip.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

/** Wave I: whether [viewer] resolves this node as hidden behind exactly the onion service [serviceKey]. */
fun DmOnionNode.isSeenBehindService(
    viewer: DmOnionNode,
    serviceKey: Ed25519PublicKey,
): Boolean =
    (viewer.runtime.resolveIdentity(key) as? DirectoryReachability.Hidden)?.descriptor?.serviceKey == serviceKey
