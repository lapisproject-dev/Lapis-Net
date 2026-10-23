package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousDirectory
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordGossip
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorGossip
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorGossip
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientConfig
import java.nio.file.Path
import java.time.Clock
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Facade of the onion wire integration for a node (what the CLI calls). Always attaches the descriptor index and its gossip
 * (read-mostly, bounded, so a node can later pick relays) and the link manager (outbound diagnostic links only); only with
 * `config.relayMode` does it start an [OnionRelayService]: key file, protocol handler on the host, descriptor publication.
 * Relay mode off means no handler is registered (a peer dialing `/lapis/onion/1.0.0` fails multistream negotiation), no
 * onion key is created and no descriptor is announced. Nothing here anonymises traffic.
 */
class OnionWire private constructor(
    val descriptors: OnionRelayDescriptorIndex,
    private val descriptorGossip: OnionRelayDescriptorGossip,
    private val links: OnionLinkManager,
    private val peerDirectory: PeerDirectoryGossip,
    private val clock: Clock,
    val relayService: OnionRelayService?,
    /** Verified onion service descriptors received through gossip (read-mostly, bounded). */
    val serviceDescriptors: OnionServiceDescriptorIndex,
    private val serviceGossip: OnionServiceDescriptorGossip,
    /** Attached on EVERY node (wave V0.10.0-D), so that senders can resolve anonymous recipients. */
    private val anonymousGossip: AnonymousPeerRecordGossip,
    /** The publication mode of the directory entries of THIS node; [DirectoryAnonymityMode.OFF] unless wave E wires it. */
    val directoryMode: DirectoryAnonymityMode,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val hidden = CopyOnWriteArrayList<AutoCloseable>()
    private val factoryHolder = lazy { OnionCircuitFactory(links, peerDirectory, clock) }
    private val factory: OnionCircuitFactory get() = factoryHolder.value

    /** The relay descriptor to publish into the DHT value, or `null` when not a relay / not yet announced. */
    fun currentDescriptor(): OnionRelayDescriptor? = relayService?.currentDescriptor()

    fun linkCount(): Int = links.linkCount()

    internal fun linksForTest(): OnionLinkManager = links

    @ExperimentalOnionApi
    fun diagnosticClient(): OnionCircuitClient = OnionCircuitClient(links, peerDirectory, clock)

    /**
     * Hosts an onion service with [serviceKey] (receiver side, wave V0.10.0-C). By default (`publication == null`) the
     * descriptor is announced through gossip from THIS node, so its gossip neighbours see this node's IP together
     * with the onion address. With a [publication] channel that does not expose the origin (wave V0.10.0-D, see
     * [experimentalDirectoryPublisher]) a relay publishes it instead. In [DirectoryAnonymityMode.ON] such a channel is
     * mandatory (fail closed). Experimental infrastructure, not anonymity. Closed with this facade.
     */
    @ExperimentalOnionApi
    fun experimentalServiceHost(
        serviceKey: Ed25519KeyPair,
        config: OnionServiceConfig,
        paths: OnionPathProvider,
        publication: DirectoryPublicationChannel? = null,
    ): OnionServiceHost {
        check(!closed.get()) { "closed" }
        require(directoryMode == DirectoryAnonymityMode.OFF || (publication != null && !publication.exposesOrigin)) {
            "anonymity mode requires a publication channel that does not expose the origin"
        }
        val publisher: (OnionServiceDescriptor) -> Unit =
            if (publication == null) {
                { serviceGossip.announce(it) }
            } else {
                { d ->
                    // never blocks: this callback runs under the host's session lock. A failed publication is retried
                    // with the host's next descriptor (republication on every change and before expiry).
                    publication.publishServiceDescriptor(d).whenComplete { ok, error ->
                        if (error != null || ok != true) logger.debug { "service descriptor publication failed" }
                    }
                }
            }
        val host =
            OnionServiceHost(
                serviceKey,
                config,
                factory,
                links,
                descriptors,
                paths,
                publisher,
                clock,
            )
        hidden += host
        host.onClosed = { hidden.remove(host) }
        return host
    }

    /** Connects to onion services (sender side). Experimental infrastructure, not anonymity. Closed with this facade. */
    @ExperimentalOnionApi
    fun experimentalRendezvousClient(config: RendezvousClientConfig = RendezvousClientConfig()): OnionRendezvousClient {
        check(!closed.get()) { "closed" }
        val client = OnionRendezvousClient(factory, links, descriptors, serviceDescriptors, null, config, clock)
        hidden += client
        client.onClosed = { hidden.remove(client) }
        return client
    }

    /**
     * Publishes directory objects through circuits (wave V0.10.0-D). [publishRelays] defaults to every relay descriptor
     * currently in the local index; [paths] decides the path (no selection in this wave). Closed with this facade.
     */
    @ExperimentalOnionApi
    fun experimentalDirectoryPublisher(
        paths: OnionPathProvider,
        publishRelays: () -> List<OnionRelayDescriptor> = { descriptors.snapshot(clock.millis() / 1000) },
    ): OnionDirectoryPublisher = directoryPublisher(paths, publishRelays)

    /** Test seam: like [experimentalDirectoryPublisher] with the timeout and attempt limit adjustable. */
    @ExperimentalOnionApi
    internal fun directoryPublisher(
        paths: OnionPathProvider,
        publishRelays: () -> List<OnionRelayDescriptor> = { descriptors.snapshot(clock.millis() / 1000) },
        ackTimeout: Duration = 15.seconds,
        maxAttempts: Int = 3,
    ): OnionDirectoryPublisher {
        check(!closed.get()) { "closed" }
        val publisher =
            OnionDirectoryPublisher(
                factory,
                paths,
                publishRelays,
                ackTimeout = ackTimeout,
                maxAttempts = maxAttempts,
                clock = clock,
            )
        hidden += publisher
        publisher.onClosed = { hidden.remove(publisher) }
        return publisher
    }

    /** Resolution over the mixed directory (anonymous and address-bearing entries); no caller is wired to it yet. */
    fun anonymousDirectory(): AnonymousDirectory =
        AnonymousDirectory(peerDirectory, serviceDescriptors, null) { clock.instant() }

    /** Circuits currently open through the hidden-service factory (leak checks). */
    internal fun hiddenServiceRoutes(): Int = factory.openRoutes()

    /** Hosts and clients still referenced by this facade (leak checks). */
    internal fun hiddenCount(): Int = hidden.size

    /** Idempotent. Order: hosts and clients, relay service, descriptor gossip, link manager. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        hidden.forEach { runCatching { it.close() } }
        if (factoryHolder.isInitialized()) runCatching { factory.close() }
        runCatching { relayService?.close() }
        runCatching { serviceGossip.stop() }
        runCatching { anonymousGossip.stop() }
        runCatching { descriptorGossip.stop() }
        runCatching { links.close() }
    }

    companion object {
        fun attach(
            node: LapisNode,
            identity: DualKeyIdentity,
            config: OnionWireConfig,
            pubsub: GossipPubSub,
            peerDirectory: PeerDirectoryGossip,
            supervisor: NodeServiceSupervisor,
            keyFile: Path,
            keystorePassphrase: CharArray?,
            clock: Clock = Clock.systemUTC(),
            directoryMode: DirectoryAnonymityMode = DirectoryAnonymityMode.OFF,
            directorySinkOverride: DirectoryPublishSink? = null,
            prekeys: PrekeyBundleGossip? = null,
        ): OnionWire {
            // A relay descriptor binds identity, peer ID and dialability publicly: a node can not be both (wave V0.10.0-D).
            require(!(directoryMode == DirectoryAnonymityMode.ON && config.relayMode)) {
                "onion relay mode and anonymity mode exclude each other"
            }
            val index = OnionRelayDescriptorIndex()
            val gossip = OnionRelayDescriptorGossip.attach(pubsub, index, clock)
            val serviceIndex = OnionServiceDescriptorIndex()
            val serviceGossip = OnionServiceDescriptorGossip.attach(pubsub, serviceIndex, clock)
            val anonymousGossip = AnonymousPeerRecordGossip.attach(pubsub, peerDirectory.anonymousRecords, clock)
            val links = OnionLinkManager(config, node, clock)
            var service: OnionRelayService? = null
            try {
                if (config.relayMode) {
                    val store = OnionKeyStore(keyFile, identity, keystorePassphrase, clock)
                    service =
                        OnionRelayService.attach(
                            node,
                            identity,
                            config,
                            store,
                            index,
                            gossip,
                            peerDirectory,
                            supervisor,
                            links,
                            directorySink =
                                directorySinkOverride
                                    ?: GossipDirectoryPublishSink(
                                        anonymousGossip,
                                        serviceGossip,
                                        serviceIndex,
                                        pubsub,
                                        clock,
                                        prekeys,
                                    ),
                            clock = clock,
                        )
                } else {
                    logger.info { "onion relay mode off" }
                }
                return OnionWire(
                    index,
                    gossip,
                    links,
                    peerDirectory,
                    clock,
                    service,
                    serviceIndex,
                    serviceGossip,
                    anonymousGossip,
                    directoryMode,
                )
            } catch (e: Exception) {
                runCatching { service?.close() }
                runCatching { anonymousGossip.stop() }
                runCatching { serviceGossip.stop() }
                runCatching { gossip.stop() }
                runCatching { links.close() }
                throw e
            }
        }
    }
}
