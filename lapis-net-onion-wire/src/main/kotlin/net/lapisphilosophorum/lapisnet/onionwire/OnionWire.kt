package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorGossip
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.nio.file.Path
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean

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
) : AutoCloseable {
    private val closed = AtomicBoolean(false)

    /** The relay descriptor to publish into the DHT value, or `null` when not a relay / not yet announced. */
    fun currentDescriptor(): OnionRelayDescriptor? = relayService?.currentDescriptor()

    fun linkCount(): Int = links.linkCount()

    internal fun linksForTest(): OnionLinkManager = links

    @ExperimentalOnionApi
    fun diagnosticClient(): OnionCircuitClient = OnionCircuitClient(links, peerDirectory, clock)

    /** Idempotent. Order: relay service, descriptor gossip, link manager. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { relayService?.close() }
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
        ): OnionWire {
            val index = OnionRelayDescriptorIndex()
            val gossip = OnionRelayDescriptorGossip.attach(pubsub, index, clock)
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
                            clock = clock,
                        )
                } else {
                    logger.info { "onion relay mode off" }
                }
                return OnionWire(index, gossip, links, peerDirectory, clock, service)
            } catch (e: Exception) {
                runCatching { service?.close() }
                runCatching { gossip.stop() }
                runCatching { links.close() }
                throw e
            }
        }
    }
}
