package net.lapisphilosophorum.lapisnet.networking

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.dsl.host
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.mux.StreamMuxerProtocol
import io.libp2p.discovery.MDnsDiscovery
import io.libp2p.security.noise.NoiseXXSecureChannel
import io.libp2p.transport.tcp.TcpTransport
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.relay.LapisCircuitHopBinding
import net.lapisphilosophorum.lapisnet.networking.relay.LapisCircuitHopProtocol
import net.lapisphilosophorum.lapisnet.networking.relay.LapisCircuitStopBinding
import net.lapisphilosophorum.lapisnet.networking.relay.LapisCircuitStopProtocol
import net.lapisphilosophorum.lapisnet.networking.relay.LapisRelayTransport
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayReservationClient
import net.lapisphilosophorum.lapisnet.networking.relay.RelayReservationRegistry
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

private val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(10)
private val DEFAULT_LISTEN_ADDRESS = Multiaddr("/ip4/127.0.0.1/tcp/0")

/** Caps [LapisNode.discovered] so a noisy or malicious LAN (mDNS is trivially spoofable - any
 * device can announce arbitrary, freshly-generated PeerIds) can't grow it without bound. */
private const val MAX_DISCOVERED_PEERS = 256

/** Bounds how many simultaneously-OPEN [Connection]s (any transport, any remote [PeerId]) this
 * node's [Host] will hold at once, host-wide - follow-up hardening item 5 (2026-08-11).
 * Deliberately GLOBAL, not per-peer: `lapis-net-dm`'s own `MAX_CONCURRENT_STREAMS_PER_PEER`
 * (see [net.lapisphilosophorum.lapisnet.dm.DmProtocolHandler]) bounds concurrent STREAMS on ONE
 * connection from ONE [PeerId], but that [PeerId] itself is attacker-mintable at the cost of only
 * one Ed25519 keygen plus one TCP+Noise handshake - nothing in this module (before this fix)
 * bounded how many DISTINCT such connections this node would simultaneously hold open at all, so a
 * flood of freshly-minted identities, each opening one connection, could grow this node's
 * connection-held resources (file descriptors, per-connection Netty channel/pipeline state, muxer
 * session bookkeeping) without any host-level ceiling - the same class of gap [MAX_DISCOVERED_PEERS]
 * already closes for mDNS-announced (never-dialed) peer records, now closed here for actually-live
 * connections.
 *
 * **Registered via [Host.addConnectionHandler] - the SAME mechanism [GossipPubSub.attach] already
 * uses ([io.libp2p.pubsub.gossip.Gossip] itself implements [ConnectionHandler]).**
 * `HostImpl.addConnectionHandler` (verified by decompiling the resolved
 * `jvm-libp2p-1.3.5-RELEASE` jar) is a `ConnectionHandler$Broadcast` - a plain ordered list of
 * handlers, not a single overwritable slot - so this handler and `GossipPubSub`'s own coexist
 * without interference, mirroring how [GossipPubSub.attach]'s own doc comment already documents
 * that mechanism. Registered in [create] itself, BEFORE this node is ever [start]ed - unlike
 * [GossipPubSub.attach]'s documented "must be called before [connect]" precedent (which exists
 * because [io.libp2p.pubsub.gossip.Gossip] only observes connections made AFTER it attaches), this
 * handler registering at construction time, prior to [start], means it observes EVERY connection
 * this node ever makes or accepts over its whole lifetime, with no analogous "attached too late"
 * gap possible.
 *
 * **What this does and does not close.** [ConnectionHandler.handleConnection] fires only AFTER a
 * [Connection] is already fully established (TCP accept/dial plus a completed Noise handshake) -
 * exactly the same point [GossipPubSub]'s own [ConnectionHandler] observes connections at. This
 * bounds how many such ALREADY-AUTHENTICATED connections this node holds open SIMULTANEOUSLY (the
 * resource-accumulation half of the gap): once [MAX_CONCURRENT_CONNECTIONS] are live, any
 * additional connection is closed immediately upon being handed to this handler, freeing its
 * resources right away rather than letting it linger. It does NOT, and cannot from this layer,
 * reduce the PER-ATTEMPT cost of the TCP+Noise handshake itself (that cost is paid by the OS/Netty
 * transport layer before a [Connection] object exists at all to hand to any [ConnectionHandler]) -
 * bounding raw connection-ATTEMPT rate would need to live below jvm-libp2p's own transport/security
 * pipeline (e.g. an OS-level `SYN` backlog / accept-rate limit), out of this module's scope. A
 * generous, provisional magnitude - same "generous headroom, not derived from a protocol
 * requirement" framing as [MAX_DISCOVERED_PEERS] and `lapis-net-dm`'s own numeric caps - chosen well
 * above any legitimate small-mesh peer count this codebase currently targets, while still being a
 * genuine, finite ceiling rather than no bound at all. */
const val MAX_CONCURRENT_CONNECTIONS = 512

/** [ConnectionHandler] enforcing [MAX_CONCURRENT_CONNECTIONS] - see that constant's own doc comment
 * for the full reasoning. Tracks its own live count via a plain [AtomicInteger] rather than
 * re-reading [io.libp2p.core.Network.getConnections] on every call - correct either way, but a
 * self-maintained counter avoids depending on exactly when jvm-libp2p updates that list relative to
 * invoking this handler (unverified against the decompiled jar, and irrelevant to get right when a
 * simpler alternative exists). Incremented here in [handleConnection], decremented exactly once via
 * the [Connection]'s own [io.libp2p.core.P2PChannel.closeFuture] callback - never a manual
 * decrement anywhere else, so a connection this handler let through is always accounted for exactly
 * once regardless of which side (local or remote) eventually closes it. */
private class ConnectionCapHandler : ConnectionHandler {
    private val liveCount = AtomicInteger(0)

    override fun handleConnection(conn: Connection) {
        val countAfterThisConnection = liveCount.incrementAndGet()
        if (countAfterThisConnection > MAX_CONCURRENT_CONNECTIONS) {
            logger.warn {
                "closing connection from ${conn.secureSession().remoteId} - " +
                    "MAX_CONCURRENT_CONNECTIONS ($MAX_CONCURRENT_CONNECTIONS) exceeded"
            }
            // This connection was never actually admitted - undo the speculative increment above
            // immediately, rather than waiting on its own closeFuture (which the close() call below
            // triggers anyway, but relying on that ordering for bookkeeping correctness is needless
            // when a direct decrement here is exact and immediate).
            liveCount.decrementAndGet()
            conn.close()
            return
        }
        conn.closeFuture().whenComplete { _, _ -> liveCount.decrementAndGet() }
    }
}

/** Thrown when a node lifecycle or connection operation fails or times out. */
class LapisNodeException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * A Lapis Net P2P node: wraps a jvm-libp2p [Host] whose identity is derived from a
 * [DualKeyIdentity] (see [deriveLibp2pPeerId]), plus mDNS discovery of LAN peers.
 *
 * mDNS-discovered peers are only logged and added to [discoveredPeers] - never auto-dialed. This
 * mirrors jvm-libp2p's own [io.libp2p.core.Discoverer] design (discovery and connection are
 * separate concerns there too), and keeps discovery and connectivity independently testable.
 * Bootstrap peers are the opposite case: dialing them is the whole point of [start], so it does,
 * but non-blockingly and non-fatally - an unreachable placeholder bootstrap peer must never
 * block or fail node startup.
 *
 * [host] is exposed (read-only) so other modules that need to attach additional libp2p protocol
 * handlers to this same swarm - e.g. `lapis-net-storage`'s `NabuStorage.attach` - can do so
 * without this class growing a dependency on every protocol layered on top of it. Callers must
 * still go through [start]/[stop] for lifecycle, never call [Host.start]/[Host.stop] directly.
 */
class LapisNode private constructor(
    val host: Host,
    private val mdns: MDnsDiscovery,
    /**
     * Circuit-Relay-v2 NAT traversal for this node: obtain and hold reservations on other peers'
     * relays so peers that cannot dial this node directly can still reach it through one. Always
     * present, but entirely inert until a caller asks for a reservation - see
     * [net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig].
     */
    val relayClient: RelayReservationClient,
    /**
     * Handlers notified about **relayed inbound** connections. Such a connection is accepted by the
     * circuit-relay stop protocol, not by a listening transport, so it never travels through
     * `io.libp2p.network.NetworkImpl`'s own connection-handler broadcast the way every direct
     * connection does - a handler registered only via [Host.addConnectionHandler] would silently
     * never see it. [addConnectionHandler] registers on both paths; each connection only ever
     * traverses one of them, so a handler is invoked exactly once per connection either way.
     */
    private val relayInboundHandlers: ConnectionHandler.Broadcast,
) {
    private val discovered = BoundedPeerCache(MAX_DISCOVERED_PEERS)
    private val stopped = AtomicBoolean(false)

    /**
     * Set by `GossipPubSub.attach()` once GossipSub has been wired up on this node - a same-module
     * signal purely between [connect] and `GossipPubSub.attach()`, not part of this class's public
     * lifecycle API (round-2 N1 defensive check; see `GossipPubSub.attach`'s doc comment for the
     * full precondition this supports and the doc comment on [connectsBeforeGossipAttach] for how
     * the two are used together).
     */
    internal var gossipAttached: Boolean = false

    /**
     * Count of [connect] calls made while [gossipAttached] was still `false` - i.e. connections
     * GossipSub can never see, regardless of whether `GossipPubSub.attach()` is called later
     * (`Gossip` only observes connection-established events for connections made *after* it
     * registers as a [io.libp2p.core.ConnectionHandler]). `GossipPubSub.attach()` reads this once,
     * right after wiring up, to decide whether its documented "must be called before connect()"
     * precondition was actually violated - see its doc comment for why the check lives there
     * rather than here: at the moment [connect] runs, there is no way to know whether
     * `GossipPubSub.attach()` will ever be called at all, and a node that legitimately never wants
     * GossipSub must be free to call [connect] without triggering a warning.
     */
    internal val connectsBeforeGossipAttach = AtomicInteger(0)

    val peerId: PeerId get() = host.peerId

    /**
     * Every address this node currently claims to be reachable at, direct **and** relayed. Once
     * [relayClient] holds a reservation, this list additionally contains one
     * `<relay>/p2p-circuit/p2p/<this node>` entry per relay address - the address a peer behind
     * NAT publishes so others can dial it. See [directListenAddresses] for the direct-only subset.
     */
    fun listenAddresses(): List<Multiaddr> = host.listenAddresses()

    /** [listenAddresses] minus every relayed (`/p2p-circuit`) entry. */
    fun directListenAddresses(): List<Multiaddr> = host.listenAddresses().filterNot { it.has(Protocol.P2PCIRCUIT) }

    /**
     * Registers [handler] for **every** connection this node makes or accepts, direct or relayed -
     * see [relayInboundHandlers] for why `host.addConnectionHandler` alone is not equivalent. Any
     * protocol that reacts to connection-established events (GossipSub above all) must register
     * here rather than on [host] directly, or it will simply not exist as far as a peer reachable
     * only through a relay is concerned.
     */
    fun addConnectionHandler(handler: ConnectionHandler) {
        host.addConnectionHandler(handler)
        relayInboundHandlers += handler
    }

    /** Peers discovered via mDNS so far. Never auto-dialed - see the class doc. */
    fun discoveredPeers(): List<PeerInfo> = discovered.values()

    /** Explicitly dial a peer (bootstrap or mDNS-discovered). */
    fun connect(
        peer: PeerInfo,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Connection {
        if (!gossipAttached) connectsBeforeGossipAttach.incrementAndGet()
        return awaitOrWrap("connect to ${peer.peerId}", timeout) {
            host.network.connect(peer.peerId, *peer.addresses.toTypedArray())
        }
    }

    fun start(
        bootstrapPeers: List<Multiaddr> = emptyList(),
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        awaitOrWrap("start host", timeout) { host.start() }
        awaitOrWrap("start mDNS discovery", timeout) { mdns.start() }
        bootstrapPeers.forEach { address ->
            host.network
                .connect(address)
                .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS)
                .whenComplete { _, error ->
                    if (error != null) {
                        logger.warn { "bootstrap dial to $address failed: ${error.message}" }
                    } else {
                        logger.info { "connected to bootstrap peer $address" }
                    }
                }
        }
    }

    /**
     * Stops mDNS discovery and the host independently - a failure stopping one (e.g. mDNS was
     * never successfully started) must never prevent the other's shutdown from being attempted,
     * or the Netty-backed host (bound socket, event-loop threads) could leak. Idempotent: a
     * second or later call is a no-op, so callers (e.g. a `try { start() } finally { stop() }`
     * block after `start()` itself already failed) never have to guard against a confusing
     * "already stopped" exception. If both sub-shutdowns fail on the one call that actually
     * performs them, the host's failure is thrown (mDNS's is logged) since a leaked listening
     * socket is the more severe outcome; if only one fails, that failure is thrown.
     */
    fun stop(timeout: Duration = DEFAULT_TIMEOUT) {
        if (!stopped.compareAndSet(false, true)) return
        // Stop renewing relay reservations before anything else: the renewal task dials, and a
        // dial racing a host shutdown is pure noise. Never fatal - a failure here must not stop the
        // host's own shutdown, same reasoning as the mDNS/host split below.
        runCatching { relayClient.stop() }
            .onFailure { logger.warn(it) { "failed to stop relay reservation renewal cleanly" } }
        val mdnsFailure = runCatching { awaitOrWrap("stop mDNS discovery", timeout) { mdns.stop() } }.exceptionOrNull()
        if (mdnsFailure != null) {
            logger.warn(mdnsFailure) { "failed to stop mDNS discovery cleanly, stopping host anyway" }
        }
        val hostFailure = runCatching { awaitOrWrap("stop host", timeout) { host.stop() } }.exceptionOrNull()
        if (hostFailure != null) throw hostFailure
        if (mdnsFailure != null) throw mdnsFailure
    }

    private fun <T> awaitOrWrap(
        action: String,
        timeout: Duration,
        block: () -> CompletableFuture<T>,
    ): T =
        try {
            block().get(timeout.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw LapisNodeException("timed out waiting to $action", e)
        } catch (e: ExecutionException) {
            throw LapisNodeException("failed to $action", e.cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw LapisNodeException("interrupted while waiting to $action", e)
        }

    companion object {
        /**
         * Builds an unstarted node.
         *
         * [relayConfig] controls Circuit-Relay-v2 NAT traversal. The default
         * ([RelayConfig.CLIENT_ONLY]) makes this node able to *use* relays - it can dial
         * `/p2p-circuit` addresses and can ask for a reservation via [relayClient] - while never
         * acting as a relay for anyone else. Carrying strangers' traffic requires
         * [RelayConfig.relayServer] explicitly; see that class's doc comment for why the split
         * matters.
         */
        fun create(
            identity: DualKeyIdentity,
            listenAddress: Multiaddr = DEFAULT_LISTEN_ADDRESS,
            relayConfig: RelayConfig = RelayConfig.CLIENT_ONLY,
        ): LapisNode {
            val privKey = identity.deriveLibp2pPrivKey()
            val connectionCap = ConnectionCapHandler()
            // Relayed inbound connections never pass through NetworkImpl's own connection handler
            // (they are accepted by the stop protocol, not by a listening transport), so the
            // connection cap has to be reachable from there too. The SAME handler instance is used
            // on both paths, and each connection only ever traverses one of them, so a connection
            // is counted exactly once either way.
            val relayInboundHandlers = ConnectionHandler.createBroadcast(listOf(connectionCap))

            val registry = RelayReservationRegistry(relayConfig.serverLimits)
            val stopProtocol = LapisCircuitStopProtocol(relayConfig.clientLimits)
            val stopBinding = LapisCircuitStopBinding(stopProtocol)
            val hopProtocol = LapisCircuitHopProtocol(relayConfig, registry, stopBinding) { Instant.now() }
            val hopBinding = LapisCircuitHopBinding(hopProtocol)
            lateinit var relayTransport: LapisRelayTransport

            val builtHost =
                host {
                    identity {
                        factory = { privKey }
                    }
                    transports {
                        add(::TcpTransport)
                        add { upgrader ->
                            LapisRelayTransport(upgrader, hopBinding, relayConfig.clientLimits)
                                .also { relayTransport = it }
                        }
                    }
                    secureChannels {
                        add(::NoiseXXSecureChannel)
                    }
                    muxers {
                        add(StreamMuxerProtocol.Mplex)
                    }
                    protocols {
                        add(hopBinding)
                        add(stopBinding)
                    }
                    network {
                        listen(listenAddress.toString())
                    }
                }
            hopProtocol.setHost(builtHost)
            relayTransport.setHost(builtHost)
            stopProtocol.onCircuitAccepted = { stream, initiator ->
                relayTransport.acceptCircuit(stream, initiator, relayInboundHandlers)
            }
            val relayClient = RelayReservationClient(builtHost, hopBinding, relayConfig.clientLimits)
            relayTransport.circuitAddresses = relayClient::circuitAddresses
            stopProtocol.holdsReservationWith = relayClient::holdsReservationWith
            // Registered BEFORE start() - see MAX_CONCURRENT_CONNECTIONS's own doc comment for why
            // that ordering matters here (no "attached too late" gap, unlike GossipPubSub.attach's
            // documented must-be-before-connect() precondition).
            builtHost.addConnectionHandler(connectionCap)
            val mdns = MDnsDiscovery(builtHost)
            val node = LapisNode(builtHost, mdns, relayClient, relayInboundHandlers)
            mdns.addHandler { peerInfo ->
                if (node.discovered.record(peerInfo)) {
                    logger.info { "mDNS discovered peer ${peerInfo.peerId}" }
                } else {
                    logger.warn { "discovered-peer cache full ($MAX_DISCOVERED_PEERS) - dropping ${peerInfo.peerId}" }
                }
            }
            return node
        }
    }
}
