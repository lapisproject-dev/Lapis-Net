package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.protocol.IdentifyController
import net.lapisphilosophorum.lapisnet.networking.relay.LapisRelayTransport
import net.lapisphilosophorum.lapisnet.networking.relay.relayControlExecutor
import net.lapisphilosophorum.lapisnet.networking.transport.PunchRoleRegistry
import net.lapisphilosophorum.lapisnet.networking.transport.ReusePortTcpTransport
import java.net.InetAddress
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

private val logger = KotlinLogging.logger {}

private const val IDENTIFY_PROTOCOL_ID = "/ipfs/id/1.0.0"

/**
 * Asks relays which address they see this node at (libp2p Identify). **Only ever asks relays this node
 * holds a reservation with** - the one party that is already trusted with seeing this node's address.
 * The answer is filtered by [HolePunchAddressFilter] before it is stored.
 */
internal class IdentifyObserver(
    private val host: Host,
    private val book: ObservedAddressBook,
    private val reservedRelays: () -> Collection<PeerId>,
    private val isRelayed: (Connection) -> Boolean,
    private val timeout: Duration,
) {
    fun observe(relay: PeerId): CompletableFuture<Unit> {
        val connection =
            host.network.connections
                .firstOrNull { it.secureSession().remoteId == relay && !it.closeFuture().isDone && !isRelayed(it) }
                ?: return CompletableFuture.completedFuture(Unit)
        return try {
            val promise = host.newStream<IdentifyController>(listOf(IDENTIFY_PROTOCOL_ID), connection)
            promise.controller
                .thenCompose { it.id() }
                .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS)
                .thenApply { id ->
                    if (!id.observedAddr.isEmpty) {
                        val observed = Multiaddr.deserialize(id.observedAddr.toByteArray())
                        if (!book.record(
                                relay,
                                observed,
                            )
                        ) {
                            logger.debug { "ignored an unusable observed address from $relay" }
                        }
                    }
                }.handle { _, error ->
                    if (error != null) logger.debug { "identify of $relay failed: ${error.javaClass.simpleName}" }
                    promise.stream.thenAccept { runCatching { it.close() } }
                    Unit
                }
        } catch (e: RuntimeException) {
            CompletableFuture.completedFuture(Unit)
        }
    }

    fun observeAsync(relay: PeerId) {
        relayControlExecutor.execute { observe(relay) }
    }

    fun refreshAll(): CompletableFuture<Unit> {
        val all = reservedRelays().distinct().map { observe(it) }
        return CompletableFuture.allOf(*all.toTypedArray()).thenApply { }
    }
}

/** The real [HolePunchEnvironment]: a node's host, its reuse-port transport and its role register. */
internal class NodeHolePunchEnvironment(
    private val host: Host,
    private val transport: ReusePortTcpTransport,
    private val roles: PunchRoleRegistry,
    private val relayTransport: LapisRelayTransport,
    private val protocol: DcutrBinding,
    private val observer: IdentifyObserver,
    private val punchTtl: Duration,
    private val clock: () -> Instant = { Instant.now() },
) : HolePunchEnvironment {
    override fun openWire(connection: Connection): CompletableFuture<DcutrWire> {
        val promise = host.newStream<DcutrWire>(listOf(DCUTR_PROTOCOL_ID), connection)
        // Hopped off the negotiation stack on purpose: a write issued inline from the continuation of a
        // freshly negotiated stream is silently dropped (see relayControlExecutor).
        return promise.controller.thenApplyAsync({ it }, relayControlExecutor)
    }

    override fun hasDirectConnection(peer: PeerId): Boolean =
        host.network.connections.any {
            !it.closeFuture().isDone && it.secureSession().remoteId == peer && !isRelayed(it)
        }

    override fun isRelayed(connection: Connection): Boolean =
        connection.remoteAddress().has(Protocol.P2PCIRCUIT) || relayTransport.owns(connection)

    override fun ownAddresses(): Set<InetSocketAddress> =
        host
            .listenAddresses()
            .filterNot { it.has(Protocol.P2PCIRCUIT) }
            .mapNotNull { address ->
                runCatching {
                    val ip = address.components.first { it.protocol == Protocol.IP4 || it.protocol == Protocol.IP6 }
                    val port =
                        address.components
                            .first { it.protocol == Protocol.TCP }
                            .stringValue!!
                            .toInt()
                    InetSocketAddress(InetAddress.getByAddress(ip.value!!), port)
                }.getOrNull()
            }.toSet()

    override fun punchDial(
        remote: InetSocketAddress,
        expected: PeerId,
        initiatorRole: Boolean,
    ): CompletableFuture<Connection> = transport.punchDial(remote, expected, initiatorRole)

    override fun registerRole(
        peer: PeerId,
        remote: InetSocketAddress,
        initiatorRole: Boolean,
    ): AutoCloseable? {
        // The address comes from the remote peer's CONNECT message: never let it claim the address of
        // another peer we are already directly connected to (a relay, a bootstrap node, a contact).
        val claimedByOther = isClaimedByOther(host.network.connections, peer, remote)
        if (claimedByOther) return null
        return roles.register(PunchRoleRegistry.Expectation(peer, remote, initiatorRole, clock().plus(punchTtl)))
    }

    override fun hasForeignRoleEntries(
        peer: PeerId,
        remote: InetSocketAddress,
    ): Boolean = roles.foreignEntries(remote, peer) > 0

    override fun expectedPeerAt(connection: Connection): PeerId? {
        val remote = connection.remoteAddress()
        val ip =
            remote.components.firstOrNull { it.protocol == Protocol.IP4 || it.protocol == Protocol.IP6 } ?: return null
        val port = remote.components.firstOrNull { it.protocol == Protocol.TCP } ?: return null
        return runCatching {
            roles.lookup(InetSocketAddress(InetAddress.getByAddress(ip.value!!), port.stringValue!!.toInt()))?.peer
        }.getOrNull()
    }

    override fun refreshObservedAddresses(): CompletableFuture<Unit> = observer.refreshAll()
}

/** Whether [remote] is the endpoint of a live connection to a peer other than [peer]. */
internal fun isClaimedByOther(
    connections: Collection<Connection>,
    peer: PeerId,
    remote: InetSocketAddress,
): Boolean =
    connections.any { c ->
        !c.closeFuture().isDone &&
            sameEndpoint(c, remote) &&
            runCatching { c.secureSession().remoteId }.getOrNull() != peer
    }

private fun sameEndpoint(
    connection: Connection,
    remote: InetSocketAddress,
): Boolean {
    val address = connection.remoteAddress()
    val ip =
        address.components.firstOrNull { it.protocol == Protocol.IP4 || it.protocol == Protocol.IP6 }
            ?: return false
    val port = address.components.firstOrNull { it.protocol == Protocol.TCP } ?: return false
    return runCatching {
        InetAddress.getByAddress(ip.value!!) == remote.address && port.stringValue!!.toInt() == remote.port
    }.getOrDefault(false)
}
