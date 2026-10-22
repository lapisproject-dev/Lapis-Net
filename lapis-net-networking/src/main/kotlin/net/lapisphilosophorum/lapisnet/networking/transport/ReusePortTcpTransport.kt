package net.lapisphilosophorum.lapisnet.networking.transport

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.ChannelVisitor
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.P2PChannel
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.transport.ConnectionUpgrader
import io.libp2p.transport.implementation.ConnectionBuilder
import io.libp2p.transport.implementation.NettyTransport
import io.netty.bootstrap.Bootstrap
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.nio.NioChannelOption
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import java.net.BindException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/** A punch dial that could not be made or lost the race (bind collision, refused, unreachable). Not an error of the node. */
class PunchDialLost(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * A TCP transport whose listener and **every outgoing dial** share one local port (`SO_REUSEADDR` +
 * `SO_REUSEPORT`), which TCP hole punching needs.
 *
 * Written from scratch because jvm-libp2p's `PlainNettyTransport` exposes none of this: its
 * bootstrap objects are private, it sets no socket options and it never binds a dial to a local
 * address. The public [ConnectionBuilder] lets this class pick the Noise/muxer role per channel
 * (see [PunchRoleRegistry]), so neither a fork of the library nor reflection is needed.
 *
 * Used only when hole punching is active; otherwise the node keeps the stock `TcpTransport`.
 * `SO_REUSEPORT` on the listener lets other processes of the **same OS user** bind the port too -
 * this is the reason the transport is not used unconditionally (see docs/architecture.adoc).
 */
class ReusePortTcpTransport internal constructor(
    private val upgrader: ConnectionUpgrader,
    private val roles: PunchRoleRegistry,
    private val connectTimeout: Duration = Duration.ofSeconds(15),
) : NettyTransport {
    private val bossGroup = MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())
    private val workerGroup = MultiThreadIoEventLoopGroup(NioIoHandler.newFactory())
    private val allocator = PooledByteBufAllocator(true)
    private val closed = AtomicBoolean(false)
    private val listeners = ConcurrentHashMap<Multiaddr, Channel>()
    private val channels = ConcurrentHashMap.newKeySet<Channel>()

    /** The (network-hooked) handler passed to [listen]; punch dials report their connection to it. */
    @Volatile
    private var connectionHandler: ConnectionHandler? = null

    override val activeListeners: Int get() = listeners.size
    override val activeConnections: Int get() = channels.size

    override fun initialize() = Unit

    override fun handles(addr: Multiaddr): Boolean =
        addr.hasAny(Protocol.IP4, Protocol.IP6, Protocol.DNS4, Protocol.DNS6, Protocol.DNS) &&
            addr.has(Protocol.TCP) &&
            !addr.has(Protocol.WS) &&
            !addr.has(Protocol.WSS) &&
            !addr.has(Protocol.P2PCIRCUIT)

    override fun listenAddresses(): List<Multiaddr> =
        listeners.values.mapNotNull { (it.localAddress() as? InetSocketAddress)?.let(::toMultiaddr) }

    internal fun boundListenAddresses(): List<InetSocketAddress> =
        listeners.values.mapNotNull { it.localAddress() as? InetSocketAddress }

    override fun localAddress(ch: Channel): Multiaddr = toMultiaddr(ch.localAddress() as InetSocketAddress)

    override fun remoteAddress(ch: Channel): Multiaddr = toMultiaddr(ch.remoteAddress() as InetSocketAddress)

    override fun listen(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Unit> {
        if (closed.get()) return CompletableFuture.failedFuture(IllegalStateException("transport is closed"))
        connectionHandler = connHandler
        val result = CompletableFuture<Unit>()
        val self = this
        val bootstrap =
            ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel::class.java)
                .option(ChannelOption.SO_REUSEADDR, true)
                .option(NioChannelOption.of(StandardSocketOptions.SO_REUSEPORT), true)
                .childOption(ChannelOption.ALLOCATOR, allocator)
                .childHandler(
                    object : ChannelInitializer<Channel>() {
                        override fun initChannel(ch: Channel) {
                            track(ch)
                            val expected = (ch.remoteAddress() as? InetSocketAddress)?.let { roles.lookup(it) }
                            ch.pipeline().addLast(
                                ConnectionBuilder(
                                    self,
                                    upgrader,
                                    connHandler,
                                    expected?.initiatorRole ?: false,
                                    // The initiator (client) role cannot be built without the expected peer id; the
                                    // server role never needs one, so it is not pinned.
                                    if (expected?.initiatorRole == true) expected.peer else null,
                                    preHandler,
                                ),
                            )
                        }
                    },
                )
        bootstrap.bind(socketAddressOf(addr)).addListener { f ->
            if (f.isSuccess) {
                val channel = (f as io.netty.channel.ChannelFuture).channel()
                listeners[addr] = channel
                channel.closeFuture().addListener { listeners.remove(addr, channel) }
                result.complete(Unit)
            } else {
                result.completeExceptionally(f.cause())
            }
        }
        return result
    }

    override fun unlisten(addr: Multiaddr): CompletableFuture<Unit> {
        val channel = listeners.remove(addr) ?: return CompletableFuture.completedFuture(Unit)
        val result = CompletableFuture<Unit>()
        channel.close().addListener { result.complete(Unit) }
        return result
    }

    /**
     * A normal dial. Leaves from the listener port when one fits the target (same address family and
     * scope class), so the NAT mapping a relay observes is the one a later punch will use. If that
     * bind collides with an earlier dial to the same target, it retries **once** from an ephemeral port.
     */
    override fun dial(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Connection> {
        if (closed.get()) return CompletableFuture.failedFuture(IllegalStateException("transport is closed"))
        val remote = socketAddressOf(addr)
        val peer = addr.getPeerId()
        val local = localBindFor(remote)
        val first = dialInternal(remote, peer, true, local, connHandler, preHandler)
        if (local == null) return first
        val result = CompletableFuture<Connection>()
        first.whenComplete { c, e ->
            when {
                c != null -> result.complete(c)
                isBindFailure(e) -> {
                    logger.debug { "dial from the listener port collided, retrying from an ephemeral port" }
                    dialInternal(remote, peer, true, null, connHandler, preHandler).whenComplete { c2, e2 ->
                        if (c2 != null) result.complete(c2) else result.completeExceptionally(e2)
                    }
                }
                else -> result.completeExceptionally(e)
            }
        }
        return result
    }

    /**
     * A hole-punch dial: bound **strictly** to the listener port (an ephemeral fallback would defeat
     * the punch), with the Noise/muxer [initiatorRole] the state machine decided. Completes with
     * [PunchDialLost] when the bind collides or the target cannot be reached.
     */
    internal fun punchDial(
        remote: InetSocketAddress,
        expected: PeerId,
        initiatorRole: Boolean,
    ): CompletableFuture<Connection> {
        val handler =
            connectionHandler
                ?: return CompletableFuture.failedFuture(PunchDialLost("transport is not listening"))
        val local =
            localBindFor(remote)
                ?: return CompletableFuture.failedFuture(PunchDialLost("no listener port fits the target"))
        val result = CompletableFuture<Connection>()
        val inner = dialInternal(remote, expected, initiatorRole, local, handler, null)
        // Cancelling the punch dial (the attempt ended) must also stop the connect in flight.
        result.whenComplete { _, _ -> if (result.isCancelled) inner.cancel(true) }
        inner.whenComplete { c, e ->
            if (c != null) {
                if (!result.complete(c)) c.close()
            } else {
                result.completeExceptionally(
                    if (e is PunchDialLost) e else PunchDialLost("punch dial lost: ${e?.javaClass?.simpleName}", e),
                )
            }
        }
        return result
    }

    private fun dialInternal(
        remote: InetSocketAddress,
        peer: PeerId?,
        initiator: Boolean,
        local: InetSocketAddress?,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Connection> {
        val builder = ConnectionBuilder(this, upgrader, connHandler, initiator, peer, preHandler)
        val bootstrap =
            Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel::class.java)
                .option(ChannelOption.ALLOCATOR, allocator)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout.toMillis().toInt())
                .handler(
                    object : ChannelInitializer<Channel>() {
                        override fun initChannel(ch: Channel) {
                            track(ch)
                            ch.pipeline().addLast(builder)
                        }
                    },
                )
        if (local != null) {
            bootstrap
                .option(ChannelOption.SO_REUSEADDR, true)
                .option(NioChannelOption.of(StandardSocketOptions.SO_REUSEPORT), true)
        }
        val result = CompletableFuture<Connection>()
        val connectFuture = if (local != null) bootstrap.connect(remote, local) else bootstrap.connect(remote)
        connectFuture.addListener { f ->
            if (!f.isSuccess) result.completeExceptionally(f.cause())
        }
        builder.connectionEstablished.whenComplete { c, e ->
            if (c != null) result.complete(c) else result.completeExceptionally(e)
        }
        result.whenComplete { _, _ ->
            if (result.isCancelled || result.isCompletedExceptionally) connectFuture.channel().close()
        }
        return result
    }

    /** The local address a dial to [remote] should be bound to (the listener's port), or `null` if no listener fits. */
    internal fun localBindFor(remote: InetSocketAddress): InetSocketAddress? {
        val target = remote.address ?: return null
        for (listener in boundListenAddresses()) {
            val bound = listener.address ?: continue
            val sameFamily =
                (bound is Inet4Address && target is Inet4Address) || (bound is Inet6Address && target is Inet6Address)
            if (!sameFamily) continue
            if (bound.isAnyLocalAddress) return InetSocketAddress(bound, listener.port)
            if (bound.isLoopbackAddress == target.isLoopbackAddress) return InetSocketAddress(bound, listener.port)
        }
        return null
    }

    private fun track(ch: Channel) {
        channels += ch
        ch.closeFuture().addListener { channels -= ch }
    }

    private fun isBindFailure(error: Throwable?): Boolean =
        generateSequence(error) { it.cause }.any { it is BindException }

    override fun close(): CompletableFuture<Unit> {
        if (!closed.compareAndSet(false, true)) return CompletableFuture.completedFuture(Unit)
        listeners.values.forEach { runCatching { it.close() } }
        listeners.clear()
        channels.forEach { runCatching { it.close() } }
        roles.clear()
        val boss = CompletableFuture<Unit>()
        val worker = CompletableFuture<Unit>()
        bossGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS).addListener { boss.complete(Unit) }
        workerGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS).addListener { worker.complete(Unit) }
        return CompletableFuture.allOf(boss, worker).thenApply { }
    }

    private fun socketAddressOf(addr: Multiaddr): InetSocketAddress {
        val hostComponent =
            addr.components.firstOrNull {
                it.protocol in setOf(Protocol.IP4, Protocol.IP6, Protocol.DNS4, Protocol.DNS6, Protocol.DNS)
            } ?: throw IllegalArgumentException("no host in $addr")
        val port =
            addr.components
                .firstOrNull { it.protocol == Protocol.TCP }
                ?.stringValue
                ?.toInt()
                ?: throw IllegalArgumentException("no tcp port in $addr")
        return InetSocketAddress(hostComponent.stringValue, port)
    }

    internal companion object {
        fun toMultiaddr(address: InetSocketAddress): Multiaddr {
            val ip = address.address
            val host = (ip?.hostAddress ?: address.hostString).substringBefore('%')
            val family = if (ip is Inet6Address) "ip6" else "ip4"
            return Multiaddr("/$family/$host/tcp/${address.port}")
        }
    }
}
