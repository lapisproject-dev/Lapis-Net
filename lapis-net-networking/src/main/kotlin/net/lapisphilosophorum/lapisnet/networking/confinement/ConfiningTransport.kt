package net.lapisphilosophorum.lapisnet.networking.confinement

import io.libp2p.core.ChannelVisitor
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.P2PChannel
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.transport.Transport
import java.util.concurrent.CompletableFuture

/**
 * Wraps a libp2p [Transport] of a node in anonymity mode (wave V0.10.0-J1b). [dial] is refused with
 * [ConnectionConfinedException] unless [ConnectionConfinement.permitsDial] holds - BEFORE the delegate is touched, so
 * no TCP SYN and no Noise handshake leaves the node. jvm-libp2p 1.3.5 (`NetworkImpl.connect`, checked with `javap`)
 * appends `/p2p/<peer id>` to every address before calling `Transport.dial`, so every dial path of the host (direct
 * connect, `host.newStream`, GossipSub, bootstrap) passes here with its target. [listen] is refused as well: a node in
 * anonymity mode never accepts connections.
 */
internal class ConfiningTransport(
    private val delegate: Transport,
    private val confinement: ConnectionConfinement,
) : Transport {
    override val activeListeners: Int get() = delegate.activeListeners

    override val activeConnections: Int get() = delegate.activeConnections

    override fun listenAddresses(): List<Multiaddr> = delegate.listenAddresses()

    override fun handles(addr: Multiaddr): Boolean = delegate.handles(addr)

    override fun initialize() = delegate.initialize()

    override fun close(): CompletableFuture<Unit> = delegate.close()

    override fun listen(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Unit> =
        CompletableFuture.failedFuture(
            ConnectionConfinedException("listening is disabled while connections are confined"),
        )

    override fun unlisten(addr: Multiaddr): CompletableFuture<Unit> = delegate.unlisten(addr)

    override fun dial(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?,
    ): CompletableFuture<Connection> {
        if (!confinement.permitsDial(addr)) {
            confinement.countRefusedDial()
            return CompletableFuture.failedFuture(
                ConnectionConfinedException("dial refused: peer outside the confined set"),
            )
        }
        return delegate.dial(addr, connHandler, preHandler)
    }
}
