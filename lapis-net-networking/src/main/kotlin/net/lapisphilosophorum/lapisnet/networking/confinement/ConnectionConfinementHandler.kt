package net.lapisphilosophorum.lapisnet.networking.confinement

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler

private val logger = KotlinLogging.logger {}

/**
 * Backstop of [ConnectionConfinement] for connections that exist already (wave V0.10.0-J1b): closes every connection
 * whose Noise-authenticated remote peer is not allowed, at once. A node in anonymity mode does not listen, so this only
 * fires for a path the transport check did not see (a relayed inbound circuit, a future transport). Registered FIRST on
 * both handler paths of the node (direct and relayed inbound), before the connection cap, and every later handler is
 * wrapped in [Gated], so a refused connection takes no slot in the cap and is never announced to GossipSub. Logs
 * counters only.
 */
internal class ConnectionConfinementHandler(
    private val confinement: ConnectionConfinement,
) : ConnectionHandler {
    override fun handleConnection(conn: Connection) {
        if (admits(conn)) return
        confinement.countClosedConnection()
        logger.debug { "closed a connection outside the confined set (total ${confinement.closedConnections})" }
        runCatching { conn.close() }
    }

    fun admits(conn: Connection): Boolean =
        runCatching { confinement.isAllowed(conn.secureSession().remoteId) }.getOrDefault(false)

    /** Runs [delegate] only for connections [admits] lets through. */
    class Gated(
        private val gate: ConnectionConfinementHandler,
        private val delegate: ConnectionHandler,
    ) : ConnectionHandler {
        override fun handleConnection(conn: Connection) {
            if (gate.admits(conn)) delegate.handleConnection(conn)
        }
    }
}
