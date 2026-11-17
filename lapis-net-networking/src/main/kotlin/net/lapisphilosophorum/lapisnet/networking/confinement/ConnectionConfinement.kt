package net.lapisphilosophorum.lapisnet.networking.confinement

import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.networking.LapisNodeException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * The set of peers a node in anonymity mode may hold connections with (wave V0.10.0-J1b): its two guards, and its
 * bootstrap peers while [setBootstrapAllowed] is `true` (no usable relay view or no live guard connection yet). Every
 * dial (direct, through `host.newStream`, GossipSub, bootstrap) is checked against it in [ConfiningTransport] before TCP
 * or Noise start, and every established connection in [ConnectionConfinementHandler]. Thread-safe.
 *
 * The set starts empty and bootstrap peers start NOT allowed: until the controller of anonymity mode allows them,
 * nothing can be dialled at all (fail-closed). Only counters are kept about refusals, never a peer id.
 */
class ConnectionConfinement {
    @Volatile private var guards: Set<PeerId> = emptySet()

    @Volatile private var bootstrap: Set<PeerId> = emptySet()

    @Volatile private var bootstrapAllowed: Boolean = false
    private val lock = Any()
    private val shrinkListeners = CopyOnWriteArrayList<() -> Unit>()
    private val refused = AtomicLong(0)
    private val closed = AtomicLong(0)

    /** The primary and backup guard (their transport peer ids from the relay descriptors). Replaces the previous set. */
    fun setGuardPeers(peers: Set<PeerId>) {
        val shrunk =
            synchronized(lock) {
                val before = allowedLocked()
                guards = peers.toSet()
                !allowedLocked().containsAll(before)
            }
        if (shrunk) notifyShrunk()
    }

    /** The peer ids named in the `/p2p/<id>` component of the configured bootstrap addresses. */
    fun setBootstrapPeers(peers: Set<PeerId>) {
        val shrunk =
            synchronized(lock) {
                val before = allowedLocked()
                bootstrap = peers.toSet()
                !allowedLocked().containsAll(before)
            }
        if (shrunk) notifyShrunk()
    }

    /** Whether the bootstrap peers are part of the allowed set. Switching it off closes their connections. */
    fun setBootstrapAllowed(allowed: Boolean) {
        val shrunk =
            synchronized(lock) {
                val before = allowedLocked()
                bootstrapAllowed = allowed
                !allowedLocked().containsAll(before)
            }
        if (shrunk) notifyShrunk()
    }

    fun bootstrapAllowed(): Boolean = bootstrapAllowed

    fun isAllowed(peer: PeerId): Boolean = peer in guards || (bootstrapAllowed && peer in bootstrap)

    /**
     * `true` only for an address that names its peer (`/p2p/<id>`), is not relayed (`/p2p-circuit`) and whose peer is
     * [isAllowed]. jvm-libp2p appends `/p2p/<id>` to every address before `Transport.dial`, so a missing component
     * means a dial path this check does not know: refused (fail-closed).
     */
    fun permitsDial(address: Multiaddr): Boolean {
        if (address.has(Protocol.P2PCIRCUIT)) return false
        val peer = runCatching { address.getPeerId() }.getOrNull() ?: return false
        return isAllowed(peer)
    }

    fun allowedSnapshot(): Set<PeerId> = synchronized(lock) { allowedLocked() }

    /** Dials refused before any byte left the node. */
    val refusedDials: Long get() = refused.get()

    /** Established connections closed because their peer was not (or no longer) allowed. */
    val closedConnections: Long get() = closed.get()

    internal fun countRefusedDial() {
        refused.incrementAndGet()
    }

    internal fun countClosedConnection() {
        closed.incrementAndGet()
    }

    /** Registers [listener], run (outside the lock) whenever the allowed set lost a member. */
    fun addShrinkListener(listener: () -> Unit) {
        shrinkListeners += listener
    }

    private fun allowedLocked(): Set<PeerId> = if (bootstrapAllowed) guards + bootstrap else guards

    private fun notifyShrunk() {
        shrinkListeners.forEach { runCatching(it) }
    }
}

/**
 * A dial or connection refused by [ConnectionConfinement]. The message never names a peer or an address. A
 * [LapisNodeException], so callers that treat a failed connect as "not reached" keep working.
 */
class ConnectionConfinedException(
    message: String,
) : LapisNodeException(message)
