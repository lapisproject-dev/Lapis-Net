package net.lapisphilosophorum.lapisnet.networking.transport

import io.libp2p.core.PeerId
import java.net.InetSocketAddress
import java.time.Instant

/**
 * A small, bounded register of TCP connections the hole-punching state machine is currently
 * expecting, keyed by the remote `ip:port`.
 *
 * Why it exists: during a punch both peers dial each other, and the kernel may deliver the result as
 * a simultaneous open (both dials succeed on the same socket pair) or as an ordinary accept on the
 * listener of one side. In the accept case the listener would take the Noise/muxer **responder**
 * role on both ends. The libp2p specification says the hole-punch initiator ("A") is the client for
 * everything above TCP, even if the connection arrives at A through its listener, so the listener
 * consults this register and builds the connection with the role the state machine decided.
 *
 * Only an exact `ip:port` match counts, entries expire, and the register is capped: nobody can use
 * it to flip the role of arbitrary inbound connections. Entries are keyed by address AND peer, so an
 * address registered first by one peer does not lock out another peer's punch towards it.
 */
internal class PunchRoleRegistry(
    private val maxEntries: Int,
    private val clock: () -> Instant = { Instant.now() },
) {
    data class Expectation(
        val peer: PeerId,
        val remote: InetSocketAddress,
        val initiatorRole: Boolean,
        val expiresAt: Instant,
    )

    /** The role to build an incoming connection with; [peer] is set only when exactly one peer is expected there. */
    data class Lookup(
        val initiatorRole: Boolean,
        val peer: PeerId?,
    )

    // Several peers may expect the same ip:port at once (keyed by address + peer), so nobody can squat an
    // address and thereby block another peer's punch towards it. Whoever claims an address only ever
    // occupies a slot under their own peer id.
    private val entries = LinkedHashMap<Pair<String, PeerId>, Expectation>()

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    /** Registers [e]; `null` when the register is full (the caller then aborts its attempt). The returned handle removes the entry. */
    @Synchronized
    fun register(e: Expectation): AutoCloseable? {
        purgeExpired()
        val key = keyOf(e.remote) to e.peer
        if (!entries.containsKey(key)) {
            if (entries.size >= maxEntries) return null
            if (entries.keys.count { it.first == key.first } >= MAX_PEERS_PER_ADDRESS) return null
        }
        entries[key] = e
        return AutoCloseable { removeIfSame(key, e) }
    }

    /**
     * The role for a connection from exactly [remote], or `null`. With a single live entry the peer is
     * pinned. With several entries from different peers: exactly one initiator entry wins (its peer is pinned,
     * the other entries are foreign claims on the same address and cannot turn the honest initiator into a
     * responder); only responder entries agree on the responder role (nothing is pinned); several initiator
     * entries are ambiguous and yield `null`.
     */
    @Synchronized
    fun lookup(remote: InetSocketAddress): Lookup? {
        purgeExpired()
        val address = keyOf(remote)
        val live = entries.entries.filter { it.key.first == address }.map { it.value }
        return when {
            live.isEmpty() -> null
            live.size == 1 -> Lookup(live[0].initiatorRole, live[0].peer)
            live.all { !it.initiatorRole } -> Lookup(false, null)
            live.count { it.initiatorRole } == 1 -> live.first { it.initiatorRole }.let { Lookup(true, it.peer) }
            else -> null
        }
    }

    /** How many live entries of peers other than [peer] sit on [remote]; non-zero means the address is contested. */
    @Synchronized
    fun foreignEntries(
        remote: InetSocketAddress,
        peer: PeerId,
    ): Int {
        purgeExpired()
        val address = keyOf(remote)
        return entries.keys.count { it.first == address && it.second != peer }
    }

    @Synchronized
    fun size(): Int {
        purgeExpired()
        return entries.size
    }

    @Synchronized
    fun clear() = entries.clear()

    @Synchronized
    private fun removeIfSame(
        key: Pair<String, PeerId>,
        e: Expectation,
    ) {
        if (entries[key] === e) entries.remove(key)
    }

    private fun purgeExpired() {
        val now = clock()
        entries.values.removeIf { !it.expiresAt.isAfter(now) }
    }

    private fun keyOf(a: InetSocketAddress): String = "${a.address?.hostAddress ?: a.hostString}:${a.port}"

    private companion object {
        const val MAX_PEERS_PER_ADDRESS = 4
    }
}
