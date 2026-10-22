package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant

/**
 * The addresses relays have **observed** this node at (via Identify). Bounded (LRU), expiring, and
 * restricted to what [HolePunchAddressFilter] accepts, so a hostile relay cannot make the node
 * advertise internal or non-TCP addresses. With a threshold above 1 an address is only reported
 * once that many distinct observers agree.
 */
internal class ObservedAddressBook(
    private val filter: HolePunchAddressFilter,
    private val maxEntries: Int = 8,
    private val ttl: Duration = Duration.ofMinutes(30),
    private val clock: () -> Instant = { Instant.now() },
) {
    private class Entry(
        val address: InetSocketAddress,
    ) {
        val observers = HashMap<PeerId, Instant>()
    }

    private val entries =
        object : LinkedHashMap<InetSocketAddress, Entry>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<InetSocketAddress, Entry>?): Boolean =
                size > maxEntries
        }

    @Synchronized
    fun record(
        observer: PeerId,
        observed: Multiaddr,
    ): Boolean {
        val address = filter.parse(observed) ?: return false
        val entry = entries.getOrPut(address) { Entry(address) }
        entry.observers[observer] = clock()
        return true
    }

    /** Addresses confirmed by at least [threshold] distinct, unexpired observers. */
    @Synchronized
    fun confirmed(threshold: Int): List<Multiaddr> {
        val cutoff = clock().minus(ttl)
        val iterator = entries.values.iterator()
        val result = ArrayList<Multiaddr>()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            entry.observers.values.removeIf { it.isBefore(cutoff) }
            if (entry.observers.isEmpty()) {
                iterator.remove()
            } else if (entry.observers.size >= threshold) {
                result += toMultiaddr(entry.address)
            }
        }
        return result
    }

    private fun toMultiaddr(a: InetSocketAddress): Multiaddr {
        val family = if (a.address.address.size == 4) "ip4" else "ip6"
        return Multiaddr("/$family/${a.address.hostAddress.substringBefore('%')}/tcp/${a.port}")
    }
}
