package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.ipfs.multihash.Multihash
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import org.peergos.protocol.dht.ProviderStore
import org.peergos.protocol.dht.pb.Dht

/**
 * Bounded, in-memory [ProviderStore]. Nabu's `RamProviderStore` bounds only the number of DHT keys
 * (an LRU): per key it keeps an unbounded `HashSet` of whole provider records, and each record's
 * address list is as large as the sender made it (a message may carry up to 1 MiB). Any connected
 * peer can send `ADD_PROVIDER` for any key, so the store is reachable from the network on every
 * node that attached [NabuStorage] - and the entries are later turned into dial targets by
 * `get()`. This store bounds all three dimensions:
 *
 * - keys: LRU over [DhtLimits.providerStoreKeyCapacity];
 * - providers per key: [DhtLimits.maxProvidersPerKey], one record per provider peer ID (the newest
 *   wins, and is the most recently used), least recently refreshed evicted first;
 * - addresses per record: [DhtLimits.maxAddressesPerPeer], capped at storage time.
 *
 * Worst-case memory with the defaults: 1024 keys x 8 providers x 8 addresses x 256 bytes ~= 16 MiB.
 * [getProviders] returns a COPY - Nabu's store hands out its live `HashSet`, which another thread's
 * `addProvider` can mutate while a reader iterates it.
 *
 * Eviction is deliberately simple (LRU, newest wins): a Sybil attacker who keeps announcing can
 * still crowd honest providers out of one key. That is documented in docs/architecture.adoc; the
 * real defence would be reputation (Madli), not a smarter eviction order.
 */
internal class BoundedProviderStore(
    private val limits: DhtLimits,
) : ProviderStore {
    private val keys =
        object : LinkedHashMap<Multihash, LinkedHashMap<ByteString, Dht.Message.Peer>>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Multihash, LinkedHashMap<ByteString, Dht.Message.Peer>>,
            ): Boolean = size > limits.providerStoreKeyCapacity
        }

    @Synchronized
    override fun addProvider(
        m: Multihash,
        peer: Dht.Message.Peer,
    ) {
        val id = peer.id
        if (id.size() < MIN_PEER_ID_BYTES || id.size() > MAX_PEER_ID_BYTES) return
        if (!CidBytesValidation.isSafeToDeserializeMultihash(id.toByteArray())) return
        val stored =
            Dht.Message.Peer
                .newBuilder()
                .setId(id)
                .addAllAddrs(PeerAddressSanitizer.capRawForStorage(peer.addrsList, limits))
                .build()
        val providers = keys.getOrPut(m.bareMultihash()) { LinkedHashMap() }
        // remove + put: re-insertion moves the peer to the "most recent" end of the order
        providers.remove(id)
        providers[id] = stored
        while (providers.size > limits.maxProvidersPerKey) {
            val eldest = providers.keys.iterator()
            eldest.next()
            eldest.remove()
        }
    }

    @Synchronized
    override fun getProviders(m: Multihash): Set<Dht.Message.Peer> {
        val providers = keys[m.bareMultihash()] ?: return emptySet()
        return LinkedHashSet(providers.values)
    }

    private companion object {
        // io.libp2p.core.PeerId accepts 32..50 bytes
        const val MIN_PEER_ID_BYTES = 32
        const val MAX_PEER_ID_BYTES = 50
    }
}
