package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.MultiaddrComponent
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.networking.IpClassification

/**
 * Turns the untrusted address list of a DHT response (or of an `ADD_PROVIDER`) into a short list
 * this node is willing to dial - the SSRF / amplification boundary of the DHT layer.
 *
 * Why it exists: Nabu hands every address of a peer entry straight to
 * `NetworkImpl.connect`, which dials ALL of them in parallel and `withP2P`-maps every one first, so
 * (a) one address carrying a foreign `/p2p/` ID makes the whole dial throw, and (b) a response
 * entry with hundreds of addresses is a request to open hundreds of connections to hosts of the
 * responder's choosing. A single peer entry may be at most 1 MiB, i.e. tens of thousands of
 * addresses.
 */
internal object PeerAddressSanitizer {
    /** How many raw entries are looked at, as a multiple of the per-peer cap, before parsing. */
    private const val RAW_LOOKAHEAD_FACTOR = 4

    /** Parses and sanitizes serialized addresses of [peerId]; see [sanitize]. */
    fun fromRaw(
        peerId: PeerId,
        raw: List<ByteString>,
        limits: DhtLimits,
        localDht: Boolean,
        canDial: (Multiaddr) -> Boolean,
    ): List<Multiaddr> =
        sanitize(
            peerId,
            raw
                .asSequence()
                .take(RAW_LOOKAHEAD_FACTOR * limits.maxAddressesPerPeer)
                .filter { it.size() <= limits.maxAddressBytes }
                .mapNotNull { parseOrNull(it) },
            limits,
            localDht,
            canDial,
        )

    /**
     * Rules, in order: DNS-form addresses dropped; addresses with more than one IP component
     * dropped (the dialer takes the first IP4-or-IP6 component in order, so a later, public-looking
     * one could disguise a private target - and the per-IP cap would count the wrong host); an address naming a different `/p2p/` peer
     * dropped (the check `NetworkImpl.connect` would otherwise fail the whole dial on); addresses
     * no registered transport can dial dropped; with [localDht] `false` non-public addresses
     * dropped (the LAN mode deliberately keeps loopback and RFC 1918 - that is its address
     * space); duplicates dropped; at most [DhtLimits.maxAddressesPerIp] per target IP (a circuit
     * address counts against its relay's IP); direct addresses ordered before circuit ones; at
     * most [DhtLimits.maxAddressesPerPeer] kept.
     */
    fun sanitize(
        peerId: PeerId,
        candidates: Sequence<Multiaddr>,
        limits: DhtLimits,
        localDht: Boolean,
        canDial: (Multiaddr) -> Boolean,
    ): List<Multiaddr> {
        val seen = HashSet<String>()
        val perIp = HashMap<String, Int>()
        val kept = ArrayList<Multiaddr>()
        for (candidate in candidates) {
            if (candidate.hasAny(Protocol.DNS, Protocol.DNS4, Protocol.DNS6, Protocol.DNSADDR)) continue
            if (candidate.components.count(::isIpComponent) > 1) continue
            val withPeer = runCatching { candidate.withP2P(peerId) }.getOrNull() ?: continue
            if (!canDial(withPeer)) continue
            if (!localDht && !isPublicAddress(withPeer)) continue
            if (!seen.add(withPeer.toString())) continue
            val ip = ipKeyOf(withPeer)
            val count = perIp.getOrDefault(ip, 0)
            if (count >= limits.maxAddressesPerIp) continue
            perIp[ip] = count + 1
            kept += withPeer
        }
        return kept.sortedBy { if (it.has(Protocol.P2PCIRCUIT)) 1 else 0 }.take(limits.maxAddressesPerPeer)
    }

    /**
     * Whether [addr] points at a publicly routable host: its first IP component (a circuit address's
     * is its relay's) is a global-unicast address. Written here instead of using Nabu's
     * `KademliaEngine.isPublic`, which answers `true` for ANY address carrying a `/ip6zone` and only
     * excludes what `java.net.InetAddress` calls loopback, site-local (RFC 1918, but IPv6 only the
     * deprecated `fec0::/10`), link-local and wildcard - so IPv6 unique-local (`fc00::/7`), CGNAT
     * (`100.64.0.0/10`), multicast, `0.0.0.0/8`, the reserved/documentation ranges and NAT64 passed.
     * An address without an IP component, or with a zone, is not public.
     */
    fun isPublicAddress(addr: Multiaddr): Boolean {
        if (addr.has(Protocol.IP6ZONE)) return false
        val component = firstIpComponent(addr) ?: return false
        val bytes = runCatching { component.value }.getOrNull() ?: return false
        return IpClassification.isPublicIp(bytes)
    }

    /**
     * Store-side cap for raw provider-record addresses (no host, no dial check): at most the
     * lookahead window is examined, oversized and unparseable entries and duplicates are dropped,
     * and [DhtLimits.maxAddressesPerPeer] are kept. Parsing here (instead of storing blindly) keeps
     * entries out of the store that every later reader would have to skip anyway.
     */
    fun capRawForStorage(
        raw: List<ByteString>,
        limits: DhtLimits,
    ): List<ByteString> =
        raw
            .asSequence()
            .take(RAW_LOOKAHEAD_FACTOR * limits.maxAddressesPerPeer)
            .filter { it.size() <= limits.maxAddressBytes }
            .filter { parseOrNull(it) != null }
            .distinct()
            .take(limits.maxAddressesPerPeer)
            .toList()

    private fun parseOrNull(raw: ByteString): Multiaddr? =
        runCatching {
            Multiaddr.deserialize(raw.toByteArray())
        }.getOrNull()

    private fun isIpComponent(c: MultiaddrComponent): Boolean = c.protocol == Protocol.IP4 || c.protocol == Protocol.IP6

    /** The first IP4-or-IP6 component in address order - the one the jvm-libp2p dialer connects to. */
    private fun firstIpComponent(addr: Multiaddr): MultiaddrComponent? = addr.components.firstOrNull(::isIpComponent)

    private fun ipKeyOf(addr: Multiaddr): String = firstIpComponent(addr)?.stringValue ?: ""
}
