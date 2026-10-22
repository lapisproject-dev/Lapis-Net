package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.networking.IpClassification
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The only gate between addresses a peer SENDS us and sockets we open. A hole-punch partner is an
 * arbitrary peer, so everything it names is hostile input: without this filter a peer could use a
 * punch to make us connect to internal addresses (SSRF) or to many targets at once (amplification).
 *
 * Accepts exactly `[ip4|ip6, tcp]` - no DNS names, no `/p2p-circuit`, no WebSocket, no extra
 * components - with a public unicast IP ([IpClassification.isPublicIp]) and a port in 1..65535.
 * At most [MAX_DIAL_ADDRESSES_PER_FAMILY] per address family survive, so one attempt makes at most
 * two dials.
 */
internal class HolePunchAddressFilter(
    private val allowNonPublic: Boolean = false,
) {
    /** Parses one wire address; `null` for anything that is not an acceptable `/ip/tcp` pair. Never throws. */
    fun parse(raw: ByteArray): InetSocketAddress? =
        runCatching { Multiaddr.deserialize(raw) }.getOrNull()?.let { parse(it) }

    fun parse(address: Multiaddr): InetSocketAddress? =
        runCatching {
            val components = address.components.filter { it.protocol != Protocol.P2P }
            if (components.size != 2) return null
            val host = components[0]
            val tcp = components[1]
            if (host.protocol != Protocol.IP4 && host.protocol != Protocol.IP6) return null
            if (tcp.protocol != Protocol.TCP) return null
            val port = tcp.stringValue!!.toInt()
            if (port !in 1..MAX_PORT) return null
            val raw = host.value!!
            // Classified on the wire bytes: InetAddress would silently turn ::ffff:a.b.c.d into an IPv4 address.
            if (!allowNonPublic && !IpClassification.isPublicIp(raw)) return null
            val ip = InetAddress.getByAddress(raw)
            InetSocketAddress(ip, port)
        }.getOrNull()

    /** The addresses worth dialling out of [raw], excluding [ownAddresses]; deduplicated, at most one per family. */
    fun dialable(
        raw: List<ByteArray>,
        ownAddresses: Set<InetSocketAddress>,
    ): List<InetSocketAddress> {
        val result = ArrayList<InetSocketAddress>()
        var v4 = 0
        var v6 = 0
        for (candidate in raw.asSequence().take(HolePunchCodec.MAX_OBSERVED_ADDRESSES).mapNotNull { parse(it) }) {
            if (candidate in ownAddresses || candidate in result) continue
            val isV4 = candidate.address.address.size == 4
            if (isV4 && v4 >= MAX_DIAL_ADDRESSES_PER_FAMILY) continue
            if (!isV4 && v6 >= MAX_DIAL_ADDRESSES_PER_FAMILY) continue
            if (isV4) v4++ else v6++
            result += candidate
        }
        return result
    }

    companion object {
        const val MAX_DIAL_ADDRESSES_PER_FAMILY = 1
        private const val MAX_PORT = 65535
    }
}
