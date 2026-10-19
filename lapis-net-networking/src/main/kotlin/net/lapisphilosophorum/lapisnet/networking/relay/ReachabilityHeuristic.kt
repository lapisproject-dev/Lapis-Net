package net.lapisphilosophorum.lapisnet.networking.relay

import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.networking.IpClassification
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** What the local interface addresses suggest about whether this node is directly dialable. */
enum class ReachabilityHint { LIKELY_PUBLIC, LIKELY_PRIVATE, INCONCLUSIVE }

/**
 * A best-effort, local-only guess whether this node sits behind NAT, derived purely from its own
 * addresses. **It never changes behaviour** - there is no AutoNAT in this build, so
 * [RelayConfig.reachability] is an operator declaration; this heuristic only produces a log
 * warning when the declaration and the addresses obviously disagree.
 *
 * Also hosts the address classification [isPubliclyRoutable] used by the automatic relay
 * selection to refuse non-public candidate addresses.
 */
internal object ReachabilityHeuristic {
    /**
     * Classifies a node's own [addresses]: loopback and wildcard addresses carry no information and
     * are ignored; any publicly routable address makes the node [ReachabilityHint.LIKELY_PUBLIC];
     * only non-public ones (RFC 1918, CGNAT, link-local, ULA, ...) make it
     * [ReachabilityHint.LIKELY_PRIVATE]; nothing left is [ReachabilityHint.INCONCLUSIVE].
     */
    fun assess(addresses: Collection<InetAddress>): ReachabilityHint {
        val informative = addresses.filterNot { it.isLoopbackAddress || it.isAnyLocalAddress || it.isMulticastAddress }
        if (informative.isEmpty()) return ReachabilityHint.INCONCLUSIVE
        return if (informative.any { isPubliclyRoutable(it) }) {
            ReachabilityHint.LIKELY_PUBLIC
        } else {
            ReachabilityHint.LIKELY_PRIVATE
        }
    }

    /** A warning text when [declared] and [hint] contradict each other, else `null`. */
    fun warningFor(
        declared: NodeReachability,
        hint: ReachabilityHint,
    ): String? =
        when {
            declared != NodeReachability.PRIVATE && hint == ReachabilityHint.LIKELY_PRIVATE ->
                "this node is configured as reachability=$declared, but its addresses are all private " +
                    "(RFC 1918 / CGNAT / link-local / ULA) - it is probably behind NAT; consider " +
                    "reachability=PRIVATE to enable automatic relay selection"
            declared == NodeReachability.PRIVATE && hint == ReachabilityHint.LIKELY_PUBLIC ->
                "this node is configured as reachability=PRIVATE, but it has a publicly routable address - " +
                    "it may be directly reachable and not need a relay"
            else -> null
        }

    /** `true` iff [address] is a globally routable unicast address (not loopback, wildcard,
     * multicast, link-local, RFC 1918, CGNAT, ULA or a reserved/documentation block). */
    fun isPubliclyRoutable(address: InetAddress): Boolean {
        if (address.isLoopbackAddress || address.isAnyLocalAddress || address.isMulticastAddress) return false
        if (address.isLinkLocalAddress || address.isSiteLocalAddress) return false
        return when (address) {
            is Inet4Address, is Inet6Address -> IpClassification.isPublicIp(address.address)
            else -> false
        }
    }

    /** The literal IPv4/IPv6 address components of [address] as [InetAddress]es (no DNS lookups
     * are ever performed: literals only). DNS-name components are ignored. */
    fun literalAddressesOf(address: Multiaddr): List<InetAddress> =
        address.components.mapNotNull { component ->
            if (component.protocol == Protocol.IP4 || component.protocol == Protocol.IP6) {
                component.stringValue?.let { literal ->
                    // The Multiaddr parser has already validated the literal; InetAddress.getByName
                    // performs no lookup for an IP literal.
                    runCatching { InetAddress.getByName(literal.substringBefore('%')) }.getOrNull()
                }
            } else {
                null
            }
        }
}
