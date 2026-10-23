@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionConstants
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Constants of the path selection policy (wave V0.10.0-E). Every value is an *assumption awaiting confirmation*
 * (docs/anonymity.adoc, "Assumptions awaiting confirmation (wave E)").
 */
@ExperimentalOnionApi
object PathPolicy {
    /** A production circuit never has fewer hops; equals [OnionConstants.DEFAULT_HOPS] and is not configurable. */
    const val PRODUCTION_PATH_LENGTH = OnionConstants.DEFAULT_HOPS

    /** Lower bound of the selection weight of any relay: Madli is advisory, never a hard gate. */
    const val MIN_WEIGHT = 0.02

    /** Weight of a relay without any Madli history. */
    const val NO_HISTORY_WEIGHT = 0.05

    /** A single network bucket (or relay family) never receives more than `max(MIN_BUCKET_CAP, 1 / buckets)` of the weight. */
    const val MIN_BUCKET_CAP = 0.10

    /** Relays without history together never receive more than this share of the weight (if others exist). */
    const val NEW_RELAYS_TOTAL_CAP = 0.15
    const val IPV4_PREFIX = 16
    const val IPV6_PREFIX = 32
}

/**
 * The coarse network location of a relay. Two relays in the same bucket never share a path. [Unknown] stands for a
 * relay without a usable public address; at most one [Unknown] relay is allowed per path.
 */
@ExperimentalOnionApi
sealed interface NetworkBucket : Comparable<NetworkBucket> {
    /** The /16 of an IPv4 address (upper 16 bits). */
    data class V4(
        val prefix16: Int,
    ) : NetworkBucket

    /** The /32 of an IPv6 address (upper 32 bits, as an unsigned value). */
    data class V6(
        val prefix32: Long,
    ) : NetworkBucket

    data object Unknown : NetworkBucket

    override fun compareTo(other: NetworkBucket): Int = rankOf(this).compareTo(rankOf(other))
}

private fun rankOf(b: NetworkBucket): Long =
    when (b) {
        is NetworkBucket.V4 -> b.prefix16.toLong() and 0xFFFF
        is NetworkBucket.V6 -> 0x1_0000_0000L + (b.prefix32 and 0xFFFF_FFFFL)
        NetworkBucket.Unknown -> Long.MAX_VALUE
    }

/**
 * Supplies the network buckets of a relay. The descriptor carries no address, so production reads them from the
 * relay's peer record ([PeerDirectoryRelayNetworkLocator]). These addresses are SELF-DECLARED and unverified.
 */
@ExperimentalOnionApi
fun interface RelayNetworkLocator {
    fun bucketsOf(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): Set<NetworkBucket>
}

/**
 * Locator backed by the peer directory. Only public `ip4`/`ip6` addresses count; `/p2p-circuit`, `dns*`, loopback,
 * private, link-local, CGNAT, ULA and multicast addresses are ignored. NEVER resolves a name (a resolution would be a
 * network call and a leak). A relay without a usable public address lands in [NetworkBucket.Unknown].
 */
@ExperimentalOnionApi
class PeerDirectoryRelayNetworkLocator(
    private val peerDirectory: PeerDirectoryGossip,
) : RelayNetworkLocator {
    override fun bucketsOf(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): Set<NetworkBucket> {
        val record = peerDirectory.lookup(identity, nowEpochSecond) ?: return setOf(NetworkBucket.Unknown)
        return bucketsOfAddresses(record.addresses)
    }

    companion object {
        fun bucketsOfAddresses(addresses: List<Multiaddr>): Set<NetworkBucket> {
            val result = LinkedHashSet<NetworkBucket>()
            for (a in addresses) {
                if (a.toString().contains("p2p-circuit")) continue
                val ip = a.filterComponents(Protocol.IP4, Protocol.IP6).firstOrNull() ?: continue
                val inet =
                    try {
                        // numeric literal only (an ip4/ip6 component is always numeric): no name resolution happens
                        InetAddress.getByName(ip.stringValue)
                    } catch (e: UnknownHostException) {
                        continue
                    }
                bucketOf(inet)?.let { result += it }
            }
            return if (result.isEmpty()) setOf(NetworkBucket.Unknown) else result
        }

        /** `null` for anything that is not a globally routable unicast address. */
        fun bucketOf(inet: InetAddress): NetworkBucket? {
            if (inet.isAnyLocalAddress ||
                inet.isLoopbackAddress ||
                inet.isLinkLocalAddress ||
                inet.isSiteLocalAddress ||
                inet.isMulticastAddress
            ) {
                return null
            }
            val b = inet.address
            return when (inet) {
                is Inet4Address -> {
                    val first = b[0].toInt() and 0xFF
                    val second = b[1].toInt() and 0xFF
                    // CGNAT 100.64.0.0/10 is not public either
                    if (first == 100 && second in 64..127) return null
                    // "this network", reserved/broadcast, benchmarking and documentation ranges are not public either
                    val third = b[2].toInt() and 0xFF
                    if (first == 0 || first >= 240) return null
                    if (first == 198 && (second == 18 || second == 19)) return null
                    if (first == 192 && second == 0 && third == 2) return null
                    if (first == 198 && second == 51 && third == 100) return null
                    if (first == 203 && second == 0 && third == 113) return null
                    NetworkBucket.V4((first shl 8) or second)
                }
                is Inet6Address -> {
                    // unique local fc00::/7
                    if ((b[0].toInt() and 0xFE) == 0xFC) return null
                    // documentation 2001:db8::/32
                    val doc = intArrayOf(0x20, 0x01, 0x0d, 0xb8)
                    if (doc.indices.all { (b[it].toInt() and 0xFF) == doc[it] }) return null
                    val p =
                        ((b[0].toLong() and 0xFF) shl 24) or ((b[1].toLong() and 0xFF) shl 16) or
                            ((b[2].toLong() and 0xFF) shl 8) or (b[3].toLong() and 0xFF)
                    NetworkBucket.V6(p)
                }
                else -> null
            }
        }
    }
}

/** An operator-declared relay family (not available in the current descriptor format, hence always `null` today). */
@ExperimentalOnionApi
class RelayFamilyId(
    bytes: ByteArray,
) {
    private val stored = bytes.copyOf()

    override fun equals(other: Any?): Boolean = other is RelayFamilyId && stored.contentEquals(other.stored)

    override fun hashCode(): Int = stored.contentHashCode()
}

/** Maps a descriptor to its family; two relays of the same non-null family never share a path. */
@ExperimentalOnionApi
fun interface RelayFamilyResolver {
    fun familyOf(d: OnionRelayDescriptor): RelayFamilyId?
}

/** The normalised Madli relay reliability in `[0, 1]`, or `null` when there is no history for the relay. */
@ExperimentalOnionApi
fun interface RelayReputation {
    fun reliabilityOf(peerId: PeerId): Double?
}

/** Internal switches. [forbidVeritasEdge] is deliberately not reachable from a CLI option, environment or file. */
@ExperimentalOnionApi
data class PathSelectionOptions(
    val forbidVeritasEdge: Boolean = false,
    val veritasEdge: ((Secp256k1PublicKey, Secp256k1PublicKey) -> Boolean)? = null,
)

/** No diverse path can be built from the known relays. The message carries no identity and no address. */
@ExperimentalOnionApi
class InsufficientRelaysException : RuntimeException("insufficient relays")

/** The prescribed last hop collides with the guard (same network, family or identity). The message carries no detail. */
@ExperimentalOnionApi
class PathConflictException : RuntimeException("path conflict")

@ExperimentalOnionApi
sealed interface PathSelectionResult {
    class Selected(
        val hops: List<OnionRelayDescriptor>,
    ) : PathSelectionResult

    data object Insufficient : PathSelectionResult
}
