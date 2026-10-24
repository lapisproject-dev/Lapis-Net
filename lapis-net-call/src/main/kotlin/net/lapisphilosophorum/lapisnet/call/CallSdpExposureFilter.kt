package net.lapisphilosophorum.lapisnet.call

import java.net.Inet4Address
import java.net.Inet6Address

/**
 * V0.10.0-G: reduces the IP addresses an SDP discloses, for [CallMediaPolicy.EXPOSED]. Pure text function: no
 * network, no DNS, no logging, and no exception message ever carries an address. The PeerConnection is not touched
 * (no native close/free path changes, no STUN, no TURN, no TCP).
 *
 * This is NOT anonymisation: the remaining public host candidate is exactly the address call media reveals. It only
 * keeps private/internal addresses (LAN topology, VPN, container networks) out of the signal and limits the exposure
 * to at most one address per component.
 *
 * Rules: keep only `typ host` UDP candidates with a PUBLIC unicast IP literal; drop RFC 1918, loopback, link-local,
 * unspecified, multicast, CGNAT 100.64.0.0/10, ULA fc00::/7, IPv4-mapped IPv6 and `.local`; at most one candidate
 * per component (IPv4 preferred, IPv6 only when no IPv4 candidate exists); `c=`, `a=rtcp:` and `o=` addresses are
 * rewritten to the placeholder `0.0.0.0`/`IN IP4`. Zero remaining candidates are allowed (peer-reflexive discovery
 * through connectivity checks, when the other side is public).
 */
internal object CallSdpExposureFilter {
    private const val PLACEHOLDER = "0.0.0.0"

    fun filterLocal(sdp: String): String = filter(sdp)

    fun filterRemote(sdp: String): String = filter(sdp)

    private class Candidate(
        val line: String,
        val component: String,
        val ipv4: Boolean,
        val order: Int,
    )

    private fun filter(sdp: String): String {
        val separator = if (sdp.contains("\r\n")) "\r\n" else "\n"
        val lines = sdp.split(separator)
        val candidates = mutableListOf<Candidate>()
        lines.forEachIndexed { index, line ->
            if (line.startsWith("a=candidate:")) parseCandidate(line, index)?.let(candidates::add)
        }
        val keep = mutableSetOf<Int>()
        candidates.groupBy { it.component }.values.forEach { perComponent ->
            val chosen = perComponent.firstOrNull { it.ipv4 } ?: perComponent.first()
            keep.add(chosen.order)
        }
        val out = ArrayList<String>(lines.size)
        lines.forEachIndexed { index, line ->
            when {
                line.startsWith("a=candidate:") -> if (index in keep) out.add(line)
                line.startsWith("c=") -> out.add("c=IN IP4 $PLACEHOLDER")
                line.startsWith("a=rtcp:") -> out.add("a=rtcp:9 IN IP4 $PLACEHOLDER")
                line.startsWith("o=") -> out.add(rewriteOrigin(line))
                else -> out.add(line)
            }
        }
        return out.joinToString(separator)
    }

    private fun rewriteOrigin(line: String): String {
        // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
        val tokens = line.removePrefix("o=").split(' ')
        if (tokens.size != 6) return line
        return "o=${tokens[0]} ${tokens[1]} ${tokens[2]} IN IP4 $PLACEHOLDER"
    }

    private fun parseCandidate(
        line: String,
        order: Int,
    ): Candidate? {
        val tokens = line.removePrefix("a=candidate:").trim().split(Regex("\\s+"))
        if (tokens.size < 8) return null
        if (!tokens[2].equals("udp", ignoreCase = true)) return null
        val typIndex = tokens.indexOf("typ")
        if (typIndex < 0 || typIndex >= tokens.lastIndex || tokens[typIndex + 1] != "host") return null
        val address = tokens[4]
        if (address.endsWith(".local", ignoreCase = true) || !CallSdpPolicy.isIpLiteral(address)) return null
        val normalized =
            try {
                CallSdpPolicy.normalizedLiteralAddress(address)
            } catch (e: java.net.UnknownHostException) {
                return null
            }
        // an IPv4-mapped IPv6 literal normalises to an Inet4Address, but its spelling still contains a colon
        if (address.contains(':') && normalized is Inet4Address) return null
        if (!isPublicUnicast(normalized)) return null
        return Candidate(line, tokens[1], normalized is Inet4Address, order)
    }

    private fun isPublicUnicast(address: java.net.InetAddress): Boolean {
        if (address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
        ) {
            return false
        }
        val b = address.address
        return when (address) {
            is Inet4Address -> {
                val first = b[0].toInt() and 0xFF
                val second = b[1].toInt() and 0xFF
                val cgnat = first == 100 && second in 64..127
                val broadcast = b.all { it == 0xFF.toByte() }
                first != 0 && !cgnat && !broadcast && first < 240
            }
            is Inet6Address -> (b[0].toInt() and 0xFE) != 0xFC
            else -> false
        }
    }
}
