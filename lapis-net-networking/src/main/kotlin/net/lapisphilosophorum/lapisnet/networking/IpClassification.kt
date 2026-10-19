package net.lapisphilosophorum.lapisnet.networking

/**
 * The single, hardened "is this IP literal a globally routable unicast address" classification
 * shared by every SSRF boundary (DHT address sanitising in `lapis-net-storage`, automatic relay
 * candidate selection in `lapis-net-networking`).
 *
 * Besides loopback / RFC 1918 / CGNAT / link-local / ULA / multicast / reserved ranges it rejects
 * IPv6 forms that smuggle an IPv4 target past a naive check: NAT64 (`64:ff9b::/96`,
 * `64:ff9b:1::/48`), IPv4-compatible (`::/96`), Teredo (`2001::/32`), `100::/64`, site-local
 * (`fec0::/10`); IPv4-mapped and 6to4 (`2002::/16`) addresses are decided by their embedded IPv4.
 */
object IpClassification {
    private const val IPV4_BYTES = 4
    private const val IPV6_BYTES = 16

    /** [bytes] is a 4- or 16-byte raw address; any other length is not public. */
    fun isPublicIp(bytes: ByteArray): Boolean =
        when (bytes.size) {
            IPV4_BYTES -> isPublicV4(bytes)
            IPV6_BYTES -> isPublicV6(bytes)
            else -> false
        }

    internal fun isPublicV4(b: ByteArray): Boolean {
        val a = b[0].toInt() and 0xFF
        val c = b[1].toInt() and 0xFF
        val d = b[2].toInt() and 0xFF
        return when {
            a == 0 -> false // "this network" 0.0.0.0/8
            a == 10 -> false // RFC 1918
            a == 100 && c in 64..127 -> false // CGNAT 100.64.0.0/10
            a == 127 -> false // loopback
            a == 169 && c == 254 -> false // link-local
            a == 172 && c in 16..31 -> false // RFC 1918
            a == 192 && c == 0 && d in 0..2 -> false // IETF protocol assignments 192.0.0.0/24, TEST-NET-1
            a == 192 && c == 168 -> false // RFC 1918
            a == 192 && c == 88 && d == 99 -> false // deprecated 6to4 relay anycast
            a == 198 && c in 18..19 -> false // benchmarking 198.18.0.0/15
            a == 198 && c == 51 && d == 100 -> false // TEST-NET-2
            a == 203 && c == 0 && d == 113 -> false // TEST-NET-3
            a >= 224 -> false // multicast 224.0.0.0/4 and reserved 240.0.0.0/4, including broadcast
            else -> true
        }
    }

    internal fun isPublicV6(b: ByteArray): Boolean {
        val first = b[0].toInt() and 0xFF
        val second = b[1].toInt() and 0xFF

        fun zeros(range: IntRange) = range.all { b[it].toInt() == 0 }

        fun embeddedV4(at: Int) = b.copyOfRange(at, at + IPV4_BYTES)
        return when {
            // ::/128 unspecified, ::1 loopback, ::/96 IPv4-compatible (deprecated)
            zeros(0..11) -> false
            // ::ffff:0:0/96 IPv4-mapped: the embedded IPv4 address decides
            zeros(0..9) && (b[10].toInt() and 0xFF) == 0xFF && (b[11].toInt() and 0xFF) == 0xFF ->
                isPublicV4(embeddedV4(12))
            // 64:ff9b::/96 NAT64 (and 64:ff9b:1::/48 local-use): translates to IPv4 hosts of the gateway's choosing
            first == 0x00 && second == 0x64 && (b[2].toInt() and 0xFF) == 0xFF && (b[3].toInt() and 0xFF) == 0x9B ->
                false
            // 100::/64 discard-only
            first == 0x01 && second == 0x00 && zeros(2..7) -> false
            // 2001::/32 Teredo, 2001:db8::/32 documentation
            first == 0x20 && second == 0x01 && b[2].toInt() == 0 && b[3].toInt() == 0 -> false
            first == 0x20 && second == 0x01 && (b[2].toInt() and 0xFF) == 0x0D && (b[3].toInt() and 0xFF) == 0xB8 ->
                false
            // 2002::/16 6to4: the embedded IPv4 address decides
            first == 0x20 && second == 0x02 -> isPublicV4(embeddedV4(2))
            (first and 0xFE) == 0xFC -> false // fc00::/7 unique local
            first == 0xFE && (second and 0xC0) == 0x80 -> false // fe80::/10 link-local
            first == 0xFE && (second and 0xC0) == 0xC0 -> false // fec0::/10 site-local (deprecated)
            first == 0xFF -> false // ff00::/8 multicast
            else -> true
        }
    }
}
