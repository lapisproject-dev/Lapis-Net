package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr

class PeerAddressSanitizerTest :
    FunSpec({
        val peer = PeerId.random()
        val limits = DhtLimits()
        val anything: (Multiaddr) -> Boolean = { true }

        fun tcp(
            ip: String,
            port: Int,
        ) = Multiaddr("/ip4/$ip/tcp/$port")

        fun raw(addr: Multiaddr) = ByteString.copyFrom(addr.serialize())

        fun sanitize(
            vararg addrs: Multiaddr,
            limits: DhtLimits = DhtLimits(),
            localDht: Boolean = true,
            canDial: (Multiaddr) -> Boolean = anything,
        ) = PeerAddressSanitizer.sanitize(peer, addrs.asSequence(), limits, localDht, canDial)

        test("duplicates are removed and the peer ID is appended") {
            val out = sanitize(tcp("1.2.3.4", 1), tcp("1.2.3.4", 1), tcp("1.2.3.4", 1).withP2P(peer))
            out shouldHaveSize 1
            out.single().getPeerId() shouldBe peer
        }

        test("at most maxAddressesPerPeer are kept, across distinct hosts") {
            val l = DhtLimits(maxAddressesPerPeer = 4, maxAddressesPerIp = 4)
            sanitize(*(1..10).map { tcp("1.2.3.$it", 1) }.toTypedArray(), limits = l) shouldHaveSize 4
        }

        test("at most maxAddressesPerIp per target IP, but other IPs still get their share") {
            val out =
                sanitize(
                    *(1..10).map { tcp("1.2.3.4", it) }.toTypedArray(),
                    tcp("5.6.7.8", 1),
                    tcp("5.6.7.8", 2),
                    tcp("5.6.7.8", 3),
                )
            out.count { it.toString().contains("1.2.3.4") } shouldBe limits.maxAddressesPerIp
            out.count { it.toString().contains("5.6.7.8") } shouldBe limits.maxAddressesPerIp
        }

        test("direct addresses come before circuit addresses") {
            val relay = PeerId.random()
            val circuit = Multiaddr("/ip4/9.9.9.9/tcp/1/p2p/${relay.toBase58()}/p2p-circuit")
            val out = sanitize(circuit, tcp("1.2.3.4", 1))
            out shouldHaveSize 2
            out[0].toString().contains("p2p-circuit") shouldBe false
            out[1].toString().contains("p2p-circuit") shouldBe true
        }

        test("a circuit address counts against its relay's IP") {
            val relay = PeerId.random()
            val circuits = (1..5).map { Multiaddr("/ip4/9.9.9.9/tcp/$it/p2p/${relay.toBase58()}/p2p-circuit") }
            sanitize(*circuits.toTypedArray()) shouldHaveSize limits.maxAddressesPerIp
        }

        test("addresses with several IP components are dropped, in WAN and LAN mode") {
            val tricky =
                listOf(
                    Multiaddr("/ip6/fd00::5/tcp/22/ip4/8.8.8.8"),
                    Multiaddr("/ip6/::1/tcp/22/ip4/8.8.8.8"),
                    Multiaddr("/ip4/10.0.0.1/tcp/22/ip4/8.8.8.8"),
                )
            sanitize(*tricky.toTypedArray(), localDht = false) shouldHaveSize 0
            sanitize(*tricky.toTypedArray(), localDht = true) shouldHaveSize 0
            // the per-IP cap cannot be dodged by varying a trailing second IP
            val perIpDodge = (1..6).map { Multiaddr("/ip6/fd00::5/tcp/$it/ip4/1.1.1.$it") }
            sanitize(*perIpDodge.toTypedArray()) shouldHaveSize 0
        }

        test("isPublicAddress judges the first IP component, as the dialer does") {
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/ip6/fd00::5/tcp/22/ip4/8.8.8.8")) shouldBe false
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/ip4/8.8.8.8/tcp/22/ip6/fd00::5")) shouldBe true
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/ip6/2606:4700::1111/tcp/22")) shouldBe true
        }

        test("DNS-form addresses are dropped") {
            sanitize(Multiaddr("/dns4/example.org/tcp/1"), Multiaddr("/dns/example.org/tcp/1")) shouldHaveSize 0
            sanitize(Multiaddr("/dnsaddr/example.org"), Multiaddr("/dns6/example.org/tcp/1")) shouldHaveSize 0
        }

        test("an address naming a different peer is dropped without failing the others") {
            val foreign = tcp("1.2.3.4", 1).withP2P(PeerId.random())
            val out = sanitize(foreign, tcp("5.6.7.8", 1))
            out shouldHaveSize 1
            out.single().toString().contains("5.6.7.8") shouldBe true
        }

        test("addresses no transport can dial are dropped") {
            val out =
                sanitize(
                    tcp("1.2.3.4", 1),
                    Multiaddr("/ip4/5.6.7.8/udp/1"),
                    canDial = { it.toString().contains("tcp") },
                )
            out shouldHaveSize 1
        }

        test("WAN mode drops non-public addresses, LAN mode keeps loopback and RFC 1918") {
            val all =
                arrayOf(
                    tcp("127.0.0.1", 1),
                    tcp("192.168.1.5", 1),
                    tcp("10.0.0.5", 1),
                    tcp("169.254.1.1", 1),
                    tcp("8.8.8.8", 1),
                )
            sanitize(*all, localDht = false).map { it.toString() }.single().contains("8.8.8.8") shouldBe true
            sanitize(*all, localDht = true) shouldHaveSize all.size.coerceAtMost(limits.maxAddressesPerPeer)
        }

        test("isPublicAddress accepts global unicast addresses") {
            listOf(
                "/ip4/8.8.8.8/tcp/1",
                "/ip4/1.1.1.1/udp/1/quic-v1",
                "/ip4/100.63.255.255/tcp/1",
                "/ip4/100.128.0.0/tcp/1",
                "/ip4/172.15.0.1/tcp/1",
                "/ip4/172.32.0.1/tcp/1",
                "/ip4/223.255.255.255/tcp/1",
                "/ip6/2606:4700:4700::1111/tcp/1",
                "/ip6/2a00:1450:4001::1/tcp/1",
                "/ip6/2002:0808:0808::1/tcp/1",
            ).forEach { PeerAddressSanitizer.isPublicAddress(Multiaddr(it)) shouldBe true }
        }

        test("isPublicAddress rejects every private, shared, special-use and multicast range") {
            listOf(
                "/ip4/0.0.0.0/tcp/1",
                "/ip4/0.1.2.3/tcp/1",
                "/ip4/10.1.2.3/tcp/1",
                "/ip4/100.64.0.1/tcp/1",
                "/ip4/100.127.255.254/tcp/1",
                "/ip4/127.0.0.1/tcp/1",
                "/ip4/169.254.169.254/tcp/1",
                "/ip4/172.16.0.1/tcp/1",
                "/ip4/172.31.255.255/tcp/1",
                "/ip4/192.0.0.8/tcp/1",
                "/ip4/192.0.2.1/tcp/1",
                "/ip4/192.168.0.1/tcp/1",
                "/ip4/198.18.0.1/tcp/1",
                "/ip4/198.51.100.1/tcp/1",
                "/ip4/203.0.113.1/tcp/1",
                "/ip4/224.0.0.1/tcp/1",
                "/ip4/239.255.255.250/tcp/1",
                "/ip4/240.0.0.1/tcp/1",
                "/ip4/255.255.255.255/tcp/1",
                "/ip6/::/tcp/1",
                "/ip6/::1/tcp/1",
                "/ip6/fc00::5/tcp/22",
                "/ip6/fd00::5/tcp/22",
                "/ip6/fdff:ffff::1/tcp/1",
                "/ip6/fe80::1/tcp/1",
                "/ip6/febf::1/tcp/1",
                "/ip6/fec0::1/tcp/1",
                "/ip6/ff02::1/tcp/1",
                "/ip6/64:ff9b::808:808/tcp/1",
                "/ip6/64:ff9b::7f00:1/tcp/1",
                "/ip6/2001::1/tcp/1",
                "/ip6/2001:db8::1/tcp/1",
                "/ip6/::7f00:1/tcp/1",
                "/ip6/2002:7f00:0001::1/tcp/1",
                "/ip6/2002:c0a8:0101::1/tcp/1",
            ).forEach {
                PeerAddressSanitizer.isPublicAddress(Multiaddr(it)) shouldBe false
            }
        }

        test("an IPv4-mapped IPv6 address is judged by the IPv4 address inside it") {
            // the text parser refuses "::ffff:a.b.c.d", but a peer can send the bytes
            fun mapped(vararg v4: Int): Multiaddr {
                val ip = ByteArray(10) + byteArrayOf(-1, -1) + v4.map { it.toByte() }.toByteArray()
                val tcp = byteArrayOf(0x06, 0x00, 0x01)
                return Multiaddr.deserialize(byteArrayOf(0x29) + ip + tcp)
            }
            PeerAddressSanitizer.isPublicAddress(mapped(8, 8, 8, 8)) shouldBe true
            PeerAddressSanitizer.isPublicAddress(mapped(127, 0, 0, 1)) shouldBe false
            PeerAddressSanitizer.isPublicAddress(mapped(10, 0, 0, 1)) shouldBe false
            PeerAddressSanitizer.isPublicAddress(mapped(169, 254, 169, 254)) shouldBe false
        }

        test("isPublicAddress rejects an address with a zone or without an IP") {
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/ip6zone/eth0/ip6/fe80::1/tcp/1")) shouldBe false
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/ip6zone/eth0/ip6/fd00::5/tcp/1")) shouldBe false
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/ip6zone/eth0/ip6/2606:4700:4700::1111/tcp/1")) shouldBe
                false
            PeerAddressSanitizer.isPublicAddress(Multiaddr("/dns4/example.org/tcp/1")) shouldBe false
        }

        test("a circuit address is judged by its relay's IP") {
            val relay = PeerId.random()
            PeerAddressSanitizer.isPublicAddress(
                Multiaddr("/ip4/8.8.8.8/tcp/1/p2p/${relay.toBase58()}/p2p-circuit"),
            ) shouldBe true
            PeerAddressSanitizer.isPublicAddress(
                Multiaddr("/ip4/10.0.0.1/tcp/1/p2p/${relay.toBase58()}/p2p-circuit"),
            ) shouldBe false
        }

        test("WAN mode also drops IPv6 unique-local, CGNAT, multicast, 0.0.0.0/8 and zoned addresses") {
            val rejected =
                arrayOf(
                    Multiaddr("/ip6/fd00::5/tcp/22"),
                    Multiaddr("/ip4/100.64.0.9/tcp/1"),
                    Multiaddr("/ip4/224.0.0.251/tcp/1"),
                    Multiaddr("/ip4/0.1.2.3/tcp/1"),
                    Multiaddr("/ip6zone/eth0/ip6/fe80::1/tcp/1"),
                )
            sanitize(*rejected, localDht = false) shouldHaveSize 0
            sanitize(Multiaddr("/ip6/2606:4700:4700::1111/tcp/1"), *rejected, localDht = false) shouldHaveSize 1
        }

        test("fromRaw skips unparseable bytes and oversized entries") {
            val junk = ByteString.copyFrom(byteArrayOf(1, 2, 3, 4, 5))
            val oversized = ByteString.copyFrom(ByteArray(1000) { 7 })
            val ok = raw(tcp("1.2.3.4", 1))
            val out = PeerAddressSanitizer.fromRaw(peer, listOf(junk, oversized, ok), limits, true, anything)
            out shouldHaveSize 1
        }

        test("fromRaw drops an address bigger than maxAddressBytes even if it parses") {
            val withPeerId = raw(tcp("1.2.3.4", 1).withP2P(PeerId.random()))
            val tight = DhtLimits(maxAddressBytes = 32)
            PeerAddressSanitizer.fromRaw(peer, listOf(withPeerId), tight, true, anything) shouldHaveSize 0
            // the same entry is fine under the default (and then, being for another peer, still dropped)
            PeerAddressSanitizer.fromRaw(peer, listOf(withPeerId), limits, true, anything) shouldHaveSize 0
            PeerAddressSanitizer.fromRaw(
                peer,
                listOf(raw(tcp("1.2.3.4", 1).withP2P(peer))),
                limits,
                true,
                anything,
            ) shouldHaveSize
                1
        }

        test("fromRaw only looks at the first 4 x maxAddressesPerPeer raw entries before parsing") {
            val window = 4 * limits.maxAddressesPerPeer
            val junk = List(window) { ByteString.copyFrom(byteArrayOf(9, 9, 9)) }
            val valid = (1..5).map { raw(tcp("1.2.3.$it", 1)) }
            PeerAddressSanitizer.fromRaw(peer, junk + valid, limits, true, anything) shouldHaveSize 0
            PeerAddressSanitizer.fromRaw(peer, junk.drop(1) + valid, limits, true, anything).isNotEmpty() shouldBe true
        }

        test("capRawForStorage drops junk, oversized and duplicates and caps the count") {
            val l = DhtLimits(maxAddressesPerPeer = 3, maxAddressesPerIp = 3)
            val valid = (1..6).map { raw(tcp("1.2.3.4", it)) }
            val junk = ByteString.copyFrom(byteArrayOf(1, 2, 3))
            val out = PeerAddressSanitizer.capRawForStorage(listOf(junk, valid[0], valid[0]) + valid, l)
            out shouldHaveSize 3
            out.distinct() shouldHaveSize 3
            out.none { it == junk } shouldBe true
        }
    })
