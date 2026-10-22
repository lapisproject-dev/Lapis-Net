package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import java.net.InetAddress
import java.net.InetSocketAddress

private fun raw(address: String) = Multiaddr(address).serialize()

class HolePunchAddressFilterTest :
    FunSpec({
        val filter = HolePunchAddressFilter()

        fun accepted(address: String) = filter.parse(Multiaddr(address)) != null

        test("a public ip4/tcp pair is accepted") {
            filter.parse(Multiaddr("/ip4/8.8.4.4/tcp/4001")) shouldBe
                InetSocketAddress(InetAddress.getByName("8.8.4.4"), 4001)
        }

        test("a public ip6/tcp pair is accepted") {
            accepted("/ip6/2606:4700:4700::1111/tcp/4001") shouldBe true
        }

        listOf(
            "/ip4/10.1.2.3/tcp/4001" to "private",
            "/ip4/192.168.1.5/tcp/4001" to "private",
            "/ip4/172.16.0.1/tcp/4001" to "private",
            "/ip4/127.0.0.1/tcp/4001" to "loopback",
            "/ip4/169.254.1.1/tcp/4001" to "link-local",
            "/ip4/100.64.0.1/tcp/4001" to "CGNAT",
            "/ip4/192.0.2.1/tcp/4001" to "documentation",
            "/ip4/198.51.100.1/tcp/4001" to "documentation",
            "/ip4/203.0.113.1/tcp/4001" to "documentation",
            "/ip6/::1/tcp/4001" to "ip6 loopback",
            "/ip6/fe80::1/tcp/4001" to "ip6 link-local",
            "/ip6/fc00::1/tcp/4001" to "ip6 ula",
            "/ip4/8.8.4.4/tcp/0" to "port zero",
            "/dns4/example.com/tcp/4001" to "dns",
            "/ip4/8.8.4.4/udp/4001" to "not tcp",
            "/ip4/8.8.4.4/tcp/4001/ws" to "websocket",
            "/ip4/8.8.4.4/tcp/4001/p2p-circuit" to "circuit",
            "/ip4/8.8.4.4/tcp/4001/tcp/5" to "extra component",
            "/ip4/8.8.4.4" to "no port",
        ).forEach { (address, why) ->
            test("rejected: $why ($address)") { accepted(address) shouldBe false }
        }

        test("an ipv4-mapped ipv6 address is decided by its embedded ipv4 address") {
            fun mapped(v4: ByteArray) =
                Multiaddr
                    .empty()
                    .withComponent(Protocol.IP6, ByteArray(10) + byteArrayOf(-1, -1) + v4)
                    .withComponent(Protocol.TCP, "4001")
            filter.parse(mapped(byteArrayOf(10, 0, 0, 1))) shouldBe null
            (filter.parse(mapped(byteArrayOf(8, 8, 4, 4))) != null) shouldBe true
        }

        test("a trailing /p2p component is tolerated") {
            accepted("/ip4/8.8.4.4/tcp/4001/p2p/12D3KooWD3KddNPCTGupmCen5KBSrT5CqtBMNbX3maXJzuup6ogg") shouldBe true
        }

        test("garbage bytes never throw") {
            filter.parse(byteArrayOf(1, 2, 3)) shouldBe null
            filter.parse(ByteArray(0)) shouldBe null
        }

        test("the test mode accepts loopback") {
            HolePunchAddressFilter(allowNonPublic = true).parse(Multiaddr("/ip4/127.0.0.1/tcp/4001")) shouldBe
                InetSocketAddress(InetAddress.getByName("127.0.0.1"), 4001)
        }

        test("dialable drops own addresses, deduplicates and keeps at most one address per family") {
            val own = setOf(InetSocketAddress(InetAddress.getByName("8.8.4.4"), 4001))
            val result =
                filter.dialable(
                    listOf(
                        raw("/ip4/8.8.4.4/tcp/4001"), // own
                        raw("/ip4/1.1.1.1/tcp/4001"),
                        raw("/ip4/1.1.1.1/tcp/4001"), // duplicate
                        raw("/ip4/9.9.9.9/tcp/4001"), // second v4
                        raw("/ip4/10.0.0.1/tcp/4001"), // private
                        raw("/ip6/2606:4700:4700::1111/tcp/4001"),
                        raw("/ip6/2606:4700:4700::1001/tcp/4001"), // second v6
                    ),
                    own,
                )
            result.size shouldBe 2
            result[0].address.hostAddress shouldBe "1.1.1.1"
            result[1].address.address.size shouldBe 16
        }

        test("dialable of nothing acceptable is empty") {
            filter.dialable(listOf(raw("/ip4/127.0.0.1/tcp/1")), emptySet()).shouldBeEmpty()
        }
    })
