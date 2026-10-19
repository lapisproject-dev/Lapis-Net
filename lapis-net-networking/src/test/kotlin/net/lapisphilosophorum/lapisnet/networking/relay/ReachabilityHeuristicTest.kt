package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.multiformats.Multiaddr
import java.net.InetAddress

private fun ip(literal: String): InetAddress = InetAddress.getByName(literal)

class ReachabilityHeuristicTest :
    FunSpec({
        val privateOnes =
            listOf(
                "10.0.0.5",
                "10.255.255.255",
                "172.16.0.1",
                "172.31.255.254",
                "192.168.1.10",
                "100.64.0.1",
                "100.127.255.254",
                "169.254.1.1",
                "fe80::1",
                "fd12:3456::1",
                "fc00::1",
            )
        val publicOnes =
            listOf(
                "8.8.8.8",
                "93.184.216.34",
                "172.15.0.1",
                "172.32.0.1",
                "100.63.0.1",
                "100.128.0.1",
                "2606:4700::1111",
            )

        privateOnes.forEach { literal ->
            test("$literal is classified as non-public") {
                ReachabilityHeuristic.isPubliclyRoutable(ip(literal)) shouldBe false
                ReachabilityHeuristic.assess(listOf(ip(literal))) shouldBe ReachabilityHint.LIKELY_PRIVATE
            }
        }

        publicOnes.forEach { literal ->
            test("$literal is classified as public") {
                ReachabilityHeuristic.isPubliclyRoutable(ip(literal)) shouldBe true
                ReachabilityHeuristic.assess(listOf(ip(literal))) shouldBe ReachabilityHint.LIKELY_PUBLIC
            }
        }

        test("reserved and documentation blocks are not public") {
            listOf(
                "0.1.2.3",
                "192.0.2.1",
                "198.51.100.1",
                "203.0.113.9",
                "198.18.0.1",
                "240.0.0.1",
                "224.0.0.1",
                "2001:db8::1",
                "64:ff9b::a00:1", // NAT64 embedding 10.0.0.1
                "64:ff9b::808:808", // NAT64 even for a public v4: gateway's choice
                "2002:a00:1::1", // 6to4 embedding 10.0.0.1
                "2002:7f00:1::1", // 6to4 embedding 127.0.0.1
                "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
                "::a00:1", // IPv4-compatible
                "100::1", // discard-only
                "fec0::1", // site-local
            ).forEach { ReachabilityHeuristic.isPubliclyRoutable(ip(it)) shouldBe false }
        }

        test("loopback, wildcard and an empty list are inconclusive") {
            ReachabilityHeuristic.assess(listOf(ip("127.0.0.1"), ip("::1"))) shouldBe ReachabilityHint.INCONCLUSIVE
            ReachabilityHeuristic.assess(listOf(ip("0.0.0.0"))) shouldBe ReachabilityHint.INCONCLUSIVE
            ReachabilityHeuristic.assess(emptyList()) shouldBe ReachabilityHint.INCONCLUSIVE
        }

        test("a mixed set with any public address is likely public; loopback does not count") {
            ReachabilityHeuristic.assess(listOf(ip("192.168.0.2"), ip("8.8.4.4"))) shouldBe
                ReachabilityHint.LIKELY_PUBLIC
            ReachabilityHeuristic.assess(listOf(ip("127.0.0.1"), ip("192.168.0.2"))) shouldBe
                ReachabilityHint.LIKELY_PRIVATE
        }

        test("warning matrix: declared x hint") {
            val w = ReachabilityHeuristic::warningFor
            w(NodeReachability.UNSPECIFIED, ReachabilityHint.LIKELY_PRIVATE)!! shouldContain "PRIVATE"
            w(NodeReachability.PUBLIC, ReachabilityHint.LIKELY_PRIVATE)!! shouldContain "behind NAT"
            w(NodeReachability.PRIVATE, ReachabilityHint.LIKELY_PUBLIC)!! shouldContain "publicly routable"
            w(NodeReachability.PRIVATE, ReachabilityHint.LIKELY_PRIVATE) shouldBe null
            w(NodeReachability.PUBLIC, ReachabilityHint.LIKELY_PUBLIC) shouldBe null
            w(NodeReachability.UNSPECIFIED, ReachabilityHint.LIKELY_PUBLIC) shouldBe null
            NodeReachability.entries.forEach { w(it, ReachabilityHint.INCONCLUSIVE) shouldBe null }
        }

        test("literalAddressesOf extracts IP literals and ignores DNS names") {
            ReachabilityHeuristic.literalAddressesOf(Multiaddr("/ip4/8.8.8.8/tcp/4001")) shouldBe listOf(ip("8.8.8.8"))
            ReachabilityHeuristic.literalAddressesOf(Multiaddr("/dns4/example.org/tcp/4001")) shouldBe emptyList()
        }
    })
