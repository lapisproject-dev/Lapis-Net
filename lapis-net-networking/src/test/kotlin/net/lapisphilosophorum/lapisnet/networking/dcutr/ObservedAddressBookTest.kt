package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import java.time.Duration
import java.time.Instant

private fun peer() = PeerId.random()

class ObservedAddressBookTest :
    FunSpec({
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val clock = { now }

        fun book(max: Int = 8) = ObservedAddressBook(HolePunchAddressFilter(), max, Duration.ofMinutes(30), clock)

        test("the threshold counts distinct observers") {
            val b = book()
            val addr = Multiaddr("/ip4/8.8.4.4/tcp/4001")
            val r1 = peer()
            b.record(r1, addr)
            b.record(r1, addr)
            b.confirmed(2).shouldBeEmpty()
            b.confirmed(1) shouldBe listOf(addr)
            b.record(peer(), addr)
            b.confirmed(2) shouldBe listOf(addr)
        }

        test("non-public and non-tcp addresses are not recorded") {
            val b = book()
            b.record(peer(), Multiaddr("/ip4/10.0.0.1/tcp/4001")) shouldBe false
            b.record(peer(), Multiaddr("/ip4/127.0.0.1/tcp/4001")) shouldBe false
            b.record(peer(), Multiaddr("/dns4/example.com/tcp/4001")) shouldBe false
            b.confirmed(1).shouldBeEmpty()
        }

        test("observations expire") {
            val b = book()
            b.record(peer(), Multiaddr("/ip4/8.8.4.4/tcp/4001"))
            now = now.plus(Duration.ofMinutes(31))
            b.confirmed(1).shouldBeEmpty()
        }

        test("the book is bounded (least recently used goes first)") {
            val b = book(max = 3)
            repeat(10) { b.record(peer(), Multiaddr("/ip4/8.8.4.4/tcp/${4000 + it}")) }
            b.confirmed(1).size shouldBe 3
        }
    })
