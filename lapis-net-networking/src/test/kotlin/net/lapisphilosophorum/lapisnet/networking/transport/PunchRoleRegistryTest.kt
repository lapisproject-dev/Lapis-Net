package net.lapisphilosophorum.lapisnet.networking.transport

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import java.net.InetAddress
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant

private fun addr(
    ip: String,
    port: Int,
) = InetSocketAddress(InetAddress.getByName(ip), port)

class PunchRoleRegistryTest :
    FunSpec({
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val peer = PeerId.random()

        fun expectation(
            remote: InetSocketAddress,
            ttl: Duration = Duration.ofSeconds(30),
        ) = PunchRoleRegistry.Expectation(peer, remote, true, now.plus(ttl))

        test("only an exact ip:port matches") {
            val r = PunchRoleRegistry(4) { now }
            r.register(expectation(addr("8.8.4.4", 4001)))
            r.lookup(addr("8.8.4.4", 4001))?.initiatorRole shouldBe true
            r.lookup(addr("8.8.4.4", 4002)) shouldBe null
            r.lookup(addr("8.8.4.5", 4001)) shouldBe null
        }

        test("an address registered first by one peer does not block another peer (no squatting)") {
            val r = PunchRoleRegistry(4) { now }
            val squatter =
                PunchRoleRegistry.Expectation(
                    PeerId.random(),
                    addr("8.8.4.4", 4001),
                    false,
                    now.plusSeconds(30),
                )
            r.register(squatter) shouldNotBe null
            r.register(expectation(addr("8.8.4.4", 4001))) shouldNotBe null
            r.size() shouldBe 2
        }

        test("a foreign responder entry does not turn the honest initiator entry into null") {
            val r = PunchRoleRegistry(4) { now }
            r.register(expectation(addr("8.8.4.4", 4001)))
            r.register(
                PunchRoleRegistry.Expectation(PeerId.random(), addr("8.8.4.4", 4001), false, now.plusSeconds(30)),
            )
            r.lookup(addr("8.8.4.4", 4001)) shouldBe PunchRoleRegistry.Lookup(true, peer)
            r.foreignEntries(addr("8.8.4.4", 4001), peer) shouldBe 1
        }

        test("several initiator entries are ambiguous") {
            val r = PunchRoleRegistry(4) { now }
            r.register(expectation(addr("8.8.4.4", 4001)))
            r.register(
                PunchRoleRegistry.Expectation(PeerId.random(), addr("8.8.4.4", 4001), true, now.plusSeconds(30)),
            )
            r.lookup(addr("8.8.4.4", 4001)) shouldBe null
        }

        test("a single entry pins the peer") {
            val r = PunchRoleRegistry(4) { now }
            r.register(expectation(addr("8.8.4.4", 4001)))
            r.lookup(addr("8.8.4.4", 4001))?.peer shouldBe peer
            r.lookup(addr("8.8.4.4", 4001))?.initiatorRole shouldBe true
        }

        test("several responder entries agree on the role without pinning a peer") {
            val r = PunchRoleRegistry(4) { now }
            repeat(2) {
                r.register(
                    PunchRoleRegistry.Expectation(PeerId.random(), addr("8.8.4.4", 4001), false, now.plusSeconds(30)),
                )
            }
            r.lookup(addr("8.8.4.4", 4001)) shouldBe PunchRoleRegistry.Lookup(false, null)
        }

        test("one address holds at most a few peers and closing a handle removes only its entry") {
            val r = PunchRoleRegistry(10) { now }
            val handles =
                (1..4).map {
                    r.register(
                        PunchRoleRegistry.Expectation(
                            PeerId.random(),
                            addr("8.8.4.4", 4001),
                            false,
                            now.plusSeconds(30),
                        ),
                    )
                }
            handles.all { it != null } shouldBe true
            r.register(expectation(addr("8.8.4.4", 4001))) shouldBe null
            handles[0]!!.close()
            r.size() shouldBe 3
            r.register(expectation(addr("8.8.4.4", 4001))) shouldNotBe null
        }

        test("entries expire") {
            val r = PunchRoleRegistry(4) { now }
            r.register(expectation(addr("8.8.4.4", 4001), Duration.ofSeconds(5)))
            now = now.plusSeconds(6)
            r.lookup(addr("8.8.4.4", 4001)) shouldBe null
            r.size() shouldBe 0
        }

        test("the register is capped and a closed handle frees its slot") {
            val r = PunchRoleRegistry(2) { now }
            val first = r.register(expectation(addr("8.8.4.4", 1)))
            (r.register(expectation(addr("8.8.4.4", 2))) != null) shouldBe true
            r.register(expectation(addr("8.8.4.4", 3))) shouldBe null
            first!!.close()
            (r.register(expectation(addr("8.8.4.4", 3))) != null) shouldBe true
        }
    })
