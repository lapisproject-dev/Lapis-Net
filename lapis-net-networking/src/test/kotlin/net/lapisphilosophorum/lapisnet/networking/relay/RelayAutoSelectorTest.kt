package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

private fun peer(seed: Int): PeerId = PeerId(ByteArray(32) { seed.toByte() })

private fun peerIdx(i: Int): PeerId = PeerId(ByteArray(32) { idx -> if (idx < 2) (i shr (idx * 8)).toByte() else 9 })

private fun info(
    id: PeerId,
    ip: String,
): PeerInfo = PeerInfo(id, listOf(Multiaddr("/ip4/$ip/tcp/4001")))

private class FakeSlots(
    var failFor: Set<PeerId> = emptySet(),
    val clock: () -> Instant,
) : RelaySlots {
    val held = LinkedHashMap<PeerId, RelayReservation>()
    val expired = HashSet<PeerId>()
    val attempts = ArrayList<PeerId>()

    override fun reserve(relay: PeerInfo): RelayReservation {
        attempts += relay.peerId
        if (relay.peerId in failFor) throw RelayException("refused")
        val r = RelayReservation(relay.peerId, relay.addresses, clock().plusSeconds(900))
        held[relay.peerId] = r
        return r
    }

    override fun reservations(): List<RelayReservation> = held.values.toList()

    override fun holdsReservationWith(relay: PeerId): Boolean = relay in held && relay !in expired

    override fun release(relay: PeerId) {
        held.remove(relay)
        expired.remove(relay)
    }
}

class RelayAutoSelectorTest :
    FunSpec({
        var now = Instant.parse("2026-10-18T12:00:00Z")
        val clock = { now }
        val self = peer(100)

        fun selector(
            slots: FakeSlots,
            candidates: () -> List<PeerInfo>,
            ranker: RelayCandidateRanker = RelayCandidateRanker.UNRANKED,
            config: AutoRelayConfig = AutoRelayConfig(),
        ) = RelayAutoSelector(slots, config, candidates, ranker, self, clock)

        beforeTest { now = Instant.parse("2026-10-18T12:00:00Z") }

        test("reserves exactly targetRelayCount relays, in ranked order") {
            val slots = FakeSlots(clock = clock)
            val list = (1..5).map { info(peer(it), "8.8.$it.1") }
            val ranker = RelayCandidateRanker { it.reversed() }
            val result = selector(slots, { list }, ranker).runSelectionPass()
            result.reserved shouldBe listOf(peer(5), peer(4))
            result.held shouldBe 2
            slots.attempts shouldBe listOf(peer(5), peer(4))
        }

        test("prefers candidates on source hosts not yet used (diversity)") {
            val slots = FakeSlots(clock = clock)
            val list =
                listOf(
                    info(peer(1), "8.8.8.8"),
                    info(peer(2), "8.8.8.8"), // same host as 1
                    info(peer(3), "9.9.9.9"),
                )
            val result = selector(slots, { list }).runSelectionPass()
            result.reserved shouldBe listOf(peer(1), peer(3))
        }

        test("diversity also considers hosts of relays already held") {
            val slots = FakeSlots(clock = clock)
            slots.reserve(info(peer(1), "8.8.8.8"))
            val list = listOf(info(peer(2), "8.8.8.8"), info(peer(3), "9.9.9.9"))
            val result = selector(slots, { list }).runSelectionPass()
            result.reserved shouldBe listOf(peer(3))
        }

        test("nothing happens when enough relays are held") {
            val slots = FakeSlots(clock = clock)
            slots.reserve(info(peer(1), "8.8.1.1"))
            slots.reserve(info(peer(2), "8.8.2.2"))
            slots.attempts.clear()
            val result = selector(slots, { listOf(info(peer(3), "8.8.3.3")) }).runSelectionPass()
            result.reserved.shouldBeEmpty()
            slots.attempts.shouldBeEmpty()
            result.held shouldBe 2
        }

        test("refills after a held relay lapses, without replacing healthy relays") {
            val slots = FakeSlots(clock = clock)
            val list = (1..4).map { info(peer(it), "8.8.$it.1") }
            val sel = selector(slots, { list })
            sel.runSelectionPass().reserved shouldBe listOf(peer(1), peer(2))
            slots.expired += peer(1)
            val second = sel.runSelectionPass()
            second.reserved shouldBe listOf(peer(3))
            slots.held.keys.toList() shouldBe listOf(peer(2), peer(3))
        }

        test("failed relays are backed off and retried only after the backoff") {
            val slots = FakeSlots(failFor = setOf(peer(1)), clock = clock)
            val list = listOf(info(peer(1), "8.8.1.1"))
            val sel =
                selector(
                    slots,
                    { list },
                    config = AutoRelayConfig(targetRelayCount = 1, failureBackoff = Duration.ofMinutes(10)),
                )
            sel.runSelectionPass().failed shouldBe listOf(peer(1))
            now = now.plus(Duration.ofMinutes(5))
            sel.runSelectionPass().failed.shouldBeEmpty()
            slots.attempts.size shouldBe 1
            now = now.plus(Duration.ofMinutes(6))
            sel.runSelectionPass().failed shouldBe listOf(peer(1))
            slots.attempts.size shouldBe 2
        }

        test("a throwing ranker falls back to the directory order") {
            val slots = FakeSlots(clock = clock)
            val list = (1..3).map { info(peer(it), "8.8.$it.1") }
            val result = selector(slots, { list }, { error("boom") }).runSelectionPass()
            result.reserved shouldBe listOf(peer(1), peer(2))
        }

        test("candidates a ranker invents are discarded, omitted ones are kept after the ranked ones") {
            val slots = FakeSlots(clock = clock)
            val list = (1..3).map { info(peer(it), "8.8.$it.1") }
            val invented = info(peer(77), "8.8.77.1")
            val ranker = RelayCandidateRanker { listOf(invented, it[2]) } // omits 1 and 2
            val result = selector(slots, { list }, ranker).runSelectionPass()
            result.reserved shouldBe listOf(peer(3), peer(1))
            slots.attempts.contains(peer(77)) shouldBe false
        }

        test("our own peer id and duplicates are skipped") {
            val slots = FakeSlots(clock = clock)
            val list = listOf(info(self, "8.8.0.1"), info(peer(1), "8.8.1.1"), info(peer(1), "8.8.1.1"))
            val result = selector(slots, { list }).runSelectionPass()
            result.reserved shouldBe listOf(peer(1))
        }

        test("a failing candidate source is survived") {
            val slots = FakeSlots(clock = clock)
            selector(slots, { error("directory down") }).runSelectionPass().reserved.shouldBeEmpty()
        }

        test("DoS: with 1000 hostile candidates only candidateLimit are considered and maxAttemptsPerPass tried") {
            val slots = FakeSlots(failFor = (1..1000).map { peerIdx(it) }.toSet(), clock = clock)
            val list = (1..1000).map { info(peerIdx(it), "8.8.${it % 250}.${(it / 250) + 1}") }
            val rankerInput = AtomicInteger(0)
            val ranker =
                RelayCandidateRanker {
                    rankerInput.set(it.size)
                    it
                }
            val result = selector(slots, { list }, ranker).runSelectionPass()
            rankerInput.get() shouldBe 16
            slots.attempts.size shouldBe 4
            result.failed.size shouldBe 4
        }

        test("unusable entries do not use up the candidateLimit (backed-off, held, self, duplicates)") {
            val slots = FakeSlots(failFor = (1..16).map { peerIdx(it) }.toSet(), clock = clock)
            val list = (1..20).map { info(peerIdx(it), "8.8.$it.1") }
            val sel = selector(slots, { list }, config = AutoRelayConfig(maxAttemptsPerPass = 16))
            // Pass 1 fails the first 16 and backs them off.
            sel.runSelectionPass().failed.size shouldBe 16
            slots.attempts.clear()
            // Pass 2: the 16 are in backoff; the working 17..20 must still be reached.
            val result = sel.runSelectionPass()
            result.reserved shouldBe listOf(peerIdx(17), peerIdx(18))
        }

        test("a huge candidateLimit does not overflow the raw scan bound") {
            val slots = FakeSlots(clock = clock)
            val list = (1..3).map { info(peer(it), "8.8.$it.1") }
            val result =
                selector(slots, { list }, config = AutoRelayConfig(candidateLimit = Int.MAX_VALUE)).runSelectionPass()
            result.reserved.size shouldBe 2
        }

        test("the failure memory is capped") {
            val slots = FakeSlots(failFor = (1..40).map { peerIdx(it) }.toSet(), clock = clock)
            val list = (1..40).map { info(peerIdx(it), "8.8.$it.1") }
            val sel =
                selector(
                    slots,
                    { list },
                    config = AutoRelayConfig(candidateLimit = 40, maxAttemptsPerPass = 40, maxBackoffEntries = 5),
                )
            sel.runSelectionPass().failed.size shouldBe 40
            // A second pass retries those that fell out of the capped memory (40 - 5 = 35), not all 40.
            slots.attempts.clear()
            sel.runSelectionPass()
            slots.attempts.size shouldBe 35
        }

        test("non-public candidate addresses are dropped unless explicitly allowed") {
            val slots = FakeSlots(clock = clock)
            val hostile =
                listOf(
                    info(peer(1), "127.0.0.1"),
                    info(peer(2), "10.0.0.7"),
                    info(peer(3), "169.254.169.254"),
                    info(peer(4), "192.168.1.1"),
                    PeerInfo(peer(5), listOf(Multiaddr("/dns4/localhost/tcp/4001"))),
                    PeerInfo(peer(6), listOf(Multiaddr("/ip4/10.0.0.1/tcp/4001"), Multiaddr("/ip4/8.8.6.6/tcp/4001"))),
                )
            val result =
                selector(slots, {
                    hostile
                }, config = AutoRelayConfig(targetRelayCount = 4, maxAttemptsPerPass = 10)).runSelectionPass()
            result.reserved shouldBe listOf(peer(6))
            // The unsafe address of a mixed candidate is stripped before dialling.
            slots.held[peer(6)]!!.relayAddresses.map { it.toString() } shouldBe listOf("/ip4/8.8.6.6/tcp/4001")

            val lan = FakeSlots(clock = clock)
            val allowed =
                selector(
                    lan,
                    { hostile },
                    config =
                        AutoRelayConfig(
                            targetRelayCount = 4,
                            maxAttemptsPerPass = 10,
                            allowNonPublicCandidateAddresses = true,
                        ),
                ).runSelectionPass()
            allowed.reserved.size shouldBe 4
        }

        test("SSRF: DNS-form and smuggled IPv6 candidate addresses are dropped by default") {
            val hostileAddrs =
                listOf(
                    "/dns4/localtest.me/tcp/4001",
                    "/dns4/10.0.0.1.nip.io/tcp/22",
                    "/dns6/rebind.attacker.example/tcp/4001",
                    "/dns/relay.example.org/tcp/4001",
                    "/dnsaddr/bootstrap.example.org",
                    "/ip6/64:ff9b::a00:1/tcp/4001", // NAT64 -> 10.0.0.1
                    "/ip6/2002:a00:1::1/tcp/4001", // 6to4 embedding 10.0.0.1
                    "/ip6/2001:0:4136:e378:8000:63bf:3fff:fdd2/tcp/4001", // Teredo
                    "/ip6/::a00:1/tcp/4001", // IPv4-compatible
                    "/ip6/100::1/tcp/4001", // discard-only
                    "/ip6/fec0::1/tcp/4001", // site-local
                )
            val hostile = hostileAddrs.mapIndexed { i, a -> PeerInfo(peer(i + 1), listOf(Multiaddr(a))) }
            val slots = FakeSlots(clock = clock)
            val result =
                selector(
                    slots,
                    { hostile },
                    config = AutoRelayConfig(targetRelayCount = 4, maxAttemptsPerPass = 20),
                ).runSelectionPass()
            result.reserved.shouldBeEmpty()
            slots.attempts.shouldBeEmpty()

            // Explicit operator opt-in still allows them.
            val lan = FakeSlots(clock = clock)
            val allowed =
                selector(
                    lan,
                    { hostile },
                    config =
                        AutoRelayConfig(
                            targetRelayCount = 4,
                            maxAttemptsPerPass = 20,
                            allowNonPublicCandidateAddresses = true,
                        ),
                ).runSelectionPass()
            allowed.reserved.size shouldBe 4
        }

        test("start() runs a first pass immediately and stop() ends the thread") {
            val slots = FakeSlots(clock = clock)
            val list = listOf(info(peer(1), "8.8.1.1"))
            val sel = selector(slots, { list }, config = AutoRelayConfig(targetRelayCount = 1))
            sel.start()
            sel.isRunning() shouldBe true
            val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos()
            while (slots.held.isEmpty() && System.nanoTime() < deadline) Thread.sleep(20)
            slots.held.keys.toList() shouldBe listOf(peer(1))
            sel.stop()
            sel.isRunning() shouldBe false
            val alive = Thread.getAllStackTraces().keys.any { it.name == "lapis-relay-autoselect" && it.isAlive }
            // The thread must terminate shortly after stop().
            val gone = System.nanoTime() + Duration.ofSeconds(5).toNanos()
            var still = alive
            while (still && System.nanoTime() < gone) {
                Thread.sleep(20)
                still = Thread.getAllStackTraces().keys.any { it.name == "lapis-relay-autoselect" && it.isAlive }
            }
            still shouldBe false
        }

        test("start() after stop() does nothing") {
            val slots = FakeSlots(clock = clock)
            val sel = selector(slots, { listOf(info(peer(1), "8.8.1.1")) })
            sel.stop()
            sel.start()
            sel.isRunning() shouldBe false
            slots.held.isEmpty() shouldBe true
        }
    })
