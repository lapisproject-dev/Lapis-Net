package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun pid(seed: Int): PeerId = PeerId(ByteArray(34) { seed.toByte() })

private fun pinfo(seed: Int): PeerInfo = PeerInfo(pid(seed), listOf(Multiaddr("/ip4/8.8.8.$seed/tcp/4001")))

private fun relayVector(
    observer: Secp256k1KeyPair,
    peer: PeerId,
    reliability: Int,
    day: Long = 10L,
): MadliDailyVector = MadliDailyVector.create(observer, peer, day, null, MadliRelayMetrics(reliability, 5))

class MadliRelayRankerTest :
    FunSpec({
        val observer = Secp256k1KeyPair.generate()

        fun ranker(data: Map<PeerId, List<MadliDailyVector>>) =
            MadliRelayRanker(vectorsFor = { data[it].orEmpty() }, observerWeight = { 1.0 }, epochDay = { 10L })

        test("candidates are ordered by relay reliability, best first") {
            val data =
                mapOf(
                    pid(1) to listOf(relayVector(observer, pid(1), 300_000)),
                    pid(2) to listOf(relayVector(observer, pid(2), 900_000)),
                    pid(3) to listOf(relayVector(observer, pid(3), 600_000)),
                )
            ranker(data).rank(listOf(pinfo(1), pinfo(2), pinfo(3))).map { it.peerId } shouldBe
                listOf(pid(2), pid(3), pid(1))
        }

        test("candidates without a signal come last but are still returned (no hard gate)") {
            val data = mapOf(pid(2) to listOf(relayVector(observer, pid(2), 10)))
            val ranked = ranker(data).rank(listOf(pinfo(1), pinfo(2), pinfo(3)))
            ranked.map { it.peerId } shouldBe listOf(pid(2), pid(1), pid(3))
        }

        test("ties are broken deterministically by peer id bytes") {
            val a = ranker(emptyMap()).rank(listOf(pinfo(3), pinfo(1), pinfo(2)))
            val b = ranker(emptyMap()).rank(listOf(pinfo(2), pinfo(3), pinfo(1)))
            a.map { it.peerId } shouldBe listOf(pid(1), pid(2), pid(3))
            b shouldBe a
        }

        test("an empty list and a single candidate pass through") {
            ranker(emptyMap()).rank(emptyList()) shouldBe emptyList()
            ranker(emptyMap()).rank(listOf(pinfo(1))).map { it.peerId } shouldBe listOf(pid(1))
        }

        test("only elements of the input are returned, each exactly once") {
            val input = listOf(pinfo(1), pinfo(2), pinfo(3))
            val out = ranker(emptyMap()).rank(input)
            out.toSet() shouldBe input.toSet()
            out.size shouldBe 3
        }

        test("zero-weight (Sybil) observers have no influence") {
            val sybil = Secp256k1KeyPair.generate()
            val data =
                mapOf(
                    pid(1) to listOf(relayVector(observer, pid(1), 800_000), relayVector(sybil, pid(1), 800_000)),
                    pid(2) to listOf(relayVector(sybil, pid(2), 1_000_000)),
                )
            val r = MadliRelayRanker({ data[it].orEmpty() }, { if (it == sybil.publicKey) 0.0 else 1.0 }, { 10L })
            r.score(pid(2)).shouldBeNull()
            r.rank(listOf(pinfo(2), pinfo(1))).map { it.peerId } shouldBe listOf(pid(1), pid(2))
        }

        test("a bad relay praised by 50 weightless Sybils and rated 10% by 3 real observers does not rank first") {
            val honest = (1..3).map { Secp256k1KeyPair.generate() }
            val sybils = (1..50).map { Secp256k1KeyPair.generate() }
            val bad = pid(1)
            val good = pid(2)
            val data =
                mapOf(
                    bad to honest.map {
                        relayVector(
                            it,
                            bad,
                            100_000,
                        )
                    } + sybils.map { relayVector(it, bad, 1_000_000) },
                    good to honest.map { relayVector(it, good, 900_000) },
                )
            val honestKeys = honest.map { it.publicKey }.toSet()
            val r = MadliRelayRanker({ data[it].orEmpty() }, { if (it in honestKeys) 1.0 else 0.0 }, { 10L })
            r.rank(listOf(pinfo(1), pinfo(2))).first().peerId shouldBe good
            (r.score(bad)!! < 0.2) shouldBe true
        }

        test("core reachability breaks near-ties in favour of the more reachable relay") {
            val core = MadliMetrics(1_000_000, 1L, 1, 1_000_000, 1_000_000, 1)
            val lowCore = MadliMetrics(100_000, 1L, 1, 1_000_000, 1_000_000, 1)
            val data =
                mapOf(
                    pid(1) to
                        listOf(MadliDailyVector.create(observer, pid(1), 10L, lowCore, MadliRelayMetrics(500_000, 5))),
                    pid(2) to
                        listOf(MadliDailyVector.create(observer, pid(2), 10L, core, MadliRelayMetrics(500_000, 5))),
                )
            ranker(data).rank(listOf(pinfo(1), pinfo(2))).first().peerId shouldBe pid(2)
        }
    })
