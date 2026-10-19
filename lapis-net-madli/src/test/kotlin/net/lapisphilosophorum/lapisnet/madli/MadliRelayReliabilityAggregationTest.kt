package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

private fun peerOf(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private val coreMetrics = MadliMetrics(500_000, 10_000_000L, 50, 900_000, 700_000, 10)

private fun relayVec(
    observer: Secp256k1KeyPair,
    peer: PeerId,
    day: Long,
    reliability: Int,
    core: MadliMetrics? = null,
): MadliDailyVector = MadliDailyVector.create(observer, peer, day, core, MadliRelayMetrics(reliability, 5))

class MadliRelayReliabilityAggregationTest :
    FunSpec({
        val peer = peerOf(1)

        test("a single observer's relay reliability is returned as is") {
            val v = relayVec(Secp256k1KeyPair.generate(), peer, 10L, 640_000)
            MadliAggregator.aggregateRelayReliability(listOf(v), { 1.0 }, 10L) shouldBe 640_000
        }

        test("no vector with a relay block yields null") {
            val core = MadliDailyVector.create(Secp256k1KeyPair.generate(), peer, 10L, coreMetrics)
            MadliAggregator.aggregateRelayReliability(listOf(core), { 1.0 }, 10L).shouldBeNull()
            MadliAggregator.aggregateRelayReliability(emptyList(), { 1.0 }, 10L).shouldBeNull()
        }

        test("weighted median follows the heavier observers") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val c = Secp256k1KeyPair.generate()
            val vectors =
                listOf(
                    relayVec(a, peer, 10L, 100_000),
                    relayVec(b, peer, 10L, 100_000),
                    relayVec(c, peer, 10L, 1_000_000),
                )
            MadliAggregator.aggregateRelayReliability(vectors, { 1.0 }, 10L) shouldBe 100_000
            // Give the outlier overwhelming weight: median follows it.
            MadliAggregator.aggregateRelayReliability(vectors, { if (it == c.publicKey) 10.0 else 1.0 }, 10L) shouldBe
                1_000_000
        }

        test("zero-weight observers are ignored") {
            val a = Secp256k1KeyPair.generate()
            val sybil = Secp256k1KeyPair.generate()
            val vectors = listOf(relayVec(a, peer, 10L, 200_000), relayVec(sybil, peer, 10L, 1_000_000))
            MadliAggregator.aggregateRelayReliability(vectors, {
                if (it ==
                    sybil.publicKey
                ) {
                    0.0
                } else {
                    1.0
                }
            }, 10L) shouldBe
                200_000
            MadliAggregator.aggregateRelayReliability(vectors, { 0.0 }, 10L).shouldBeNull()
        }

        test("decay: a fresh observer outweighs an old one at the same base weight") {
            val old = Secp256k1KeyPair.generate()
            val fresh = Secp256k1KeyPair.generate()
            val vectors = listOf(relayVec(old, peer, 0L, 900_000), relayVec(fresh, peer, 100L, 100_000))
            MadliAggregator.aggregateRelayReliability(vectors, { 1.0 }, 100L) shouldBe 100_000
        }

        test("an observer with many backdated days counts once (freshest representative)") {
            val flooder = Secp256k1KeyPair.generate()
            val honest1 = Secp256k1KeyPair.generate()
            val honest2 = Secp256k1KeyPair.generate()
            val vectors =
                (0L..100L).map { relayVec(flooder, peer, 200L - it, 1_000_000) } +
                    listOf(relayVec(honest1, peer, 200L, 100_000), relayVec(honest2, peer, 200L, 100_000))
            MadliAggregator.aggregateRelayReliability(vectors, { 1.0 }, 200L) shouldBe 100_000
        }

        test("relay-only vectors do not change the core aggregate") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val coreOnly = listOf(MadliDailyVector.create(a, peer, 10L, coreMetrics))
            val withRelayOnly = coreOnly + relayVec(b, peer, 10L, 1_000_000)

            MadliAggregator.aggregate(withRelayOnly, { 1.0 }, 10L) shouldBe
                MadliAggregator.aggregate(coreOnly, { 1.0 }, 10L)
            MadliAggregator.aggregate(listOf(relayVec(b, peer, 10L, 1)), { 1.0 }, 10L).shouldBeNull()
        }

        test("a combined vector contributes to both aggregates") {
            val a = Secp256k1KeyPair.generate()
            val v = relayVec(a, peer, 10L, 420_000, core = coreMetrics)
            MadliAggregator.aggregate(listOf(v), { 1.0 }, 10L)?.reachabilityMicros shouldBe 500_000
            MadliAggregator.aggregateRelayReliability(listOf(v), { 1.0 }, 10L) shouldBe 420_000
        }

        test("Sybil scenario: 50 weightless Sybils praising a bad relay do not lift it above honest observers") {
            val consumer = Secp256k1KeyPair.generate()
            val honest = (1..3).map { Secp256k1KeyPair.generate() }
            val sybils = (1..50).map { Secp256k1KeyPair.generate() }
            val graph = TrustGraph.fromEdges(honest.map { Triple(consumer.publicKey, it.publicKey, 900_000) })
            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)
            val vectors =
                honest.map { relayVec(it, peer, 10L, 100_000) } + sybils.map { relayVec(it, peer, 10L, 1_000_000) }

            MadliAggregator.aggregateRelayReliability(vectors, weight, 10L) shouldBe 100_000
        }

        test("MadliHalfLives rejects a non-positive relay half-life") {
            runCatching { MadliHalfLives(relayReliabilityDays = 0.0) }.isFailure shouldBe true
        }
    })
