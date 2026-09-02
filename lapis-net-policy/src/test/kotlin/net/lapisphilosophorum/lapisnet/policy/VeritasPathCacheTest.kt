package net.lapisphilosophorum.lapisnet.policy

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

class VeritasPathCacheTest :
    FunSpec({
        test("checkFor agrees with the raw, uncached veritasPathCheck") {
            val localIdentity = Secp256k1KeyPair.generate().publicKey
            val trusted = Secp256k1KeyPair.generate().publicKey
            val untrusted = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(localIdentity, trusted, MAX_TRUST_MICROS)))
            val cache = VeritasPathCache(graph)
            val cached = cache.checkFor(localIdentity)
            val raw = AcceptanceGateEvaluator.veritasPathCheck(graph, localIdentity)

            cached(trusted) shouldBe raw(trusted)
            cached(untrusted) shouldBe raw(untrusted)
            cached(trusted) shouldBe true
            cached(untrusted) shouldBe false
        }

        test("a zero-weight edge is NOT treated as a positive trust path - existence != positive score") {
            val localIdentity = Secp256k1KeyPair.generate().publicKey
            val zeroWeightTarget = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(localIdentity, zeroWeightTarget, 0)))
            val cache = VeritasPathCache(graph)

            cache.checkFor(localIdentity)(zeroWeightTarget) shouldBe false
        }

        test("memoizes: a repeat query against the same candidate is not recomputed") {
            val pLayerSize = 150
            val tLayerSize = 150
            val localIdentity = Secp256k1KeyPair.generate().publicKey
            val pLayer = List(pLayerSize) { Secp256k1KeyPair.generate().publicKey }
            val tLayer = List(tLayerSize) { Secp256k1KeyPair.generate().publicKey }
            val edges = mutableListOf<Triple<Secp256k1PublicKey, Secp256k1PublicKey, Int>>()
            for (p in pLayer) edges += Triple(localIdentity, p, 500_000)
            for (p in pLayer) for (t in tLayer) edges += Triple(p, t, 500_000)
            val graph = TrustGraph.fromEdges(edges)
            val candidate = tLayer.first()

            val cache = VeritasPathCache(graph)
            val check = cache.checkFor(localIdentity)

            val firstResult = check(candidate)
            val start = System.nanoTime()
            val secondResult = check(candidate)
            val elapsedMs = (System.nanoTime() - start) / 1_000_000

            secondResult shouldBe firstResult
            (elapsedMs < 5) shouldBe true
        }

        test("keyed on (localIdentity, candidate) - two identities sharing one cache don't leak into each other") {
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val candidate = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(identityA, candidate, MAX_TRUST_MICROS)))
            val cache = VeritasPathCache(graph)

            cache.checkFor(identityA)(candidate) shouldBe true
            cache.checkFor(identityB)(candidate) shouldBe false
            cache.checkFor(identityB)(candidate) shouldBe false
            cache.checkFor(identityA)(candidate) shouldBe true
        }

        test(
            "bounded: a flood of DISTINCT candidate identities (e.g. one throwaway keypair per " +
                "message) does not grow the cache without limit - regression test for the finding " +
                "that an unbounded map keyed on an attacker-controlled candidate identity is an " +
                "unbounded-heap-growth denial-of-service vector",
        ) {
            val maxTrackedEntries = 8
            val localIdentity = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())
            val cache = VeritasPathCache(graph, maxTrackedEntries = maxTrackedEntries)
            val check = cache.checkFor(localIdentity)

            // Far more distinct throwaway identities than the cap - every single one is a cache
            // miss (never repeats), exactly the attack this cap defends against.
            repeat(maxTrackedEntries * 50) {
                check(Secp256k1KeyPair.generate().publicKey)
            }

            cache.sizeForTest() shouldBe maxTrackedEntries
        }
    })
