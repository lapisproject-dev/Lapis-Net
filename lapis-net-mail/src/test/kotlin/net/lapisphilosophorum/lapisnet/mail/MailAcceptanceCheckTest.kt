package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

/**
 * Unit tests for [MailAcceptanceCheck]'s [MailAcceptanceCheck.cachedVeritasPathCheck] memoization -
 * the round-2 security audit's mitigation for the BFS-cost finding documented on that method (V0.9.4
 * hardening: `TrustPathFinder.findPath`, newly wired into the gossip validator hot path this wave,
 * benchmarked at 13.8-16.1 ms/call on an adversarial near-cap graph, ~100-150x the ECDSA verify that
 * precedes it in `InboxGossip.onGossipMessage`).
 */
class MailAcceptanceCheckTest :
    FunSpec({
        test(
            "cachedVeritasPathCheck agrees with the raw, uncached veritasPathCheck for several " +
                "distinct candidates",
        ) {
            val localIdentity = Secp256k1KeyPair.generate().publicKey
            val trusted = Secp256k1KeyPair.generate().publicKey
            val untrusted = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(localIdentity, trusted, MAX_TRUST_MICROS)))
            val acceptance =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = graph,
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )

            val cached = acceptance.cachedVeritasPathCheck(localIdentity)
            val raw = MailAcceptancePolicy.veritasPathCheck(graph, localIdentity)

            cached(trusted) shouldBe raw(trusted)
            cached(untrusted) shouldBe raw(untrusted)
            cached(trusted) shouldBe true
            cached(untrusted) shouldBe false
            // Self always passes, cached or not - same axiom as veritasPathCheck's own regression.
            cached(localIdentity) shouldBe true
        }

        // --- ROUND-2 SECURITY AUDIT FINDING: unmemoized BFS in the gossip hot path ----------------
        // Scaled-down permanent regression, same bipartite/all-tied-weight adversarial construction
        // TrustPathFinderTest's own "bipartite tie-layer" regression uses (see that test's doc
        // comment for the full reasoning on why all-tied weights are the worst case for this
        // codebase's BFS comparator) - here used to prove the CACHE eliminates the repeat-query cost,
        // not to re-verify the BFS's own correctness (already covered by lapis-net-trust's tests).
        test(
            "cachedVeritasPathCheck memoizes: a repeat query against the same candidate on an " +
                "adversarial graph is not recomputed",
        ) {
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

            val acceptance =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = graph,
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            val check = acceptance.cachedVeritasPathCheck(localIdentity)

            // First call: cache miss, pays the full BFS cost (uncached, matches the audit's
            // benchmarked per-call cost order of magnitude on a graph this size/shape).
            val firstResult = check(candidate)

            // Second call, same candidate: cache hit - a plain ConcurrentHashMap lookup, several
            // orders of magnitude cheaper than a fresh BFS over this adversarial graph. 5ms is a
            // deliberately generous bound (this project prefers non-flaky tests over tight
            // performance assertions, mirroring TrustPathFinderTest's own "2 seconds" bound for the
            // analogous uncached case) - a hashmap hit is normally sub-microsecond, so 5ms leaves
            // several orders of magnitude of headroom for CI/JIT/GC jitter while still catching a
            // genuine regression back to "every call re-runs the BFS".
            val start = System.nanoTime()
            val secondResult = check(candidate)
            val elapsedMs = (System.nanoTime() - start) / 1_000_000

            secondResult shouldBe firstResult
            (elapsedMs < 5) shouldBe true
        }

        test(
            "cachedVeritasPathCheck keeps independent results for two different localIdentity " +
                "values sharing one MailAcceptanceCheck instance",
        ) {
            // Nothing in MailAcceptanceCheck's public shape enforces "one instance per identity" -
            // see cachedVeritasPathCheck's own doc comment on why the cache key includes
            // localIdentity, not just the candidate. This test pins that the cache genuinely keeps
            // the two separate rather than accidentally sharing/poisoning one verdict across them.
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val candidate = Secp256k1KeyPair.generate().publicKey
            // candidate is trusted FROM identityA, but NOT from identityB.
            val graph = TrustGraph.fromEdges(listOf(Triple(identityA, candidate, MAX_TRUST_MICROS)))
            val acceptance =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = graph,
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )

            acceptance.cachedVeritasPathCheck(identityA)(candidate) shouldBe true
            acceptance.cachedVeritasPathCheck(identityB)(candidate) shouldBe false
            // Repeat, in the opposite order, to rule out a cache keyed on candidate-only having
            // let the first lookup's verdict leak into the second.
            acceptance.cachedVeritasPathCheck(identityB)(candidate) shouldBe false
            acceptance.cachedVeritasPathCheck(identityA)(candidate) shouldBe true
        }
    })
