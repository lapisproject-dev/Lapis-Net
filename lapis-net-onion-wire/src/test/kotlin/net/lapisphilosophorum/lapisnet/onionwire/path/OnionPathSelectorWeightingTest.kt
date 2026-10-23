@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.shouldBeGreaterThan
import io.kotest.matchers.doubles.shouldBeLessThan
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi

class OnionPathSelectorWeightingTest :
    FunSpec({
        test("a relay with a higher Madli reliability is drawn more often") {
            var goodDraws = 0
            var badDraws = 0
            for (seed in 1L..20L) {
                val f = SelectorFixture(seed = seed)
                val good = f.add(1, 1)
                val bad = f.add(2, 2)
                // many networks, so that the share cap of a bucket (max(0.10, 1/buckets)) does not flatten the weights
                repeat(38) { f.add(10 + it, 1) }
                f.relays.forEach { f.reputation[it.peerId] = 0.5 }
                f.reputation[good.peerId] = 0.95
                f.reputation[bad.peerId] = 0.05
                repeat(500) {
                    val d = f.selector.selectEndpoint(emptySet())!!
                    if (d.identity == good.identity) goodDraws++
                    if (d.identity == bad.identity) badDraws++
                }
            }
            (goodDraws > badDraws * 2) shouldBe true
            (badDraws > 0) shouldBe true // never a hard gate
        }

        test("weight 0 stays above the floor, NaN and infinity count as no history") {
            val f = SelectorFixture()
            val zero = f.add(1, 1)
            val nan = f.add(2, 2)
            val inf = f.add(3, 3)
            val none = f.add(4, 4)
            f.reputation[zero.peerId] = 0.0
            f.reputation[nan.peerId] = Double.NaN
            f.reputation[inf.peerId] = Double.POSITIVE_INFINITY
            val cands =
                listOf(zero, nan, inf, none).map {
                    f.selector.candidateForTesting(
                        it,
                        System.currentTimeMillis() / 1000,
                    )
                }
            val w = f.selector.weightsForTesting(cands)
            w.sum().shouldBeLessThan(1.0000001)
            w[0].shouldBeGreaterThan(0.0) // the floor: Madli is never a hard gate
            // NaN and infinity were treated as "no history": the same weight as the relay that has none
            w[1] shouldBe w[3]
            w[2] shouldBe w[3]
        }

        test("a degenerate set (one bucket, one candidate) still yields a draw, no division by zero") {
            val f = SelectorFixture()
            val d = f.add(1, 1)
            val w =
                f.selector.weightsForTesting(
                    listOf(
                        f.selector.candidateForTesting(
                            d,
                            System.currentTimeMillis() / 1000,
                        ),
                    ),
                )
            w.single() shouldBe 1.0
        }
    })

class OnionPathSelectorSybilCapTest :
    FunSpec({
        test("100 relays in one /16 plus a few others: the flood's share is capped, per hop, on the remaining set") {
            val f = SelectorFixture(seed = 11)
            val flood = (1..100).map { f.locator.put(syntheticDescriptor(), v4(66, 66)).also { d -> f.relays += d } }
            val others = (1..4).map { f.add(it, it) }
            val now = System.currentTimeMillis() / 1000
            val cands = (flood + others).map { f.selector.candidateForTesting(it, now) }
            val w = f.selector.weightsForTesting(cands)
            val floodShare = (0 until flood.size).sumOf { w[it] }
            // 5 buckets: cap = max(0.10, 1/5) = 0.2 of the total, plus a numerical tolerance
            floodShare.shouldBeLessThan(0.2 + 1e-6)
            // and without the cap it would have been 100/104
            val othersShare = (flood.size until cands.size).sumOf { w[it] }
            othersShare.shouldBeGreaterThan(0.79)
        }

        test(
            "the share is recomputed on the remaining candidates: after one other bucket is excluded the cap rises to 1/4",
        ) {
            val f = SelectorFixture(seed = 12)
            val flood = (1..100).map { f.locator.put(syntheticDescriptor(), v4(66, 66)).also { d -> f.relays += d } }
            val others = (1..3).map { f.add(it, it) }
            val now = System.currentTimeMillis() / 1000
            val w = f.selector.weightsForTesting((flood + others).map { f.selector.candidateForTesting(it, now) })
            (0 until flood.size).sumOf { w[it] }.shouldBeLessThan(0.25 + 1e-6)
        }

        test("a path through a flooded network still contains the flood in at most one hop") {
            repeat(40) { seed ->
                val f = SelectorFixture(seed = seed.toLong())
                repeat(100) { f.locator.put(syntheticDescriptor(), v4(66, 66)).also { d -> f.relays += d } }
                repeat(4) { f.add(it + 1, it + 1) }
                val hops = f.selector.select(null).hops()
                (hops.count { f.locator.bucketsOf(it.identity, 0).single() == v4(66, 66) } <= 1) shouldBe true
            }
        }
    })

class OnionPathSelectorNewRelayCapTest :
    FunSpec({
        test("relays without history together get at most 15 percent when others exist") {
            val f = SelectorFixture()
            // enough old networks that the per-bucket cap does not force mass over to the fresh relays
            val old = (1..40).map { f.add(it, it) }
            val fresh = (1..40).map { f.add(100 + it, it) }
            old.forEach { f.reputation[it.peerId] = 0.8 }
            val now = System.currentTimeMillis() / 1000
            val cands = (old + fresh).map { f.selector.candidateForTesting(it, now) }
            val w = f.selector.weightsForTesting(cands)
            val freshShare = (old.size until cands.size).sumOf { w[it] }
            freshShare.shouldBeLessThan(0.15 + 1e-6)
        }

        test("only new relays: no scaling, a path is still built") {
            val f = SelectorFixture()
            repeat(6) { f.add(it + 1, it + 1) }
            (f.selector.select(null) is PathSelectionResult.Selected) shouldBe true
        }
    })
