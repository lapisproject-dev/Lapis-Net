@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path.sybil

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.shouldBeGreaterThan
import io.kotest.matchers.doubles.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock
import java.io.File
import kotlin.math.abs
import kotlin.math.max
import kotlin.time.Duration.Companion.minutes

/**
 * Sybil simulation of the REAL path selection (wave I). The small sample runs in `check` (about 500 clients per cell);
 * the full run for the published table is gated by `-PlapisSybilFull=true` (see docs/anonymity.adoc).
 */
class SybilPathSimulationTest :
    FunSpec({
        val clock = WireTestClock()
        val population = RelayPopulation(100, clock.millis() / 1000)
        val sim = SybilPathSimulation(population, clock)
        val seed = 20261027L
        val sample = 500

        fun cell(
            f: Double,
            placement: AdversaryPlacement,
            reputation: AdversaryReputation,
            honestBuckets: Int = 100,
        ) = sim.run(
            SybilScenario(
                adversaryFraction = f,
                placement = placement,
                reputation = reputation,
                honestBuckets = honestBuckets,
            ),
            sample,
            seed,
        )

        test("the same seed gives identical counts (the parallel run is deterministic)") {
            val a = cell(0.20, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.LIKE_HONEST)
            val b = cell(0.20, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.LIKE_HONEST)
            a shouldBe b
        }

        test("adversary relays in one /16 can never hold guard and exit of the same circuit (diversity rule)") {
            for (f in listOf(0.10, 0.33)) {
                val r = cell(f, AdversaryPlacement.SAME_V4_16, AdversaryReputation.MAXIMAL)
                r.guardAndExit.successes shouldBe 0
                r.clientEverGuardAndExit.successes shouldBe 0
                r.insufficientCircuits shouldBe 0
            }
        }

        test("the same holds for relays in one /48") {
            val r = cell(0.33, AdversaryPlacement.SAME_V6_48, AdversaryReputation.MAXIMAL)
            r.guardAndExit.successes shouldBe 0
            r.clientEverGuardAndExit.successes shouldBe 0
        }

        test("relays without any address: at most one unknown-network relay per path, so never guard and exit") {
            // NetworkBucket.Unknown conflicts with Unknown in OnionPathSelector.conflicts(), so two unknown relays never share a path
            val r = cell(0.33, AdversaryPlacement.NO_ADDRESS, AdversaryReputation.MAXIMAL)
            r.guardAndExit.successes shouldBe 0
            r.clientEverGuardAndExit.successes shouldBe 0
        }

        test("bucket cap: 33 % of the relays in one /16 hold at most max(0.10, 1/buckets) of the guard choices") {
            val r = cell(0.33, AdversaryPlacement.SAME_V4_16, AdversaryReputation.MAXIMAL)
            val buckets = 1 + (100 - 33) // one adversary bucket plus one bucket per honest relay
            r.guardAdversarial.estimate shouldBeLessThanOrEqual
                (max(0.10, 1.0 / buckets) + 3 * r.guardAdversarial.standardError)
        }

        test("relays without history together stay below their cap even at 33 % of the relays") {
            val r = cell(0.33, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.NEW)
            r.guardAdversarial.estimate shouldBeLessThanOrEqual (0.15 + 3 * r.guardAdversarial.standardError)
        }

        test("more adversary relays mean a higher chance (distinct addresses, maximal reputation)") {
            val small = cell(0.05, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.MAXIMAL)
            val large = cell(0.33, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.MAXIMAL)
            large.guardAdversarial.estimate shouldBeGreaterThan small.guardAdversarial.estimate
        }

        test("Madli is a weight, not a gate: a maximal reputation helps the adversary compared with being new") {
            val new = cell(0.20, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.NEW)
            val maximal = cell(0.20, AdversaryPlacement.DISTINCT_V4_16, AdversaryReputation.MAXIMAL)
            maximal.guardAdversarial.estimate shouldBeGreaterThan new.guardAdversarial.estimate
            // never a gate: a new relay still gets chosen sometimes
            (new.guardAdversarial.successes > 0) shouldBe true
        }

        test("Wilson interval against reference values") {
            fun near(
                a: Double,
                b: Double,
            ) = abs(a - b) < 5e-4
            val zero = ProportionEstimate(0, 100).wilson95()
            near(zero.start, 0.0) shouldBe true
            near(zero.endInclusive, 0.0370) shouldBe true
            val all = ProportionEstimate(100, 100).wilson95()
            near(all.start, 0.9630) shouldBe true
            near(all.endInclusive, 1.0) shouldBe true
            val half = ProportionEstimate(50, 100).wilson95()
            near(half.start, 0.4038) shouldBe true
            near(half.endInclusive, 0.5962) shouldBe true
            ProportionEstimate(0, 0).wilson95() shouldBe 0.0..1.0
        }

        test("full run for the published table (only with -PlapisSybilFull=true)")
            .config(enabled = System.getProperty("lapis.sybil.full") == "true", timeout = 120.minutes) {
                val clients = 20_000
                val cells = ArrayList<SybilCellResult>()
                for (f in listOf(0.05, 0.10, 0.20, 0.33)) {
                    for (placement in AdversaryPlacement.entries) {
                        for (reputation in listOf(AdversaryReputation.NEW, AdversaryReputation.MAXIMAL)) {
                            cells +=
                                sim.run(
                                    SybilScenario(
                                        adversaryFraction = f,
                                        placement = placement,
                                        reputation = reputation,
                                    ),
                                    clients,
                                    seed,
                                )
                        }
                    }
                }
                for (f in listOf(0.05, 0.10, 0.20, 0.33)) {
                    for (reputation in listOf(AdversaryReputation.NEW, AdversaryReputation.MAXIMAL)) {
                        cells +=
                            sim.run(
                                SybilScenario(
                                    adversaryFraction = f,
                                    placement = AdversaryPlacement.DISTINCT_V4_16,
                                    reputation = reputation,
                                    honestBuckets = 20,
                                ),
                                clients,
                                seed,
                            )
                    }
                }
                val out = File("build/sybil-simulation").also { it.mkdirs() }.resolve("table.adoc")
                out.writeText(
                    SybilTableFormatter.asciidoc(
                        cells,
                        seed,
                        "./gradlew clean :lapis-net-onion-wire:test --tests '*SybilPathSimulationTest*' -PlapisSybilFull=true",
                    ),
                )
                println("SYBIL table written: ${out.absolutePath}")
            }
    })
