@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path.sybil

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardManager
import net.lapisphilosophorum.lapisnet.onionwire.path.InMemoryGuardStateStore
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.NetworkBucket
import net.lapisphilosophorum.lapisnet.onionwire.path.OnionPathSelector
import net.lapisphilosophorum.lapisnet.onionwire.path.PathSelectionResult
import net.lapisphilosophorum.lapisnet.onionwire.path.RelayReputation
import net.lapisphilosophorum.lapisnet.onionwire.path.seededRandom
import net.lapisphilosophorum.lapisnet.onionwire.path.syntheticDescriptor
import java.util.concurrent.atomic.AtomicInteger
import java.util.stream.IntStream
import kotlin.math.roundToInt
import kotlin.math.sqrt

/** Where the adversary claims its relays to be. The addresses are SELF-DECLARED by relays, so every placement is possible. */
enum class AdversaryPlacement { DISTINCT_V4_16, SAME_V4_16, SAME_V6_48, NO_ADDRESS }

/** The Madli reliability the adversary's relays carry: none (new), like the honest distribution, or the maximum. */
enum class AdversaryReputation { NEW, LIKE_HONEST, MAXIMAL }

data class SybilScenario(
    val totalRelays: Int = 100,
    /** Share of adversarial relays: 0.05, 0.10, 0.20, 0.33. */
    val adversaryFraction: Double,
    val placement: AdversaryPlacement,
    val reputation: AdversaryReputation,
    /** Honest relays are spread over this many distinct /16 networks (100 = each in its own). */
    val honestBuckets: Int = 100,
    val circuitsPerClient: Int = 20,
) {
    val adversaryCount: Int get() = (totalRelays * adversaryFraction).roundToInt()
}

/** A proportion with its 95 % Wilson score interval. */
data class ProportionEstimate(
    val successes: Int,
    val trials: Int,
) {
    val estimate: Double get() = if (trials == 0) 0.0 else successes.toDouble() / trials

    /** Standard error of the plain estimate (used for the three-sigma bounds of the CI tests). */
    val standardError: Double get() = if (trials == 0) 0.0 else sqrt(estimate * (1 - estimate) / trials)

    fun wilson95(): ClosedFloatingPointRange<Double> {
        if (trials == 0) return 0.0..1.0
        val n = trials.toDouble()
        val p = estimate
        val z2 = Z * Z
        val denom = 1 + z2 / n
        val center = (p + z2 / (2 * n)) / denom
        val half = Z * sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
        return maxOf(0.0, center - half)..minOf(1.0, center + half)
    }

    private companion object {
        const val Z = 1.959964
    }
}

data class SybilCellResult(
    val scenario: SybilScenario,
    val seed: Long,
    val clients: Int,
    /** P(guard is adversarial), first circuit of each client. */
    val guardAdversarial: ProportionEstimate,
    /** P(last hop is adversarial), drawn exit, first circuit of each client. */
    val exitAdversarial: ProportionEstimate,
    /** P(guard and exit adversarial), first circuit of each client. */
    val guardAndExit: ProportionEstimate,
    /** P(at least one of the client's circuits has guard and exit adversarial). */
    val clientEverGuardAndExit: ProportionEstimate,
    /** P(guard of a client AND guard of a second, independent client are adversarial): both ends of one conversation. */
    val bothEndsGuardsAdversarial: ProportionEstimate,
    /** f squared, the value a uniform choice without any policy would give; for comparison only. */
    val uniformBaseline: Double,
    /** Circuits that ended as "insufficient relays" (counted and reported, never swallowed). */
    val insufficientCircuits: Int,
)

/** The expensive part (signed descriptors over fresh identities) is done ONCE; scenarios only relabel them. */
class RelayPopulation(
    val size: Int,
    nowEpochSecond: Long,
) {
    val descriptors: List<OnionRelayDescriptor> = List(size) { syntheticDescriptor(nowEpochSecond = nowEpochSecond) }
    val peerIds: List<PeerId> = descriptors.map { it.peerId }
}

/**
 * Drives the REAL [OnionPathSelector], [GuardManager] and path policy (no mock) over a synthetic relay population with
 * an adversary that controls a share of the relays. No network, deterministic for a given seed.
 *
 * Model assumptions (they appear next to the published table): honest reliability is spread evenly over [0.5, 0.95],
 * 10 % of the honest relays have no history; honest relays sit in [SybilScenario.honestBuckets] distinct /16 networks;
 * the adversary needs no more than self-declared addresses. Not modelled: a global observer, timing correlation beyond
 * guard plus exit, circuits with a prescribed last hop (intro and rendezvous), churn, guard lifetime over time.
 */
class SybilPathSimulation(
    private val population: RelayPopulation,
    private val clock: WireTestClock,
) {
    private class Setup(
        val locator: MapLocator,
        val reputation: Map<PeerId, Double>,
        val adversarial: Set<net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey>,
        val descriptors: List<OnionRelayDescriptor>,
    )

    private fun setup(scenario: SybilScenario): Setup {
        require(scenario.totalRelays <= population.size) { "population too small" }
        val all = population.descriptors.take(scenario.totalRelays)
        val k = scenario.adversaryCount
        val locator = MapLocator()
        val reputation = HashMap<PeerId, Double>()
        val honest = all.drop(k)
        // honest: bucket by index, reputation evenly spread, every tenth without history
        val withHistory = honest.indices.filter { it % NO_HISTORY_EVERY != 0 }
        honest.forEachIndexed { j, d ->
            locator.put(d, NetworkBucket.V4(HONEST_BASE + j % scenario.honestBuckets))
        }
        withHistory.forEachIndexed { rank, j ->
            reputation[population.peerIds[k + j]] = spread(rank, withHistory.size)
        }
        for (i in 0 until k) {
            val d = all[i]
            when (scenario.placement) {
                AdversaryPlacement.DISTINCT_V4_16 -> locator.put(d, NetworkBucket.V4(ADVERSARY_BASE + i))
                AdversaryPlacement.SAME_V4_16 -> locator.put(d, NetworkBucket.V4(ADVERSARY_BASE))
                AdversaryPlacement.SAME_V6_48 -> locator.put(d, NetworkBucket.V6(ADVERSARY_V6))
                AdversaryPlacement.NO_ADDRESS -> Unit // the locator answers "unknown network"
            }
            when (scenario.reputation) {
                AdversaryReputation.NEW -> Unit
                AdversaryReputation.LIKE_HONEST -> reputation[population.peerIds[i]] = spread(i, k)
                AdversaryReputation.MAXIMAL -> reputation[population.peerIds[i]] = 1.0
            }
        }
        return Setup(locator, reputation, all.take(k).map { it.identity }.toSet(), all)
    }

    private fun spread(
        rank: Int,
        count: Int,
    ): Double = if (count <= 1) 0.725 else HONEST_MIN + (HONEST_MAX - HONEST_MIN) * rank / (count - 1)

    fun run(
        scenario: SybilScenario,
        clients: Int,
        seed: Long,
    ): SybilCellResult {
        val s = setup(scenario)
        val guardAdv = AtomicInteger()
        val exitAdv = AtomicInteger()
        val both = AtomicInteger()
        val ever = AtomicInteger()
        val bothEnds = AtomicInteger()
        val insufficient = AtomicInteger()
        val reputation = RelayReputation { s.reputation[it] }

        fun newSelector(clientSeed: Long): OnionPathSelector {
            val random = seededRandom(clientSeed)
            return OnionPathSelector(
                { s.descriptors },
                OWN_IDENTITY.secp256k1KeyPair.publicKey,
                s.locator,
                reputation,
                guards = GuardManager(InMemoryGuardStateStore(), random, clock),
                random = random,
                clock = clock,
            )
        }

        IntStream.range(0, clients).parallel().forEach { i ->
            val selector = newSelector(seed * SEED_MIX + i)
            var firstDone = false
            var anyBoth = false
            repeat(scenario.circuitsPerClient) {
                when (val r = selector.select(lastHop = null)) {
                    is PathSelectionResult.Selected -> {
                        val g = r.hops.first().identity in s.adversarial
                        val e = r.hops.last().identity in s.adversarial
                        if (!firstDone) {
                            firstDone = true
                            if (g) guardAdv.incrementAndGet()
                            if (e) exitAdv.incrementAndGet()
                            if (g && e) both.incrementAndGet()
                        }
                        if (g && e) anyBoth = true
                    }
                    PathSelectionResult.Insufficient -> insufficient.incrementAndGet()
                }
            }
            if (anyBoth) ever.incrementAndGet()
            // a second, independent client (the other end of a conversation): only its guard matters
            val peer = newSelector(seed * SEED_MIX + clients + i)
            val clientGuard = selector.select(lastHop = null)
            val peerGuard = peer.select(lastHop = null)
            if (clientGuard is PathSelectionResult.Selected &&
                peerGuard is PathSelectionResult.Selected &&
                clientGuard.hops.first().identity in s.adversarial &&
                peerGuard.hops.first().identity in s.adversarial
            ) {
                bothEnds.incrementAndGet()
            }
        }
        val f = scenario.adversaryCount.toDouble() / scenario.totalRelays
        return SybilCellResult(
            scenario,
            seed,
            clients,
            ProportionEstimate(guardAdv.get(), clients),
            ProportionEstimate(exitAdv.get(), clients),
            ProportionEstimate(both.get(), clients),
            ProportionEstimate(ever.get(), clients),
            ProportionEstimate(bothEnds.get(), clients),
            f * f,
            insufficient.get(),
        )
    }

    private companion object {
        const val NO_HISTORY_EVERY = 10
        const val HONEST_MIN = 0.5
        const val HONEST_MAX = 0.95
        const val HONEST_BASE = 1_000
        const val ADVERSARY_BASE = 40_000
        const val ADVERSARY_V6 = 0x2001_0DB8_0001L
        const val SEED_MIX = 1_000_003L
        val OWN_IDENTITY: DualKeyIdentity = DualKeyIdentity.generate()
    }
}

object SybilTableFormatter {
    private fun pct(p: ProportionEstimate): String {
        val ci = p.wilson95()
        return "%.2f%% (%.2f-%.2f)".format(
            java.util.Locale.ROOT,
            p.estimate * 100,
            ci.start * 100,
            ci.endInclusive * 100,
        )
    }

    fun asciidoc(
        results: List<SybilCellResult>,
        seed: Long,
        command: String,
    ): String =
        buildString {
            appendLine("// generated by SybilPathSimulationTest, do not edit by hand")
            appendLine("// seed: $seed")
            appendLine("// command: $command")
            appendLine()
            appendLine("[cols=\"1,2,2,2,2,2,2,2,1\", options=\"header\"]")
            appendLine("|===")
            appendLine(
                "| f | Placement | Reputation | P(G) | P(E) | P(G and E) | P(any G and E in ${results.firstOrNull()?.scenario?.circuitsPerClient ?: 20} circuits) | P(both ends G) | f^2",
            )
            for (r in results) {
                val sc = r.scenario
                val placement =
                    sc.placement.name + if (sc.honestBuckets != 100) " (honest in ${sc.honestBuckets} /16)" else ""
                appendLine(
                    "| %.0f%% | %s | %s | %s | %s | %s | %s | %s | %.2f%%".format(
                        java.util.Locale.ROOT,
                        sc.adversaryFraction * 100,
                        placement,
                        sc.reputation.name,
                        pct(r.guardAdversarial),
                        pct(r.exitAdversarial),
                        pct(r.guardAndExit),
                        pct(r.clientEverGuardAndExit),
                        pct(r.bothEndsGuardsAdversarial),
                        r.uniformBaseline * 100,
                    ),
                )
            }
            appendLine("|===")
            val clients = results.firstOrNull()?.clients ?: 0
            val insufficient = results.sumOf { it.insufficientCircuits }
            appendLine()
            appendLine(
                "Clients per cell: $clients. Circuits that ended as \"insufficient relays\" over all cells: $insufficient.",
            )
        }
}
