@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardManager
import net.lapisphilosophorum.lapisnet.onionwire.path.PathSelectionResult
import net.lapisphilosophorum.lapisnet.onionwire.path.SelectorFixture
import net.lapisphilosophorum.lapisnet.onionwire.path.hops
import net.lapisphilosophorum.lapisnet.onionwire.path.syntheticDescriptor
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The refusal path of the REAL [OnionCircuitFactory] with a [CircuitPolicy]: a path refused before any link was tried
 * is handed to [CircuitPolicy.unbuiltPath] (so a primary probe on it goes back unused), a granted build never is. Wired
 * to [net.lapisphilosophorum.lapisnet.onionwire.path.OnionPathSelector.releaseUnbuiltPath] as in `AnonymityRuntime`,
 * only the path that carries the probe frees it.
 */
class CircuitPolicyUnbuiltPathTest :
    FunSpec({
        val node = WireTestNode(relay = false)
        afterSpec { node.close() }
        val factory = node.wire.circuitFactory()

        fun failureOf(f: CompletableFuture<*>): Throwable =
            try {
                f.get(30, TimeUnit.SECONDS)
                throw AssertionError("expected a failure")
            } catch (e: ExecutionException) {
                e.cause!!
            }

        fun recorder(): MutableList<List<OnionRelayDescriptor>> = Collections.synchronizedList(ArrayList())

        fun threeHops() = List(3) { syntheticDescriptor() }

        test("LOCKED, POOL_FULL, RATE_LIMITED and PATH_TOO_SHORT hand the refused path to unbuiltPath") {
            val cases =
                listOf(
                    CircuitAdmissionException.Kind.LOCKED to CircuitBuildGovernor().also { it.lockdown() },
                    CircuitAdmissionException.Kind.POOL_FULL to
                        CircuitBuildGovernor(maxOpenClientCircuits = 1).also {
                            it.admit(null, "other") shouldBe CircuitBuildGovernor.Admission.Granted
                        },
                    CircuitAdmissionException.Kind.RATE_LIMITED to
                        CircuitBuildGovernor(burst = 1, ratePerMinute = 1).also {
                            it.admit(null, "other") shouldBe CircuitBuildGovernor.Admission.Granted
                        },
                )
            for ((kind, governor) in cases) {
                val seen = recorder()
                node.wire.installCircuitPolicy(
                    CircuitPolicy(governor, maxDefer = 1.milliseconds, unbuiltPath = { seen += it }),
                )
                val path = threeHops()
                val e = failureOf(factory.build(path, 2.seconds, CircuitPurpose.DIRECTORY_PUBLISH))
                (e as CircuitAdmissionException).kind shouldBe kind
                seen shouldHaveSize 1
                seen[0] shouldBeSameInstanceAs path
            }
            val seen = recorder()
            node.wire.installCircuitPolicy(CircuitPolicy(CircuitBuildGovernor(), unbuiltPath = { seen += it }))
            val short = threeHops().take(2)
            val e = failureOf(factory.build(short, 2.seconds))
            (e as CircuitAdmissionException).kind shouldBe CircuitAdmissionException.Kind.PATH_TOO_SHORT
            seen shouldHaveSize 1
            seen[0] shouldBeSameInstanceAs short
        }

        test("a granted build never calls unbuiltPath, even when it fails at the first hop") {
            val seen = recorder()
            val firstHops = Collections.synchronizedList(ArrayList<Boolean>())
            node.wire.installCircuitPolicy(
                CircuitPolicy(
                    CircuitBuildGovernor(),
                    firstHopResult = { _, ok -> firstHops += ok },
                    unbuiltPath = { seen += it },
                ),
            )
            val e = failureOf(factory.build(threeHops(), 2.seconds, CircuitPurpose.DIRECTORY_PUBLISH))
            (e is CircuitAdmissionException) shouldBe false
            seen.shouldBeEmpty()
            // the build was tried: its first hop reported instead
            firstHops shouldBe listOf(false)
        }

        /** Primary and backup fixed, the primary marked unreachable and its retry delay passed: the probe is due. */
        fun probeDue(seed: Long): SelectorFixture {
            val f = SelectorFixture(seed = seed)
            repeat(8) { f.add(it + 1, 1) }
            f.selector.select(null)
            f.guards.recordFirstHopFailure(
                f.guards
                    .snapshot()
                    .primary!!
                    .identity,
            )
            f.clock.advanceSeconds(GuardManager.PRIMARY_RETRY_MAX_SECONDS + 1)
            return f
        }

        test(
            "wired to the selector: a refused probe build frees the probe, a refused non-probe build over P does not",
        ) {
            repeat(3) { seed ->
                val f = probeDue(seed.toLong())
                val p =
                    f.guards
                        .snapshot()
                        .primary!!
                        .identity
                val k =
                    f.guards
                        .snapshot()
                        .backup!!
                        .identity
                node.wire.installCircuitPolicy(
                    CircuitPolicy(
                        CircuitBuildGovernor().also { it.lockdown() },
                        unbuiltPath = f.selector::releaseUnbuiltPath,
                    ),
                )
                // the probe path is refused: the next build probes P again
                val probe = f.selector.select(null) as PathSelectionResult.Selected
                probe.probe shouldBe true
                failureOf(factory.build(probe.hops, 2.seconds)).shouldBeLocked()
                val inFlight = f.selector.select(null) as PathSelectionResult.Selected
                inFlight.hops.first().identity shouldBe p
                inFlight.probe shouldBe true
                // inFlight is not built yet; a remote last hop equal to K enters through P without the probe and is refused
                val backupDescriptor = f.relays.first { it.identity == k }
                val alternative =
                    f.selector.select(backupDescriptor, lastHopChosenRemotely = true) as PathSelectionResult.Selected
                alternative.hops.first().identity shouldBe p
                alternative.probe shouldBe false
                failureOf(factory.build(alternative.hops, 2.seconds, CircuitPurpose.INTRODUCE)).shouldBeLocked()
                // the probe of inFlight is still out: no second probe over P
                f.selector
                    .select(null)
                    .hops()
                    .first()
                    .identity shouldBe k
            }
        }
    })

private fun Throwable.shouldBeLocked() {
    (this as CircuitAdmissionException).kind shouldBe CircuitAdmissionException.Kind.LOCKED
}
