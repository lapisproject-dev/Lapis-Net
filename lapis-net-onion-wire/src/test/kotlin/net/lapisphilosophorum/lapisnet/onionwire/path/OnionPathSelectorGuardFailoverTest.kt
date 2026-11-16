@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi

/**
 * Path selection after a guard failover (fix wave "rendezvous after guard failover"): the remotely chosen last hop equal
 * to the effective guard, and the in-memory reachability mark of the primary.
 */
class OnionPathSelectorGuardFailoverTest :
    FunSpec({
        fun fixture(seed: Long = 1): SelectorFixture {
            val f = SelectorFixture(seed = seed)
            repeat(8) { f.add(it + 1, 1) }
            f.selector.select(null) // fixes primary and backup
            return f
        }

        fun SelectorFixture.primary() = guards.snapshot().primary!!.identity

        fun SelectorFixture.backup() = guards.snapshot().backup!!.identity

        test("remote last hop equals the backup while the primary's descriptor is missing: GuardConflict") {
            repeat(5) { seed ->
                val f = fixture(seed.toLong())
                val p = f.primary()
                val k = f.backup()
                f.relays.removeAll { it.identity == p }
                // the backup is the effective guard now
                f.selector
                    .select(null)
                    .hops()
                    .first()
                    .identity shouldBe k
                val backupDescriptor = f.relays.first { it.identity == k }
                f.selector.select(backupDescriptor, lastHopChosenRemotely = true) shouldBe
                    PathSelectionResult.GuardConflict
                val e =
                    shouldThrow<GuardConflictException> {
                        SelectingOnionPathProvider(f.selector).pathEndingAt(
                            backupDescriptor,
                            CircuitPurpose.RENDEZVOUS_RECEIVER,
                        )
                    }
                // existing callers that catch InsufficientRelaysException are unaffected, the text names nothing
                e.shouldBeInstanceOf<InsufficientRelaysException>()
                e.message shouldBe "insufficient relays"
            }
        }

        test(
            "a primary marked unreachable: builds enter through the backup, a remote hop equal to it through the primary",
        ) {
            repeat(5) { seed ->
                val f = fixture(seed.toLong())
                val p = f.primary()
                val k = f.backup()
                f.guards.recordFirstHopFailure(p)
                f.guards.isPrimaryMarkedUnreachable() shouldBe true
                f.selector
                    .select(null)
                    .hops()
                    .first()
                    .identity shouldBe k
                val backupDescriptor = f.relays.first { it.identity == k }
                val path = f.selector.select(backupDescriptor, lastHopChosenRemotely = true).hops()
                path shouldHaveSize 3
                path.first().identity shouldBe p
                path.last().identity shouldBe k
                path.map { it.identity }.toSet() shouldHaveSize 3
                // the persisted primary is unchanged
                f.primary() shouldBe p
            }
        }

        test("selectEndpoint excludes a primary marked unreachable (and the effective guard)") {
            val f = fixture()
            val p = f.primary()
            val k = f.backup()
            f.guards.recordFirstHopFailure(p)
            repeat(200) {
                val e = f.selector.selectEndpoint(emptySet())!!.identity
                (e == p) shouldBe false
                (e == k) shouldBe false
            }
        }

        test("a check without a build never takes the primary probe; a build does, exactly once") {
            val f = fixture()
            val p = f.primary()
            val k = f.backup()
            f.guards.recordFirstHopFailure(p)
            f.clock.advanceSeconds(GuardManager.PRIMARY_RETRY_MAX_SECONDS + 1)
            repeat(5) {
                f.selector
                    .select(null, forBuild = false)
                    .hops()
                    .first()
                    .identity shouldBe k
                f.selector.selectEndpoint(emptySet())
            }
            f.selector
                .select(null)
                .hops()
                .first()
                .identity shouldBe p
            f.selector
                .select(null)
                .hops()
                .first()
                .identity shouldBe k
        }

        /** The `a` of the primary's /16 in [SelectorFixture.add] (relay i was added as `add(i + 1, 1)`). */
        fun SelectorFixture.primaryNet() = relays.indexOfFirst { it.identity == primary() } + 1

        test("selectEndpoint is diverse to a marked primary's network as well, not only to its identity") {
            repeat(5) { seed ->
                val f = fixture(seed.toLong())
                val p = f.primary()
                f.guards.recordFirstHopFailure(p)
                val net = f.primaryNet()
                // three more relays in the primary's /16
                val sameNet = List(3) { f.add(net, 1).identity }.toSet()
                repeat(200) {
                    val e = f.selector.selectEndpoint(emptySet())!!.identity
                    (e in sameNet) shouldBe false
                    (e == p) shouldBe false
                }
            }
        }

        test("a probe taken for a path that conflicts is handed back: the next build probes the primary") {
            val f = fixture()
            val p = f.primary()
            val k = f.backup()
            f.guards.recordFirstHopFailure(p)
            f.clock.advanceSeconds(GuardManager.PRIMARY_RETRY_MAX_SECONDS + 1)
            // a locally chosen last hop in the primary's /16 conflicts with the probe guard
            val sameNet = f.add(f.primaryNet(), 1)
            shouldThrow<PathConflictException> { f.selector.select(sameNet) }
            val probe = f.selector.select(null) as PathSelectionResult.Selected
            probe.hops.first().identity shouldBe p
            probe.probe shouldBe true
            // without a build the caller hands it back; then the next build probes again
            f.selector.releaseUnusedPath(probe)
            val again = f.selector.select(null) as PathSelectionResult.Selected
            again.hops.first().identity shouldBe p
            // a path that is built keeps the probe: the next one enters through the backup
            val next = f.selector.select(null) as PathSelectionResult.Selected
            next.hops.first().identity shouldBe k
            next.probe shouldBe false
            // releasing a non-probe path changes nothing
            f.selector.releaseUnusedPath(next)
            f.selector
                .select(null)
                .hops()
                .first()
                .identity shouldBe k
        }

        test("a remote hop equal to the probed primary enters through the backup and hands the probe back") {
            val f = fixture()
            val p = f.primary()
            val k = f.backup()
            f.guards.recordFirstHopFailure(p)
            f.clock.advanceSeconds(GuardManager.PRIMARY_RETRY_MAX_SECONDS + 1)
            val primaryDescriptor = f.relays.first { it.identity == p }
            val path =
                f.selector.select(
                    primaryDescriptor,
                    lastHopChosenRemotely = true,
                ) as PathSelectionResult.Selected
            path.hops.first().identity shouldBe k
            path.probe shouldBe false
            f.selector
                .select(null)
                .hops()
                .first()
                .identity shouldBe p
        }

        test(
            "a refused non-probe build entering through the marked primary does not free the outstanding probe",
        ) {
            repeat(5) { seed ->
                val f = fixture(seed.toLong())
                val p = f.primary()
                val k = f.backup()
                f.guards.recordFirstHopFailure(p)
                f.clock.advanceSeconds(GuardManager.PRIMARY_RETRY_MAX_SECONDS + 1)
                // the probe goes to one build, which is still in flight (no first-hop result yet)
                val probe = f.selector.select(null) as PathSelectionResult.Selected
                probe.hops.first().identity shouldBe p
                probe.probe shouldBe true
                // a remote last hop equal to the effective guard K enters through P, WITHOUT the probe
                val backupDescriptor = f.relays.first { it.identity == k }
                val alternative =
                    f.selector.select(backupDescriptor, lastHopChosenRemotely = true) as PathSelectionResult.Selected
                alternative.hops.first().identity shouldBe p
                alternative.probe shouldBe false
                // that build is refused (governor): handing its path back must leave the probe outstanding
                f.selector.releaseUnbuiltPath(alternative.hops)
                f.selector.releaseUnusedPath(alternative)
                // a copy of the probe path is not the probe path either
                f.selector.releaseUnbuiltPath(probe.hops.toList())
                f.selector
                    .select(null)
                    .hops()
                    .first()
                    .identity shouldBe k
                // the probe path itself does hand the probe back: the next build probes P
                f.selector.releaseUnbuiltPath(probe.hops)
                val again = f.selector.select(null) as PathSelectionResult.Selected
                again.hops.first().identity shouldBe p
                again.probe shouldBe true
            }
        }
    })
