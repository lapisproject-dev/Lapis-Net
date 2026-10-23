@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionConstants

class OnionPathSelectorDeterminismTest :
    FunSpec({
        val relays = (1..12).map { syntheticDescriptor() }

        fun run(seed: Long): List<Int> {
            val f = SelectorFixture(seed = seed)
            relays.forEachIndexed { i, d -> f.locator.put(d, v4(i + 1, i + 1)) }
            f.relays += relays
            return f.selector
                .select(null)
                .hops()
                .map { h -> relays.indexOfFirst { it.identity == h.identity } }
        }

        test("the same seed over the same relay list yields the same path") {
            for (seed in 1L..10L) run(seed) shouldBe run(seed)
        }

        test("different seeds yield different paths") {
            ((1L..30L).map { run(it) }.toSet().size > 1) shouldBe true
        }
    })

class OnionPathSelectorDiversityTest :
    FunSpec({
        test("a path never contains an identity twice and never the own identity") {
            repeat(30) { seed ->
                val f = SelectorFixture(seed = seed.toLong())
                repeat(8) { f.add(it + 1, 1) }
                val hops = f.selector.select(null).hops()
                hops.map { it.identity }.toSet() shouldHaveSize hops.size
                hops.none { it.identity == f.own.secp256k1KeyPair.publicKey } shouldBe true
            }
        }

        test("relays in the same IPv4 /16 never share a path") {
            repeat(30) { seed ->
                val f = SelectorFixture(seed = seed.toLong())
                repeat(6) { f.add(1, 1) }
                repeat(2) { f.add(2, it + 1) }
                f.add(3, 1)
                val hops = f.selector.select(null).hops()
                hops.map { f.locator.bucketsOf(it.identity, 0).single() }.toSet() shouldHaveSize 3
            }
        }

        test("IPv6: the same /32 conflicts, even if the /48 differs; different /32 do not") {
            val f = SelectorFixture()
            val a = f.locator.put(syntheticDescriptor(), NetworkBucket.V6(0x20010db8L)).also { f.relays += it }
            val b = f.locator.put(syntheticDescriptor(), NetworkBucket.V6(0x20010db8L)).also { f.relays += it }
            val c = f.locator.put(syntheticDescriptor(), NetworkBucket.V6(0x20010db9L)).also { f.relays += it }
            val d = f.locator.put(syntheticDescriptor(), NetworkBucket.V6(0x20010dbaL)).also { f.relays += it }
            repeat(20) {
                val hops =
                    f.selector
                        .select(null)
                        .hops()
                        .map { it.identity }
                (a.identity in hops && b.identity in hops) shouldBe false
                hops shouldHaveSize 3
                (c.identity in hops || d.identity in hops) shouldBe true
            }
        }

        test("an overlap of any of several declared addresses excludes the pair") {
            val f = SelectorFixture()
            val multi = f.locator.put(syntheticDescriptor(), v4(1, 1), v4(2, 2)).also { f.relays += it }
            val clash = f.locator.put(syntheticDescriptor(), v4(2, 2)).also { f.relays += it }
            f.add(3, 3)
            f.add(4, 4)
            f.add(5, 5)
            repeat(30) {
                val ids =
                    f.selector
                        .select(null)
                        .hops()
                        .map { it.identity }
                (multi.identity in ids && clash.identity in ids) shouldBe false
            }
        }

        test("at most one relay of unknown network per path") {
            val f = SelectorFixture()
            repeat(5) { f.relays += syntheticDescriptor() } // unknown bucket
            repeat(3) { f.add(10 + it, 1) }
            repeat(30) {
                val hops = f.selector.select(null).hops()
                (hops.count { f.locator.bucketsOf(it.identity, 0) == setOf(NetworkBucket.Unknown) } <= 1) shouldBe true
            }
        }

        test("two relays of the same non-null family never share a path") {
            val f = SelectorFixture()
            val fam = RelayFamilyId(byteArrayOf(1, 2, 3))
            val a = f.add(1, 1).also { f.families[it.identity] = fam }
            val b = f.add(2, 2).also { f.families[it.identity] = fam }
            repeat(3) { f.add(5 + it, 5) }
            repeat(40) {
                val ids =
                    f.selector
                        .select(null)
                        .hops()
                        .map { it.identity }
                (a.identity in ids && b.identity in ids) shouldBe false
            }
        }

        test("the Veritas edge flag: off allows the pair, on excludes it") {
            fun run(forbid: Boolean): Boolean {
                var together = false
                val relays = List(4) { syntheticDescriptor() }
                val edge = (relays[0].identity to relays[1].identity)
                repeat(60) { seed ->
                    val f =
                        SelectorFixture(
                            seed = seed.toLong(),
                            options =
                                PathSelectionOptions(
                                    forbid,
                                ) { x, y -> x == edge.first && y == edge.second },
                        )
                    relays.forEachIndexed { i, d -> f.locator.put(d, v4(i + 1, i + 1)) }
                    f.relays += relays
                    val ids =
                        f.selector
                            .select(null)
                            .hops()
                            .map { it.identity }
                    if (edge.first in ids && edge.second in ids) together = true
                }
                return together
            }
            run(false) shouldBe true
            run(true) shouldBe false
        }

        test("expired descriptors are never chosen") {
            val f = SelectorFixture()
            val expired = f.locator.put(syntheticDescriptor(expiresInSeconds = 10), v4(9, 9)).also { f.relays += it }
            repeat(4) { f.add(it + 1, 1) }
            f.clock.advanceSeconds(100)
            repeat(20) {
                f.selector
                    .select(null)
                    .hops()
                    .none { it.identity == expired.identity } shouldBe true
            }
        }

        test("a prescribed last hop is the last hop and the path stays diverse to it") {
            repeat(20) { seed ->
                val f = SelectorFixture(seed = seed.toLong())
                repeat(6) { f.add(it + 1, 1) }
                val last = f.locator.relayIn(77, 1)
                val hops = f.selector.select(last).hops()
                hops shouldHaveSize 3
                hops.last().identity shouldBe last.identity
                hops[0].identity shouldBe
                    f.guards
                        .snapshot()
                        .primary!!
                        .identity
            }
        }

        test("a prescribed last hop in the guard's network is a path conflict") {
            val f = SelectorFixture()
            repeat(4) { f.add(it + 1, 1) }
            f.selector.select(null) // fixes the guard
            val guard =
                f.guards
                    .snapshot()
                    .primary!!
                    .identity
            val guardBucket = f.locator.bucketsOf(guard, 0).single()
            val last =
                f.locator.put(
                    syntheticDescriptor(),
                    guardBucket,
                )
            shouldThrow<PathConflictException> { f.selector.select(last) }.message shouldBe "path conflict"
        }

        test("a remotely chosen last hop in the guard's bucket or equal to the guard is still connected") {
            repeat(10) { seed ->
                val f = SelectorFixture(seed = seed.toLong())
                repeat(6) { f.add(it + 1, 1) }
                f.selector.select(null) // fixes the guard
                val guardId =
                    f.guards
                        .snapshot()
                        .primary!!
                        .identity
                val guardBucket = f.locator.bucketsOf(guardId, 0).single()
                val sameNet = f.locator.put(syntheticDescriptor(), guardBucket)
                val remote = f.selector.select(sameNet, lastHopChosenRemotely = true).hops()
                remote shouldHaveSize 3
                remote.first().identity shouldBe guardId
                remote.last().identity shouldBe sameNet.identity
                val guardDescriptor = f.relays.first { it.identity == guardId }
                val self = f.selector.select(guardDescriptor, lastHopChosenRemotely = true).hops()
                self shouldHaveSize 3
                self.last().identity shouldBe guardId
            }
        }

        test("the provider treats RENDEZVOUS_RECEIVER as remote and RENDEZVOUS_SENDER as locally chosen") {
            val f = SelectorFixture()
            repeat(4) { f.add(it + 1, 1) }
            f.selector.select(null)
            val guardBucket =
                f.locator
                    .bucketsOf(
                        f.guards
                            .snapshot()
                            .primary!!
                            .identity,
                        0,
                    ).single()
            val last = f.locator.put(syntheticDescriptor(), guardBucket)
            val provider = SelectingOnionPathProvider(f.selector)
            provider.pathEndingAt(last, CircuitPurpose.RENDEZVOUS_RECEIVER) shouldHaveSize 3
            shouldThrow<PathConflictException> { provider.pathEndingAt(last, CircuitPurpose.RENDEZVOUS_SENDER) }
        }
    })

class OnionPathSelectorInsufficientTest :
    FunSpec({
        test("0, 1 and 2 relays are insufficient, never a shorter path") {
            for (n in 0..2) {
                val f = SelectorFixture()
                repeat(n) { f.add(it + 1, 1) }
                f.selector.select(null) shouldBe PathSelectionResult.Insufficient
            }
        }

        test("three relays in the same /16 are insufficient") {
            val f = SelectorFixture()
            repeat(3) { f.add(5, 5) }
            f.selector.select(null) shouldBe PathSelectionResult.Insufficient
        }

        test("the provider turns it into an InsufficientRelaysException without identity or address in the text") {
            val f = SelectorFixture()
            f.add(1, 1)
            val seen = ArrayList<Throwable>()
            val provider = SelectingOnionPathProvider(f.selector) { seen += it }
            val last = f.locator.relayIn(9, 9)
            val e =
                shouldThrow<InsufficientRelaysException> {
                    provider.pathEndingAt(
                        last,
                        CircuitPurpose.DIRECTORY_PUBLISH,
                    )
                }
            e.message shouldBe "insufficient relays"
            seen.single().shouldBeInstanceOf<InsufficientRelaysException>()
        }

        test("everything unknown: at most one unknown relay per path, so insufficient") {
            val f = SelectorFixture()
            repeat(10) { f.relays += syntheticDescriptor() }
            f.selector.select(null) shouldBe PathSelectionResult.Insufficient
        }
    })

class OnionPathSelectorDowngradeTest :
    FunSpec({
        test("fewer than three hops are refused, more than the maximum too") {
            val f = SelectorFixture()
            repeat(6) { f.add(it + 1, 1) }
            shouldThrow<IllegalArgumentException> { f.selector.select(null, hops = 2) }
            shouldThrow<IllegalArgumentException> { f.selector.select(null, hops = 1) }
            shouldThrow<IllegalArgumentException> { f.selector.select(null, hops = OnionConstants.MAX_HOPS + 1) }
            f.selector.select(null, hops = 4).hops() shouldHaveSize 4
        }

        test("the production path length is the default hop count") {
            PathPolicy.PRODUCTION_PATH_LENGTH shouldBe OnionConstants.DEFAULT_HOPS
        }
    })
