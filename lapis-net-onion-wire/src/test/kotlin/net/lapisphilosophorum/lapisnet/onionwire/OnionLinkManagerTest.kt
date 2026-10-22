package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

class OnionLinkManagerTest :
    FunSpec({
        val nodes = ArrayList<WireTestNode>()

        afterSpec { nodes.forEach { it.close() } }

        test("concurrent dials to one peer share one link and a later request reuses it") {
            val r = WireTestNode(relay = true).also { nodes += it }
            val a = WireTestNode(relay = false).also { nodes += it }
            val links = a.wire.linksForTest()
            val futures = List(8) { links.linkTo(r.peerId, r.node.listenAddresses()) }
            val ids = futures.map { it.get(15, TimeUnit.SECONDS) }.toSet()
            ids.size shouldBe 1
            links.linkTo(r.peerId, r.node.listenAddresses()).get(5, TimeUnit.SECONDS) shouldBe ids.single()
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            a.wire.linkCount() shouldBe 1
            links.pendingDialCount() shouldBe 0
        }

        test("a link is reused in the opposite direction as well") {
            val r = WireTestNode(relay = true).also { nodes += it }
            val a = WireTestNode(relay = true).also { nodes += it }
            a.wire
                .linksForTest()
                .linkTo(r.peerId, r.node.listenAddresses())
                .get(15, TimeUnit.SECONDS)
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            // r reaches a over the link a opened
            r.wire
                .linksForTest()
                .linkTo(a.peerId, emptyList())
                .get(5, TimeUnit.SECONDS)
            r.wire.linkCount() shouldBe 1
        }

        test("a dial without any usable address fails fast and leaves no pending dial") {
            val a = WireTestNode(relay = false).also { nodes += it }
            val ghost = WireTestNode(relay = false).also { nodes += it }
            val links = a.wire.linksForTest()
            shouldThrow<ExecutionException> {
                links.linkTo(ghost.peerId, emptyList()).get(10, TimeUnit.SECONDS)
            }
            shouldThrow<ExecutionException> {
                links.linkTo(ghost.peerId, listOf(Multiaddr("/ip4/0.0.0.0/tcp/1"))).get(10, TimeUnit.SECONDS)
            }
            links.pendingDialCount() shouldBe 0
            links.reservedSlots() shouldBe 0
        }

        test("an unreachable address times out or is refused and the bookkeeping is clean") {
            val a = WireTestNode(relay = false).also { nodes += it }
            val ghost = WireTestNode(relay = false).also { nodes += it }
            val links = a.wire.linksForTest()
            shouldThrow<ExecutionException> {
                links.linkTo(ghost.peerId, listOf(Multiaddr("/ip4/127.0.0.1/tcp/1"))).get(20, TimeUnit.SECONDS)
            }
            links.pendingDialCount() shouldBe 0
        }
    })
