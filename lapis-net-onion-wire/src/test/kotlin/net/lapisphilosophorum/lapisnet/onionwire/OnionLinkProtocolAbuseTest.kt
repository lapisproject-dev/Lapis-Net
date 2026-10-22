package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCodec
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.OnionConstants
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

private val PADDING = CellCodec.encode(Cell(0, CellCommand.PADDING, ByteArray(OnionConstants.BODY_SIZE)))

/** Hostile peers against a real relay: every abuse closes the link, the relay stays up. */
@OptIn(ExperimentalOnionApi::class)
class OnionLinkProtocolAbuseTest :
    FunSpec({
        val nodes = ArrayList<WireTestNode>()

        afterSpec { nodes.forEach { it.close() } }

        fun relay(config: OnionWireConfig = fastWireConfig(true)) =
            WireTestNode(relay = true, config).also {
                nodes +=
                    it
            }

        fun peer(config: OnionWireConfig = fastWireConfig(false)) =
            WireTestNode(relay = false, config).also {
                nodes +=
                    it
            }

        fun open(
            from: WireTestNode,
            to: WireTestNode,
        ): LinkId =
            from.wire
                .linksForTest()
                .linkTo(to.peerId, to.node.listenAddresses())
                .get(15, TimeUnit.SECONDS)

        fun closes(
            r: WireTestNode,
            within: Duration = Duration.ofSeconds(15),
        ) = awaitTrue(within) { r.wire.linkCount() == 0 }

        test("a started cell that never completes closes the link (slowloris)") {
            val r = relay()
            val a = peer()
            val link = open(a, r)
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            a.wire.linksForTest().writeRawForTest(link, ByteArray(500))
            closes(r) shouldBe true
        }

        test("an inbound link that never sends a cell is closed after the handshake window") {
            val r = relay()
            val a = peer()
            open(a, r)
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            closes(r) shouldBe true
        }

        test("a slowloris after a valid cell is closed as well") {
            val r = relay()
            val a = peer()
            val link = open(a, r)
            a.wire.linksForTest().writeRawForTest(link, PADDING + ByteArray(100))
            closes(r) shouldBe true
        }

        test("a malformed cell (unknown command) closes the link") {
            val r = relay()
            val a = peer()
            val link = open(a, r)
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            a.wire.linksForTest().writeRawForTest(link, ByteArray(OnionConstants.CELL_SIZE).also { it[4] = 99 })
            closes(r) shouldBe true
        }

        test("a cell flood above the per-link rate closes the link") {
            val r = relay(fastWireConfig(true, OnionWireConfig(cellsPerSecondPerLink = 50)))
            val a = peer()
            val link = open(a, r)
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            a.wire.linksForTest().writeRawForTest(
                link,
                ByteArray(0).let { _ ->
                    ByteArray(PADDING.size * 300) {
                        PADDING[
                            it %
                                PADDING.size,
                        ]
                    }
                },
            )
            closes(r) shouldBe true
        }

        test("a second inbound link of one peer is refused beyond the per-peer cap") {
            val r = relay(fastWireConfig(true, OnionWireConfig(maxInboundLinksPerPeer = 1)))
            val a = peer()
            val first = open(a, r)
            awaitTrue { r.wire.linkCount() == 1 } shouldBe true
            val connection = a.node.liveConnectionTo(r.peerId)!!
            val second =
                connection
                    .muxerSession()
                    .createStream(
                        a.wire.linksForTest().binding,
                    ).controller
                    .get(10, TimeUnit.SECONDS)
            // refused by the relay: its reset ends the second link on our side too; the first one stays
            awaitTrue { a.wire.linkCount() == 1 } shouldBe true
            r.wire.linkCount() shouldBe 1
            (second.linkId.value == first.value) shouldBe false
        }

        test("the global link cap holds across peers") {
            val r = relay(fastWireConfig(true, OnionWireConfig(maxLinks = 2)))
            val attackers = List(4) { peer() }
            attackers.forEach { runCatching { open(it, r) } }
            Thread.sleep(1000)
            (r.wire.linkCount() <= 2) shouldBe true
            (r.wire.linksForTest().reservedSlots() <= 2) shouldBe true
        }

        test("an overfull write queue closes the link instead of buffering without bound") {
            val r = relay()
            val a = peer(fastWireConfig(false, OnionWireConfig(maxQueuedCellsPerLink = 2)))
            val link = open(a, r)
            val padding = Cell(0, CellCommand.PADDING, ByteArray(OnionConstants.BODY_SIZE))
            var refused = false
            repeat(50_000) { if (!a.wire.linksForTest().send(link, padding)) refused = true }
            refused shouldBe true
            awaitTrue { a.wire.linkCount() == 0 } shouldBe true
        }

        test("the relay still serves an honest peer after all of the abuse") {
            val r = relay()
            val honest = peer()
            honest.connectTo(r)
            val client = honest.wire.diagnosticClient()
            client.build(listOf(r.wire.currentDescriptor()!!), 15.seconds).get(20, TimeUnit.SECONDS).close()
            client.close()
        }

        test("idle inbound links cannot starve outbound links: the reserved slots stay usable") {
            val cfg =
                OnionWireConfig(maxLinks = 4, reservedOutboundLinks = 2, inboundIdleWithoutCircuitTimeout = 60.seconds)
            val r = relay(fastWireConfig(true, cfg))
            val target = relay()
            val attackers = List(6) { peer() }
            attackers.forEach { runCatching { open(it, r) } }
            awaitTrue { r.wire.linkCount() == 2 } shouldBe true
            Thread.sleep(500)
            r.wire.linkCount() shouldBe 2
            // inbound is capped at maxLinks - reserved; the relay can still open an outbound link
            r.wire
                .linksForTest()
                .linkTo(target.peerId, target.node.listenAddresses())
                .get(15, TimeUnit.SECONDS)
            r.wire.linkCount() shouldBe 3
        }

        test("an inbound link without circuit is closed even if it keeps sending PADDING") {
            val cfg = OnionWireConfig(inboundIdleWithoutCircuitTimeout = 2.seconds)
            val r = relay(fastWireConfig(true, cfg))
            val a = peer()
            val link = open(a, r)
            val padding = Cell(0, CellCommand.PADDING, ByteArray(OnionConstants.BODY_SIZE))
            val keepAlive =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor().also {
                    it.scheduleAtFixedRate({ a.wire.linksForTest().send(link, padding) }, 0, 300, TimeUnit.MILLISECONDS)
                }
            try {
                closes(r, Duration.ofSeconds(15)) shouldBe true
            } finally {
                keepAlive.shutdownNow()
            }
        }

        test("an inbound link is closed even if it keeps sending DESTROY and RELAY for unknown circuits") {
            val cfg = OnionWireConfig(inboundIdleWithoutCircuitTimeout = 2.seconds)
            val r = relay(fastWireConfig(true, cfg))
            val a = peer()
            val link = open(a, r)
            val destroy = Cell(0x1234, CellCommand.DESTROY, ByteArray(OnionConstants.BODY_SIZE))
            val relayCell = Cell(0x4321, CellCommand.RELAY, ByteArray(OnionConstants.BODY_SIZE))
            val keepAlive =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor().also {
                    it.scheduleAtFixedRate(
                        {
                            a.wire.linksForTest().send(link, destroy)
                            a.wire.linksForTest().send(link, relayCell)
                        },
                        0,
                        300,
                        TimeUnit.MILLISECONDS,
                    )
                }
            try {
                closes(r, Duration.ofSeconds(15)) shouldBe true
            } finally {
                keepAlive.shutdownNow()
            }
        }
    })
