package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.onion.LinkId
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration.Companion.seconds

/**
 * Link reuse while a link is admitted but not yet attached, and the deterministic tie-break for simultaneous dials.
 * The hooks block a Netty event loop on purpose; every latch is released in `finally` and awaited with a timeout.
 *
 * Every wait for a positive event uses [WAIT] (30 s): under CPU load (two cores shared with busy loops) dials and
 * handshakes took more than the former 5-10 s, which broke the rendezvous barrier and failed the test although the
 * behaviour under test was correct. Counters that [OnionLinkManager.linkEnded] updates one after another (link table,
 * slots, per-peer entries) are awaited together, never read as a snapshot right after only one of them changed.
 */
private val WAIT: Duration = Duration.ofSeconds(30)
private const val WAIT_SECONDS = 30L

class OnionLinkReuseRaceTest :
    FunSpec({
        val nodes = ArrayList<WireTestNode>()

        afterSpec { nodes.forEach { it.close() } }

        // The inbound handshake timer would close a link without traffic after 2s; these tests send no cells, so lengthen it.
        val quiet = fastWireConfig(true).copy(linkHandshakeTimeout = 60.seconds)

        fun relay(config: OnionWireConfig = quiet) =
            WireTestNode(relay = true, config = config).also {
                nodes +=
                    it
            }

        test("a link that is admitted but not yet attached is reused instead of dialing a second one") {
            val r = relay()
            val a = relay()
            val rLinks = r.wire.linksForTest()
            val admitted = CountDownLatch(1)
            val release = CountDownLatch(1)
            val pending = AtomicReference<OnionLink>()
            rLinks.beforeAttachForTest = {
                pending.set(it)
                admitted.countDown()
                release.await(WAIT_SECONDS, TimeUnit.SECONDS)
            }
            try {
                val opened = a.wire.linksForTest().linkTo(r.peerId, r.node.listenAddresses())
                admitted.await(WAIT_SECONDS, TimeUnit.SECONDS) shouldBe true
                val f = rLinks.linkTo(a.peerId, emptyList())
                rLinks.pendingDialCount() shouldBe 0
                rLinks.linkCount() shouldBe 1
                release.countDown()
                f.get(WAIT_SECONDS, TimeUnit.SECONDS) shouldBe pending.get().id
                opened.get(WAIT_SECONDS, TimeUnit.SECONDS)
                rLinks.linkCount() shouldBe 1
                awaitTrue(WAIT) { a.wire.linkCount() == 1 } shouldBe true
            } finally {
                release.countDown()
            }
        }

        test("a pending link that ends before it is attached fails the waiter without a silent re-dial") {
            val r = relay()
            val a = relay()
            val rLinks = r.wire.linksForTest()
            val admitted = CountDownLatch(1)
            val release = CountDownLatch(1)
            val pending = AtomicReference<OnionLink>()
            rLinks.beforeAttachForTest = {
                pending.set(it)
                admitted.countDown()
                release.await(WAIT_SECONDS, TimeUnit.SECONDS)
            }
            try {
                a.wire.linksForTest().linkTo(r.peerId, r.node.listenAddresses())
                admitted.await(WAIT_SECONDS, TimeUnit.SECONDS) shouldBe true
                val f = rLinks.linkTo(a.peerId, emptyList())
                rLinks.close(pending.get().id)
                shouldThrow<ExecutionException> { f.get(WAIT_SECONDS, TimeUnit.SECONDS) }
                rLinks.pendingDialCount() shouldBe 0
            } finally {
                release.countDown()
            }
            awaitTrue(WAIT) {
                rLinks.linkCount() == 0 && rLinks.reservedSlots() == 0 && rLinks.inboundPeerEntries() == 0
            } shouldBe true
            rLinks.linkCount() shouldBe 0
            rLinks.reservedSlots() shouldBe 0
            rLinks.inboundPeerEntries() shouldBe 0
        }

        test("a failing handler attach closes the admitted link and fails its waiters") {
            val r = relay()
            val a = relay()
            val rLinks = r.wire.linksForTest()
            val waiter = AtomicReference<CompletableFuture<LinkId>>()
            rLinks.beforeAttachForTest = {
                waiter.set(rLinks.linkTo(a.peerId, emptyList()))
                // an exception here takes the same path as a failing pushHandler
                error("attach failed")
            }
            runCatching {
                a.wire
                    .linksForTest()
                    .linkTo(r.peerId, r.node.listenAddresses())
                    .get(WAIT_SECONDS, TimeUnit.SECONDS)
            }
            // the attach hook must really have run: otherwise "no link" below would hold trivially (under load the dial
            // above could time out before r admitted the stream, and waiter was still null)
            awaitTrue(WAIT) { waiter.get() != null } shouldBe true
            awaitTrue(WAIT) {
                rLinks.linkCount() == 0 && rLinks.reservedSlots() == 0 && rLinks.inboundPeerEntries() == 0
            } shouldBe true
            rLinks.linkCount() shouldBe 0
            rLinks.reservedSlots() shouldBe 0
            rLinks.inboundPeerEntries() shouldBe 0
            shouldThrow<ExecutionException> { waiter.get().get(WAIT_SECONDS, TimeUnit.SECONDS) }
        }

        /** Orders two relays: first = lower peer id, second = higher. */
        fun ordered(config: OnionWireConfig = quiet): Pair<WireTestNode, WireTestNode> {
            val x = relay(config)
            val y = relay(config)
            return if (x.wire.linksForTest().lowerPeer(x.peerId, y.peerId) == x.peerId) x to y else y to x
        }

        /**
         * Both sides call linkTo before either link is visible, and both dial threads are held at the rendezvous until both
         * streams exist, so two links really coexist when the tie-break runs.
         *
         * Under CPU load the start barrier alone did not guarantee the first half: one side could open its stream before the
         * other side's linkTo ran, which then reused that link instead of dialing (no second dial, the rendezvous waited in
         * vain). The [OnionLinkManager.beforeDialForTest] barrier holds each dial before it opens anything until both dials
         * are registered.
         */
        fun simultaneousDial(
            low: WireTestNode,
            high: WireTestNode,
            highKeepsOwn: Boolean,
            beforeMeetHigh: () -> Unit = {},
        ): Triple<LinkIdPair, Boolean, Unit> {
            val start = CyclicBarrier(3)
            val registered = CyclicBarrier(2)
            val meet = CyclicBarrier(2)
            val met =
                java.util.concurrent.atomic
                    .AtomicBoolean(false)
            val hook: (PeerId) -> Unit = {
                meet.await(WAIT_SECONDS, TimeUnit.SECONDS)
                met.set(true)
            }
            val lLinks = low.wire.linksForTest()
            val hLinks = high.wire.linksForTest()
            val armedLow = AtomicBoolean(true)
            val armedHigh = AtomicBoolean(true)
            lLinks.beforeDialForTest = {
                if (it == high.peerId && armedLow.compareAndSet(true, false)) {
                    registered.await(WAIT_SECONDS, TimeUnit.SECONDS)
                }
            }
            hLinks.beforeDialForTest = {
                if (it == low.peerId && armedHigh.compareAndSet(true, false)) {
                    registered.await(WAIT_SECONDS, TimeUnit.SECONDS)
                }
            }
            lLinks.beforeDialResultForTest = hook
            hLinks.beforeDialResultForTest = {
                beforeMeetHigh()
                hook(it)
            }
            if (highKeepsOwn) hLinks.hasCircuits = { true }
            val pool =
                java.util.concurrent.Executors
                    .newFixedThreadPool(2)
            try {
                val h =
                    AtomicReference<CompletableFuture<LinkId>>()
                val l =
                    AtomicReference<CompletableFuture<LinkId>>()
                val t1 =
                    pool.submit {
                        start.await(WAIT_SECONDS, TimeUnit.SECONDS)
                        h.set(hLinks.linkTo(low.peerId, low.node.listenAddresses()))
                    }
                val t2 =
                    pool.submit {
                        start.await(WAIT_SECONDS, TimeUnit.SECONDS)
                        l.set(lLinks.linkTo(high.peerId, high.node.listenAddresses()))
                    }
                start.await(WAIT_SECONDS, TimeUnit.SECONDS)
                t1.get(WAIT_SECONDS, TimeUnit.SECONDS)
                t2.get(WAIT_SECONDS, TimeUnit.SECONDS)
                val highId = h.get().get(WAIT_SECONDS, TimeUnit.SECONDS)
                val lowId = l.get().get(WAIT_SECONDS, TimeUnit.SECONDS)
                return Triple(LinkIdPair(highId, lowId), met.get(), Unit)
            } finally {
                pool.shutdownNow()
            }
        }

        test("simultaneous dials fall back to the link opened by the lower peer id") {
            val (low, high) = ordered()
            low.connectTo(high)
            val lLinks = low.wire.linksForTest()
            val hLinks = high.wire.linksForTest()
            val (ids, met, _) = simultaneousDial(low, high, highKeepsOwn = false)
            met shouldBe true
            awaitTrue(WAIT) {
                hLinks.linkCount() == 1 &&
                    lLinks.linkCount() == 1 &&
                    hLinks.reservedSlots() == 1 &&
                    lLinks.reservedSlots() == 1
            } shouldBe true
            // both sides ended on the link the lower peer opened
            ids.high shouldBe hLinks.linkTo(low.peerId, emptyList()).get(WAIT_SECONDS, TimeUnit.SECONDS)
            ids.low shouldBe lLinks.linkTo(high.peerId, emptyList()).get(WAIT_SECONDS, TimeUnit.SECONDS)
            hLinks.reservedSlots() shouldBe 1
            lLinks.reservedSlots() shouldBe 1
            hLinks.pendingDialCount() shouldBe 0
            lLinks.pendingDialCount() shouldBe 0
        }

        test("a link handed out to a concurrent linkTo during the dial window is not closed by the tie-break") {
            val (low, high) = ordered()
            low.connectTo(high)
            val hLinks = high.wire.linksForTest()
            val handed = AtomicReference<CompletableFuture<LinkId>>()
            // inside the dial window, before the tie-break: a second caller asks for a link to the same peer
            val (ids, met, _) =
                simultaneousDial(low, high, highKeepsOwn = false) {
                    handed.set(hLinks.linkTo(low.peerId, emptyList()))
                }
            met shouldBe true
            // whichever link that caller got (the dialer's own or the canonical one) it was not closed under it
            handed.get().get(WAIT_SECONDS, TimeUnit.SECONDS) shouldBe ids.high
        }

        test("a loser that was already handed out is retired by the idle check, never closed from outside") {
            val cfg = quiet.copy(inboundIdleWithoutCircuitTimeout = 2.seconds)
            val (low, high) = ordered(cfg)
            low.connectTo(high)
            val lLinks = low.wire.linksForTest()
            val hLinks = high.wire.linksForTest()
            // The 2 s idle check at low must not run out while the dial and the checks of the intermediate state below
            // are still going on (under load they took longer than 2 s): until then low reports a circuit on every
            // link, which only defers its idle check (rescheduled every 2 s). low's tie-break does not depend on it,
            // its own link is the canonical one.
            val lowCircuits = lLinks.hasCircuits
            lLinks.hasCircuits = { true }
            // high reports circuits on its link, so it must not close it: the loser is handed out
            val (ids, met, _) = simultaneousDial(low, high, highKeepsOwn = true)
            met shouldBe true
            hLinks.linkCount() shouldBe 2
            lLinks.linkCount() shouldBe 2
            // new requests prefer the canonical link on both sides
            val canonical = lLinks.linkTo(high.peerId, emptyList()).get(WAIT_SECONDS, TimeUnit.SECONDS)
            canonical shouldBe ids.low
            (hLinks.linkTo(low.peerId, emptyList()).get(WAIT_SECONDS, TimeUnit.SECONDS) != ids.high) shouldBe true
            // the inbound loser at low carries no circuit and goes idle; the canonical link keeps its circuits at high.
            // Nothing in the test closes a link: only low's idle check can retire the loser from here on.
            hLinks.hasCircuits = { it != ids.high }
            lLinks.hasCircuits = lowCircuits
            awaitTrue(WAIT) {
                hLinks.linkCount() == 1 &&
                    lLinks.linkCount() == 1 &&
                    hLinks.reservedSlots() == 1 &&
                    lLinks.reservedSlots() == 1 &&
                    lLinks.inboundPeerEntries() == 0 &&
                    hLinks.inboundPeerEntries() == 1
            } shouldBe true
            hLinks.linkCount() shouldBe 1
            lLinks.linkCount() shouldBe 1
            hLinks.reservedSlots() shouldBe 1
            lLinks.reservedSlots() shouldBe 1
            lLinks.inboundPeerEntries() shouldBe 0
            hLinks.inboundPeerEntries() shouldBe 1
        }
    })

private data class LinkIdPair(
    val high: LinkId,
    val low: LinkId,
)
