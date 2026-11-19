package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.concurrent.thread

/**
 * Regression test for the "DM lock" stall: a send to peer B whose dial (or anonymous online delivery) hangs must not
 * block anything else that maps to B's stripe lock - inbound envelopes from B, rejection handling for B, or sends to a
 * different peer whose key lands on the same stripe. A slow dial is simulated with [DmSessionManager.beforeDispatchForTest]
 * (deterministic) and, in one case, with a peer record that points at a TCP listener that accepts and never answers.
 *
 * The time budget ([STALL_BUDGET]) is far below [DmSessionManager.DIAL_TIMEOUT]: it measures "does not wait for the
 * dial at all", not raw speed.
 */
class DmPeerLockDialStallTest :
    FunSpec({
        test("a) an inbound envelope from B is delivered while the dial to B hangs") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val blocker = DispatchBlocker(b.pub())
            var stalled: Thread? = null
            try {
                connectAndConverge(a, b)
                establishBothWays(a, b)
                val receivedByA = LinkedBlockingQueue<DmInboundMessage>()
                a.dmSessionManager.addInboundListener { receivedByA.add(it) }

                blocker.install(a.dmSessionManager)
                stalled =
                    thread(
                        name = "stalled-send",
                    ) { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "stalled")) } }
                blocker.awaitEntered()

                b.dmSessionManager.send(a.pub(), DmContent(body = "ping"))
                val got = receivedByA.poll(STALL_BUDGET.toMillis(), TimeUnit.MILLISECONDS)
                got shouldNotBe null
                got!!.content.body shouldBe "ping"
                blocker.heldStripeLock shouldBe false
            } finally {
                blocker.release()
                stalled?.join(30_000)
                a.stop()
                b.stop()
            }
        }

        test("a2) realistic: a peer record pointing at a black-hole listener does not stall inbound from that peer") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val hole = blackHoleListener()
            var stalled: Thread? = null
            try {
                connectAndConverge(a, b)
                establishBothWays(a, b)
                val receivedByA = LinkedBlockingQueue<DmInboundMessage>()
                a.dmSessionManager.addInboundListener { receivedByA.add(it) }
                // A now believes B lives behind the black hole; B keeps its own (correct) view of A.
                announceUnreachableRecord(a, b, hole.multiaddr())
                a.peerDirectory.lookup(b.pub())!!.addresses shouldBe listOf(hole.multiaddr())
                // Drop the live connection so the next send really dials the black hole.
                a.node.closeConnectionsOutside(emptySet())

                val dialStarted = CountDownLatch(1)
                a.dmSessionManager.beforeDispatchForTest = { r, _ -> if (r == b.pub()) dialStarted.countDown() }
                stalled =
                    thread(
                        name = "black-hole-send",
                    ) { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "lost")) } }
                dialStarted.await(10, TimeUnit.SECONDS) shouldBe true
                Thread.sleep(500) // let the dial reach the black hole

                b.dmSessionManager.send(a.pub(), DmContent(body = "ping over a fresh connection"))
                val got = receivedByA.poll(STALL_BUDGET.toMillis(), TimeUnit.MILLISECONDS)
                got shouldNotBe null
                got!!.content.body shouldBe "ping over a fresh connection"
            } finally {
                hole.close()
                stalled?.join(30_000)
                a.stop()
                b.stop()
            }
        }

        test("b) a send to another peer on the SAME stripe completes while the dial to B hangs") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val cIdentity = identityOnStripeOf(a.dmSessionManager, b.pub())
            val c = buildDmTestNode(identity = cIdentity)
            val blocker = DispatchBlocker(b.pub())
            var stalled: Thread? = null
            try {
                a.dmSessionManager.stripeIndexForTest(c.pub()) shouldBe a.dmSessionManager.stripeIndexForTest(b.pub())
                connectAndConverge(a, b)
                connectAndConverge(a, c)
                val receivedByC = LinkedBlockingQueue<DmInboundMessage>()
                c.dmSessionManager.addInboundListener { receivedByC.add(it) }

                blocker.install(a.dmSessionManager)
                stalled =
                    thread(
                        name = "stalled-send",
                    ) { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "stalled")) } }
                blocker.awaitEntered()

                withinBudget { a.dmSessionManager.send(c.pub(), DmContent(body = "to c")) }
                receivedByC.poll(30, TimeUnit.SECONDS)?.content?.body shouldBe "to c"
                blocker.heldStripeLock shouldBe false
            } finally {
                blocker.release()
                stalled?.join(30_000)
                a.stop()
                b.stop()
                c.stop()
            }
        }

        test("c) control: a send to a peer on a different stripe completes while the dial to B hangs") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            var c = buildDmTestNode()
            while (a.dmSessionManager.stripeIndexForTest(c.pub()) == a.dmSessionManager.stripeIndexForTest(b.pub())) {
                c.stop()
                c = buildDmTestNode()
            }
            val blocker = DispatchBlocker(b.pub())
            var stalled: Thread? = null
            try {
                connectAndConverge(a, b)
                connectAndConverge(a, c)
                blocker.install(a.dmSessionManager)
                stalled =
                    thread(
                        name = "stalled-send",
                    ) { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "stalled")) } }
                blocker.awaitEntered()
                withinBudget { a.dmSessionManager.send(c.pub(), DmContent(body = "to c")) }
            } finally {
                blocker.release()
                stalled?.join(30_000)
                a.stop()
                b.stop()
                c.stop()
            }
        }

        test("d) rejection handling for B returns at once while the dial to B hangs") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val blocker = DispatchBlocker(b.pub())
            var stalled: Thread? = null
            try {
                connectAndConverge(a, b)
                blocker.install(a.dmSessionManager)
                stalled =
                    thread(
                        name = "stalled-send",
                    ) { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "stalled")) } }
                blocker.awaitEntered()
                val rejection =
                    DmX3dhRejection(
                        rejecterIdentity = b.pub(),
                        rejectedEphemeralPublicKey = X25519KeyPair.generate(SecureRandom()).publicKey,
                        signedPrekeyId = 1,
                        oneTimePrekeyId = 1,
                        reason = DmX3dhRejectionReason.ONE_TIME_PREKEY_CONSUMED,
                        issuedAtEpochSecond = Instant.now().epochSecond,
                        tag = ByteArray(DmX3dhRejectionCodec.TAG_SIZE),
                    )
                withinBudget { a.dmSessionManager.handleX3dhRejectionForTest(rejection) }
                blocker.heldStripeLock shouldBe false
            } finally {
                blocker.release()
                stalled?.join(30_000)
                a.stop()
                b.stop()
            }
        }

        test("e) anonymity mode: a circuit envelope from B is processed while the online delivery to B hangs") {
            val a = buildDmTestNode(anonymous = true)
            val b = buildDmTestNode(anonymous = true)
            var stalled: Thread? = null
            val transportA =
                BlockingAnonymousTransport { requireNotNull(a.prekeyBundleGossip.lookup(it)).x25519IdentityKey }
            try {
                connectAndConverge(a, b)
                val transportB =
                    BlockingAnonymousTransport { requireNotNull(b.prekeyBundleGossip.lookup(it)).x25519IdentityKey }
                transportA.stripeHeldProbe = { a.dmSessionManager.holdsPeerLockForTest(it) }
                a.dmSessionManager.installAnonymousTransport(transportA)
                b.dmSessionManager.installAnonymousTransport(transportB)
                val receivedByA = LinkedBlockingQueue<DmInboundMessage>()
                a.dmSessionManager.addInboundListener { receivedByA.add(it) }

                b.dmSessionManager.sendAuto(a.pub(), DmContent(body = "hello")) shouldBe DmSendOutcome.SENT_ONLINE
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(transportB.onlineBytes.removeAt(0))
                receivedByA.poll(10, TimeUnit.SECONDS)?.content?.body shouldBe "hello"

                transportA.block = true
                stalled =
                    thread(name = "stalled-anonymous-send") {
                        runCatching { a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "stalled")) }
                    }
                transportA.entered.await(10, TimeUnit.SECONDS) shouldBe true

                b.dmSessionManager.sendAuto(a.pub(), DmContent(body = "second")) shouldBe DmSendOutcome.SENT_ONLINE
                val second = transportB.onlineBytes.removeAt(0)
                withinBudget { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(second) }
                receivedByA.poll(STALL_BUDGET.toMillis(), TimeUnit.MILLISECONDS)?.content?.body shouldBe "second"
                transportA.heldStripeLock shouldBe false
            } finally {
                transportA.release.countDown()
                stalled?.join(30_000)
                a.stop()
                b.stop()
            }
        }
    }) {
    companion object {
        /** Far below [DmSessionManager.DIAL_TIMEOUT] (15 s); generous for a loaded CI host. */
        val STALL_BUDGET: Duration = Duration.ofSeconds(5)
    }
}

private fun DmTestNode.pub(): Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey

/** Runs [block] on its own thread and fails if it does not return within [DmPeerLockDialStallTest.STALL_BUDGET]. */
private fun withinBudget(block: () -> Unit) {
    val future = CompletableFuture.runAsync({ block() }, { r -> thread(name = "within-budget") { r.run() } })
    try {
        future.get(DmPeerLockDialStallTest.STALL_BUDGET.toMillis(), TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
        throw AssertionError("operation did not complete within ${DmPeerLockDialStallTest.STALL_BUDGET} - stalled", e)
    }
}

/** Blocks the dispatch of frames to [target] until [release]; records whether the stripe lock was held there. */
private class DispatchBlocker(
    private val target: Secp256k1PublicKey,
) {
    private val entered = CountDownLatch(1)
    private val released = CountDownLatch(1)

    @Volatile var heldStripeLock: Boolean? = null

    fun install(manager: DmSessionManager) {
        manager.beforeDispatchForTest = { recipient, _ ->
            if (recipient == target && released.count > 0) {
                heldStripeLock = manager.holdsPeerLockForTest(recipient)
                entered.countDown()
                released.await(40, TimeUnit.SECONDS)
            }
        }
    }

    fun awaitEntered() {
        check(entered.await(10, TimeUnit.SECONDS)) { "the blocked dispatch never started" }
    }

    fun release() = released.countDown()
}

/** Anonymity transport whose online delivery can block (on a latch); records delivered bytes otherwise. */
private class BlockingAnonymousTransport(
    private val sealingKeyFor: (Secp256k1PublicKey) -> net.lapisphilosophorum.lapisnet.identity.X25519PublicKey,
) : AnonymousDmTransport {
    @Volatile var block = false

    @Volatile var heldStripeLock: Boolean? = null

    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val onlineBytes: MutableList<ByteArray> = Collections.synchronizedList(mutableListOf())

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget =
        AnonymousDmTarget(recipient, sealingKeyFor(recipient), null, true)

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        if (block) {
            heldStripeLock = stripeHeldProbe?.invoke(target.recipient)
            entered.countDown()
            release.await(40, TimeUnit.SECONDS)
            return false
        }
        onlineBytes.add(envelopeBytes)
        return true
    }

    @Volatile var stripeHeldProbe: ((Secp256k1PublicKey) -> Boolean)? = null

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) = Unit

    override fun close() = Unit
}

/** Sends A->B and B->A until each side has received one message, so both sessions can send. */
private fun establishBothWays(
    a: DmTestNode,
    b: DmTestNode,
) {
    fun oneWay(
        from: DmTestNode,
        to: DmTestNode,
    ) {
        val got = LinkedBlockingQueue<DmInboundMessage>()
        val listener: (DmInboundMessage) -> Unit = { got.add(it) }
        to.dmSessionManager.addInboundListener(listener)
        val deadline = Instant.now().plus(Duration.ofSeconds(30))
        while (got.isEmpty() && Instant.now().isBefore(deadline)) {
            runCatching { from.dmSessionManager.send(to.pub(), DmContent(body = "setup")) }
            got.poll(1, TimeUnit.SECONDS)?.let { got.add(it) }
        }
        check(got.isNotEmpty()) { "setup message never arrived" }
    }
    oneWay(a, b)
    oneWay(b, a)
}

/** Makes [a] believe that [b] is reachable only at [address] (a newer, validly signed record for [b]'s identity). */
private fun announceUnreachableRecord(
    a: DmTestNode,
    b: DmTestNode,
    address: io.libp2p.core.multiformats.Multiaddr,
) {
    val record =
        net.lapisphilosophorum.lapisnet.directory.PeerRecord.create(
            identity = b.identity,
            addresses = listOf(address),
            capabilities = setOf(net.lapisphilosophorum.lapisnet.directory.PeerCapability.DM),
            sequenceNumber = System.nanoTime(),
            notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
        )
    a.peerDirectory.announce(record)
}

/** A fresh identity whose key maps to the same stripe of [manager] as [peer] (bounded search). */
private fun identityOnStripeOf(
    manager: DmSessionManager,
    peer: Secp256k1PublicKey,
): DualKeyIdentity {
    val wanted = manager.stripeIndexForTest(peer)
    repeat(200_000) {
        val candidate = DualKeyIdentity.generate()
        if (manager.stripeIndexForTest(candidate.secp256k1KeyPair.publicKey) == wanted) return candidate
    }
    error("no identity on stripe $wanted within 200000 attempts")
}
