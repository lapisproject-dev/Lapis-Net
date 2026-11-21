package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Regression test for the inbound half of the "DM lock" stall: an inbound listener (or call-signal listener) that
 * blocks must not hold the sender's stripe lock. Before the fix the listeners ran inside [DmSessionManager]'s
 * `withPeerLock(claimedSender)`, so a slow listener stalled every send to that peer (phase A), rejection handling for
 * it, and all inbound and outbound traffic of other peers on the same stripe. After the fix listeners run after the
 * lock, per peer in ratchet order, and the receiving call still returns only after its own message was delivered.
 *
 * Anonymity-mode nodes are used where possible: a capturing transport hands the envelope bytes to the test, which
 * feeds them into [DmInboundSink.acceptCircuitEnvelope] on a thread of its own - deterministic, no Netty event loop.
 * Case b) covers the direct path, where the listener blocks a Netty thread.
 */
class DmInboundListenerStallTest :
    FunSpec({
        test(
            "a) anonymity mode: a blocking inbound listener does not stall a send to that peer or rejection handling",
        ) {
            val pair = anonymousPair()
            val (a, b) = pair
            val blocker = ListenerBlocker(a.dmSessionManager, b.pub())
            var deliverer: Thread? = null
            try {
                val received = LinkedBlockingQueue<String>()
                a.dmSessionManager.addInboundListener {
                    blocker.onBody(it.content.body)
                    received.add(it.content.body)
                }
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(pair.sendCaptured(b, a, "hello"))
                received.poll(10, TimeUnit.SECONDS) shouldBe "hello"

                val blockBytes = pair.sendCaptured(b, a, BLOCK)
                deliverer =
                    thread(name = "blocked-delivery") {
                        a.dmSessionManager.inboundSink().acceptCircuitEnvelope(blockBytes)
                    }
                blocker.awaitEntered()

                withinStallBudget { a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "reply while blocked")) }
                withinStallBudget { a.dmSessionManager.handleX3dhRejectionForTest(unrelatedRejection(b.pub())) }
                blocker.heldStripeLock shouldBe false
            } finally {
                blocker.release()
                deliverer?.join(30_000)
                pair.stop()
            }
        }

        test("b) direct mode: a listener blocking the Netty thread does not hold back phase A of a send to that peer") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val blocker = ListenerBlocker(a.dmSessionManager, b.pub())
            var sender: Thread? = null
            try {
                connectAndConverge(a, b)
                listenerTestEstablishBothWays(a, b)
                val received = LinkedBlockingQueue<String>()
                a.dmSessionManager.addInboundListener {
                    blocker.onBody(it.content.body)
                    received.add(it.content.body)
                }
                val dispatchReached = CountDownLatch(1)
                a.dmSessionManager.beforeDispatchForTest = { r, _ -> if (r == b.pub()) dispatchReached.countDown() }

                b.dmSessionManager.send(a.pub(), DmContent(body = BLOCK))
                blocker.awaitEntered()
                // The stream this send opens needs the blocked event loop, so only the end of phase A is measured.
                sender =
                    thread(name = "send-while-blocked") {
                        runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "reply while blocked")) }
                    }
                dispatchReached.await(STALL_BUDGET.toMillis(), TimeUnit.MILLISECONDS) shouldBe true
                blocker.heldStripeLock shouldBe false

                blocker.release()
                received.poll(30, TimeUnit.SECONDS) shouldBe BLOCK
            } finally {
                blocker.release()
                sender?.join(60_000)
                a.stop()
                b.stop()
            }
        }

        test("c) a blocking listener for B does not stall inbound from, or a send to, a peer on the same stripe") {
            val a = buildDmTestNode(anonymous = true)
            val b = buildDmTestNode(anonymous = true)
            val c = buildDmTestNode(identity = identityOnStripeOf(a.dmSessionManager, b.pub()), anonymous = true)
            val nodes = CapturingNodes(listOf(a, b, c))
            val blocker = ListenerBlocker(a.dmSessionManager, b.pub())
            var deliverer: Thread? = null
            try {
                a.dmSessionManager.stripeIndexForTest(c.pub()) shouldBe a.dmSessionManager.stripeIndexForTest(b.pub())
                connectAndConverge(a, b)
                connectAndConverge(a, c)
                nodes.install()
                val received = LinkedBlockingQueue<String>()
                a.dmSessionManager.addInboundListener {
                    blocker.onBody(it.content.body)
                    received.add(it.content.body)
                }
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(nodes.sendCaptured(b, a, "hello from b"))
                // C must not pick the one-time prekey B just consumed (a genuine collision, rejected): wait until C
                // sees A's bundle without it.
                awaitTrue {
                    a.publishSelf()
                    val available =
                        a.prekeyStore
                            .publishBundle(a.identity, Instant.now().epochSecond + 3600)
                            .oneTimePrekeys
                            .map { it.id }
                            .toSet()
                    c.prekeyBundleGossip
                        .lookup(a.pub())!!
                        .oneTimePrekeys
                        .all { it.id in available }
                } shouldBe true
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(nodes.sendCaptured(c, a, "hello from c"))
                received.poll(10, TimeUnit.SECONDS) shouldBe "hello from b"
                received.poll(10, TimeUnit.SECONDS) shouldBe "hello from c"

                val blockBytes = nodes.sendCaptured(b, a, BLOCK)
                deliverer =
                    thread(name = "blocked-delivery") {
                        a.dmSessionManager.inboundSink().acceptCircuitEnvelope(blockBytes)
                    }
                blocker.awaitEntered()

                val fromC = nodes.sendCaptured(c, a, "second from c")
                withinStallBudget { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(fromC) }
                received.poll(1, TimeUnit.SECONDS) shouldBe "second from c"
                withinStallBudget { a.dmSessionManager.sendAuto(c.pub(), DmContent(body = "to c")) }
            } finally {
                blocker.release()
                deliverer?.join(30_000)
                nodes.stop()
            }
        }

        test("d) delivery order per peer equals ratchet order, and each caller returns after its own delivery") {
            val pair = anonymousPair()
            val (a, b) = pair
            val blocker = ListenerBlocker(a.dmSessionManager, b.pub())
            val threads = mutableListOf<Thread>()
            try {
                val committed = Collections.synchronizedList(mutableListOf<String>())
                a.dmSessionManager.onInboundCommittedForTest = { peer, plaintext ->
                    if (peer == b.pub()) committed += DmContentCodec.decode(plaintext).body
                }
                val delivered = Collections.synchronizedList(mutableListOf<String>())
                a.dmSessionManager.addInboundListener {
                    delivered += it.content.body
                    blocker.onBody(it.content.body)
                }
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(pair.sendCaptured(b, a, "hello"))

                val m1 = pair.sendCaptured(b, a, BLOCK)
                val m2 = pair.sendCaptured(b, a, "m2")
                threads += thread(name = "deliver-m1") { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(m1) }
                blocker.awaitEntered()
                val secondReturned = AtomicBoolean(false)
                threads +=
                    thread(name = "deliver-m2") {
                        a.dmSessionManager.inboundSink().acceptCircuitEnvelope(m2)
                        secondReturned.set(true)
                    }
                // m2 is decrypted while m1's listener still blocks, but not delivered before m1's listener finished.
                awaitTrue(STALL_BUDGET) { committed.contains("m2") } shouldBe true
                Thread.sleep(300)
                delivered.toList() shouldBe listOf("hello", BLOCK)
                secondReturned.get() shouldBe false

                blocker.release()
                threads.forEach { it.join(30_000) }
                secondReturned.get() shouldBe true
                delivered.toList() shouldBe listOf("hello", BLOCK, "m2")

                // 20 messages from 4 threads at once: whatever order they are decrypted in, they are delivered in it.
                val bodies = (0 until 20).map { "burst-$it" }
                val frames = ConcurrentLinkedQueue(bodies.map { pair.sendCaptured(b, a, it) })
                val burst =
                    (0 until 4).map { i ->
                        thread(name = "burst-$i") {
                            while (true) {
                                val frame = frames.poll() ?: break
                                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(frame)
                            }
                        }
                    }
                burst.forEach { it.join(60_000) }
                awaitTrue { delivered.size == 23 } shouldBe true
                delivered.toList() shouldBe committed.toList()
                delivered.drop(3).toSet() shouldBe bodies.toSet()
                delivered.size shouldBe delivered.toSet().size
                a.dmSessionManager.inboundDeliveryQueueForTest().queuedPeerCountForTest() shouldBe 0
            } finally {
                blocker.release()
                threads.forEach { it.join(30_000) }
                pair.stop()
            }
        }

        test("e) a blocking call-signal listener does not stall a send or a call signal to that peer") {
            val pair = anonymousPair()
            val (a, b) = pair
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val heldStripeLock = AtomicReference<Boolean?>(null)
            var deliverer: Thread? = null
            try {
                val received = LinkedBlockingQueue<String>()
                a.dmSessionManager.addInboundListener { received.add(it.content.body) }
                a.dmSessionManager.addCallSignalListener { signal ->
                    if (String(signal.payload) == BLOCK) {
                        heldStripeLock.set(a.dmSessionManager.holdsPeerLockForTest(signal.sender))
                        entered.countDown()
                        release.await(40, TimeUnit.SECONDS)
                    }
                }
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(pair.sendCaptured(b, a, "hello"))
                received.poll(10, TimeUnit.SECONDS) shouldBe "hello"

                b.dmSessionManager.sendCallSignal(a.pub(), BLOCK.toByteArray(), marksAcceptance = false)
                val signalBytes = pair.takeCaptured(b, a)
                deliverer =
                    thread(name = "blocked-call-signal") {
                        a.dmSessionManager.inboundSink().acceptCircuitEnvelope(signalBytes)
                    }
                entered.await(10, TimeUnit.SECONDS) shouldBe true

                withinStallBudget { a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "text while ringing")) }
                withinStallBudget {
                    a.dmSessionManager.sendCallSignal(b.pub(), "busy".toByteArray(), marksAcceptance = false)
                }
                heldStripeLock.get() shouldBe false
            } finally {
                release.countDown()
                deliverer?.join(30_000)
                pair.stop()
            }
        }

        test("f) offline path: a blocking listener does not stall a parallel send; true only after its own delivery") {
            val pair = anonymousPair()
            val (a, b) = pair
            val blocker = ListenerBlocker(a.dmSessionManager, b.pub())
            var deliverer: Thread? = null
            try {
                val received = LinkedBlockingQueue<String>()
                a.dmSessionManager.addInboundListener {
                    blocker.onBody(it.content.body)
                    received.add(it.content.body)
                }
                a.dmSessionManager.inboundSink().acceptCircuitEnvelope(pair.sendCaptured(b, a, "hello"))
                received.poll(10, TimeUnit.SECONDS) shouldBe "hello"

                val envelope =
                    (DmEnvelopeCodec.decodeFrame(pair.sendCaptured(b, a, BLOCK)) as DmInboundFrame.Envelope).envelope
                val result = AtomicReference<Boolean?>(null)
                deliverer =
                    thread(name = "blocked-offline") {
                        result.set(a.dmSessionManager.handleOfflineEnvelope(envelope))
                    }
                blocker.awaitEntered()

                withinStallBudget { a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "parallel")) }
                result.get() shouldBe null
                blocker.release()
                deliverer.join(30_000)
                result.get() shouldBe true
                received.poll(10, TimeUnit.SECONDS) shouldBe BLOCK
            } finally {
                blocker.release()
                deliverer?.join(30_000)
                pair.stop()
            }
        }
    }) {
    companion object {
        /** Far below any timeout of the code under test; generous for a loaded CI host. */
        val STALL_BUDGET: Duration = Duration.ofSeconds(5)

        const val BLOCK = "block"
    }
}

private fun DmTestNode.pub(): Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey

/** Runs [block] on its own thread and fails if it does not return within [DmInboundListenerStallTest.STALL_BUDGET]. */
private fun withinStallBudget(block: () -> Unit) {
    val budget = DmInboundListenerStallTest.STALL_BUDGET
    val future = CompletableFuture.runAsync({ block() }, { r -> thread(name = "within-budget") { r.run() } })
    try {
        future.get(budget.toMillis(), TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
        throw AssertionError("operation did not complete within $budget - stalled", e)
    }
}

/** A rejection that matches no pending initiation: [DmSessionManager.handleX3dhRejectionForTest] only takes the lock. */
private fun unrelatedRejection(peer: Secp256k1PublicKey): DmX3dhRejection =
    DmX3dhRejection(
        rejecterIdentity = peer,
        rejectedEphemeralPublicKey = X25519KeyPair.generate(SecureRandom()).publicKey,
        signedPrekeyId = 1,
        oneTimePrekeyId = 1,
        reason = DmX3dhRejectionReason.ONE_TIME_PREKEY_CONSUMED,
        issuedAtEpochSecond = Instant.now().epochSecond,
        tag = ByteArray(DmX3dhRejectionCodec.TAG_SIZE),
    )

/** Blocks the listener on the body [DmInboundListenerStallTest.BLOCK] until [release]; records the stripe-lock state. */
private class ListenerBlocker(
    private val manager: DmSessionManager,
    private val sender: Secp256k1PublicKey,
) {
    private val entered = CountDownLatch(1)
    private val released = CountDownLatch(1)

    @Volatile var heldStripeLock: Boolean? = null

    fun onBody(body: String) {
        if (body == DmInboundListenerStallTest.BLOCK && released.count > 0) {
            heldStripeLock = manager.holdsPeerLockForTest(sender)
            entered.countDown()
            released.await(40, TimeUnit.SECONDS)
        }
    }

    fun awaitEntered() {
        check(entered.await(10, TimeUnit.SECONDS)) { "the blocking listener was never entered" }
    }

    fun release() = released.countDown()
}

/** Anonymity transport that delivers nothing itself: every frame is captured for the test to feed in. */
private class CapturingAnonymousTransport(
    private val sealingKeyFor: (Secp256k1PublicKey) -> X25519PublicKey,
) : AnonymousDmTransport {
    val captured = LinkedBlockingQueue<Pair<Secp256k1PublicKey, ByteArray>>()

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget =
        AnonymousDmTarget(recipient, sealingKeyFor(recipient), null, true)

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        captured.add(target.recipient to envelopeBytes)
        return true
    }

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        captured.add(target.recipient to envelopeBytes)
    }

    override fun close() = Unit
}

/** Anonymity-mode nodes, each with its own [CapturingAnonymousTransport]. */
private class CapturingNodes(
    val nodes: List<DmTestNode>,
) {
    private val transports = mutableMapOf<DmTestNode, CapturingAnonymousTransport>()

    operator fun component1(): DmTestNode = nodes[0]

    operator fun component2(): DmTestNode = nodes[1]

    fun install() {
        for (node in nodes) {
            val transport =
                CapturingAnonymousTransport { requireNotNull(node.prekeyBundleGossip.lookup(it)).x25519IdentityKey }
            transports[node] = transport
            node.dmSessionManager.installAnonymousTransport(transport)
        }
    }

    /** [from] sends [body] to [to] (online); returns the captured envelope bytes. */
    fun sendCaptured(
        from: DmTestNode,
        to: DmTestNode,
        body: String,
    ): ByteArray {
        from.dmSessionManager.sendAuto(to.pub(), DmContent(body = body)) shouldBe DmSendOutcome.SENT_ONLINE
        return takeCaptured(from, to)
    }

    /** The next frame [from] handed to its transport; it must be addressed to [to]. */
    fun takeCaptured(
        from: DmTestNode,
        to: DmTestNode,
    ): ByteArray {
        val (recipient, bytes) =
            checkNotNull(transports.getValue(from).captured.poll(10, TimeUnit.SECONDS)) { "nothing was sent" }
        check(recipient == to.pub()) { "frame was addressed to another peer" }
        return bytes
    }

    fun stop() = nodes.forEach { it.stop() }
}

private fun anonymousPair(): CapturingNodes {
    val pair = CapturingNodes(listOf(buildDmTestNode(anonymous = true), buildDmTestNode(anonymous = true)))
    try {
        connectAndConverge(pair.nodes[0], pair.nodes[1])
        pair.install()
    } catch (t: Throwable) {
        pair.stop()
        throw t
    }
    return pair
}

/** Sends A->B and B->A until each side has received one message, so both sessions can send (direct mode). */
private fun listenerTestEstablishBothWays(
    a: DmTestNode,
    b: DmTestNode,
) {
    fun oneWay(
        from: DmTestNode,
        to: DmTestNode,
    ) {
        val got = LinkedBlockingQueue<DmInboundMessage>()
        to.dmSessionManager.addInboundListener { got.add(it) }
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
