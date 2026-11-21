package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Regression test for the "Argon2 residual gap" of the DM receive-path fix: the one-time-prekey consumption of an
 * inbound `X3DH_INITIAL` ([net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore.consumeOneTimePrekey], Argon2id twice
 * for an encrypted store, plus the wait at the store's monitor) ran inside the sender's stripe lock, so every send to
 * that peer and all traffic of other peers on the same stripe waited for it (measured once: 434 ms per first contact,
 * up to 1.7 s with four at once). After the fix the consumption runs before the stripe lock, under the sender's
 * inbound admission lock, which keeps inbound processing of one sender serialized as before.
 *
 * The test nodes use an unencrypted prekey store, so the Argon2id cost is replaced by a pause in the test seam
 * [DmSessionManager.beforePrekeyConsumptionForTest]. Case a) was red before the fix; b) and c) pin the unchanged
 * per-sender semantics (identical replays, order behind a first contact) and were green before and after.
 */
class DmPrekeyConsumptionLockTest :
    FunSpec({
        test("a) a send to the peer does not wait for that peer's one-time-prekey consumption") {
            val pair = consumptionTestPair()
            val (a, b) = pair
            val pause = ConsumptionPause(a.dmSessionManager)
            var deliverer: Thread? = null
            try {
                val received = LinkedBlockingQueue<String>()
                a.dmSessionManager.addInboundListener { received.add(it.content.body) }
                val first = pair.sendCaptured(b, a, "hello")
                deliverer =
                    thread(
                        name = "paused-consumption",
                    ) { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(first) }
                pause.awaitEntered()

                consumptionWithinBudget { a.dmSessionManager.sendAuto(b.consumptionPub(), DmContent(body = "reply")) }
                pause.heldStripeLock shouldBe false
                received.poll(300, TimeUnit.MILLISECONDS) shouldBe null

                pause.release()
                received.poll(10, TimeUnit.SECONDS) shouldBe "hello"
            } finally {
                pause.release()
                deliverer?.join(30_000)
                pair.stop()
            }
        }

        test("b) two identical first contacts at once: one consumption, one delivery, no rejection (as before)") {
            val pair = consumptionTestPair()
            val (a, b) = pair
            val pause = ConsumptionPause(a.dmSessionManager)
            val threads = mutableListOf<Thread>()
            try {
                val received = Collections.synchronizedList(mutableListOf<String>())
                a.dmSessionManager.addInboundListener { received += it.content.body }
                val first = pair.sendCaptured(b, a, "hello")
                threads += thread(name = "copy-1") { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(first) }
                pause.awaitEntered()
                threads += thread(name = "copy-2") { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(first) }
                // The second copy waits behind the first (admission lock); it never reaches the consumption meanwhile.
                Thread.sleep(300)
                pause.invocations.get() shouldBe 1

                pause.release()
                threads.forEach { it.join(30_000) }
                awaitTrue { received.size == 1 } shouldBe true
                Thread.sleep(300)
                received.toList() shouldBe listOf("hello")
                pause.invocations.get() shouldBe 1
                val diagnostics = a.dmSessionManager.diagnostics()
                diagnostics.x3dhInitialRejectedOtkConsumed shouldBe 0
                diagnostics.rejectionsSent shouldBe 0
            } finally {
                pause.release()
                threads.forEach { it.join(30_000) }
                pair.stop()
            }
        }

        test("c) a later message of the same sender waits for its first contact and is delivered after it") {
            val pair = consumptionTestPair()
            val (a, b) = pair
            val pause = ConsumptionPause(a.dmSessionManager)
            val threads = mutableListOf<Thread>()
            try {
                val committed = Collections.synchronizedList(mutableListOf<String>())
                a.dmSessionManager.onInboundCommittedForTest = { peer, plaintext ->
                    if (peer == b.consumptionPub()) committed += DmContentCodec.decode(plaintext).body
                }
                val received = Collections.synchronizedList(mutableListOf<String>())
                a.dmSessionManager.addInboundListener { received += it.content.body }
                val first = pair.sendCaptured(b, a, "hello")
                val second = pair.sendCaptured(b, a, "second")
                threads += thread(name = "first") { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(first) }
                pause.awaitEntered()
                threads += thread(name = "second") { a.dmSessionManager.inboundSink().acceptCircuitEnvelope(second) }
                Thread.sleep(300)
                committed.toList() shouldBe emptyList()

                pause.release()
                threads.forEach { it.join(30_000) }
                awaitTrue { received.size == 2 } shouldBe true
                committed.toList() shouldBe listOf("hello", "second")
                received.toList() shouldBe listOf("hello", "second")
            } finally {
                pause.release()
                threads.forEach { it.join(30_000) }
                pair.stop()
            }
        }
    }) {
    companion object {
        /** Far below any timeout of the code under test; generous for a loaded CI host. */
        val STALL_BUDGET: Duration = Duration.ofSeconds(5)
    }
}

private fun DmTestNode.consumptionPub(): Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey

private fun consumptionWithinBudget(block: () -> Unit) {
    val budget = DmPrekeyConsumptionLockTest.STALL_BUDGET
    val future = CompletableFuture.runAsync({ block() }, { r -> thread(name = "within-budget") { r.run() } })
    try {
        future.get(budget.toMillis(), TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
        throw AssertionError("operation did not complete within $budget - stalled", e)
    }
}

/** Pauses the first one-time-prekey consumption of [manager] until [release]; records the stripe-lock state. */
private class ConsumptionPause(
    private val manager: DmSessionManager,
) {
    private val entered = CountDownLatch(1)
    private val released = CountDownLatch(1)
    val invocations = AtomicInteger()

    @Volatile var heldStripeLock: Boolean? = null

    init {
        manager.beforePrekeyConsumptionForTest = { peer ->
            if (invocations.incrementAndGet() == 1) {
                heldStripeLock = manager.holdsPeerLockForTest(peer)
                entered.countDown()
                released.await(40, TimeUnit.SECONDS)
            }
        }
    }

    fun awaitEntered() {
        check(entered.await(10, TimeUnit.SECONDS)) { "the one-time-prekey consumption was never reached" }
    }

    fun release() = released.countDown()
}

/** Anonymity transport that delivers nothing itself: every frame is captured for the test to feed in. */
private class ConsumptionCapturingTransport(
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

private class ConsumptionTestPair(
    val a: DmTestNode,
    val b: DmTestNode,
) {
    private val transports = mutableMapOf<DmTestNode, ConsumptionCapturingTransport>()

    operator fun component1(): DmTestNode = a

    operator fun component2(): DmTestNode = b

    fun install() {
        for (node in listOf(a, b)) {
            val transport =
                ConsumptionCapturingTransport { requireNotNull(node.prekeyBundleGossip.lookup(it)).x25519IdentityKey }
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
        from.dmSessionManager.sendAuto(to.consumptionPub(), DmContent(body = body)) shouldBe DmSendOutcome.SENT_ONLINE
        val (recipient, bytes) =
            checkNotNull(transports.getValue(from).captured.poll(10, TimeUnit.SECONDS)) { "nothing was sent" }
        check(recipient == to.consumptionPub()) { "frame was addressed to another peer" }
        return bytes
    }

    fun stop() {
        a.stop()
        b.stop()
    }
}

private fun consumptionTestPair(): ConsumptionTestPair {
    val pair = ConsumptionTestPair(buildDmTestNode(anonymous = true), buildDmTestNode(anonymous = true))
    try {
        connectAndConverge(pair.a, pair.b)
        pair.install()
    } catch (t: Throwable) {
        pair.stop()
        throw t
    }
    return pair
}
