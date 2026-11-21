package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Two-phase send (state under the stripe lock, network in the per-peer outbound lane): ordering, single flight,
 * cancellation, bounds and shutdown, end to end through [DmSessionManager].
 */
class DmOutboundLaneTest :
    FunSpec({
        test("a) 50 parallel sends to one peer all arrive, and leave the node in ratchet order") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val pool = Executors.newFixedThreadPool(8)
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                val received = Collections.synchronizedList(mutableListOf<String>())
                b.dmSessionManager.addInboundListener { received += it.content.body }
                val numbers = Collections.synchronizedList(mutableListOf<Int>())
                a.dmSessionManager.beforeDispatchForTest = { r, bytes ->
                    if (r == b.pub()) numbers += envelopeOf(bytes).ratchetMessage.header.messageNumber
                }
                val futures =
                    (0 until 50).map { i ->
                        pool.submit { a.dmSessionManager.send(b.pub(), DmContent(body = "m-$i")) }
                    }
                futures.forEach { it.get(60, TimeUnit.SECONDS) }
                awaitCondition { received.size >= 50 }
                received.toSet() shouldBe (0 until 50).map { "m-$it" }.toSet()
                received shouldHaveSize 50
                numbers shouldHaveSize 50
                numbers.zipWithNext().all { (x, y) -> y > x } shouldBe true
                a.dmSessionManager.outboundLanesForTest().laneCountForTest() shouldBe 0
            } finally {
                pool.shutdownNow()
                a.stop()
                b.stop()
            }
        }

        test(
            "b) 20 parallel first-contact sendAuto calls: exactly one X3DH_INITIAL, first on the wire, all delivered",
        ) {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val pool = Executors.newFixedThreadPool(8)
            try {
                connectAndConverge(a, b)
                val received = Collections.synchronizedList(mutableListOf<String>())
                b.dmSessionManager.addInboundListener { received += it.content.body }
                val types = Collections.synchronizedList(mutableListOf<DmMessageType>())
                a.dmSessionManager.onDirectFrameSentForTest = { bytes -> types += envelopeOf(bytes).messageType }
                val outcomes =
                    (0 until 20)
                        .map { i ->
                            pool.submit<DmSendOutcome> {
                                a.dmSessionManager.sendAuto(
                                    b.pub(),
                                    DmContent(body = "f-$i"),
                                )
                            }
                        }.map { it.get(60, TimeUnit.SECONDS) }
                outcomes.all { it == DmSendOutcome.SENT_ONLINE } shouldBe true
                awaitCondition { received.size >= 20 }
                received.toSet() shouldBe (0 until 20).map { "f-$it" }.toSet()
                types shouldHaveSize 20
                types.first() shouldBe DmMessageType.X3DH_INITIAL
                types.count { it == DmMessageType.X3DH_INITIAL } shouldBe 1
            } finally {
                pool.shutdownNow()
                a.stop()
                b.stop()
            }
        }

        test("c) a failed dial frees the lane and the dial slot; the next send works") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                val received = LinkedBlockingQueue<String>()
                b.dmSessionManager.addInboundListener { received += it.content.body }
                var fail = true
                a.dmSessionManager.beforeDispatchForTest = { r, _ ->
                    if (r == b.pub() && fail) {
                        fail = false
                        throw DmSessionException("simulated dial failure")
                    }
                }
                shouldThrow<DmSessionException> { a.dmSessionManager.send(b.pub(), DmContent(body = "lost")) }
                a.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) shouldBe 0
                a.dmSessionManager.outboundLanesForTest().laneCountForTest() shouldBe 0
                a.dmSessionManager.availableDialPermitsForTest() shouldBe DmSessionManager.MAX_CONCURRENT_OUTBOUND_DIALS
                a.dmSessionManager.send(b.pub(), DmContent(body = "after"))
                received.poll(30, TimeUnit.SECONDS) shouldBe "after"
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("d) single flight: sendAuto calls queued behind a failed head go offline without dialing again") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val head = HeadBlocker()
            val outcomes = Collections.synchronizedList(mutableListOf<DmSendOutcome>())
            val threads = mutableListOf<Thread>()
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                head.install(a.dmSessionManager, b.pub(), throwOnRelease = true)
                threads +=
                    thread {
                        runCatching {
                            outcomes +=
                                a.dmSessionManager.sendAuto(
                                    b.pub(),
                                    DmContent(body = "head"),
                                )
                        }
                    }
                head.awaitEntered()
                repeat(3) { i ->
                    threads +=
                        thread {
                            runCatching {
                                outcomes +=
                                    a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "w-$i"))
                            }
                        }
                }
                awaitCondition { a.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) == 4 }
                val dialsBefore = a.dmSessionManager.dialAttemptsForTest.get()
                head.release()
                threads.forEach { it.join(30_000) }
                outcomes shouldHaveSize 4
                outcomes.all { it == DmSendOutcome.QUEUED_FOR_PICKUP } shouldBe true
                a.dmSessionManager.dialAttemptsForTest.get() shouldBe dialsBefore
                // A ticket reserved after the failure dials again.
                a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "fresh")) shouldBe DmSendOutcome.SENT_ONLINE
                a.dmSessionManager.dialAttemptsForTest.get() shouldBe dialsBefore + 1
            } finally {
                head.release()
                threads.forEach { it.join(30_000) }
                a.stop()
                b.stop()
            }
        }

        test("e) an interrupted waiter fails, restores its interrupt flag and lets the next send through") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val head = HeadBlocker()
            val threads = mutableListOf<Thread>()
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                val received = LinkedBlockingQueue<String>()
                b.dmSessionManager.addInboundListener { received += it.content.body }
                head.install(a.dmSessionManager, b.pub())
                threads += thread { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "head")) } }
                head.awaitEntered()
                val failure = AtomicReference<Throwable?>()
                val flag = AtomicReference<Boolean?>()
                val waiter =
                    thread {
                        try {
                            a.dmSessionManager.send(b.pub(), DmContent(body = "interrupted"))
                        } catch (e: Throwable) {
                            failure.set(e)
                            flag.set(Thread.currentThread().isInterrupted)
                        }
                    }
                threads += thread { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "third")) } }
                awaitCondition { a.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) == 3 }
                waiter.interrupt()
                waiter.join(10_000)
                failure.get().shouldBeInstanceOf<DmSessionException>()
                flag.get() shouldBe true
                a.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) shouldBe 2
                head.release()
                threads.forEach { it.join(30_000) }
                val got = listOfNotNull(received.poll(30, TimeUnit.SECONDS), received.poll(30, TimeUnit.SECONDS))
                got.toSet() shouldBe setOf("head", "third")
                a.dmSessionManager.outboundLanesForTest().laneCountForTest() shouldBe 0
            } finally {
                head.release()
                threads.forEach { it.join(30_000) }
                a.stop()
                b.stop()
            }
        }

        test("f) the lane wait is bounded: send fails, sendAuto deposits offline, the lane stays consistent") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val head = HeadBlocker()
            var headThread: Thread? = null
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                a.dmSessionManager.laneWaitTimeout = Duration.ofSeconds(1)
                head.install(a.dmSessionManager, b.pub())
                headThread = thread { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "head")) } }
                head.awaitEntered()
                val started = System.nanoTime()
                shouldThrow<DmLaneWaitTimeoutException> { a.dmSessionManager.send(b.pub(), DmContent(body = "late")) }
                (Duration.ofNanos(System.nanoTime() - started) < Duration.ofSeconds(10)) shouldBe true
                a.dmSessionManager.sendAuto(b.pub(), DmContent(body = "late auto")) shouldBe
                    DmSendOutcome.QUEUED_FOR_PICKUP
                a.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) shouldBe 1
            } finally {
                head.release()
                headThread?.join(30_000)
                a.stop()
                b.stop()
            }
        }

        test("g) a full lane refuses the send BEFORE its ratchet step (no session state changes)") {
            val b = buildDmTestNode()
            val head = HeadBlocker()
            val threads = mutableListOf<Thread>()
            val sessionDir = Files.createTempDirectory("lane-full-sessions")
            val a2 = buildDmTestNode(sessionStoreDirectory = sessionDir)
            try {
                connectAndConverge(a2, b)
                laneEstablishBothWays(a2, b)
                a2.dmSessionManager.outboundLanesForTest().maxQueuedPerPeer = 2
                head.install(a2.dmSessionManager, b.pub())
                threads += thread { runCatching { a2.dmSessionManager.send(b.pub(), DmContent(body = "head")) } }
                head.awaitEntered()
                threads += thread { runCatching { a2.dmSessionManager.send(b.pub(), DmContent(body = "second")) } }
                awaitCondition { a2.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) == 2 }
                // The ticket is reserved before the envelope is persisted: wait until the second send's files settle.
                var before = directoryDigest(sessionDir)
                while (true) {
                    Thread.sleep(500)
                    val now = directoryDigest(sessionDir)
                    if (now == before) break
                    before = now
                }
                val e = shouldThrow<DmSessionException> { a2.dmSessionManager.send(b.pub(), DmContent(body = "third")) }
                e.message shouldBe "too many queued sends to the same peer"
                directoryDigest(sessionDir) shouldBe before
            } finally {
                head.release()
                threads.forEach { it.join(30_000) }
                a2.stop()
                b.stop()
            }
        }

        test("h) a rejection accepted while an old-chain TEXT waits in the lane: every message arrives exactly once") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val a = buildDmTestNode()
            val c = buildDmTestNode()
            try {
                connectAndConverge(a, b)
                connectAndConverge(c, b)
                val sharedId =
                    a.prekeyBundleGossip
                        .lookup(b.pub())!!
                        .oneTimePrekeys
                        .first()
                        .id
                a.dmSessionManager.oneTimePrekeyChooserForTest = { sharedId }
                c.dmSessionManager.oneTimePrekeyChooserForTest = { sharedId }
                val fromC = Collections.synchronizedList(mutableListOf<String>())
                b.dmSessionManager.addInboundListener { if (it.sender == c.pub()) fromC += it.content.body }
                val fromA = LinkedBlockingQueue<String>()
                b.dmSessionManager.addInboundListener { if (it.sender == a.pub()) fromA += it.content.body }
                a.dmSessionManager.send(b.pub(), DmContent(body = "from a"))
                fromA.poll(30, TimeUnit.SECONDS) shouldBe "from a"

                // Dispatch 1 (c1, X3DH_INITIAL on the colliding prekey) waits until c2 is queued behind it;
                // dispatch 2 (c2, TEXT of the refused chain) waits until C has accepted B's rejection.
                val dispatches =
                    java.util.concurrent.atomic
                        .AtomicInteger()
                c.dmSessionManager.beforeDispatchForTest = { r, _ ->
                    if (r == b.pub()) {
                        when (dispatches.incrementAndGet()) {
                            1 ->
                                awaitCondition {
                                    c.dmSessionManager.outboundLanesForTest().queuedForTest(
                                        b.pub(),
                                    ) >= 2
                                }
                            2 -> awaitCondition { c.dmSessionManager.diagnostics().rejectionsAccepted >= 1 }
                            else -> Unit
                        }
                    }
                }
                val c1 = thread { runCatching { c.dmSessionManager.send(b.pub(), DmContent(body = "c1")) } }
                awaitCondition { c.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) == 1 }
                val c2 = thread { runCatching { c.dmSessionManager.send(b.pub(), DmContent(body = "c2")) } }
                c1.join(60_000)
                c2.join(60_000)
                awaitCondition(Duration.ofSeconds(60)) { fromC.contains("c1") && fromC.contains("c2") }
                Thread.sleep(1_000)
                fromC.count { it == "c1" } shouldBe 1
                fromC.count { it == "c2" } shouldBe 1
                c.dmSessionManager.diagnostics().rejectionsAccepted shouldBe 1L
                c.dmSessionManager.diagnostics().rebootstrapsAfterRejection shouldBe 1L
            } finally {
                a.stop()
                b.stop()
                c.stop()
            }
        }

        test("i) phantom protection: no directory record -> no session file, no lane") {
            val a = buildDmTestNode()
            try {
                val stranger = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                shouldThrow<DmUnknownRecipientException> { a.dmSessionManager.send(stranger, DmContent(body = "x")) }
                a.dmSessionManager.liveSessionForTest(stranger) shouldBe null
                a.dmSessionManager.outboundLanesForTest().laneCountForTest() shouldBe 0
            } finally {
                a.stop()
            }
        }

        test("j) stop() wakes every send waiting for its turn; no thread hangs") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            val head = HeadBlocker()
            var headThread: Thread? = null
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                head.install(a.dmSessionManager, b.pub())
                headThread = thread { runCatching { a.dmSessionManager.send(b.pub(), DmContent(body = "head")) } }
                head.awaitEntered()
                val failures = Collections.synchronizedList(mutableListOf<Throwable>())
                val waiters =
                    (0 until 3).map { i ->
                        thread(name = "lane-waiter-$i") {
                            try {
                                a.dmSessionManager.send(b.pub(), DmContent(body = "w-$i"))
                            } catch (e: Throwable) {
                                failures += e
                            }
                        }
                    }
                awaitCondition { a.dmSessionManager.outboundLanesForTest().queuedForTest(b.pub()) == 4 }
                a.dmSessionManager.stop()
                waiters.forEach { it.join(10_000) }
                waiters.none { it.isAlive } shouldBe true
                failures shouldHaveSize 3
                failures.all { it is DmSessionException && it.message == "dm session manager stopped" } shouldBe true
                Thread.getAllStackTraces().keys.count { it.name.startsWith("lane-waiter-") && it.isAlive } shouldBe 0
            } finally {
                head.release()
                headThread?.join(30_000)
                a.stop()
                b.stop()
            }
        }

        test("k) a listener that sends synchronously no longer dials under the stripe lock, and does not deadlock") {
            // Listeners run after the stripe lock (InboundDeliveryQueue), so even a listener that sends synchronously
            // cannot dial under it any more: the guard counter stays 0 (before the inbound fix it was > 0 here). On the
            // direct path such a send still runs on the Netty thread that delivers the inbound message and may time
            // out (the stream it opens needs that same event loop). What must hold: no deadlock, no dial under the
            // stripe lock, and the peer is usable again afterwards.
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            try {
                connectAndConverge(a, b)
                laneEstablishBothWays(a, b)
                val listenerDone = CountDownLatch(1)
                a.dmSessionManager.addInboundListener { message ->
                    if (message.content.body == "please reply") {
                        runCatching { a.dmSessionManager.send(message.sender, DmContent(body = "reply")) }
                        listenerDone.countDown()
                    }
                }
                b.dmSessionManager.send(a.pub(), DmContent(body = "please reply"))
                val bound =
                    DmSessionManager.DIAL_TIMEOUT
                        .multipliedBy(2)
                        .plusSeconds(15)
                        .seconds
                listenerDone.await(bound, TimeUnit.SECONDS) shouldBe true
                a.dmSessionManager.diagnostics().dialsUnderPeerLock shouldBe 0L
                a.dmSessionManager.outboundLanesForTest().laneCountForTest() shouldBe 0
                val atB = LinkedBlockingQueue<String>()
                b.dmSessionManager.addInboundListener { atB += it.content.body }
                a.dmSessionManager.send(b.pub(), DmContent(body = "afterwards"))
                var got: String? = null
                val deadline = Instant.now().plusSeconds(30)
                while (got != "afterwards" && Instant.now().isBefore(deadline)) got = atB.poll(1, TimeUnit.SECONDS)
                got shouldBe "afterwards"
            } finally {
                a.stop()
                b.stop()
            }
        }
    })

private fun DmTestNode.pub(): Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey

private fun envelopeOf(bytes: ByteArray): DmEnvelope =
    (DmEnvelopeCodec.decodeFrame(bytes) as DmInboundFrame.Envelope).envelope

private fun awaitCondition(
    timeout: Duration = Duration.ofSeconds(30),
    condition: () -> Boolean,
) {
    val deadline = Instant.now().plus(timeout)
    while (!condition()) {
        check(Instant.now().isBefore(deadline)) { "condition not met within $timeout" }
        Thread.sleep(20)
    }
}

private fun directoryDigest(dir: Path): String {
    val digest = MessageDigest.getInstance("SHA-256")
    Files.list(dir).use { stream ->
        stream.sorted().forEach { file ->
            digest.update(file.fileName.toString().toByteArray())
            if (Files.isRegularFile(file)) digest.update(Files.readAllBytes(file))
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

/** Blocks the FIRST dispatch to one recipient until [release]; optionally fails it afterwards. */
private class HeadBlocker {
    private val entered = CountDownLatch(1)
    private val released = CountDownLatch(1)

    @Volatile private var blocked = false

    fun install(
        manager: DmSessionManager,
        target: Secp256k1PublicKey,
        throwOnRelease: Boolean = false,
    ) {
        manager.beforeDispatchForTest = { recipient, _ ->
            if (recipient == target && !blocked) {
                blocked = true
                entered.countDown()
                released.await(40, TimeUnit.SECONDS)
                if (throwOnRelease) throw DmSessionException("simulated dial failure")
            }
        }
    }

    fun awaitEntered() {
        check(entered.await(10, TimeUnit.SECONDS)) { "the blocked dispatch never started" }
    }

    fun release() = released.countDown()
}

/** Sends A->B and B->A until each side has received one message, so both sessions can send. */
private fun laneEstablishBothWays(
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
