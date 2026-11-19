package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

private fun freshKey(): Secp256k1PublicKey = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

private val LONG = Duration.ofSeconds(30)

class OutboundLanesTest :
    FunSpec({
        test("tickets get their turn in FIFO order") {
            val lanes = OutboundLanes(64, 16)
            val peer = freshKey()
            val tickets = (0 until 5).map { lanes.reserve(peer) }
            val order = Collections.synchronizedList(mutableListOf<Int>())
            val threads =
                tickets.mapIndexed { i, t ->
                    thread {
                        lanes.awaitTurn(t, LONG)
                        order += i
                        lanes.release(t)
                    }
                }
            threads.forEach { it.join(30_000) }
            order shouldBe listOf(0, 1, 2, 3, 4)
            lanes.laneCountForTest() shouldBe 0
        }

        test("releasing a middle ticket (cancel) lets the next one through, and the empty lane is removed") {
            val lanes = OutboundLanes(64, 16)
            val peer = freshKey()
            val t1 = lanes.reserve(peer)
            val t2 = lanes.reserve(peer)
            val t3 = lanes.reserve(peer)
            lanes.release(t2)
            lanes.queuedForTest(peer) shouldBe 2
            lanes.awaitTurn(t1, LONG)
            lanes.release(t1)
            lanes.awaitTurn(t3, Duration.ofSeconds(1)).previousDialFailed shouldBe false
            lanes.release(t3)
            lanes.release(t3) // idempotent
            lanes.laneCountForTest() shouldBe 0
        }

        test("a wait that times out removes its own ticket and leaves the lane consistent") {
            val lanes = OutboundLanes(64, 16)
            val peer = freshKey()
            val head = lanes.reserve(peer)
            val waiter = lanes.reserve(peer)
            shouldThrow<DmLaneWaitTimeoutException> { lanes.awaitTurn(waiter, Duration.ofMillis(200)) }
            lanes.queuedForTest(peer) shouldBe 1
            lanes.release(head)
            lanes.laneCountForTest() shouldBe 0
        }

        test("an interrupted waiter fails with its interrupt flag set and its ticket gone") {
            val lanes = OutboundLanes(64, 16)
            val peer = freshKey()
            val head = lanes.reserve(peer)
            val waiter = lanes.reserve(peer)
            val failure = AtomicReference<Throwable?>()
            val flagAfter = AtomicReference<Boolean?>()
            val t =
                thread {
                    try {
                        lanes.awaitTurn(waiter, LONG)
                    } catch (e: Throwable) {
                        failure.set(e)
                        flagAfter.set(Thread.currentThread().isInterrupted)
                    }
                }
            Thread.sleep(200)
            t.interrupt()
            t.join(10_000)
            failure.get().shouldBeInstanceOf<DmSessionException>()
            flagAfter.get() shouldBe true
            lanes.queuedForTest(peer) shouldBe 1
            lanes.release(head)
            lanes.laneCountForTest() shouldBe 0
        }

        test("close wakes every waiter and refuses later reservations") {
            val lanes = OutboundLanes(64, 16)
            val peer = freshKey()
            lanes.reserve(peer)
            val waiters = (0 until 3).map { lanes.reserve(peer) }
            val failures = AtomicInteger()
            val threads =
                waiters.map { w ->
                    thread {
                        try {
                            lanes.awaitTurn(w, LONG)
                        } catch (e: DmSessionException) {
                            failures.incrementAndGet()
                        }
                    }
                }
            Thread.sleep(200)
            lanes.close()
            threads.forEach { it.join(10_000) }
            threads.none { it.isAlive } shouldBe true
            failures.get() shouldBe 3
            shouldThrow<DmSessionException> { lanes.reserve(freshKey()) }
        }

        test("a full lane and too many active lanes are refused") {
            val lanes = OutboundLanes(2, 1)
            val peer = freshKey()
            val t1 = lanes.reserve(peer)
            lanes.reserve(peer)
            shouldThrow<DmSessionException> { lanes.reserve(peer) }.message shouldBe
                "too many queued sends to the same peer"
            val other = freshKey()
            shouldThrow<DmSessionException> { lanes.reserve(other) }.message shouldBe
                "too many peers with queued outbound sends"
            lanes.laneCountForTest() shouldBe 1
            lanes.release(t1)
            lanes.queuedForTest(peer) shouldBe 1
        }

        test("single flight: tickets queued behind a failed online attempt see it, later ones do not") {
            val lanes = OutboundLanes(64, 16)
            val peer = freshKey()
            val head = lanes.reserve(peer)
            val behind = lanes.reserve(peer)
            lanes.awaitTurn(head, LONG)
            lanes.release(head, onlineAttemptFailed = true)
            val later = lanes.reserve(peer)
            lanes.awaitTurn(behind, LONG).previousDialFailed shouldBe true
            lanes.release(behind)
            lanes.awaitTurn(later, LONG).previousDialFailed shouldBe false
            lanes.release(later)
        }

        test("race: removing an empty lane never loses a concurrent reservation (4 threads x 10k)") {
            val lanes = OutboundLanes(64, 16)
            val peers = listOf(freshKey(), freshKey())
            val start = CountDownLatch(1)
            val violations = AtomicInteger()
            val errors = AtomicInteger()
            val threads =
                (0 until 4).map { n ->
                    thread {
                        start.await()
                        repeat(10_000) { i ->
                            val peer = peers[(n + i) % 2]
                            try {
                                val t = lanes.reserve(peer)
                                // While we hold a ticket, its lane must be the one in the map.
                                if (lanes.laneOfForTest(peer) !== t.lane) violations.incrementAndGet()
                                lanes.awaitTurn(t, LONG)
                                lanes.release(t)
                            } catch (e: Throwable) {
                                errors.incrementAndGet()
                            }
                        }
                    }
                }
            start.countDown()
            threads.forEach { it.join(60_000) }
            violations.get() shouldBe 0
            errors.get() shouldBe 0
            lanes.laneCountForTest() shouldBe 0
            lanes.allLanesNonEmptyForTest() shouldBe true
        }
    })
