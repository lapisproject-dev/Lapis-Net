package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Unit tests of [InboundDeliveryQueue], without a network. A plain monitor per peer stands in for the stripe lock
 * that [DmSessionManager] holds around [InboundDeliveryQueue.enqueue].
 */
class InboundDeliveryQueueTest :
    FunSpec({
        test("FIFO per peer across 8 threads x 200 tasks: delivery order equals enqueue order") {
            val queue = InboundDeliveryQueue()
            val peer = newPeer()
            val stripe = Any()
            val enqueued = Collections.synchronizedList(mutableListOf<Int>())
            val delivered = Collections.synchronizedList(mutableListOf<Int>())
            val counter = AtomicInteger()
            val threads =
                (0 until 8).map {
                    thread {
                        repeat(200) {
                            val ticket =
                                synchronized(stripe) {
                                    val n = counter.getAndIncrement()
                                    enqueued += n
                                    queue.enqueue(peer) { delivered += n }
                                }
                            queue.deliver(ticket)
                            ticket.isDone shouldBe true
                        }
                    }
                }
            threads.forEach { it.join(60_000) }
            threads.none { it.isAlive } shouldBe true
            delivered.size shouldBe 1600
            delivered.toList() shouldBe enqueued.toList()
            queue.queuedPeerCountForTest() shouldBe 0
        }

        test("different peers are delivered in parallel: a blocked peer does not hold back another") {
            val queue = InboundDeliveryQueue()
            val blocked = newPeer()
            val other = newPeer()
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val blocker =
                thread {
                    queue.deliver(
                        queue.enqueue(blocked) {
                            entered.countDown()
                            release.await(30, TimeUnit.SECONDS)
                        },
                    )
                }
            try {
                entered.await(10, TimeUnit.SECONDS) shouldBe true
                val ran = AtomicBoolean(false)
                val otherThread = thread { queue.deliver(queue.enqueue(other) { ran.set(true) }) }
                otherThread.join(5_000)
                otherThread.isAlive shouldBe false
                ran.get() shouldBe true
            } finally {
                release.countDown()
                blocker.join(10_000)
            }
            queue.queuedPeerCountForTest() shouldBe 0
        }

        test("a waiting caller returns only after its own task ran, which runs after the earlier one") {
            val queue = InboundDeliveryQueue()
            val peer = newPeer()
            val order = Collections.synchronizedList(mutableListOf<String>())
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val first =
                queue.enqueue(peer) {
                    entered.countDown()
                    release.await(30, TimeUnit.SECONDS)
                    order += "first"
                }
            val second = queue.enqueue(peer) { order += "second" }
            val firstThread = thread { queue.deliver(first) }
            entered.await(10, TimeUnit.SECONDS) shouldBe true
            val secondReturned = AtomicBoolean(false)
            val secondThread =
                thread {
                    queue.deliver(second)
                    secondReturned.set(true)
                }
            Thread.sleep(300)
            secondReturned.get() shouldBe false
            second.isDone shouldBe false
            release.countDown()
            firstThread.join(10_000)
            secondThread.join(10_000)
            secondReturned.get() shouldBe true
            order.toList() shouldBe listOf("first", "second")
            queue.queuedPeerCountForTest() shouldBe 0
        }

        test("the drainer stops after its own task: a later caller's task runs on that caller's thread") {
            val queue = InboundDeliveryQueue()
            val peer = newPeer()
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val first =
                queue.enqueue(peer) {
                    entered.countDown()
                    release.await(30, TimeUnit.SECONDS)
                }
            val firstThread = thread(name = "first-caller") { queue.deliver(first) }
            entered.await(10, TimeUnit.SECONDS) shouldBe true
            val ranOn = AtomicReference<String?>(null)
            val second = queue.enqueue(peer) { ranOn.set(Thread.currentThread().name) }
            val secondThread = thread(name = "second-caller") { queue.deliver(second) }
            Thread.sleep(200)
            release.countDown()
            firstThread.join(10_000)
            secondThread.join(10_000)
            secondThread.isAlive shouldBe false
            ranOn.get() shouldBe "second-caller"
            queue.queuedPeerCountForTest() shouldBe 0
        }

        test("a reentrant deliver from a task of the same peer does not hang; its task runs right after") {
            val queue = InboundDeliveryQueue()
            val peer = newPeer()
            val order = Collections.synchronizedList(mutableListOf<String>())
            val done = CountDownLatch(1)
            val worker =
                thread {
                    queue.deliver(
                        queue.enqueue(peer) {
                            val inner = queue.enqueue(peer) { order += "inner" }
                            queue.deliver(inner) // returns at once: the inner task runs after this one
                            order += "outer"
                        },
                    )
                    done.countDown()
                }
            done.await(5, TimeUnit.SECONDS) shouldBe true
            worker.join(5_000)
            order.toList() shouldBe listOf("outer", "inner")
            queue.queuedPeerCountForTest() shouldBe 0
        }

        test("a throwing task does not block later tasks; an Error still releases the waiting callers") {
            val queue = InboundDeliveryQueue()
            val peer = newPeer()
            val ran = Collections.synchronizedList(mutableListOf<String>())
            queue.deliver(queue.enqueue(peer) { throw IllegalStateException("listener bug") })
            queue.deliver(queue.enqueue(peer) { ran += "after runtime exception" })
            ran.toList() shouldBe listOf("after runtime exception")

            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val failing =
                queue.enqueue(peer) {
                    entered.countDown()
                    release.await(30, TimeUnit.SECONDS)
                    throw SimulatedError()
                }
            val waiting = (0 until 3).map { i -> queue.enqueue(peer) { ran += "waiting-$i" } }
            val errorSeen = AtomicBoolean(false)
            val drainer =
                thread {
                    try {
                        queue.deliver(failing)
                    } catch (e: SimulatedError) {
                        errorSeen.set(true)
                    }
                }
            entered.await(10, TimeUnit.SECONDS) shouldBe true
            val waiters = waiting.map { ticket -> thread { queue.deliver(ticket) } }
            Thread.sleep(200)
            release.countDown()
            drainer.join(10_000)
            waiters.forEach { it.join(10_000) }
            errorSeen.get() shouldBe true
            failing.isDone shouldBe true
            waiters.none { it.isAlive } shouldBe true
            waiting.all { it.isDone } shouldBe true
            ran.toList() shouldBe listOf("after runtime exception", "waiting-0", "waiting-1", "waiting-2")
            queue.queuedPeerCountForTest() shouldBe 0
        }
    })

private fun newPeer(): Secp256k1PublicKey = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

private class SimulatedError : Error("simulated Error in a listener")
