package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PeerLinkCounterTest :
    FunSpec({
        test("the cap is enforced and a released slot is reusable") {
            val c = PeerLinkCounter<String>()
            c.tryAcquire("p", 2) shouldBe true
            c.tryAcquire("p", 2) shouldBe true
            c.tryAcquire("p", 2) shouldBe false
            c.count("p") shouldBe 2
            c.release("p")
            c.tryAcquire("p", 2) shouldBe true
            c.release("p")
            c.release("p")
            c.size() shouldBe 0
            c.release("p") // releasing an unknown key is harmless
            c.count("p") shouldBe 0
        }

        test("churning acquire and release of one peer from many threads never exceeds the cap and ends clean") {
            val c = PeerLinkCounter<String>()
            val cap = 2
            val held = AtomicInteger(0)
            val maxSeen = AtomicInteger(0)
            val threads = 16
            val pool = Executors.newFixedThreadPool(threads)
            val start = CountDownLatch(1)
            val done = CountDownLatch(threads)
            repeat(threads) {
                pool.execute {
                    start.await()
                    repeat(20_000) {
                        if (c.tryAcquire("peer", cap)) {
                            val now = held.incrementAndGet()
                            maxSeen.accumulateAndGet(now, ::maxOf)
                            held.decrementAndGet()
                            c.release("peer")
                        }
                    }
                    done.countDown()
                }
            }
            start.countDown()
            done.await(120, TimeUnit.SECONDS) shouldBe true
            pool.shutdownNow()
            (maxSeen.get() <= cap) shouldBe true
            held.get() shouldBe 0
            c.count("peer") shouldBe 0
            c.size() shouldBe 0
        }
    })
