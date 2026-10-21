package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.comparables.shouldBeGreaterThanOrEqualTo
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private fun awaitTrue(
    timeoutMillis: Long = 5_000,
    condition: () -> Boolean,
): Boolean {
    val deadline = System.nanoTime() + timeoutMillis * 1_000_000
    while (System.nanoTime() < deadline) {
        if (condition()) return true
        Thread.sleep(10)
    }
    return condition()
}

class NodeServiceSupervisorTest :
    FunSpec({
        test("stop actions run in reverse registration order") {
            val supervisor = NodeServiceSupervisor("sup-test-lifo")
            val order = CopyOnWriteArrayList<String>()
            supervisor.register("a") { order += "a" }
            supervisor.register("b") { order += "b" }
            supervisor.register("c") { order += "c" }
            supervisor.stopAll()
            order.toList() shouldBe listOf("c", "b", "a")
        }

        test("stopAll is idempotent") {
            val supervisor = NodeServiceSupervisor("sup-test-idem")
            val calls = AtomicInteger()
            supervisor.register("x") { calls.incrementAndGet() }
            supervisor.stopAll()
            supervisor.stopAll()
            supervisor.close()
            calls.get() shouldBe 1
        }

        test("a hanging component times out, the others still stop, and the whole stop stays within the budget") {
            val supervisor = NodeServiceSupervisor("sup-test-hang")
            val stopped = CopyOnWriteArrayList<String>()
            val release = CountDownLatch(1)
            supervisor.register("first") { stopped += "first" }
            supervisor.register("hanging") { release.await() } // never returns on its own
            supervisor.register("last") { stopped += "last" }
            val started = System.nanoTime()
            supervisor.stopAll(perComponent = 300.milliseconds, overall = 5.seconds)
            val elapsedMillis = (System.nanoTime() - started) / 1_000_000
            release.countDown()
            stopped.toList() shouldBe listOf("last", "first")
            elapsedMillis shouldBeLessThan 3_000L
        }

        test("the overall budget bounds a stop with several hanging components") {
            val supervisor = NodeServiceSupervisor("sup-test-overall")
            val release = CountDownLatch(1)
            repeat(10) { supervisor.register("hang-$it") { release.await() } }
            val started = System.nanoTime()
            supervisor.stopAll(perComponent = 1.seconds, overall = 1.seconds)
            val elapsedMillis = (System.nanoTime() - started) / 1_000_000
            release.countDown()
            elapsedMillis shouldBeLessThan 2_500L
        }

        test("a failing stop action does not prevent the remaining ones") {
            val supervisor = NodeServiceSupervisor("sup-test-fail")
            val ran = AtomicInteger()
            supervisor.register("ok") { ran.incrementAndGet() }
            supervisor.register("boom") { error("boom") }
            supervisor.stopAll()
            ran.get() shouldBe 1
        }

        test("backoff grows exponentially and is capped") {
            val interval = 10.seconds
            val cap = 300.seconds
            val delays = (1..8).map { NodeServiceSupervisor.backoffDelay(interval, it, cap) }
            delays[0] shouldBe 20.seconds
            delays[1] shouldBe 40.seconds
            delays[2] shouldBe 80.seconds
            delays[3] shouldBe 160.seconds
            delays[4] shouldBe cap
            delays[7] shouldBe cap
            NodeServiceSupervisor.backoffDelay(interval, 1000, cap) shouldBe cap
            // never below the regular interval, even with a tiny cap
            NodeServiceSupervisor.backoffDelay(interval, 1, 1.seconds) shouldBe interval
        }

        test("a failing periodic job backs off instead of retrying in a tight loop, and recovers on success") {
            val supervisor = NodeServiceSupervisor("sup-test-backoff")
            val runs = AtomicInteger()
            val failing =
                java.util.concurrent.atomic
                    .AtomicBoolean(true)
            val job =
                supervisor.launchPeriodic(
                    "flaky",
                    interval = 50.milliseconds,
                    jitter = 0.milliseconds,
                    initialDelay = 0.milliseconds,
                    maxBackoff = 400.milliseconds,
                ) {
                    runs.incrementAndGet()
                    if (failing.get()) error("nope")
                }
            Thread.sleep(1_000)
            // failures at +0, +100, +300 (50*2, 50*4 capped later ...) - far fewer than 1000/50 = 20 tight-loop runs
            runs.get() shouldBeLessThan 10
            job.failureCount shouldBeGreaterThanOrEqualTo 2L
            failing.set(false)
            awaitTrue(5_000) { job.runCount > job.failureCount } shouldBe true
            supervisor.stopAll()
        }

        test("an Error escaping a periodic job does not kill it - it is rescheduled") {
            val supervisor = NodeServiceSupervisor("sup-test-error")
            val runs = AtomicInteger()
            supervisor.launchPeriodic(
                "errors",
                interval = 20.milliseconds,
                jitter = 0.milliseconds,
                initialDelay = 0.milliseconds,
                maxBackoff = 50.milliseconds,
            ) {
                if (runs.incrementAndGet() == 1) throw StackOverflowError("simulated")
            }
            awaitTrue(5_000) { runs.get() >= 3 } shouldBe true
            supervisor.stopAll()
        }

        test("a periodic job runs repeatedly and stopAll ends it - no worker thread survives") {
            val supervisor = NodeServiceSupervisor("sup-test-periodic")
            val runs = AtomicInteger()
            supervisor.launchPeriodic(
                "tick",
                20.milliseconds,
                5.milliseconds,
                0.milliseconds,
            ) { runs.incrementAndGet() }
            awaitTrue { runs.get() >= 3 } shouldBe true
            supervisor.stopAll()
            val after = runs.get()
            Thread.sleep(200)
            runs.get() shouldBe after
            awaitTrue {
                Thread.getAllStackTraces().keys.none { it.name.startsWith("sup-test-periodic") && it.isAlive }
            } shouldBe true
        }

        test("cancellation interrupts a blocking call inside a periodic job") {
            val supervisor = NodeServiceSupervisor("sup-test-interrupt")
            val entered = CountDownLatch(1)
            val interrupted = CountDownLatch(1)
            supervisor.launchPeriodic("blocking", 1.seconds, 0.milliseconds, 0.milliseconds) {
                entered.countDown()
                try {
                    Thread.sleep(60_000)
                } catch (e: InterruptedException) {
                    interrupted.countDown()
                    throw e
                }
            }
            entered.await(5, TimeUnit.SECONDS) shouldBe true
            val started = System.nanoTime()
            supervisor.stopAll()
            interrupted.await(5, TimeUnit.SECONDS) shouldBe true
            ((System.nanoTime() - started) / 1_000_000) shouldBeLessThan 5_000L
        }

        test("a stopped supervisor accepts no new jobs") {
            val supervisor = NodeServiceSupervisor("sup-test-closed")
            supervisor.stopAll()
            val result = runCatching { supervisor.launchPeriodic("late", 1.seconds, 0.milliseconds, 0.milliseconds) {} }
            result.isFailure shouldBe true
        }

        test("launchOneShot runs the block once on the pool") {
            val supervisor = NodeServiceSupervisor("test-oneshot", poolSize = 2)
            try {
                val latch = CountDownLatch(1)
                supervisor.launchOneShot("once") { latch.countDown() } shouldBe true
                latch.await(5, TimeUnit.SECONDS) shouldBe true
            } finally {
                supervisor.stopAll()
            }
        }

        test("launchOneShot returns false after stopAll and runs nothing") {
            val supervisor = NodeServiceSupervisor("test-oneshot-stopped", poolSize = 2)
            supervisor.stopAll()
            var ran = false
            supervisor.launchOneShot("late") { ran = true } shouldBe false
            ran shouldBe false
        }

        test("a throwing one-shot block does not break the pool") {
            val supervisor = NodeServiceSupervisor("test-oneshot-throw", poolSize = 1)
            try {
                supervisor.launchOneShot("boom") { error("boom") } shouldBe true
                val latch = CountDownLatch(1)
                supervisor.launchOneShot("after") { latch.countDown() } shouldBe true
                latch.await(5, TimeUnit.SECONDS) shouldBe true
            } finally {
                supervisor.stopAll()
            }
        }

        test("stopAll interrupts a blocking one-shot block and the pool terminates") {
            val supervisor = NodeServiceSupervisor("test-oneshot-block", poolSize = 1)
            val started = CountDownLatch(1)
            val interrupted = CountDownLatch(1)
            supervisor.launchOneShot("block") {
                started.countDown()
                try {
                    CountDownLatch(1).await()
                } catch (e: InterruptedException) {
                    interrupted.countDown()
                    throw e
                }
            } shouldBe true
            started.await(5, TimeUnit.SECONDS) shouldBe true
            supervisor.stopAll()
            interrupted.await(5, TimeUnit.SECONDS) shouldBe true
            supervisor.isTerminated() shouldBe true
        }
    })
