package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private val OWN_THREAD_PREFIXES =
    listOf("lapis-browser-worker", "lapis-browser-stop", "lapis-relay-autoselect", "lapis-net-mail-dht-fetch")

private fun ownThreads(): List<String> =
    Thread
        .getAllStackTraces()
        .keys
        .filter { t -> t.isAlive && OWN_THREAD_PREFIXES.any { t.name.startsWith(it) } }
        .map { it.name }
        .sorted()

private fun awaitNoOwnThreads(
    timeoutSeconds: Long = 15,
    baseline: List<String> = emptyList(),
): List<String> {
    val deadline = System.nanoTime() + timeoutSeconds * 1_000_000_000L
    while (System.nanoTime() < deadline) {
        val current = ownThreads()
        if (current.size <= baseline.size) return current
        Thread.sleep(100)
    }
    return ownThreads()
}

private val ALL_ON =
    BrowserConfig(
        NodeWiringOptions.resolve(mapOf("reachability" to "private", "publish-relay-reliability" to "true")),
        DmAcceptanceSettings(veritasGate = true),
    )

/** The V0.9.15 background parts must leave no thread behind - after a stop, after a restart, and after a failed start. */
class BrowserServerLifecycleTest :
    FunSpec({
        test(
            "two start/stop cycles with every switch on leave no supervised thread behind",
        ).config(timeout = 180.seconds) {
            val baseline = ownThreads()
            repeat(2) {
                val server =
                    startWiredTestServer(
                        config = ALL_ON,
                        autoRelayConfig = AutoRelayConfig(allowNonPublicCandidateAddresses = true),
                        dhtMaintenanceInitialDelay = 100.milliseconds,
                        dhtMaintenanceInterval = 200.milliseconds,
                        selfRecordCheckInterval = 200.milliseconds,
                        acceptanceRefreshInterval = 200.milliseconds,
                    )
                val supervisor = server.supervisorForTesting
                // let every periodic job run at least once
                Thread.sleep(800)
                ownThreads().isNotEmpty() shouldBe true
                server.stop()
                supervisor.isTerminated() shouldBe true
                awaitNoOwnThreads(baseline = baseline) shouldBe baseline
            }
        }

        test("stopping while a DHT maintenance pass is blocked stays within the budget and leaves no thread").config(
            timeout = 120.seconds,
        ) {
            val baseline = ownThreads()
            val entered = CountDownLatch(1)
            val server =
                startWiredTestServer(
                    dhtMaintenanceInitialDelay = 50.milliseconds,
                    dhtMaintenanceHook = {
                        entered.countDown()
                        Thread.sleep(600_000) // a stand-in for a DHT walk stuck in network I/O; interruptible
                    },
                )
            entered.await(20, TimeUnit.SECONDS) shouldBe true
            val started = System.nanoTime()
            server.stop()
            ((System.nanoTime() - started) / 1_000_000_000L) shouldBeLessThan 15L
            awaitNoOwnThreads(baseline = baseline) shouldBe baseline
        }

        test("a failed start (HTTP port already taken) rolls the supervisor back and leaks no thread").config(
            timeout = 120.seconds,
        ) {
            val baseline = ownThreads()
            val first = startWiredTestServer(selfRecordCheckInterval = 100.milliseconds)
            try {
                Thread.sleep(300)
                shouldThrow<Exception> {
                    startWiredTestServer(
                        config = ALL_ON,
                        httpPort = first.boundPort,
                        autoRelayConfig = AutoRelayConfig(allowNonPublicCandidateAddresses = true),
                        selfRecordCheckInterval = 100.milliseconds,
                    )
                }
            } finally {
                first.stop()
            }
            // with the first server gone, anything still alive was leaked by the failed start
            awaitNoOwnThreads(baseline = baseline) shouldBe baseline
        }

        test("stop is idempotent for the supervised parts").config(timeout = 90.seconds) {
            val server = startWiredTestServer()
            server.stop()
            server.supervisorForTesting.stopAll()
            server.supervisorForTesting.isTerminated() shouldBe true
        }
    })
