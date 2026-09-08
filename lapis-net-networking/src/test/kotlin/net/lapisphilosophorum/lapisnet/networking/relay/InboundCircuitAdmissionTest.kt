package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Proves the client-side ceiling on inbound relayed circuits (`guardInboundCircuit`, used by
 * `LapisRelayTransport.acceptCircuit`).
 *
 * The gap this closes: `ConnectionCapHandler` (`MAX_CONCURRENT_CONNECTIONS`) only ever sees a
 * `Connection` that already exists, i.e. one whose Noise handshake *finished*. A relay this node
 * holds a reservation with - an untrusted intermediary by construction - could therefore offer an
 * unbounded number of circuits and simply never let any of their handshakes complete, holding a
 * stream and a half-built Noise session each, entirely invisible to that cap.
 *
 * Both properties are exercised against a handshake that genuinely never completes, which is
 * exactly the case a real relayed connection cannot be talked into.
 */
class InboundCircuitAdmissionTest :
    FunSpec({
        test("a relay cannot force more than maxConcurrentInboundCircuits hanging handshakes") {
            val counter = PendingCircuitCounter(max = 3)
            val started = AtomicInteger(0)
            val rejected = AtomicInteger(0)
            // Never completed: the shape of a relay that offers a circuit and then stalls it.
            val stalled = { CompletableFuture<String>().also { started.incrementAndGet() } }

            repeat(10) {
                guardInboundCircuit(
                    counter = counter,
                    timeout = Duration.ofMinutes(5),
                    onRejected = { rejected.incrementAndGet() },
                    upgrade = stalled,
                    onSettled = { _, _ -> },
                )
            }

            started.get() shouldBe 3
            rejected.get() shouldBe 7
            counter.inFlight() shouldBe 3
            // The upgrade is never even attempted once the budget is full: a refused circuit costs
            // this node nothing beyond closing the stream its caller owns.
        }

        test("a stalled handshake times out, is reported, and gives its slot back") {
            val counter = PendingCircuitCounter(max = 1)
            val settled = CompletableFuture<Throwable?>()
            guardInboundCircuit(
                counter = counter,
                timeout = Duration.ofMillis(150),
                onRejected = { error("must not be rejected - the budget is free") },
                upgrade = { CompletableFuture<String>() },
                onSettled = { _, error -> settled.complete(error) },
            )
            counter.inFlight() shouldBe 1

            settled.get(10, java.util.concurrent.TimeUnit.SECONDS).shouldBeInstanceOf<TimeoutException>()

            // The slot is released as part of settling, so the next circuit is admitted rather than
            // permanently locked out by the stalled one.
            val deadline = Instant.now().plus(Duration.ofSeconds(10))
            while (counter.inFlight() != 0 && Instant.now().isBefore(deadline)) Thread.sleep(20)
            counter.inFlight() shouldBe 0

            val admittedAfterTimeout = AtomicInteger(0)
            guardInboundCircuit(
                counter = counter,
                timeout = Duration.ofSeconds(5),
                onRejected = { error("slot was not released after the timeout") },
                upgrade = {
                    admittedAfterTimeout.incrementAndGet()
                    CompletableFuture.completedFuture("upgraded")
                },
                onSettled = { _, _ -> },
            )
            admittedAfterTimeout.get() shouldBe 1
            counter.inFlight() shouldBe 0
        }

        test("a completed handshake releases its slot exactly once") {
            val counter = PendingCircuitCounter(max = 2)
            repeat(5) {
                guardInboundCircuit(
                    counter = counter,
                    timeout = Duration.ofSeconds(5),
                    onRejected = { error("budget should never be exhausted when every upgrade completes") },
                    upgrade = { CompletableFuture.completedFuture(Unit) },
                    onSettled = { _, _ -> },
                )
            }
            counter.inFlight() shouldBe 0
        }

        test("an upgrade that throws synchronously still releases its slot") {
            val counter = PendingCircuitCounter(max = 1)
            val seen = CompletableFuture<Throwable?>()
            guardInboundCircuit<Unit>(
                counter = counter,
                timeout = Duration.ofSeconds(5),
                onRejected = { error("budget is free") },
                upgrade = { throw IllegalStateException("transport had no host") },
                onSettled = { _, error -> seen.complete(error) },
            )
            seen.get(5, java.util.concurrent.TimeUnit.SECONDS).shouldBeInstanceOf<IllegalStateException>()
            counter.inFlight() shouldBe 0
        }

        test("the configured client defaults are the ones acceptCircuit enforces") {
            val limits = RelayClientLimits()
            limits.maxConcurrentInboundCircuits shouldBe 32
            limits.circuitAcceptTimeout shouldBe Duration.ofSeconds(20)
        }
    })
