@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientState
import net.lapisphilosophorum.lapisnet.onion.RendezvousFailure
import net.lapisphilosophorum.lapisnet.onionwire.CircuitAdmissionException
import net.lapisphilosophorum.lapisnet.onionwire.RendezvousFailedException
import net.lapisphilosophorum.lapisnet.onionwire.path.seededRandom
import net.lapisphilosophorum.lapisnet.onionwire.path.syntheticDescriptor
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** [RendezvousRetry]: fake attempts and a manual scheduler, no network. */
class RendezvousRetryTest :
    FunSpec({
        class Attempt(
            val rp: OnionRelayDescriptor,
            val prebuilt: String?,
            val timeout: Duration,
            val future: CompletableFuture<String> = CompletableFuture(),
        )

        class Harness(
            relays: Int = 6,
            var closed: Boolean = false,
        ) {
            val relays = List(relays) { syntheticDescriptor() }
            val attempts = ArrayList<Attempt>()
            val scheduled = ArrayList<Pair<Long, () -> Unit>>()
            val excludes = ArrayList<Set<Secp256k1PublicKey>>()
            var retries = 0
            val discarded = ArrayList<String>()
            val retry =
                RendezvousRetry<String, String>(
                    attempt = { rp, warm, t -> Attempt(rp, warm, t).also { attempts += it }.future },
                    selectRendezvousPoint = { ex ->
                        excludes += ex
                        this.relays.firstOrNull { it.identity !in ex }
                    },
                    schedule = { d, task -> scheduled += d to task },
                    random = seededRandom(7),
                    isClosed = { closed },
                    onRetry = { retries++ },
                    discard = { discarded += it },
                )

            fun runNext() {
                val (_, task) = scheduled.removeAt(0)
                task()
            }
        }

        fun failure(
            reason: RendezvousFailure,
            state: RendezvousClientState = RendezvousClientState.AWAIT_RENDEZVOUS2,
        ) = RendezvousFailedException(reason, state, 1)

        fun CompletableFuture<String>.cause(): Throwable =
            try {
                get()
                throw AssertionError("expected a failure")
            } catch (e: ExecutionException) {
                e.cause!!
            }

        test("TIMEOUT in AWAIT_RENDEZVOUS2 is retried exactly once with another rendezvous point and no warm circuit") {
            val h = Harness()
            val result = h.retry.run(h.relays[0], "warm", 45.seconds)
            h.attempts shouldHaveSize 1
            h.attempts[0].prebuilt shouldBe "warm"
            h.attempts[0].future.completeExceptionally(failure(RendezvousFailure.TIMEOUT))
            h.scheduled shouldHaveSize 1
            h.retries shouldBe 1
            h.runNext()
            h.attempts shouldHaveSize 2
            h.attempts[1].prebuilt shouldBe null
            (h.attempts[1].rp.identity == h.relays[0].identity) shouldBe false
            h.excludes.single() shouldBe setOf(h.relays[0].identity)
            h.attempts[1].timeout shouldBe 45.seconds
            val second = failure(RendezvousFailure.TIMEOUT)
            h.attempts[1].future.completeExceptionally(second)
            // no third attempt; the cause of the second comes back
            h.scheduled shouldHaveSize 0
            h.attempts shouldHaveSize 2
            result.cause() shouldBeSameInstanceAs second
        }

        test("RENDEZVOUS_POINT is retried") {
            val h = Harness()
            val result = h.retry.run(h.relays[0], null, 45.seconds)
            h.attempts[0].future.completeExceptionally(
                failure(RendezvousFailure.RENDEZVOUS_POINT, RendezvousClientState.RDV_ESTABLISHING),
            )
            h.runNext()
            h.attempts[1].future.complete("stream")
            result.get() shouldBe "stream"
        }

        test("no retry after a clear answer of the service, a timeout in another state or a governor refusal") {
            val noRetry =
                listOf(
                    failure(RendezvousFailure.NO_INTRODUCTION, RendezvousClientState.INTRODUCING),
                    failure(RendezvousFailure.AUTHENTICATION),
                    failure(RendezvousFailure.INVALID_DESCRIPTOR, RendezvousClientState.NEW),
                    failure(RendezvousFailure.TIMEOUT, RendezvousClientState.INTRO_BUILDING),
                    failure(RendezvousFailure.TIMEOUT, RendezvousClientState.RDV_BUILDING),
                    IllegalStateException("could not send"),
                ) + CircuitAdmissionException.Kind.entries.map { CircuitAdmissionException(it) } +
                    // the shape a refused rendezvous circuit has behind the real client: RENDEZVOUS_POINT with the cause
                    CircuitAdmissionException.Kind.entries.map {
                        RendezvousFailedException(
                            RendezvousFailure.RENDEZVOUS_POINT,
                            RendezvousClientState.RDV_BUILDING,
                            0,
                            CircuitAdmissionException(it),
                        )
                    }
            for (e in noRetry) {
                val h = Harness()
                val result = h.retry.run(h.relays[0], null, 45.seconds)
                h.attempts[0].future.completeExceptionally(e)
                h.scheduled shouldHaveSize 0
                h.retries shouldBe 0
                result.cause() shouldBeSameInstanceAs e
            }
        }

        test("the jitter lies within 2 to 6 seconds") {
            repeat(50) {
                val h = Harness()
                h.retry.run(h.relays[0], null, 45.seconds)
                h.attempts[0].future.completeExceptionally(failure(RendezvousFailure.TIMEOUT))
                val delay = h.scheduled.single().first
                (delay in 2_000L..6_000L) shouldBe true
            }
        }

        test("closed while waiting: nothing is started any more") {
            val h = Harness()
            val result = h.retry.run(h.relays[0], null, 45.seconds)
            val first = failure(RendezvousFailure.TIMEOUT)
            h.attempts[0].future.completeExceptionally(first)
            h.closed = true
            h.runNext()
            h.attempts shouldHaveSize 1
            result.cause() shouldBeSameInstanceAs first
        }

        test("closed before the failure: no retry is scheduled") {
            val h = Harness()
            val result = h.retry.run(h.relays[0], null, 45.seconds)
            h.closed = true
            h.attempts[0].future.completeExceptionally(failure(RendezvousFailure.TIMEOUT))
            h.scheduled shouldHaveSize 0
            result.isCompletedExceptionally shouldBe true
        }

        test("no other rendezvous point: the first cause comes back") {
            val h = Harness(relays = 1)
            val result = h.retry.run(h.relays[0], null, 45.seconds)
            val first = failure(RendezvousFailure.TIMEOUT)
            h.attempts[0].future.completeExceptionally(first)
            h.runNext()
            h.attempts shouldHaveSize 1
            result.cause() shouldBeSameInstanceAs first
        }

        test(
            "scenario H6: the first rendezvous point equals the service's guard and is silently dropped, the second works",
        ) {
            val h = Harness()
            val serviceGuard = h.relays[0].identity
            val result = h.retry.run(h.relays[0], "warm", 45.seconds)
            // the service can not build to its own guard: the client times out waiting for RENDEZVOUS2
            h.attempts[0].future.completeExceptionally(failure(RendezvousFailure.TIMEOUT))
            h.runNext()
            (h.attempts[1].rp.identity == serviceGuard) shouldBe false
            h.attempts[1].future.complete("stream")
            result.get() shouldBe "stream"
            h.retries shouldBe 1
        }

        test("a success needs no retry") {
            val h = Harness()
            val result = h.retry.run(h.relays[0], null, 45.seconds)
            h.attempts[0].future.complete("stream")
            result.get() shouldBe "stream"
            h.scheduled shouldHaveSize 0
            h.discarded shouldHaveSize 0
        }
    })
