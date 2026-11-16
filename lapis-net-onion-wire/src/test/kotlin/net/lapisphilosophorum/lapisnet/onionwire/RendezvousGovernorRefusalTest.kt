@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientState
import net.lapisphilosophorum.lapisnet.onion.RendezvousFailure
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.RendezvousRetry
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.PathConflictException
import net.lapisphilosophorum.lapisnet.onionwire.path.seededRandom
import net.lapisphilosophorum.lapisnet.onionwire.path.syntheticDescriptor
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A governor refusal of the rendezvous circuit, through the REAL [OnionRendezvousClient] and [OnionCircuitFactory]: the
 * state machine only sees a failed circuit and ends in RENDEZVOUS_POINT, so the refusal must travel along as the cause,
 * and [RendezvousRetry] must not start a second admission request because of it.
 */
class RendezvousGovernorRefusalTest :
    FunSpec({
        val node = WireTestNode(relay = false)
        afterSpec { node.close() }

        val serviceKey = Ed25519KeyPair.generate()
        val address = OnionServiceAddress(serviceKey.publicKey)

        fun descriptor(): OnionServiceDescriptor {
            val now = Instant.now().epochSecond
            val binding =
                OnionKeyBinding.create(
                    DualKeyIdentity.generate().secp256k1KeyPair,
                    X25519KeyPair.generate().publicKey,
                    now + 3600,
                )
            return OnionServiceDescriptor.create(
                serviceKey,
                X25519KeyPair.generate().publicKey,
                listOf(IntroPointEntry(binding, Ed25519KeyPair.generate().publicKey)),
                1,
                now + 600,
                now,
            )
        }

        val relays = List(4) { syntheticDescriptor() }
        val rendezvousPoint = relays[3]
        val threeHops = OnionPathProvider { last, _: CircuitPurpose -> listOf(relays[0], relays[1], last) }

        fun failureOf(f: CompletableFuture<*>): Throwable =
            try {
                f.get(10, TimeUnit.SECONDS)
                throw AssertionError("expected a failure")
            } catch (e: ExecutionException) {
                e.cause!!
            }

        /** Runs one connect through [RendezvousRetry] the way `AnonymityRuntime.connectToService` does. */
        fun retried(
            client: OnionRendezvousClient,
            paths: OnionPathProvider,
            d: OnionServiceDescriptor,
        ): Triple<Throwable, Int, Int> {
            var attempts = 0
            var scheduled = 0
            val retry =
                RendezvousRetry<OnionRendezvousStream, OnionClientCircuit>(
                    attempt = { rp: OnionRelayDescriptor, warm, t ->
                        attempts++
                        client.connectWith(address, paths, rp, d, t, warm)
                    },
                    selectRendezvousPoint = { ex -> relays.firstOrNull { it.identity !in ex } },
                    schedule = { _, task ->
                        scheduled++
                        task()
                    },
                    random = seededRandom(3),
                )
            val cause = failureOf(retry.run(rendezvousPoint, null, 30.seconds))
            return Triple(cause, attempts, scheduled)
        }

        test("LOCKED: the rendezvous fails with the refusal as cause and is not retried") {
            val governor = CircuitBuildGovernor().also { it.lockdown() }
            node.wire.installCircuitPolicy(CircuitPolicy(governor))
            val client = node.wire.experimentalRendezvousClient()
            try {
                val e = failureOf(client.connect(address, threeHops, rendezvousPoint, descriptor()))
                e.shouldBeInstanceOf<RendezvousFailedException>()
                e.reason shouldBe RendezvousFailure.RENDEZVOUS_POINT
                e.atState shouldBe RendezvousClientState.RDV_BUILDING
                e.refusedByGovernor shouldBe true
                (e.cause as CircuitAdmissionException).kind shouldBe CircuitAdmissionException.Kind.LOCKED
                // the message still carries no target
                e.message shouldBe "rendezvous failed: RENDEZVOUS_POINT in RDV_BUILDING after 0 intro attempt(s)"
                RendezvousRetry.retryable(e) shouldBe false

                val (cause, attempts, scheduled) = retried(client, threeHops, descriptor())
                attempts shouldBe 1
                scheduled shouldBe 0
                (cause as RendezvousFailedException).refusedByGovernor shouldBe true
            } finally {
                client.close()
            }
        }

        test("RATE_LIMITED (the wait would exceed maxDefer): no retry either") {
            val governor = CircuitBuildGovernor(maxOpenClientCircuits = 100, burst = 1, ratePerMinute = 1)
            // the only token goes to another circuit; the next admission is Delayed by about a minute
            governor.admit(CircuitPurpose.DIRECTORY_PUBLISH, "other") shouldBe CircuitBuildGovernor.Admission.Granted
            node.wire.installCircuitPolicy(CircuitPolicy(governor, maxDefer = 1.milliseconds))
            val client = node.wire.experimentalRendezvousClient()
            try {
                val (cause, attempts, scheduled) = retried(client, threeHops, descriptor())
                attempts shouldBe 1
                scheduled shouldBe 0
                cause.shouldBeInstanceOf<RendezvousFailedException>()
                cause.reason shouldBe RendezvousFailure.RENDEZVOUS_POINT
                (cause.cause as CircuitAdmissionException).kind shouldBe CircuitAdmissionException.Kind.RATE_LIMITED
            } finally {
                client.close()
            }
        }

        test("control: a local path conflict at the rendezvous circuit is NOT a refusal and is retried once") {
            node.wire.installCircuitPolicy(CircuitPolicy(CircuitBuildGovernor().also { it.lockdown() }))
            val client = node.wire.experimentalRendezvousClient()
            try {
                val conflicting = OnionPathProvider { _, _: CircuitPurpose -> throw PathConflictException() }
                val (cause, attempts, scheduled) = retried(client, conflicting, descriptor())
                // both attempts fail the same way; the second one is the retry with another rendezvous point
                attempts shouldBe 2
                scheduled shouldBe 1
                cause.shouldBeInstanceOf<RendezvousFailedException>()
                cause.reason shouldBe RendezvousFailure.RENDEZVOUS_POINT
                cause.refusedByGovernor shouldBe false
            } finally {
                client.close()
            }
        }
    })
