package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import java.time.Clock
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Host-level regression for the introduction-relay replacement fallback: with exactly as many relays as introduction
 * points there is never a fresh relay, so after repeated failures the host must retry a relay no other slot uses
 * (here: the very same one). Once that relay is reachable again, the slot recovers and the descriptor is published.
 */
@OptIn(ExperimentalOnionApi::class)
class OnionServiceHostIntroRecoveryTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val relays = List(3) { WireTestNode(relay = true).also { all += it } }
        val receiver = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { receiver.connectTo(it) }

        test("an introduction relay that is down for a while is retried when no fresh relay exists").config(
            timeout = 180.seconds,
        ) {
            val descriptors: List<OnionRelayDescriptor> = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                descriptors.all { d -> receiver.wire.descriptors.current(d.identity, now()) != null }
            } shouldBe true

            val down = AtomicBoolean(true)
            val refused = AtomicInteger(0)
            val provider =
                OnionPathProvider { last, _: CircuitPurpose ->
                    if (down.get() && last.identity == descriptors[0].identity) {
                        refused.incrementAndGet()
                        throw IllegalStateException("relay unreachable")
                    }
                    val others = descriptors.filter { it.identity != last.identity }
                    others + last
                }
            val config =
                OnionServiceConfig(
                    maxConsecutiveFailuresPerSlot = 2,
                    backoffInitial = 100.milliseconds,
                    backoffMax = 200.milliseconds,
                    buildTimeout = 10.seconds,
                )
            val host = receiver.wire.experimentalServiceHost(Ed25519KeyPair.generate(), config, provider)
            val first = host.start(descriptors)

            // enough failures that the slot gave up on the relay at least once (NeedIntroRelay -> replaceIntro)
            awaitTrue(java.time.Duration.ofSeconds(60)) { refused.get() >= 4 } shouldBe true
            first.isDone shouldBe false

            down.set(false)
            val published = first.get(90, TimeUnit.SECONDS)
            published.introPoints.size shouldBe 3
            host.close()
        }
    })
