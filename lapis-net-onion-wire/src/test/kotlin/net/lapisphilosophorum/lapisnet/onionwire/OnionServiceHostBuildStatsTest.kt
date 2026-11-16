package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardConflictException
import net.lapisphilosophorum.lapisnet.onionwire.path.InsufficientRelaysException
import net.lapisphilosophorum.lapisnet.onionwire.path.PathConflictException
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The build outcome counters of [OnionServiceHost.hostBuildStats]: every path refusal is classified (guard conflict,
 * insufficient, path conflict), successful builds are counted, and the text holds counts only.
 */
@OptIn(ExperimentalOnionApi::class)
class OnionServiceHostBuildStatsTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val relays = List(4) { WireTestNode(relay = true).also { all += it } }
        val receiver = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { receiver.connectTo(it) }

        test("intro builds: guard conflict, insufficient, path conflict and built are counted separately").config(
            timeout = 180.seconds,
        ) {
            val descriptors: List<OnionRelayDescriptor> = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                descriptors.all { d -> receiver.wire.descriptors.current(d.identity, now()) != null }
            } shouldBe true

            val refusing = AtomicBoolean(true)
            val provider =
                OnionPathProvider { last, _: CircuitPurpose ->
                    if (refusing.get()) {
                        when (last.identity) {
                            descriptors[0].identity -> throw GuardConflictException()
                            descriptors[1].identity -> throw InsufficientRelaysException()
                            descriptors[2].identity -> throw PathConflictException()
                        }
                    }
                    descriptors.filter { it.identity != last.identity }.take(2) + last
                }
            val config =
                OnionServiceConfig(
                    maxConsecutiveFailuresPerSlot = 100,
                    backoffInitial = 100.milliseconds,
                    backoffMax = 200.milliseconds,
                    buildTimeout = 10.seconds,
                )
            val host = receiver.wire.experimentalServiceHost(Ed25519KeyPair.generate(), config, provider)
            host.start(descriptors.take(3))
            awaitTrue(java.time.Duration.ofSeconds(60)) {
                val s = host.hostBuildStats().intro
                s.guardConflict >= 1 && s.pathRefused >= 1 && s.pathConflict >= 1
            } shouldBe true
            refusing.set(false)
            awaitTrue(java.time.Duration.ofSeconds(90)) { host.hostBuildStats().intro.built >= 3 } shouldBe true
            val stats = host.hostBuildStats()
            // no rendezvous was requested
            stats.rendezvous shouldBe BuildOutcomeStats(0, 0, 0, 0, 0)
            val text = stats.toString()
            for (d in descriptors) {
                text shouldNotContain d.identity.bytes.joinToString("") { "%02x".format(it) }
                text shouldNotContain d.peerId.toString()
            }
            host.close()
        }
    })
