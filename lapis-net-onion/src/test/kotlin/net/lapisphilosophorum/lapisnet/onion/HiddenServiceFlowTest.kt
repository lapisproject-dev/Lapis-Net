@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.HsFlow
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.security.SecureRandom
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private class World(
    val config: OnionServiceConfig = OnionServiceConfig(),
    relayCount: Int = 7,
) {
    val clock = FixedClock()
    val rnd = SecureRandom()
    val relays = List(relayCount) { newTestRelay(clock = clock) }
    val net = InMemoryOnionNetwork(relays)
    val flow = HsFlow(net, clock, rnd)
    val serviceKey = Ed25519KeyPair.generate()
    val rp get() = relays[4]

    fun resolve(
        digest: ByteArray,
        fp: ByteArray,
    ) = relays
        .firstOrNull {
            it.binding.relayIdDigest().contentEquals(digest) &&
                it.binding.onionKeyFingerprint().contentEquals(fp)
        }?.binding

    val service = OnionServiceStateMachine(serviceKey, config, clock, rnd, ::resolve)

    init {
        flow.service = service
        flow.wire()
    }

    fun startService() {
        flow.runService(service.start(relays.take(config.introPoints).map { it.binding }))
        flow.settle()
        flow.tick()
    }

    fun connect(config: RendezvousClientConfig = RendezvousClientConfig()): RendezvousClientStateMachine {
        val d = flow.published.last()
        val m = RendezvousClientStateMachine(d.address(), d, rp.binding, config, clock, rnd)
        flow.client = m
        flow.runClient(m.start())
        flow.settle()
        return m
    }

    fun leaksCleared() {
        relays.forEach {
            it.relay.circuitCount shouldBe 0
            it.relay.introPointCount shouldBe 0
            it.relay.pendingRendezvousCount shouldBe 0
            it.relay.splicedPairCount shouldBe 0
        }
    }
}

class HiddenServiceFlowTest :
    FunSpec({
        test(
            "the service publishes once all introduction points are established, and a client rendezvouses and exchanges data",
        ) {
            val w = World()
            w.startService()
            w.flow.published.size shouldBe 1
            val d = w.flow.published.single()
            d.introPoints.size shouldBe 3
            OnionServiceDescriptor.verify(d, w.clock.millis() / 1000) shouldBe true
            w.relays.take(3).forEach { it.relay.introPointCount shouldBe 1 }

            val seen = mutableListOf<ByteArray>()
            w.rp.relay.rendezvousDataObserver = { seen += it }
            val client = w.connect()
            client.state shouldBe RendezvousClientState.OPEN
            w.flow.opened.size shouldBe 1
            w.flow.accepted.size shouldBe 1
            val (clientRef, sender) = w.flow.opened.single()
            val (serviceRef, receiver) = w.flow.accepted.single()
            // the introduction circuit of the sender is gone; only the rendezvous circuit remains on that side
            w.flow.clientEp.conns.size shouldBe 1
            w.rp.relay.splicedPairCount shouldBe 1
            w.rp.relay.pendingRendezvousCount shouldBe 0

            val plain = ByteArray(910) { (it % 251).toByte() }
            repeat(10) { i ->
                val blob = sender.seal(E2eType.DATA, ByteArray(0))
                w.flow.clientEp.send(clientRef, RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, blob))
                w.flow.settle()
                receiver
                    .open(
                        w.flow.serviceData
                            .last()
                            .second,
                    ).second.size shouldBe 0
                val big = sender.seal(E2eType.DATA, plain)
                w.flow.clientEp.send(clientRef, RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, big))
                w.flow.settle()
                receiver
                    .open(
                        w.flow.serviceData
                            .last()
                            .second,
                    ).second
                    .contentEquals(plain) shouldBe true
                val back = receiver.seal(E2eType.DATA, plain.copyOf(10 + i))
                w.flow.serviceEp.send(serviceRef, RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, back))
                w.flow.settle()
                sender
                    .open(
                        w.flow.clientData
                            .last()
                            .second,
                    ).second.size shouldBe 10 + i
            }
            // the rendezvous point only saw fixed-size ciphertext
            seen.size shouldBe 30
            seen.all { it.size == HsConstants.E2E_BLOB_SIZE } shouldBe true
            seen.none { b -> b.toList().windowed(16).any { it == plain.toList().take(16) } } shouldBe true

            // closing: both destroy, nothing is left behind anywhere
            w.flow.clientEp.destroy(clientRef)
            w.flow.settle()
            w.flow.serviceEp.pump()
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("a client that cannot rendezvous because every introduction point is dead fails and leaks nothing") {
            val w = World()
            w.startService()
            w.flow.clientEp.deadRelays += listOf(0, 1, 2)
            val client = w.connect()
            client.state shouldBe RendezvousClientState.FAILED
            w.flow.clientFailures.single() shouldBe RendezvousFailure.NO_INTRODUCTION
            w.flow.clientEp.conns
                .isEmpty() shouldBe true
            w.rp.relay.pendingRendezvousCount shouldBe 0
            w.rp.relay.circuitCount shouldBe 0
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("the next introduction point is tried when the first one is dead") {
            val w = World()
            w.startService()
            w.flow.clientEp.deadRelays += 0
            val client = w.connect()
            client.state shouldBe RendezvousClientState.OPEN
            w.flow.clientEp.destroy(
                w.flow.opened
                    .single()
                    .first,
            )
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("a replayed INTRODUCE yields no second rendezvous at the service") {
            val w = World()
            w.startService()
            w.connect()
            w.service.stats.accepted shouldBe 1
            // feed the very same INTRODUCE2 again on the first slot's circuit
            val slotRef = w.service.slotRef(0)!!
            val d = w.flow.published.last()
            val auths =
                (0..2).map {
                    w.service
                        .slotAuthKey(it)!!
                        .publicKey.bytes
                }
            // build a legitimate INTRODUCE for slot 0 and deliver it twice
            val plain =
                IntroducePlaintext(
                    w.rp.binding.relayIdDigest(),
                    w.rp.binding.onionKeyFingerprint(),
                    ByteArray(20) { 1 },
                    net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
                        .generate()
                        .publicKey,
                ).encode(w.rnd)
            val ip0 = d.introPoints.first { it.authKey.bytes.contentEquals(auths[0]) }
            val (enc, ct) =
                IntroduceCrypto.seal(w.service.onionAddress.serviceIdDigest(), d.encKey, ip0.authKey, plain)
            val body = IntroduceBody(ip0.authKey.bytes, enc, ct).encode()
            val before = w.service.stats.accepted
            repeat(2) {
                w.flow.runService(
                    w.service.on(HsEvent.RelayReceived(slotRef, RelayMessage(RelayCommand.INTRODUCE2, 0, body))),
                )
            }
            w.flow.settle()
            (w.service.stats.accepted - before) shouldBe 1
            w.service.stats.replays shouldBe 1
            w.flow.runService(w.service.stop())
            w.flow.clientEp.conns.keys
                .toList()
                .forEach { w.flow.clientEp.destroy(it) }
            w.flow.settle()
            w.leaksCleared()
        }

        test("INTRODUCE2 floods are rate limited and capped without work per excess message") {
            val w = World(OnionServiceConfig(introduce2PerSecond = 2, maxConcurrentRendezvous = 2))
            w.startService()
            val slotRef = w.service.slotRef(0)!!
            repeat(20) {
                w.flow.runService(
                    w.service.on(
                        HsEvent.RelayReceived(
                            slotRef,
                            RelayMessage(
                                RelayCommand.INTRODUCE2,
                                0,
                                ByteArray(HsConstants.INTRODUCE_SIZE).also { b ->
                                    b[0] =
                                        1
                                },
                            ),
                        ),
                    ),
                )
            }
            (w.service.stats.rateLimited >= 17) shouldBe true
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("introduction circuits are refreshed before the relay lifetime with make-before-break") {
            val w = World()
            w.startService()
            val first = w.service.slotRef(0)!!
            val seqBefore = w.service.slotSeq(0)
            w.flow.tick(millis = 8 * 60_000L + 1)
            w.flow.settle()
            val second = w.service.slotRef(0)!!
            (second != first) shouldBe true
            w.service.slotSeq(0) shouldBe seqBefore + 1
            w.relays[0].relay.introPointCount shouldBe 1
            // the descriptor does not change on a refresh (same auth key, same relay)
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("a failing build backs off exponentially with jitter, asks for a replacement after five failures") {
            val w = World()
            w.flow.serviceEp.deadRelays += 0
            w.flow.runService(w.service.start(w.relays.take(3).map { it.binding }))
            w.flow.settle()
            // the first build already failed synchronously (dead relay) -> 1 failure
            val delays = (1..8).map { w.service.backoffMillis(it) }
            delays[0] shouldBe delays[0].coerceIn(500, 1000)
            delays[1] shouldBe delays[1].coerceIn(1000, 2000)
            delays[2] shouldBe delays[2].coerceIn(2000, 4000)
            delays[7] shouldBe delays[7].coerceIn(30_000, 60_000)
            repeat(60) { w.flow.tick(millis = 61_000) }
            w.flow.neededRelay.distinct() shouldBe listOf(0)
            // the request is repeated (with backoff) so a host that had no candidate at first can still answer
            (w.flow.neededRelay.size >= 2) shouldBe true
            // supply a working replacement -> the slot recovers and the service publishes
            w.flow.serviceEp.deadRelays
                .clear()
            w.flow.runService(w.service.supplyIntroRelay(0, w.relays[3].binding))
            w.flow.settle()
            w.flow.tick()
            (w.flow.published.size >= 1) shouldBe true
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("a build that never completes times out and is destroyed") {
            val w = World()
            val cmds = w.service.start(w.relays.take(3).map { it.binding })
            // execute NO command: nothing is ever built
            cmds.filterIsInstance<ServiceCommand.BuildCircuit>().size shouldBe 3
            w.flow.runService(w.service.on(HsEvent.Tick).also { it.isEmpty() shouldBe true })
            w.clock.advanceMillis(31_000)
            val out = w.service.on(HsEvent.Tick)
            out.filterIsInstance<ServiceCommand.Destroy>().size shouldBe 3
            w.service.stop()
        }

        test("stop destroys every circuit and later events are ignored") {
            val w = World()
            w.startService()
            val out = w.service.stop()
            out.filterIsInstance<ServiceCommand.Destroy>().size shouldBe 3
            w.service.on(HsEvent.Tick).isEmpty() shouldBe true
            w.service.stop().isEmpty() shouldBe true
            w.flow.runService(out)
            w.flow.settle()
            w.leaksCleared()
        }

        test("encryption key rotation keeps accepting the previous key and republishes") {
            val w = World()
            w.startService()
            val before = w.flow.published.size
            val oldKey =
                w.flow.published
                    .last()
                    .encKey
            w.service.rotateEncKeyNow()
            w.flow.tick()
            (w.flow.published.size > before) shouldBe true
            (
                w.flow.published
                    .last()
                    .encKey == oldKey
            ) shouldBe false
            // a client that still uses the OLD descriptor can connect
            val oldDescriptor = w.flow.published[before - 1]
            val m =
                RendezvousClientStateMachine(
                    oldDescriptor.address(),
                    oldDescriptor,
                    w.rp.binding,
                    RendezvousClientConfig(),
                    w.clock,
                    w.rnd,
                )
            w.flow.client = m
            w.flow.runClient(m.start())
            w.flow.settle()
            m.state shouldBe RendezvousClientState.OPEN
            w.flow.clientEp.conns.keys
                .toList()
                .forEach { w.flow.clientEp.destroy(it) }
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("the replay cache fails closed when full") {
            val w =
                World(
                    OnionServiceConfig(replayCacheEntries = 1, introduce2PerSecond = 50, maxConcurrentRendezvous = 16),
                )
            w.startService()
            w.connect()
            w.service.stats.accepted shouldBe 1
            w.flow.clientEp.conns.keys
                .toList()
                .forEach { w.flow.clientEp.destroy(it) }
            w.flow.settle()
            val before = w.service.stats.accepted
            val client2 = w.connect()
            w.service.stats.accepted shouldBe before
            (w.service.stats.cacheFull >= 1) shouldBe true
            w.flow.runClient(client2.cancel())
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("a full replay cache forces an early key rotation and a client with the new descriptor is accepted") {
            val w =
                World(
                    OnionServiceConfig(replayCacheEntries = 1, introduce2PerSecond = 50, maxConcurrentRendezvous = 16),
                )
            w.startService()
            w.connect()
            w.service.stats.accepted shouldBe 1
            w.flow.clientEp.conns.keys
                .toList()
                .forEach { w.flow.clientEp.destroy(it) }
            w.flow.settle()
            val oldKey =
                w.flow.published
                    .last()
                    .encKey
            val before = w.flow.published.size
            // no 24 h wait: the full cache alone must trigger the rotation and a republish
            w.flow.tick()
            (w.flow.published.size > before) shouldBe true
            (
                w.flow.published
                    .last()
                    .encKey == oldKey
            ) shouldBe false
            val acceptedBefore = w.service.stats.accepted
            val client2 = w.connect()
            client2.state shouldBe RendezvousClientState.OPEN
            w.service.stats.accepted shouldBe acceptedBefore + 1
            w.flow.clientEp.conns.keys
                .toList()
                .forEach { w.flow.clientEp.destroy(it) }
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        // ---- sender side -------------------------------------------------------------------------
        test("every client timeout destroys all circuits and ends in FAILED") {
            val w = World()
            w.startService()
            val d = w.flow.published.last()
            // nothing executed: the rendezvous circuit never builds
            val m = RendezvousClientStateMachine(d.address(), d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            m.start().filterIsInstance<ClientCommand.BuildCircuit>().size shouldBe 1
            w.clock.advanceMillis(31_000)
            val out = m.on(HsEvent.Tick)
            out.filterIsInstance<ClientCommand.Destroy>().size shouldBe 1
            (out.last() as ClientCommand.Failed).reason shouldBe RendezvousFailure.TIMEOUT
            m.state shouldBe RendezvousClientState.FAILED
            m.liveCircuitCount shouldBe 0
            m.on(HsEvent.Tick).isEmpty() shouldBe true
            w.service.stop()
        }

        test("the overall timeout ends a stuck attempt in any state") {
            val w = World()
            w.startService()
            val m = w.connectOnlyEstablished()
            w.clock.advanceMillis(61_000)
            val out = m.on(HsEvent.Tick)
            out.any { it is ClientCommand.Failed } shouldBe true
            out.filterIsInstance<ClientCommand.Destroy>().size shouldBe 2
            m.liveCircuitCount shouldBe 0
            w.flow.runService(w.service.stop())
            w.flow.settle()
        }

        test("an invalid descriptor, an address mismatch and cancel in every state are handled without a leak") {
            val w = World()
            w.startService()
            val d = w.flow.published.last()
            val other = OnionServiceAddress(Ed25519KeyPair.generate().publicKey)
            val mismatch =
                RendezvousClientStateMachine(other, d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            (mismatch.start().last() as ClientCommand.Failed).reason shouldBe RendezvousFailure.INVALID_DESCRIPTOR
            w.clock.advanceMillis(4 * 3600 * 1000L)
            val expired =
                RendezvousClientStateMachine(d.address(), d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            (expired.start().last() as ClientCommand.Failed).reason shouldBe RendezvousFailure.INVALID_DESCRIPTOR
            w.clock.millis = FixedClock.START_MILLIS

            // cancel after start, after the rendezvous circuit is up, after the introduction is sent
            val m = RendezvousClientStateMachine(d.address(), d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            val start = m.start()
            m.cancel().filterIsInstance<ClientCommand.Destroy>().size shouldBe 1
            m.state shouldBe RendezvousClientState.CLOSED
            m.cancel().isEmpty() shouldBe true
            start.size shouldBe 1

            val m2 = w.connectOnlyEstablished()
            m2.cancel().filterIsInstance<ClientCommand.Destroy>().size shouldBe 2
            m2.liveCircuitCount shouldBe 0
            w.flow.settle()
            w.flow.runService(w.service.stop())
            w.flow.settle()
            w.leaksCleared()
        }

        test("a wrong AUTH in RENDEZVOUS2 fails the attempt and destroys its circuits") {
            val w = World()
            w.startService()
            val d = w.flow.published.last()
            val m = RendezvousClientStateMachine(d.address(), d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            val build = m.start().single() as ClientCommand.BuildCircuit
            m.on(HsEvent.CircuitBuilt(build.ref))
            val intro =
                m.on(
                    HsEvent.RelayReceived(
                        build.ref,
                        RelayMessage(RelayCommand.RENDEZVOUS_ESTABLISHED, 0, byteArrayOf(0)),
                    ),
                )
            intro.single().let { it as ClientCommand.BuildCircuit }.purpose shouldBe CircuitPurpose.INTRODUCE
            val out =
                m.on(
                    HsEvent.RelayReceived(build.ref, RelayMessage(RelayCommand.RENDEZVOUS2, 0, ByteArray(64) { 5 })),
                )
            (out.last() as ClientCommand.Failed).reason shouldBe RendezvousFailure.AUTHENTICATION
            out.filterIsInstance<ClientCommand.Destroy>().size shouldBe 2
            m.liveCircuitCount shouldBe 0
            w.service.stop()
        }

        test("a negative INTRODUCE_ACK moves on, and an unexpected message at the rendezvous point fails") {
            val w = World()
            w.startService()
            val d = w.flow.published.last()
            val m = RendezvousClientStateMachine(d.address(), d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            val rdv = (m.start().single() as ClientCommand.BuildCircuit).ref
            m.on(HsEvent.CircuitBuilt(rdv))
            var step =
                m.on(
                    HsEvent.RelayReceived(rdv, RelayMessage(RelayCommand.RENDEZVOUS_ESTABLISHED, 0, byteArrayOf(0))),
                )
            repeat(3) { n ->
                val ip = (step.single { it is ClientCommand.BuildCircuit } as ClientCommand.BuildCircuit).ref
                m
                    .on(HsEvent.CircuitBuilt(ip))
                    .single()
                    .let { it as ClientCommand.Send }
                    .message.command shouldBe
                    RelayCommand.INTRODUCE1
                step =
                    m.on(
                        HsEvent.RelayReceived(
                            ip,
                            RelayMessage(RelayCommand.INTRODUCE_ACK, 0, byteArrayOf(IntroduceStatus.UNKNOWN)),
                        ),
                    )
                if (n < 2) {
                    step.filterIsInstance<ClientCommand.Destroy>().size shouldBe 1
                }
            }
            (step.last() as ClientCommand.Failed).reason shouldBe RendezvousFailure.NO_INTRODUCTION
            m.liveCircuitCount shouldBe 0

            val m2 =
                RendezvousClientStateMachine(d.address(), d, w.rp.binding, RendezvousClientConfig(), w.clock, w.rnd)
            val r2 = (m2.start().single() as ClientCommand.BuildCircuit).ref
            m2.on(HsEvent.CircuitBuilt(r2))
            (
                m2
                    .on(
                        HsEvent.RelayReceived(r2, RelayMessage(RelayCommand.DATA, 0, ByteArray(1))),
                    ).last() as ClientCommand.Failed
            ).reason shouldBe RendezvousFailure.RENDEZVOUS_POINT
            w.service.stop()
        }

        test("configs are validated") {
            listOf(
                { OnionServiceConfig(introPoints = 0) },
                { OnionServiceConfig(introPoints = 4) },
                { OnionServiceConfig(republishInterval = 4.minutes * 100) },
                { OnionServiceConfig(introduce2PerSecond = 0) },
                { OnionServiceConfig(backoffMax = 0.seconds) },
                { RendezvousClientConfig(overallTimeout = 0.seconds) },
            ).forEach {
                var threw = false
                try {
                    it()
                } catch (e: IllegalArgumentException) {
                    threw = true
                }
                threw shouldBe true
            }
        }
    })

/** A client attempt stuck in INTRO_BUILDING: the rendezvous point acknowledged, but nobody builds the introduce circuit. */
private fun World.connectOnlyEstablished(): RendezvousClientStateMachine {
    val d = flow.published.last()
    val m = RendezvousClientStateMachine(d.address(), d, rp.binding, RendezvousClientConfig(), clock, rnd)
    val rdv = (m.start().single() as ClientCommand.BuildCircuit).ref
    m.on(HsEvent.CircuitBuilt(rdv))
    m.on(HsEvent.RelayReceived(rdv, RelayMessage(RelayCommand.RENDEZVOUS_ESTABLISHED, 0, byteArrayOf(0))))
    m.state shouldBe RendezvousClientState.INTRO_BUILDING
    m.liveCircuitCount shouldBe 2
    return m
}
