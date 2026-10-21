package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmCallReplyRoute
import net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList

/** V0.9.19: the reply-route token handed in with an inbound signal is passed 1:1 to every answer,
 * and never changes WHETHER a signal is sent. */
private class RNode(
    val identity: Secp256k1PublicKey,
    val manager: CallManager,
    val transport: FakeCallSignalTransport,
) {
    val events = CopyOnWriteArrayList<CallEvent>()

    init {
        manager.addCallListener { events.add(it) }
    }
}

private fun pair(
    configA: CallConfig = CallConfig(),
    configB: CallConfig = CallConfig(),
): Pair<RNode, RNode> {
    val network = FakeCallNetwork()
    val idA = Secp256k1KeyPair.generate().publicKey
    val idB = Secp256k1KeyPair.generate().publicKey
    val tA = FakeCallSignalTransport(idA, network)
    val tB = FakeCallSignalTransport(idB, network)
    val mA = CallManager.attachToTransport(tA, FakeCallMediaEngine(), configA)
    val mB = CallManager.attachToTransport(tB, FakeCallMediaEngine(), configB)
    network.register(idA, mA)
    network.register(idB, mB)
    return RNode(idA, mA, tA) to RNode(idB, mB, tB)
}

private fun route(seed: Int) = DmCallReplyRoute(ByteArray(DmCallReplyRoute.TOKEN_SIZE) { (it + seed).toByte() })

class CallManagerReplyRouteTest :
    FunSpec({
        test("S1: the INVITE's token goes 1:1 to REJECT") {
            val (a, b) = pair()
            val r = route(1)
            a.transport.routeToAttachOnDeliver = r
            val id = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.rejectCall(id)
            awaitCondition { b.transport.sentReplyRoutes.isNotEmpty() }
            b.transport.sentReplyRoutes.toList() shouldBe listOf(r)
            // the INVITE itself carries no route
            a.transport.sentReplyRoutes.toList() shouldBe listOf<DmCallReplyRoute?>(null)
            a.manager.stop()
            b.manager.stop()
        }

        test("S1: the token goes to ACCEPT and to HANGUP") {
            val (a, b) = pair()
            val r = route(2)
            a.transport.routeToAttachOnDeliver = r
            val id = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(id)
            awaitCondition { b.events.any { it is CallEvent.Active } }
            b.manager.hangUp(id)
            awaitCondition { b.transport.sentReplyRoutes.size == 2 }
            b.transport.sentReplyRoutes.toList() shouldBe listOf(r, r)
            a.manager.stop()
            b.manager.stop()
        }

        test("S1: the token goes to the ring-timeout REJECT") {
            val (a, b) = pair(configB = CallConfig(ringTimeout = Duration.ofMillis(300)))
            val r = route(3)
            a.transport.routeToAttachOnDeliver = r
            a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.Ended } }
            awaitCondition { b.transport.sentReplyRoutes.isNotEmpty() }
            b.transport.sentReplyRoutes.toList() shouldBe listOf(r)
            a.manager.stop()
            b.manager.stop()
        }

        test("S2: the BUSY auto-reject is sent with the incoming token") {
            val (a, b) = pair(configA = CallConfig(maxConcurrentCalls = 2))
            val r = route(4)
            a.transport.routeToAttachOnDeliver = r
            a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            val second = a.manager.placeCall(b.identity)
            awaitCondition { b.transport.sentSignals.any { it.callId == second } }
            val idx = b.transport.sentSignals.indexOfFirst { it.callId == second }
            b.transport.sentSignals[idx].reason shouldBe CallEndReason.BUSY
            b.transport.sentReplyRoutes[idx] shouldBe r
            a.manager.stop()
            b.manager.stop()
        }

        test("S3: a quarantined INVITE (autoRejectQuarantined) causes no send at all, not even after stop()") {
            val (a, b) = pair(configB = CallConfig(ringTimeout = Duration.ofMillis(300)))
            a.transport.quarantinedFromSelf = true
            a.transport.routeToAttachOnDeliver = route(5)
            a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            Thread.sleep(800)
            b.manager.stop()
            b.transport.sentSignals.size shouldBe 0
            b.transport.sentReplyRoutes.size shouldBe 0
            a.manager.stop()
        }

        test("S4: signals for unknown/ended calls and from the wrong sender cause no send and no state change") {
            val (a, b) = pair()
            val r = route(6)
            a.transport.routeToAttachOnDeliver = r
            val id = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.rejectCall(id)
            awaitCondition { b.transport.sentSignals.size == 1 }
            val now = System.currentTimeMillis()
            val stranger = Secp256k1KeyPair.generate().publicKey

            fun inject(
                from: Secp256k1PublicKey,
                signal: CallSignal,
            ) = b.manager.onInboundCallSignal(DmInboundCallSignal(from, CallSignalCodec.encode(signal), false, 0, r))
            inject(a.identity, CallSignal.accept(id, fakeAudioSdp(), now, now + 60_000)) // after REJECT
            inject(
                a.identity,
                CallSignal.hangUp(
                    CallId.random(java.security.SecureRandom()),
                    CallEndReason.NONE,
                    now,
                    now + 60_000,
                ),
            )
            inject(stranger, CallSignal.hangUp(id, CallEndReason.NONE, now, now + 60_000))
            Thread.sleep(300)
            b.transport.sentSignals.size shouldBe 1
            b.manager.activeCalls() shouldBe emptyList()
            a.manager.stop()
            b.manager.stop()
        }

        test("S5: without a token every answer goes out with a null route (unchanged behavior)") {
            val (a, b) = pair()
            val id = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.rejectCall(id)
            awaitCondition { b.transport.sentReplyRoutes.isNotEmpty() }
            b.transport.sentReplyRoutes.toList() shouldBe listOf<DmCallReplyRoute?>(null)
            a.manager.stop()
            b.manager.stop()
        }

        test("S6: stop() while an answer is still being sent over the route is clean") {
            val (a, b) = pair()
            a.transport.routeToAttachOnDeliver = route(7)
            val id = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            val latch = java.util.concurrent.CountDownLatch(1)
            b.transport.blockSendUntil = latch
            b.manager.rejectCall(id)
            Thread.sleep(100)
            val stopper = Thread { b.manager.stop() }
            stopper.start()
            latch.countDown()
            stopper.join(10_000)
            stopper.isAlive shouldBe false
            b.manager.liveMediaSessionCountForTesting() shouldBe 0
            a.manager.stop()
        }
    })
