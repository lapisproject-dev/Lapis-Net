package net.lapisphilosophorum.lapisnet.call

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.util.concurrent.CopyOnWriteArrayList

private class PNode(
    val identity: Secp256k1PublicKey,
    val manager: CallManager,
    val engine: FakeCallMediaEngine,
    val transport: FakeCallSignalTransport,
) {
    val events = CopyOnWriteArrayList<CallEvent>()

    init {
        manager.addCallListener { events.add(it) }
    }
}

private fun pair(
    policyA: CallMediaPolicy,
    policyB: CallMediaPolicy,
    configure: (CallConfig) -> CallConfig = { it },
): Pair<PNode, PNode> {
    val network = FakeCallNetwork()
    val idA = Secp256k1KeyPair.generate().publicKey
    val idB = Secp256k1KeyPair.generate().publicKey
    val tA = FakeCallSignalTransport(idA, network)
    val tB = FakeCallSignalTransport(idB, network)
    val eA = FakeCallMediaEngine().also { e -> e.configureSession = { it.sdp = ::fakePublicAudioSdp } }
    val eB = FakeCallMediaEngine().also { e -> e.configureSession = { it.sdp = ::fakePublicAudioSdp } }
    val mA = CallManager.attachToTransport(tA, eA, configure(CallConfig(mediaPolicy = policyA)))
    val mB = CallManager.attachToTransport(tB, eB, configure(CallConfig(mediaPolicy = policyB)))
    network.register(idA, mA)
    network.register(idB, mB)
    return PNode(idA, mA, eA, tA) to PNode(idB, mB, eB, tB)
}

class CallMediaPolicyTest :
    FunSpec({
        test("the factory maps anonymity and the option") {
            CallMediaPolicy.of(false, false) shouldBe CallMediaPolicy.DIRECT
            CallMediaPolicy.of(true, false) shouldBe CallMediaPolicy.DISABLED
            CallMediaPolicy.of(true, true) shouldBe CallMediaPolicy.EXPOSED
        }

        test("DISABLED: placeCall throws synchronously, nothing is sent, no event, no history") {
            val (a, b) = pair(CallMediaPolicy.DISABLED, CallMediaPolicy.DISABLED)
            shouldThrow<CallMediaDisabledException> { a.manager.placeCall(b.identity) }
            shouldThrow<CallMediaDisabledException> { a.manager.placeCall(b.identity, mediaExposureConfirmed = true) }
            Thread.sleep(100)
            a.transport.sentSignals.shouldBeEmpty()
            a.events.shouldBeEmpty()
            a.manager.callHistory().shouldBeEmpty()
            a.engine.sessions.shouldBeEmpty()
            a.manager.stop()
            b.manager.stop()
        }

        test(
            "EXPOSED: placeCall and acceptCall need the confirmation, with it the call connects and the SDP is reduced",
        ) {
            val (a, b) = pair(CallMediaPolicy.EXPOSED, CallMediaPolicy.EXPOSED)
            shouldThrow<CallMediaExposureNotConfirmedException> { a.manager.placeCall(b.identity) }
            Thread.sleep(100)
            a.transport.sentSignals.shouldBeEmpty()

            val callId = a.manager.placeCall(b.identity, mediaExposureConfirmed = true)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            shouldThrow<CallMediaExposureNotConfirmedException> { b.manager.acceptCall(callId) }
            b.manager
                .activeCalls()
                .single()
                .state shouldBe CallState.INCOMING_RINGING
            b.manager.acceptCall(callId, mediaExposureConfirmed = true)
            awaitCondition { a.events.any { it is CallEvent.Active } }
            awaitCondition { b.events.any { it is CallEvent.Active } }

            // what crossed the wire: only the public candidate, placeholder connection lines
            for (signal in a.transport.sentSignals + b.transport.sentSignals) {
                val sdp = signal.sdp ?: continue
                sdp.contains("192.168.") shouldBe false
                sdp.contains("127.0.0.1") shouldBe false
                sdp.contains("c=IN IP4 0.0.0.0") shouldBe true
                sdp.contains("198.51.100.7") shouldBe true
            }
            // what the media layer was handed: also filtered
            for (sdp in a.engine.sessions.flatMap { it.remoteSdps } + b.engine.sessions.flatMap { it.remoteSdps }) {
                sdp.contains("192.168.") shouldBe false
            }
            a.manager.stop()
            b.manager.stop()
        }

        test("DIRECT ignores the flag and leaves the SDP untouched") {
            val (a, b) = pair(CallMediaPolicy.DIRECT, CallMediaPolicy.DIRECT)
            val callId = a.manager.placeCall(b.identity, mediaExposureConfirmed = true)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId, mediaExposureConfirmed = false)
            awaitCondition { a.events.any { it is CallEvent.Active } }
            a.transport.sentSignals
                .first()
                .sdp!!
                .contains("192.168.1.5") shouldBe true
            a.manager.stop()
            b.manager.stop()
        }

        test("DISABLED callee: an INVITE is dropped silently, one IncomingSuppressed, no reply, no media session") {
            val (a, b) = pair(CallMediaPolicy.DIRECT, CallMediaPolicy.DISABLED)
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingSuppressed } }
            Thread.sleep(200)
            b.transport.sentSignals.shouldBeEmpty() // no REJECT, no BUSY
            b.engine.sessions.shouldBeEmpty()
            b.manager.activeCalls().shouldBeEmpty()
            val suppressed = b.events.filterIsInstance<CallEvent.IncomingSuppressed>()
            suppressed shouldHaveSize 1
            suppressed.single().callId shouldBe callId
            suppressed.single().cause shouldBe CallSuppressCause.ANONYMITY_MODE
            b.events.filterIsInstance<CallEvent.IncomingCall>().shouldBeEmpty()
            // a retransmit of the same callId does not emit again
            a.transport.sentSignals
                .first()
                .let { signal ->
                    b.manager.onInboundCallSignal(
                        net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                            a.identity,
                            CallSignalCodec.encode(signal),
                            false,
                            System.currentTimeMillis() / 1000,
                        ),
                    )
                }
            Thread.sleep(200)
            b.events.filterIsInstance<CallEvent.IncomingSuppressed>() shouldHaveSize 1
            a.manager.stop()
            b.manager.stop()
        }

        test("a quarantined sender wins over DISABLED: IncomingCall(quarantined), not IncomingSuppressed") {
            val network = FakeCallNetwork()
            val idA = Secp256k1KeyPair.generate().publicKey
            val idB = Secp256k1KeyPair.generate().publicKey
            val tA = FakeCallSignalTransport(idA, network).also { it.quarantinedFromSelf = true }
            val tB = FakeCallSignalTransport(idB, network)
            val mA = CallManager.attachToTransport(tA, FakeCallMediaEngine(), CallConfig())
            val mB =
                CallManager.attachToTransport(
                    tB,
                    FakeCallMediaEngine(),
                    CallConfig(mediaPolicy = CallMediaPolicy.DISABLED),
                )
            network.register(idA, mA)
            network.register(idB, mB)
            val eventsB = CopyOnWriteArrayList<CallEvent>()
            mB.addCallListener { eventsB.add(it) }
            mA.placeCall(idB)
            awaitCondition { eventsB.any { it is CallEvent.IncomingCall } }
            eventsB.filterIsInstance<CallEvent.IncomingCall>().single().quarantined shouldBe true
            eventsB.filterIsInstance<CallEvent.IncomingSuppressed>().shouldBeEmpty()
            mA.stop()
            mB.stop()
        }

        test("the global invite limit applies only in anonymity mode") {
            val network = FakeCallNetwork()
            val idB = Secp256k1KeyPair.generate().publicKey
            val tB = FakeCallSignalTransport(idB, network)
            val mB =
                CallManager.attachToTransport(
                    tB,
                    FakeCallMediaEngine(),
                    CallConfig(
                        mediaPolicy = CallMediaPolicy.EXPOSED,
                        maxGlobalInvitesPerWindow = 3,
                        maxConcurrentCalls = 100,
                    ),
                )
            network.register(idB, mB)
            val eventsB = CopyOnWriteArrayList<CallEvent>()
            mB.addCallListener { eventsB.add(it) }
            val senders = List(6) { Secp256k1KeyPair.generate().publicKey }
            for (sender in senders) {
                val sig =
                    CallSignal.invite(
                        CallId.random(java.security.SecureRandom()),
                        fakePublicAudioSdp(),
                        System.currentTimeMillis(),
                        System.currentTimeMillis() + 60_000,
                    )
                mB.onInboundCallSignal(
                    net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                        sender,
                        CallSignalCodec.encode(sig),
                        false,
                        System.currentTimeMillis() / 1000,
                    ),
                )
            }
            awaitCondition { eventsB.filterIsInstance<CallEvent.IncomingCall>().size >= 3 }
            Thread.sleep(300)
            eventsB.filterIsInstance<CallEvent.IncomingCall>() shouldHaveSize 3
            mB.stop()
        }
    })
