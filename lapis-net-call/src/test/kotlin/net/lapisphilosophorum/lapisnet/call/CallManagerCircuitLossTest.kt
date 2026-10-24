package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch

class CallManagerCircuitLossTest :
    FunSpec({
        fun build(
            policy: CallMediaPolicy = CallMediaPolicy.EXPOSED,
        ): Triple<CallManager, FakeCallSignalTransport, Pair<FakeCallMediaEngine, CopyOnWriteArrayList<CallEvent>>> {
            val network = FakeCallNetwork()
            val id = Secp256k1KeyPair.generate().publicKey
            val transport = FakeCallSignalTransport(id, network)
            val engine = FakeCallMediaEngine().also { e -> e.configureSession = { it.sdp = ::fakePublicAudioSdp } }
            val manager = CallManager.attachToTransport(transport, engine, CallConfig(mediaPolicy = policy))
            val events = CopyOnWriteArrayList<CallEvent>()
            manager.addCallListener { events.add(it) }
            return Triple(manager, transport, engine to events)
        }

        test("a lost signal path on the INVITE ends the call with CIRCUIT_LOST and closes the session exactly once") {
            val (manager, transport, rest) = build()
            val (engine, events) = rest
            transport.failWith = CallSignalPathLostException()
            val peer = Secp256k1KeyPair.generate().publicKey
            manager.placeCall(peer, mediaExposureConfirmed = true)
            awaitCondition { events.any { it is CallEvent.Ended } }
            events.filterIsInstance<CallEvent.Ended>().single().reason shouldBe CallEndReason.CIRCUIT_LOST
            awaitCondition { manager.liveMediaSessionCountForTesting() == 0 }
            engine.sessions.size shouldBe 1
            engine.sessions
                .single()
                .closed
                .get() shouldBe true
            manager.stop()
        }

        test("any other send failure stays LOCAL_ERROR") {
            val (manager, transport, rest) = build()
            val (_, events) = rest
            transport.failWith = IllegalStateException("boom")
            manager.placeCall(Secp256k1KeyPair.generate().publicKey, mediaExposureConfirmed = true)
            awaitCondition { events.any { it is CallEvent.Ended } }
            events.filterIsInstance<CallEvent.Ended>().single().reason shouldBe CallEndReason.LOCAL_ERROR
            manager.stop()
        }

        test("stop() after a circuit loss does not double-close and does not hang") {
            val (manager, transport, rest) = build()
            val (engine, events) = rest
            transport.failWith = CallSignalPathLostException()
            manager.placeCall(Secp256k1KeyPair.generate().publicKey, mediaExposureConfirmed = true)
            awaitCondition { events.any { it is CallEvent.Ended } }
            manager.stop()
            engine.sessions
                .single()
                .closed
                .get() shouldBe true
            manager.liveMediaSessionCountForTesting() shouldBe 0
        }

        test("a slow transport does not stop stop() from finishing") {
            val (manager, transport, _) = build()
            val latch = CountDownLatch(1)
            transport.blockSendUntil = latch
            manager.placeCall(Secp256k1KeyPair.generate().publicKey, mediaExposureConfirmed = true)
            Thread.sleep(300)
            val started = System.currentTimeMillis()
            latch.countDown()
            manager.stop()
            ((System.currentTimeMillis() - started) < 20_000) shouldBe true
        }
    })
