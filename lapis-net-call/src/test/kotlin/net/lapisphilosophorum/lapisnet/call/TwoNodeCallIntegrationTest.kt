package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmTestNode
import net.lapisphilosophorum.lapisnet.dm.buildDmTestNode
import net.lapisphilosophorum.lapisnet.dm.connectAndConverge
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The real end-to-end path this module's own `WebRtcCallMediaEngine.isNativeAvailable()` doc
 * comment has been flagging as missing since V0.8.7: `CallManager.attach` over a real
 * `DmSessionManager` between two real `LapisNode`s (via `lapis-net-dm`'s own `testFixtures` -
 * `buildDmTestNode`/`connectAndConverge`/`DmTestNode`, the SAME real two-node harness that
 * module's own integration tests use, not a re-implementation), wired to a real
 * `WebRtcCallMediaEngine` on BOTH sides - never `FakeCallMediaEngine`.
 *
 * What this test DOES prove, that no other test in this constellation does alone:
 * `CallManager.placeCall`/`acceptCall` drive a REAL SDP offer/answer through the REAL DM AEAD
 * transport, through REAL ICE gathering and a REAL DTLS handshake, to REAL
 * `RTCPeerConnectionState.CONNECTED` on both peer connections, surfacing as `CallEvent.Active` on
 * both `CallManager`s. `CallManagerStateMachineTest`/`CallManagerAbuseTest` prove the state machine
 * against a `FakeCallMediaEngine`; `DmSessionManagerCallSignalTest` (lapis-net-dm) proves the DM
 * transport against opaque bytes; `CallManagerDmWiringIntegrationTest` proves `CallManager.attach`'s
 * DM-listener wiring, still against `FakeCallMediaEngine`. This is the one test that removes the
 * fake from that last link.
 *
 * What this test deliberately does NOT prove: it uses `headlessAudio = true`
 * (`HeadlessAudioDeviceModule`, no real microphone/speaker), so it says nothing about actual audio
 * capture/playback quality, and nothing about connectivity across a real NAT/firewall (both peers
 * are host-only candidates on localhost, exactly like `WebRtcCallMediaEngineTest`'s own single-JVM
 * setup) - it proves the SIGNALING AND HANDSHAKE plumbing end to end, not real-world call quality.
 *
 * Gated by [WebRtcCallMediaEngine.isNativeAvailable] - mirrors `WebRtcCallMediaEngineTest`'s own
 * skip-not-fail discipline exactly: an environment where the native library cannot load skips this
 * test visibly (`disabled(...)` in the report) rather than failing or silently vanishing.
 */
class TwoNodeCallIntegrationTest :
    FunSpec({
        val nativeAvailable = WebRtcCallMediaEngine.isNativeAvailable()

        test(
            "two real nodes, real DmSessionManager, real WebRtcCallMediaEngine: A places a call, " +
                "B accepts, both reach CallEvent.Active",
        ).config(enabled = nativeAvailable) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            var engineA: WebRtcCallMediaEngine? = null
            var engineB: WebRtcCallMediaEngine? = null
            var managerA: CallManager? = null
            var managerB: CallManager? = null
            try {
                connectAndConverge(nodeA, nodeB)
                establishTextSession(nodeA, nodeB)

                val realEngineA = WebRtcCallMediaEngine.create(headlessAudio = true)
                val realEngineB = WebRtcCallMediaEngine.create(headlessAudio = true)
                engineA = realEngineA
                engineB = realEngineB
                val realManagerA = CallManager.attach(nodeA.dmSessionManager, realEngineA)
                val realManagerB = CallManager.attach(nodeB.dmSessionManager, realEngineB)
                managerA = realManagerA
                managerB = realManagerB

                val eventsA = CopyOnWriteArrayList<CallEvent>()
                val eventsB = CopyOnWriteArrayList<CallEvent>()
                realManagerA.addCallListener { eventsA.add(it) }
                realManagerB.addCallListener { eventsB.add(it) }

                val bPub = nodeB.identity.secp256k1KeyPair.publicKey
                val callId = realManagerA.placeCall(bPub)
                awaitCondition(timeoutMs = 30_000) { eventsB.any { it is CallEvent.IncomingCall } }

                realManagerB.acceptCall(callId)
                awaitCondition(timeoutMs = 30_000) { eventsA.any { it is CallEvent.Active } }
                awaitCondition(timeoutMs = 30_000) { eventsB.any { it is CallEvent.Active } }

                realManagerA.activeCalls().single().state shouldBe CallState.ACTIVE
                realManagerB.activeCalls().single().state shouldBe CallState.ACTIVE
            } finally {
                runCatching { managerA?.stop() }
                runCatching { managerB?.stop() }
                runCatching { engineA?.close() }
                runCatching { engineB?.close() }
                nodeA.stop()
                nodeB.stop()
            }
        }
    })

/** Sends a TEXT DM from [a] to [b] and retries until received - a call never begins a first
 * contact (see `DmSessionManager`'s own class doc comment), so a session must already exist before
 * [CallManager.placeCall] can send an INVITE call signal over it (see
 * `DmSessionManagerCallSignalTest`'s "without an established session" case, and
 * `CallManagerDmWiringIntegrationTest`'s own identical "text before call" ordering). Deliberately
 * NOT pulled into `lapis-net-dm`'s shared testFixtures - this ordering is a `lapis-net-call`-specific
 * precondition on placing a CALL, not a general DM-transport concern that harness should know about.
 */
private fun establishTextSession(
    a: DmTestNode,
    b: DmTestNode,
    timeout: Duration = Duration.ofSeconds(30),
) {
    val bPub = b.identity.secp256k1KeyPair.publicKey
    val received = CopyOnWriteArrayList<DmInboundMessage>()
    b.dmSessionManager.addInboundListener { received.add(it) }
    val deadline = Instant.now().plus(timeout)
    while (received.isEmpty() && Instant.now().isBefore(deadline)) {
        runCatching { a.dmSessionManager.send(bPub, DmContent(body = "hi")) }
        Thread.sleep(1000)
    }
    if (received.isEmpty()) {
        error("text DM was not received within $timeout - cannot establish a session to place a call over")
    }
}
