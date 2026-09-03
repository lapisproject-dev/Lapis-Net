package net.lapisphilosophorum.lapisnet.call

import dev.onvoid.webrtc.RTCPeerConnectionState
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Exercises the REAL `webrtc-java` native engine - two [WebRtcCallMediaEngine] sessions connecting to
 * each other within a single JVM process, exactly this wave's own realism-check probe (see the
 * planning notes' §0 "Funktioniert es headless?" row). Gated by [WebRtcCallMediaEngine
 * .isNativeAvailable] - an environment where the native library cannot load skips with a warning log,
 * never silently (see this wave's own "CI-Risiko" implementation note): a skipped test here is always
 * visible in the test report as `disabled(...)`, not a silently-vanished assertion.
 */
class WebRtcCallMediaEngineTest :
    FunSpec({
        val nativeAvailable = WebRtcCallMediaEngine.isNativeAvailable()

        // Review-fix round MINOR finding (2026-09-02): the DISCONNECTED-is-not-terminal change to
        // WebRtcCallMediaSession's onConnectionChange had no test - onConnectionChange itself lives
        // inside a private anonymous PeerConnectionObserver on a real RTCPeerConnection, unreachable
        // without a live native connection driving actual state transitions through it. Not gated by
        // nativeAvailable: callConnectionActionFor is a plain function over the RTCPeerConnectionState
        // enum, no native call involved - see its own doc comment.
        test("callConnectionActionFor maps every RTCPeerConnectionState to the documented action") {
            callConnectionActionFor(RTCPeerConnectionState.CONNECTED) shouldBe CallConnectionAction.CONNECTED
            // The one entry this whole extraction exists to pin down: DISCONNECTED must never map
            // to FAILED/CLOSED - see this class's own inline comment on why it is deliberately
            // treated as transient, not terminal.
            callConnectionActionFor(RTCPeerConnectionState.DISCONNECTED) shouldBe
                CallConnectionAction.TRANSIENT_DISCONNECT
            callConnectionActionFor(RTCPeerConnectionState.FAILED) shouldBe CallConnectionAction.FAILED
            callConnectionActionFor(RTCPeerConnectionState.CLOSED) shouldBe CallConnectionAction.CLOSED
            callConnectionActionFor(RTCPeerConnectionState.NEW) shouldBe CallConnectionAction.IGNORE
            callConnectionActionFor(RTCPeerConnectionState.CONNECTING) shouldBe CallConnectionAction.IGNORE
        }

        test("two sessions in one JVM connect end to end - offer/answer, both reach onMediaConnected").config(
            enabled = nativeAvailable,
        ) {
            val engineA = WebRtcCallMediaEngine.create(headlessAudio = true)
            val engineB = WebRtcCallMediaEngine.create(headlessAudio = true)
            try {
                val connectedA = CountDownLatch(1)
                val connectedB = CountDownLatch(1)
                val sessionA =
                    engineA.newSession(
                        object : CallMediaObserver {
                            override fun onMediaConnected() = connectedA.countDown()

                            override fun onMediaFailed(cause: String) = Unit

                            override fun onMediaClosed() = Unit
                        },
                    )
                val sessionB =
                    engineB.newSession(
                        object : CallMediaObserver {
                            override fun onMediaConnected() = connectedB.countDown()

                            override fun onMediaFailed(cause: String) = Unit

                            override fun onMediaClosed() = Unit
                        },
                    )
                try {
                    val offer = sessionA.createOffer(Duration.ofSeconds(10))
                    offer shouldContain "opus"
                    offer shouldContain "a=fingerprint"
                    // Testing-gap finding (2026-09-02): CallSdpPolicyTest only ever exercises
                    // validateRemote against a HAND-WRITTEN fakeAudioSdp() - nothing in this module
                    // previously proved that SDP this node's OWN engine actually gathers survives the
                    // policy a peer applies to it, even though round-7's udp-only tightening narrowed
                    // exactly that seam (enforced solely by WebRtcCallMediaEngine's own
                    // PORTALLOCATOR_DISABLE_TCP flag). If libwebrtc ever gathered a non-udp or
                    // non-host candidate here - a platform/interface difference, a webrtc-java
                    // upgrade - this assertion fails LOUDLY in this test instead of silently making
                    // every real call get REJECTed while the rest of the suite (built entirely on
                    // fakeAudioSdp()) stays green.
                    CallSdpPolicy.validateRemote(offer, CallMediaKind.AUDIO)

                    val answer = sessionB.acceptOfferAndCreateAnswer(offer, Duration.ofSeconds(10))
                    CallSdpPolicy.validateRemote(answer, CallMediaKind.AUDIO)
                    sessionA.applyAnswer(answer)

                    connectedA.await(30, TimeUnit.SECONDS) shouldBe true
                    connectedB.await(30, TimeUnit.SECONDS) shouldBe true
                } finally {
                    sessionA.close()
                    sessionB.close()
                }
            } finally {
                engineA.close()
                engineB.close()
            }
        }

        test("a tampered DTLS fingerprint in the answer prevents the connection from ever completing").config(
            enabled = nativeAvailable,
        ) {
            val engineA = WebRtcCallMediaEngine.create(headlessAudio = true)
            val engineB = WebRtcCallMediaEngine.create(headlessAudio = true)
            try {
                val connectedA = CountDownLatch(1)
                val sessionA =
                    engineA.newSession(
                        object : CallMediaObserver {
                            override fun onMediaConnected() = connectedA.countDown()

                            override fun onMediaFailed(cause: String) = Unit

                            override fun onMediaClosed() = Unit
                        },
                    )
                val sessionB =
                    engineB.newSession(
                        object : CallMediaObserver {
                            override fun onMediaConnected() = Unit

                            override fun onMediaFailed(cause: String) = Unit

                            override fun onMediaClosed() = Unit
                        },
                    )
                try {
                    val offer = sessionA.createOffer(Duration.ofSeconds(10))
                    val answer = sessionB.acceptOfferAndCreateAnswer(offer, Duration.ofSeconds(10))

                    // Flip a hex character in the fingerprint's colon-separated hex body - the SAME
                    // class of tamper CallSdpPolicyTest's own adversarial cases exercise structurally;
                    // here the point is the CRYPTOGRAPHIC consequence: a structurally-valid but
                    // WRONG fingerprint must never let the DTLS handshake complete.
                    val tamperedAnswer =
                        Regex("a=fingerprint:sha-256 [0-9A-Fa-f:]+").replace(answer) { match ->
                            val original = match.value
                            val flipped =
                                if (original.last().equals('A', ignoreCase = true)) {
                                    original.dropLast(1) + "B"
                                } else {
                                    original.dropLast(1) + "A"
                                }
                            flipped
                        }
                    tamperedAnswer shouldContain "a=fingerprint"

                    sessionA.applyAnswer(tamperedAnswer)

                    // Bounded wait, well under the DTLS handshake's own internal retry/give-up
                    // behavior - the assertion is "did NOT connect", so a generous but finite wait is
                    // correct; an infinite wait would make a genuine future regression hang the suite
                    // instead of failing it.
                    connectedA.await(8, TimeUnit.SECONDS) shouldBe false
                } finally {
                    sessionA.close()
                    sessionB.close()
                }
            } finally {
                engineA.close()
                engineB.close()
            }
        }
    })
