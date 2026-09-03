package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

private class Node(
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

private fun buildPair(
    config: CallConfig = CallConfig(),
    clock: () -> Instant = Instant::now,
    network: FakeCallNetwork = FakeCallNetwork(),
): Pair<Node, Node> {
    val identityA = Secp256k1KeyPair.generate().publicKey
    val identityB = Secp256k1KeyPair.generate().publicKey
    val transportA = FakeCallSignalTransport(identityA, network)
    val transportB = FakeCallSignalTransport(identityB, network)
    val engineA = FakeCallMediaEngine()
    val engineB = FakeCallMediaEngine()
    val managerA = CallManager.attachToTransport(transportA, engineA, config, clock = clock)
    val managerB = CallManager.attachToTransport(transportB, engineB, config, clock = clock)
    network.register(identityA, managerA)
    network.register(identityB, managerB)
    return Node(identityA, managerA, engineA, transportA) to Node(identityB, managerB, engineB, transportB)
}

class CallManagerStateMachineTest :
    FunSpec({
        test("happy path: A places a call, B accepts, both reach ACTIVE") {
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)

            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            val incoming = b.events.filterIsInstance<CallEvent.IncomingCall>().single()
            incoming.callId shouldBe callId
            incoming.quarantined shouldBe false

            b.manager.acceptCall(callId)

            awaitCondition { a.events.any { it is CallEvent.Active } }
            awaitCondition { b.events.any { it is CallEvent.Active } }

            a.manager
                .activeCalls()
                .single()
                .state shouldBe CallState.ACTIVE
            b.manager
                .activeCalls()
                .single()
                .state shouldBe CallState.ACTIVE

            a.manager.stop()
            b.manager.stop()
        }

        test("reject path: B rejects, A observes Ended(DECLINED)") {
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }

            b.manager.rejectCall(callId, CallEndReason.DECLINED)

            awaitCondition { a.events.any { it is CallEvent.Ended } }
            val ended = a.events.filterIsInstance<CallEvent.Ended>().single()
            ended.reason shouldBe CallEndReason.DECLINED
            a.manager.activeCalls() shouldBe emptyList()
            b.manager.activeCalls() shouldBe emptyList()
            a.manager
                .callHistory()
                .single { it.callId == callId }
                .reason shouldBe CallEndReason.DECLINED

            a.manager.stop()
            b.manager.stop()
        }

        // Review-fix regression (2026-09-02, MINOR finding): CallLog used to read Instant.now()
        // independently of CallManager's own injectable clock, so a fixed/fake clock (as every
        // skew/expiry test in this file sets) never reached callHistory()'s own timestamps.
        test("callHistory() timestamps come from the injected clock, not the real wall clock") {
            val fixedInstant = Instant.ofEpochSecond(1_700_000_000L)
            val (a, b) = buildPair(clock = { fixedInstant })
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }

            b.manager.rejectCall(callId, CallEndReason.DECLINED)

            awaitCondition { a.manager.callHistory().any { it.callId == callId } }
            a.manager
                .callHistory()
                .single { it.callId == callId }
                .endedAtEpochSecond shouldBe fixedInstant.epochSecond

            a.manager.stop()
            b.manager.stop()
        }

        test("hang up from the caller ends the call on both sides") {
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId)
            awaitCondition { a.events.any { it is CallEvent.Active } }

            a.manager.hangUp(callId)

            awaitCondition { b.events.any { it is CallEvent.Ended } }
            b.events
                .filterIsInstance<CallEvent.Ended>()
                .single()
                .reason shouldBe CallEndReason.REMOTE_HANGUP
            a.manager.stop()
            b.manager.stop()
        }

        test("hang up from the callee ends the call on both sides") {
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId)
            awaitCondition { a.events.any { it is CallEvent.Active } }

            b.manager.hangUp(callId)

            awaitCondition { a.events.any { it is CallEvent.Ended } }
            a.events
                .filterIsInstance<CallEvent.Ended>()
                .single()
                .reason shouldBe CallEndReason.REMOTE_HANGUP
            a.manager.stop()
            b.manager.stop()
        }

        test("busy: a second INVITE while one call is active is rejected with BUSY, the ongoing call unaffected") {
            val config = CallConfig(maxConcurrentCalls = 1)
            val network = FakeCallNetwork()
            val (a, b) = buildPair(config, network = network)
            // A third node, c, also calls b while a<->b is already active - registered on the SAME
            // shared network as a/b so b's own outbound BUSY reply actually reaches c (a single
            // hardcoded pen-pal transport, as this suite used before FakeCallNetwork existed, could
            // only ever route back to whichever single peer it was wired to at construction time).
            val identityC = Secp256k1KeyPair.generate().publicKey
            val transportC = FakeCallSignalTransport(identityC, network)
            val engineC = FakeCallMediaEngine()
            val managerC = CallManager.attachToTransport(transportC, engineC, config)
            network.register(identityC, managerC)
            val c = Node(identityC, managerC, engineC, transportC)

            val callId1 = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId1)
            awaitCondition { a.events.any { it is CallEvent.Active } }

            c.manager.placeCall(b.identity)
            awaitCondition { c.events.any { it is CallEvent.Ended } }
            c.events
                .filterIsInstance<CallEvent.Ended>()
                .single()
                .reason shouldBe CallEndReason.BUSY

            // The ongoing call between a and b is untouched.
            a.manager
                .activeCalls()
                .single()
                .callId shouldBe callId1
            a.manager
                .activeCalls()
                .single()
                .state shouldBe CallState.ACTIVE

            a.manager.stop()
            b.manager.stop()
            c.manager.stop()
        }

        test(
            "placeCall while already at maxConcurrentCalls is recorded in callHistory(), " +
                "consistent with every other Ended path",
        ) {
            val config = CallConfig(maxConcurrentCalls = 1)
            val (a, b) = buildPair(config)
            val callId1 = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId1)
            awaitCondition { a.events.any { it is CallEvent.Active } }

            // a is now itself at maxConcurrentCalls=1 - a second OUTGOING placeCall hits
            // placeCallOnStateThread's own early BUSY return directly (never reaches the network,
            // unlike the "busy" test above which exercises handleInboundInvite's own BUSY branch on
            // the CALLEE side instead).
            val identityC = Secp256k1KeyPair.generate().publicKey
            val busyCallId = a.manager.placeCall(identityC)

            awaitCondition { a.manager.callHistory().any { it.callId == busyCallId } }
            a.manager
                .callHistory()
                .single { it.callId == busyCallId }
                .reason shouldBe CallEndReason.BUSY

            a.manager.stop()
            b.manager.stop()
        }

        test("ring timeout: an unanswered outgoing call ends with RING_TIMEOUT on the caller's side") {
            val config = CallConfig(ringTimeout = Duration.ofMillis(150))
            val (a, b) = buildPair(config)
            a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }

            awaitCondition(timeoutMs = 2_000) { a.events.any { it is CallEvent.Ended } }
            a.events
                .filterIsInstance<CallEvent.Ended>()
                .single()
                .reason shouldBe CallEndReason.RING_TIMEOUT

            // b's OWN ring timer is independently running the same duration, started only a hair
            // later than a's (see this test's own note below) - by design (both sides ring
            // independently, exactly a real ring-timeout would), so b's end reason is a genuine race
            // between "a's own timer fired and sent HANGUP(RING_TIMEOUT), which arrived before b's own
            // timer" (REMOTE_HANGUP) and "b's own timer fired first" (RING_TIMEOUT) - either is a
            // correct outcome; asserting a single fixed value here would make this test flaky.
            awaitCondition(timeoutMs = 2_000) { b.events.any { it is CallEvent.Ended } }
            val bReason =
                b.events
                    .filterIsInstance<CallEvent.Ended>()
                    .single()
                    .reason
            (bReason == CallEndReason.RING_TIMEOUT || bReason == CallEndReason.REMOTE_HANGUP) shouldBe true

            a.manager.stop()
            b.manager.stop()
        }

        test("connect timeout: media that never connects on the caller's side ends the call with CONNECT_TIMEOUT") {
            val config = CallConfig(connectTimeout = Duration.ofMillis(150))
            val (a, b) = buildPair(config)
            // Only a's side is made to never report onMediaConnected - b's own acceptOfferAndCreateAnswer
            // still auto-connects (the FakeCallMediaSession default), so b reaches ACTIVE normally and
            // its OWN connect-timeout is cancelled well before it could ever fire. This keeps the
            // scenario deterministic: exactly one side experiences a genuine connect timeout, instead
            // of two independent per-side timers racing each other's HANGUP notifications (the same
            // race the ring-timeout test above deliberately tolerates rather than eliminates).
            a.engine.configureSession = { it.autoConnectOnApplyAnswer = false }

            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId)
            awaitCondition { b.events.any { it is CallEvent.Active } }

            awaitCondition(timeoutMs = 2_000) { a.events.any { it is CallEvent.Ended } }
            a.events
                .filterIsInstance<CallEvent.Ended>()
                .single()
                .reason shouldBe CallEndReason.CONNECT_TIMEOUT

            a.manager.stop()
            b.manager.stop()
        }

        test("an expired INVITE (notValidAfter in the past) is dropped without ringing") {
            val (a, b) = buildPair()
            val callId = CallId.random(java.security.SecureRandom())
            val expired = CallSignal.invite(callId, fakeAudioSdp(), 1_000L, 2_000L) // notValidAfter far in the past
            b.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    a.identity,
                    CallSignalCodec.encode(expired),
                    false,
                    0,
                ),
            )
            Thread.sleep(200)
            b.events.filterIsInstance<CallEvent.IncomingCall>() shouldBe emptyList()
            a.manager.stop()
            b.manager.stop()
        }

        test("an INVITE with createdAt far in the future (clock skew) is dropped") {
            val config = CallConfig(maxClockSkew = Duration.ofSeconds(5))
            val (a, b) = buildPair(config)
            val farFuture = System.currentTimeMillis() + Duration.ofDays(1).toMillis()
            val skewed =
                CallSignal.invite(
                    CallId.random(java.security.SecureRandom()),
                    fakeAudioSdp(),
                    farFuture,
                    farFuture + 60_000,
                )
            b.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    a.identity,
                    CallSignalCodec.encode(skewed),
                    false,
                    0,
                ),
            )
            Thread.sleep(200)
            b.events.filterIsInstance<CallEvent.IncomingCall>() shouldBe emptyList()
            a.manager.stop()
            b.manager.stop()
        }

        test("ACCEPT for an unknown callId is ignored, no crash") {
            val (a, b) = buildPair()
            val bogusAccept =
                CallSignal.accept(
                    CallId.random(java.security.SecureRandom()),
                    fakeAudioSdp(),
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + 60_000,
                )
            a.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    b.identity,
                    CallSignalCodec.encode(bogusAccept),
                    false,
                    0,
                ),
            )
            Thread.sleep(200)
            a.manager.activeCalls() shouldBe emptyList()
            a.manager.stop()
            b.manager.stop()
        }

        test("HANGUP for an unknown callId is ignored, no crash") {
            val (a, b) = buildPair()
            val bogusHangup =
                CallSignal.hangUp(
                    CallId.random(java.security.SecureRandom()),
                    CallEndReason.LOCAL_HANGUP,
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + 60_000,
                )
            a.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    b.identity,
                    CallSignalCodec.encode(bogusHangup),
                    false,
                    0,
                ),
            )
            Thread.sleep(200)
            a.manager.activeCalls() shouldBe emptyList()
            a.manager.stop()
            b.manager.stop()
        }

        test("ACCEPT for a call this node never placed (only ever saw as INCOMING) is ignored") {
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            // b never placed this call - an ACCEPT "for" it, claimed from a itself, must be ignored by b.
            val strayAccept =
                CallSignal.accept(
                    callId,
                    fakeAudioSdp(),
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + 60_000,
                )
            b.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    a.identity,
                    CallSignalCodec.encode(strayAccept),
                    false,
                    0,
                ),
            )
            Thread.sleep(200)
            b.manager
                .activeCalls()
                .single()
                .state shouldBe CallState.INCOMING_RINGING
            a.manager.stop()
            b.manager.stop()
        }

        test("a duplicate INVITE with the same callId rings only once") {
            val (a, b) = buildPair()
            val callId = CallId.random(java.security.SecureRandom())
            val invite =
                CallSignal.invite(
                    callId,
                    fakeAudioSdp(),
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + 60_000,
                )
            repeat(3) {
                b.manager.onInboundCallSignal(
                    net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                        a.identity,
                        CallSignalCodec.encode(invite),
                        false,
                        0,
                    ),
                )
            }
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            Thread.sleep(200)
            b.events.filterIsInstance<CallEvent.IncomingCall>().size shouldBe 1
            a.manager.stop()
            b.manager.stop()
        }

        // MINOR review-round finding (2026-09-02): CallSdpPolicy's own adversarial cases were fully
        // covered by CallSdpPolicyTest, but the two places CallManager actually WIRES a rejection into
        // the call state machine (handleInboundInvite's REJECT-and-never-ring branch, and
        // handleInboundAccept's end-the-outgoing-call branch) had no test of their own - only the
        // policy function in isolation. Both tests below reuse fakeAudioSdp()'s structurally valid
        // shape with only its m=line swapped to video, mirroring CallSdpPolicyTest's own "m=video
        // section is rejected with UNSUPPORTED_MEDIA" case exactly, so the SDP fails ONLY the check
        // this test means to exercise.
        test(
            "an INVITE with a policy-violating SDP is rejected with REJECT(reason) and never rings",
        ) {
            val (a, b) = buildPair()
            val callId = CallId.random(java.security.SecureRandom())
            val rejectedSdp =
                fakeAudioSdp().replace(
                    "m=audio 54321 UDP/TLS/RTP/SAVPF 111",
                    "m=video 54321 UDP/TLS/RTP/SAVPF 96",
                )
            val now = System.currentTimeMillis()
            val invite = CallSignal.invite(callId, rejectedSdp, now, now + 60_000)
            b.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    a.identity,
                    CallSignalCodec.encode(invite),
                    false,
                    now / 1000,
                ),
            )

            awaitCondition { b.transport.sentSignals.isNotEmpty() }
            val sent = b.transport.sentSignals.single()
            sent.type shouldBe CallSignalType.REJECT
            sent.callId shouldBe callId
            sent.reason shouldBe CallEndReason.UNSUPPORTED_MEDIA
            // marksAcceptance: T7, round-8-verification finding (2026-09-03) - this REJECT is an
            // automatic SDP-policy auto-reject (handleInboundInvite's own doc comment), never a local
            // user decision, so it must NOT promote its sender to DmAcceptedContacts.
            b.transport.sentMarksAcceptance.single() shouldBe false

            // Never rang - handleInboundInvite's SDP-policy check runs BEFORE the call is ever
            // admitted into calls/emitted as an IncomingCall.
            Thread.sleep(200)
            b.events.filterIsInstance<CallEvent.IncomingCall>() shouldBe emptyList()
            b.manager.activeCalls() shouldBe emptyList()

            a.manager.stop()
            b.manager.stop()
        }

        test(
            "an ACCEPT with a policy-violating SDP ends the outgoing call with the policy's own " +
                "reason instead of ever connecting",
        ) {
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)
            // Synchronization point: by the time b has observed the INVITE, a's own
            // runOutgoingMediaSetup has already attached its media session (attach happens strictly
            // BEFORE createOffer/the INVITE send in that function's own body) - the injected ACCEPT
            // below needs that non-null session (handleInboundAccept's own `session == null` guard
            // would otherwise end the call with LOCAL_ERROR instead of exercising this SDP-policy path).
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }

            val rejectedSdp =
                fakeAudioSdp().replace(
                    "m=audio 54321 UDP/TLS/RTP/SAVPF 111",
                    "m=video 54321 UDP/TLS/RTP/SAVPF 96",
                )
            val now = System.currentTimeMillis()
            val accept = CallSignal.accept(callId, rejectedSdp, now, now + 60_000)
            a.manager.onInboundCallSignal(
                net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal(
                    b.identity,
                    CallSignalCodec.encode(accept),
                    false,
                    now / 1000,
                ),
            )

            awaitCondition { a.events.any { it is CallEvent.Ended } }
            a.events
                .filterIsInstance<CallEvent.Ended>()
                .single()
                .reason shouldBe CallEndReason.UNSUPPORTED_MEDIA
            a.manager.activeCalls() shouldBe emptyList()
            awaitCondition {
                a.engine.sessions
                    .single()
                    .closed
                    .get()
            }

            a.manager.stop()
            b.manager.stop()
        }

        // Round-11/round-12 review findings (2026-09-03, SECURITY): CallSignalTransport.send's
        // marksAcceptance flag is the only thing standing between a remote peer and an automatic,
        // permanent DmAcceptancePolicy bypass (see DmSessionManager.sendCallSignal's own doc comment
        // for the full reasoning). Pins that CallManager passes the CORRECT literal at every one of
        // its own call sites, not just that the signal is sent at all. Round-12 fixed a bug this
        // test's own predecessor (round-11) failed to catch despite its name claiming otherwise:
        // REJECT and an unanswered HANGUP were sent `true`, letting a stranger's INVITE force its own
        // promotion to accepted contact merely by having the local user press "reject" or dismiss the
        // still-ringing call - see rejectCallOnStateThread's/hangUpOnStateThread's own doc comments.
        // Every REJECT/HANGUP variant below is pinned by an actual `rejectCall()`/`hangUp()` call, not
        // inferred from an unrelated automatic path, so a regression on any one call site fails here.
        test(
            "marksAcceptance: INVITE/ACCEPT/answered-HANGUP are sent true; " +
                "user REJECT, unanswered HANGUP, and automatic BUSY are sent false",
        ) {
            val config = CallConfig(maxConcurrentCalls = 1)
            val network = FakeCallNetwork()
            val (a, b) = buildPair(config, network = network)

            // a.placeCall -> INVITE, a real user decision to reach b.
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            a.transport.sentSignals
                .zip(a.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.INVITE }
                .second shouldBe true

            // b.acceptCall -> ACCEPT, a real user decision to answer a.
            b.manager.acceptCall(callId)
            awaitCondition { a.events.any { it is CallEvent.Active } }
            b.transport.sentSignals
                .zip(b.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.ACCEPT }
                .second shouldBe true

            // A third node, c, calls b while a<->b is already ACTIVE and config.maxConcurrentCalls=1
            // - b's own handleInboundInvite auto-rejects with BUSY, no user ever saw or decided
            // anything about c. This REJECT is the automatic path - distinct from user-initiated
            // rejectCall(), pinned separately below via a fresh pair.
            val identityC = Secp256k1KeyPair.generate().publicKey
            val transportC = FakeCallSignalTransport(identityC, network)
            val engineC = FakeCallMediaEngine()
            val managerC = CallManager.attachToTransport(transportC, engineC, config)
            network.register(identityC, managerC)
            managerC.placeCall(b.identity)
            awaitCondition {
                b.transport.sentSignals
                    .zip(b.transport.sentMarksAcceptance)
                    .any { it.first.type == CallSignalType.REJECT }
            }
            b.transport.sentSignals
                .zip(b.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.REJECT }
                .second shouldBe false

            // b.hangUp -> HANGUP on the still-ACTIVE, already-answered a<->b call: b already decided
            // to communicate with a (accepted the call), so this HANGUP is `true`.
            b.manager.hangUp(callId)
            awaitCondition { a.events.any { it is CallEvent.Ended } }
            b.transport.sentSignals
                .zip(b.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.HANGUP }
                .second shouldBe true

            // Fresh pair, d.rejectCall(): a real user-initiated REJECT of an INVITE d never accepted -
            // the exact escape path round-12 closed. Must be `false`, not merely the automatic-BUSY
            // REJECT already pinned above.
            val (dCaller, dCallee) = buildPair(config, network = network)
            val dCallId = dCaller.manager.placeCall(dCallee.identity)
            awaitCondition { dCallee.events.any { it is CallEvent.IncomingCall } }
            dCallee.manager.rejectCall(dCallId, CallEndReason.DECLINED)
            awaitCondition {
                dCallee.transport.sentSignals
                    .zip(dCallee.transport.sentMarksAcceptance)
                    .any { it.first.type == CallSignalType.REJECT }
            }
            dCallee.transport.sentSignals
                .zip(dCallee.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.REJECT }
                .second shouldBe false

            // Fresh pair, e.hangUp() on a still-INCOMING_RINGING call e never accepted (the "swipe to
            // dismiss" UI action) - must behave like a REJECT for marksAcceptance purposes, `false`,
            // NOT `true` merely because hangUp() is a user-initiated public API.
            val (eCaller, eCallee) = buildPair(config, network = network)
            val eCallId = eCaller.manager.placeCall(eCallee.identity)
            awaitCondition { eCallee.events.any { it is CallEvent.IncomingCall } }
            eCallee.manager.hangUp(eCallId, CallEndReason.DECLINED)
            awaitCondition {
                eCallee.transport.sentSignals
                    .zip(eCallee.transport.sentMarksAcceptance)
                    .any { it.first.type == CallSignalType.HANGUP }
            }
            eCallee.transport.sentSignals
                .zip(eCallee.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.HANGUP }
                .second shouldBe false

            a.manager.stop()
            b.manager.stop()
            managerC.stop()
            dCaller.manager.stop()
            dCallee.manager.stop()
            eCaller.manager.stop()
            eCallee.manager.stop()
        }

        test(
            "marksAcceptance: an automatic RING_TIMEOUT/CONNECT_TIMEOUT hangup/reject is sent false",
        ) {
            val ringConfig = CallConfig(ringTimeout = Duration.ofMillis(150))
            val (ringA, ringB) = buildPair(ringConfig)
            ringA.manager.placeCall(ringB.identity)
            awaitCondition { ringB.events.any { it is CallEvent.IncomingCall } }
            awaitCondition(timeoutMs = 2_000) { ringA.events.any { it is CallEvent.Ended } }
            // awaitCondition on sentSignals too, not just a direct single{} read straight after the
            // Ended await above: MINOR round-8-verification finding (2026-09-03) - onRingTimeout
            // enqueues the actual transport.send onto mediaExecutor and only THEN emits Ended
            // synchronously on the state thread, so the Ended event can observably fire before the
            // media-thread send has landed in sentSignals - a bare single{} right after Ended raced
            // NoSuchElementException on a slow/loaded CI box even though the signal was always sent.
            awaitCondition {
                ringA.transport.sentSignals
                    .zip(ringA.transport.sentMarksAcceptance)
                    .any { it.first.reason == CallEndReason.RING_TIMEOUT }
            }
            ringA.transport.sentSignals
                .zip(ringA.transport.sentMarksAcceptance)
                .single { it.first.reason == CallEndReason.RING_TIMEOUT }
                .second shouldBe false
            ringA.manager.stop()
            ringB.manager.stop()

            val connectConfig = CallConfig(connectTimeout = Duration.ofMillis(150))
            val (connectA, connectB) = buildPair(connectConfig)
            connectA.engine.configureSession = { it.autoConnectOnApplyAnswer = false }
            val connectCallId = connectA.manager.placeCall(connectB.identity)
            awaitCondition { connectB.events.any { it is CallEvent.IncomingCall } }
            connectB.manager.acceptCall(connectCallId)
            awaitCondition { connectB.events.any { it is CallEvent.Active } }
            awaitCondition(timeoutMs = 2_000) { connectA.events.any { it is CallEvent.Ended } }
            // Same race as the RING_TIMEOUT half above (MINOR round-8-verification finding,
            // 2026-09-03) - onConnectTimeout enqueues its send before emitting Ended too.
            awaitCondition {
                connectA.transport.sentSignals
                    .zip(connectA.transport.sentMarksAcceptance)
                    .any { it.first.reason == CallEndReason.CONNECT_TIMEOUT }
            }
            connectA.transport.sentSignals
                .zip(connectA.transport.sentMarksAcceptance)
                .single { it.first.reason == CallEndReason.CONNECT_TIMEOUT }
                .second shouldBe false
            connectA.manager.stop()
            connectB.manager.stop()
        }

        test("a listener that throws does not break the state machine - other listeners still notified") {
            val (a, b) = buildPair()
            var throwingListenerCalled = false
            a.manager.addCallListener {
                throwingListenerCalled = true
                throw RuntimeException("boom")
            }
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { throwingListenerCalled }
            // The manager's own state machine is unaffected - the ordinary listener registered in
            // Node's own init{} still received the OutgoingRinging event.
            a.events shouldContain CallEvent.OutgoingRinging(callId, b.identity)
            a.manager.stop()
            b.manager.stop()
        }

        test(
            "marksAcceptance: an automatic media-failure hangup is sent false - T8, " +
                "round-8-verification finding (2026-09-03)",
        ) {
            // The last of the five automatic sendSignalAsync call sites without its own dedicated
            // test - onMediaFailedOnStateThread's HANGUP was previously only verified by reading
            // CallManager.kt itself. Drives a REAL onMediaFailed callback through a live ACTIVE call,
            // exactly as WebRtcCallMediaEngine's own signaling-thread JNI callback would.
            val (a, b) = buildPair()
            val callId = a.manager.placeCall(b.identity)
            awaitCondition { b.events.any { it is CallEvent.IncomingCall } }
            b.manager.acceptCall(callId)
            awaitCondition { a.events.any { it is CallEvent.Active } }

            val observer =
                a.engine
                    .sessions
                    .single()
                    .observer
            observer.onMediaFailed("simulated media failure")

            awaitCondition { a.events.any { it is CallEvent.Ended } }
            val ended = a.events.filterIsInstance<CallEvent.Ended>().single()
            ended.reason shouldBe CallEndReason.LOCAL_ERROR

            awaitCondition {
                a.transport.sentSignals
                    .zip(a.transport.sentMarksAcceptance)
                    .any { it.first.type == CallSignalType.HANGUP && it.first.reason == CallEndReason.LOCAL_ERROR }
            }
            a.transport.sentSignals
                .zip(a.transport.sentMarksAcceptance)
                .single { it.first.type == CallSignalType.HANGUP && it.first.reason == CallEndReason.LOCAL_ERROR }
                .second shouldBe false

            a.manager.stop()
            b.manager.stop()
        }
    })
