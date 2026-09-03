package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.security.SecureRandom
import java.time.Duration

private val random = SecureRandom()

class CallManagerAbuseTest :
    FunSpec({
        test("an invite flood beyond the rate limit is throttled - the state machine stays bounded") {
            // maxConcurrentCalls is deliberately set well above maxInvitesPerWindow here - this test
            // isolates the RATE limiter's own effect from the (separately tested, in
            // CallManagerStateMachineTest) BUSY/maxConcurrentCalls ceiling, which would otherwise
            // dominate the result (every INVITE past the first would be BUSY-rejected regardless of
            // the rate limiter, at the default maxConcurrentCalls=1).
            val config =
                CallConfig(maxConcurrentCalls = 100, maxInvitesPerWindow = 5, inviteRateWindow = Duration.ofSeconds(60))
            val network = FakeCallNetwork()
            val identityCaller = Secp256k1KeyPair.generate().publicKey
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            val engineVictim = FakeCallMediaEngine()
            val victim = CallManager.attachToTransport(transportVictim, engineVictim, config)
            network.register(identityVictim, victim)

            val events = java.util.concurrent.CopyOnWriteArrayList<CallEvent>()
            victim.addCallListener { events.add(it) }

            // 20 distinct-callId INVITEs from the same claimed sender, well beyond
            // maxInvitesPerWindow=5 - every one delivered directly (bypassing FakeCallSignalTransport,
            // which would itself require a registered caller manager we do not need for this test).
            repeat(20) {
                val callId = CallId.random(random)
                val now = System.currentTimeMillis()
                val invite = CallSignal.invite(callId, fakeAudioSdp(), now, now + 60_000)
                victim.onInboundCallSignal(
                    DmInboundCallSignal(identityCaller, CallSignalCodec.encode(invite), false, 0),
                )
            }

            awaitCondition { events.filterIsInstance<CallEvent.IncomingCall>().isNotEmpty() }
            Thread.sleep(300)
            val admitted = events.filterIsInstance<CallEvent.IncomingCall>().count { !it.quarantined }
            admitted shouldBe config.maxInvitesPerWindow

            victim.stop()
        }

        test(
            "an invite flood from one sender never starves a DIFFERENT sender's own legitimate invites " +
                "(per-sender rate limiting, not one shared global budget)",
        ) {
            val config =
                CallConfig(maxConcurrentCalls = 100, maxInvitesPerWindow = 5, inviteRateWindow = Duration.ofSeconds(60))
            val network = FakeCallNetwork()
            val identityFlooder = Secp256k1KeyPair.generate().publicKey
            val identityLegitimate = Secp256k1KeyPair.generate().publicKey
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            val engineVictim = FakeCallMediaEngine()
            val victim = CallManager.attachToTransport(transportVictim, engineVictim, config)
            network.register(identityVictim, victim)

            val events = java.util.concurrent.CopyOnWriteArrayList<CallEvent>()
            victim.addCallListener { events.add(it) }

            // The flooder burns through (and past) its own maxInvitesPerWindow=5 budget first.
            repeat(20) {
                val callId = CallId.random(random)
                val now = System.currentTimeMillis()
                val invite = CallSignal.invite(callId, fakeAudioSdp(), now, now + 60_000)
                victim.onInboundCallSignal(
                    DmInboundCallSignal(identityFlooder, CallSignalCodec.encode(invite), false, 0),
                )
            }
            awaitCondition {
                val admittedFromFlooder = events.filterIsInstance<CallEvent.IncomingCall>().count { !it.quarantined }
                admittedFromFlooder == config.maxInvitesPerWindow
            }

            // A single, unrelated INVITE from a DIFFERENT sender, in the same window, right after the
            // flood - with a single shared limiter this would already be exhausted and silently
            // dropped; with a per-sender limiter it is admitted like any other first invite.
            val legitimateCallId = CallId.random(random)
            val now = System.currentTimeMillis()
            val legitimateInvite = CallSignal.invite(legitimateCallId, fakeAudioSdp(), now, now + 60_000)
            victim.onInboundCallSignal(
                DmInboundCallSignal(identityLegitimate, CallSignalCodec.encode(legitimateInvite), false, 0),
            )

            awaitCondition {
                events.filterIsInstance<CallEvent.IncomingCall>().any { it.callId == legitimateCallId }
            }

            victim.stop()
        }

        test("garbage (non-decodable) payloads never escape as an exception, from any thread") {
            val network = FakeCallNetwork()
            val identity = Secp256k1KeyPair.generate().publicKey
            val transport = FakeCallSignalTransport(identity, network)
            val engine = FakeCallMediaEngine()
            val manager = CallManager.attachToTransport(transport, engine)
            network.register(identity, manager)

            val stranger = Secp256k1KeyPair.generate().publicKey
            val rng = SecureRandom()
            repeat(500) {
                val garbage = ByteArray(rng.nextInt(200)).also(rng::nextBytes)
                // onInboundCallSignal itself must never throw - it is invoked directly from a Netty
                // callback in production and must never let anything escape.
                manager.onInboundCallSignal(DmInboundCallSignal(stranger, garbage, false, 0))
            }
            Thread.sleep(200)
            manager.activeCalls() shouldBe emptyList()
            manager.stop()
        }

        test("many completed calls do not grow the tracked-call map without bound") {
            // maxInvitesPerWindow raised well above the 50 calls this test places in rapid
            // succession - the invite-flood RATE limiter is covered by its own dedicated test above;
            // this one is purely about calls map bookkeeping across many sequential, legitimate calls.
            val config = CallConfig(ringTimeout = Duration.ofSeconds(30), maxInvitesPerWindow = 1_000)
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val transportB = FakeCallSignalTransport(identityB, network)
            val managerA = CallManager.attachToTransport(transportA, FakeCallMediaEngine(), config)
            val managerB = CallManager.attachToTransport(transportB, FakeCallMediaEngine(), config)
            network.register(identityA, managerA)
            network.register(identityB, managerB)

            repeat(50) {
                val callId = managerA.placeCall(identityB)
                awaitCondition { managerB.activeCalls().any { it.callId == callId } }
                managerB.rejectCall(callId, CallEndReason.DECLINED)
                awaitCondition { managerA.activeCalls().isEmpty() }
            }

            managerA.activeCalls() shouldBe emptyList()
            managerB.activeCalls() shouldBe emptyList()
            managerA.stop()
            managerB.stop()
        }

        test("inviteRateLimiters never grows past its LRU cap, even across many distinct senders") {
            // Regression coverage for the MEDIUM review-round finding (2026-09-02): every INVITE -
            // including one from a sender whose call is then silently dropped for being
            // quarantined - registers that sender in CallManager's own inviteRateLimiters map
            // BEFORE the quarantine check ever runs (see handleInboundInvite's own call order). An
            // attacker minting a fresh identity per INVITE used to grow that map without bound for
            // the rest of this process's lifetime; it must now stay capped via LRU eviction.
            val network = FakeCallNetwork()
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            val engineVictim = FakeCallMediaEngine()
            val victim = CallManager.attachToTransport(transportVictim, engineVictim)
            network.register(identityVictim, victim)

            val floodSize = CallManager.MAX_INVITE_RATE_LIMITER_ENTRIES + 100
            repeat(floodSize) {
                val sender = Secp256k1KeyPair.generate().publicKey
                val now = System.currentTimeMillis()
                val invite = CallSignal.invite(CallId.random(random), fakeAudioSdp(), now, now + 60_000)
                // Delivered directly, quarantined=true, exactly like the "a quarantined caller never
                // rings" test below - every one of these is silently dropped, never rings, but each
                // still costs one inviteRateLimiterFor(sender) lookup first.
                victim.onInboundCallSignal(
                    DmInboundCallSignal(sender, CallSignalCodec.encode(invite), true, 0),
                )
            }

            // "== cap", not "<= cap": the map's size climbs monotonically from 0 towards the cap
            // while these floodSize enqueued signals are still draining through the state thread,
            // so "<= cap" would be trivially true from the very first signal onward and prove
            // nothing about whether eviction actually kicked in once the flood finished processing.
            awaitCondition(timeoutMs = 10_000) {
                victim.inviteRateLimiterCountForTesting() == CallManager.MAX_INVITE_RATE_LIMITER_ENTRIES
            }
            victim.inviteRateLimiterCountForTesting() shouldBe CallManager.MAX_INVITE_RATE_LIMITER_ENTRIES

            victim.stop()
        }

        test("a quarantined caller never rings and never receives any reply") {
            val network = FakeCallNetwork()
            val identityCaller = Secp256k1KeyPair.generate().publicKey
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportCaller = FakeCallSignalTransport(identityCaller, network)
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            transportCaller.quarantinedFromSelf = true
            val engineVictim = FakeCallMediaEngine()
            val managerVictim = CallManager.attachToTransport(transportVictim, engineVictim)
            network.register(identityVictim, managerVictim)
            network.register(identityCaller, CallManager.attachToTransport(transportCaller, FakeCallMediaEngine()))

            val events = java.util.concurrent.CopyOnWriteArrayList<CallEvent>()
            managerVictim.addCallListener { events.add(it) }

            val now = System.currentTimeMillis()
            val invite = CallSignal.invite(CallId.random(random), fakeAudioSdp(), now, now + 60_000)
            // Delivered as if it arrived from the caller's own transport with quarantined=true - the
            // shape DmSessionManager.addCallSignalListener would hand CallManager for a sender its
            // own DmAcceptancePolicy already rejected.
            managerVictim.onInboundCallSignal(
                DmInboundCallSignal(identityCaller, CallSignalCodec.encode(invite), true, 0),
            )

            Thread.sleep(300)
            events.filterIsInstance<CallEvent.IncomingCall>().single().quarantined shouldBe true
            // No REJECT/BUSY/anything else was ever sent back to the caller.
            transportVictim.sentSignals shouldBe emptyList()
            // The call was never admitted - it does not actually ring. Pins the exact property
            // CallEvent.IncomingCall.quarantined's own doc comment describes: this IncomingCall is
            // the only event ever emitted for this callId, and there is no ActiveCall behind it.
            managerVictim.activeCalls() shouldBe emptyList()

            managerVictim.stop()
        }

        test("quarantinedCallIds never grows past its LRU cap, even across many distinct callIds") {
            // Regression coverage for the MINOR review-round finding (2026-09-03), mirroring
            // "inviteRateLimiters never grows past its LRU cap" above: quarantinedCallIds records
            // every callId a silently-dropped quarantined INVITE has already been emitted for, so it
            // must stay capped via LRU eviction rather than growing without bound for the lifetime of
            // a long-running node under a sustained flood of distinct callIds.
            val network = FakeCallNetwork()
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            val engineVictim = FakeCallMediaEngine()
            val victim = CallManager.attachToTransport(transportVictim, engineVictim)
            network.register(identityVictim, victim)

            val floodSize = CallManager.MAX_QUARANTINED_CALL_IDS + 100
            repeat(floodSize) {
                val sender = Secp256k1KeyPair.generate().publicKey
                val now = System.currentTimeMillis()
                val invite = CallSignal.invite(CallId.random(random), fakeAudioSdp(), now, now + 60_000)
                victim.onInboundCallSignal(
                    DmInboundCallSignal(sender, CallSignalCodec.encode(invite), true, 0),
                )
            }

            // "== cap", not "<= cap" - same reasoning as the inviteRateLimiters LRU test above.
            awaitCondition(timeoutMs = 10_000) {
                victim.quarantinedCallIdCountForTesting() == CallManager.MAX_QUARANTINED_CALL_IDS
            }
            victim.quarantinedCallIdCountForTesting() shouldBe CallManager.MAX_QUARANTINED_CALL_IDS

            victim.stop()
        }

        test(
            "a retransmitted quarantined INVITE with the same callId emits IncomingCall only once " +
                "(review-fix round, 2026-09-03)",
        ) {
            // Mirrors "a duplicate INVITE with the same callId rings only once" (see
            // CallManagerStateMachineTest), but for the SILENT-DROP branch: that branch never admits
            // signal.callId into `calls`, so handleInboundInvite's own `calls.containsKey` retransmit
            // guard can never catch a repeat here - only the dedicated quarantinedCallIds dedup can.
            // Each of the three deliveries below uses a freshly re-encoded CallSignal (distinct bytes,
            // same callId) to mirror an attacker re-encrypting the identical plaintext under a fresh DM
            // ratchet message - a scenario that produces a distinct DmDedupKey each time and so sails
            // straight past DM-layer dedup, leaving CallManager's own guard as the only one that can
            // still catch it.
            val network = FakeCallNetwork()
            val identityCaller = Secp256k1KeyPair.generate().publicKey
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            val engineVictim = FakeCallMediaEngine()
            val managerVictim = CallManager.attachToTransport(transportVictim, engineVictim)
            network.register(identityVictim, managerVictim)

            val events = java.util.concurrent.CopyOnWriteArrayList<CallEvent>()
            managerVictim.addCallListener { events.add(it) }

            val callId = CallId.random(random)
            val now = System.currentTimeMillis()
            repeat(3) {
                val invite = CallSignal.invite(callId, fakeAudioSdp(), now, now + 60_000)
                managerVictim.onInboundCallSignal(
                    DmInboundCallSignal(identityCaller, CallSignalCodec.encode(invite), true, 0),
                )
            }

            awaitCondition { events.any { it is CallEvent.IncomingCall } }
            Thread.sleep(200)
            events.filterIsInstance<CallEvent.IncomingCall>().size shouldBe 1
            managerVictim.activeCalls() shouldBe emptyList()

            managerVictim.stop()
        }

        test(
            "with autoRejectQuarantined=false, a quarantined caller is still admitted (not silently " +
                "dropped) but reported to the listener as quarantined=true, not false " +
                "(MAJOR review-round finding, 2026-09-02)",
        ) {
            // Before this fix, handleInboundInvite's admission branch hard-coded
            // `quarantined = false` in the emitted CallEvent.IncomingCall regardless of the actual,
            // already-computed [quarantined] parameter - the ONLY way to reach that line with
            // quarantined == true is via config.autoRejectQuarantined == false (the silent-drop branch
            // above it returns early otherwise), so a node operator who opted OUT of auto-rejection to
            // decide for themselves lost the exact signal they need to make that decision.
            val config = CallConfig(autoRejectQuarantined = false)
            val network = FakeCallNetwork()
            val identityCaller = Secp256k1KeyPair.generate().publicKey
            val identityVictim = Secp256k1KeyPair.generate().publicKey
            val transportCaller = FakeCallSignalTransport(identityCaller, network)
            val transportVictim = FakeCallSignalTransport(identityVictim, network)
            transportCaller.quarantinedFromSelf = true
            val managerVictim = CallManager.attachToTransport(transportVictim, FakeCallMediaEngine(), config)
            network.register(identityVictim, managerVictim)
            network.register(identityCaller, CallManager.attachToTransport(transportCaller, FakeCallMediaEngine()))

            val events = java.util.concurrent.CopyOnWriteArrayList<CallEvent>()
            managerVictim.addCallListener { events.add(it) }

            val now = System.currentTimeMillis()
            val invite = CallSignal.invite(CallId.random(random), fakeAudioSdp(), now, now + 60_000)
            managerVictim.onInboundCallSignal(
                DmInboundCallSignal(identityCaller, CallSignalCodec.encode(invite), true, 0),
            )

            awaitCondition { events.any { it is CallEvent.IncomingCall } }
            val incoming = events.filterIsInstance<CallEvent.IncomingCall>().single()
            incoming.quarantined shouldBe true
            // Admitted (unlike the autoRejectQuarantined=true default above) - a real ActiveCall now
            // exists for it, ringing normally, so the operator genuinely can accept/reject it.
            managerVictim.activeCalls().single().callId shouldBe incoming.callId

            managerVictim.stop()
        }

        test(
            "outgoing placeCall past MAX_TRACKED_CALLS is rejected with BUSY too, not just inbound " +
                "INVITE (MINOR review-round finding, 2026-09-02)",
        ) {
            // maxConcurrentCalls set comfortably above MAX_TRACKED_CALLS so the ordinary BUSY/
            // maxConcurrentCalls check never fires first - isolating this ceiling specifically. Before
            // this fix, MAX_TRACKED_CALLS was enforced only in handleInboundInvite, contradicting that
            // constant's own doc comment ("independent of CallConfig.maxConcurrentCalls").
            val config = CallConfig(maxConcurrentCalls = CallManager.MAX_TRACKED_CALLS * 2)
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val managerA = CallManager.attachToTransport(transportA, FakeCallMediaEngine(), config)
            network.register(identityA, managerA)

            val events = java.util.concurrent.CopyOnWriteArrayList<CallEvent>()
            managerA.addCallListener { events.add(it) }

            // Every callee identity is distinct and never registered on the network, so none of these
            // calls ever completes/ends on its own - they simply accumulate in `calls` up to the
            // ceiling.
            repeat(CallManager.MAX_TRACKED_CALLS) {
                managerA.placeCall(Secp256k1KeyPair.generate().publicKey)
            }
            awaitCondition { managerA.activeCalls().size == CallManager.MAX_TRACKED_CALLS }

            val overflowCallId = managerA.placeCall(Secp256k1KeyPair.generate().publicKey)
            awaitCondition { events.filterIsInstance<CallEvent.Ended>().any { it.callId == overflowCallId } }
            events
                .filterIsInstance<CallEvent.Ended>()
                .single { it.callId == overflowCallId }
                .reason shouldBe CallEndReason.BUSY
            managerA.activeCalls().size shouldBe CallManager.MAX_TRACKED_CALLS

            managerA.stop()
        }
    })
