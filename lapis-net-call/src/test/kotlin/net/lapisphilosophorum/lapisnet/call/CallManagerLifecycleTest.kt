package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * V0.8.7 review-fix regression coverage: [CallManager.stop]'s idempotency contract, the
 * orphaned-media-session leak that a `hangUp`/`rejectCall` racing a still-in-flight
 * [CallMediaEngine.newSession] used to cause - see [CallManager.attachMediaSessionOrCloseIfEnded]'s
 * own doc comment for the full mechanism this second test exercises - and the analogous leak a media-
 * setup task still queued behind a slow send used to cause once [CallManager.stop] itself started
 * running (fourth test, see [CallManager.executeOnStateThreadIfRunning]'s own doc comment). The last
 * three tests cover the mirror-image direction - a state-thread task handing off to [mediaExecutor]/
 * `scheduler` instead of the other way around - see [CallManager.executeOnMediaThreadIfRunning]'s own
 * doc comment for that finding's full mechanism.
 */
class CallManagerLifecycleTest :
    FunSpec({
        test("stop() is idempotent - a second (and third) call never throws") {
            val network = FakeCallNetwork()
            val identity = Secp256k1KeyPair.generate().publicKey
            val transport = FakeCallSignalTransport(identity, network)
            val manager = CallManager.attachToTransport(transport, FakeCallMediaEngine())
            network.register(identity, manager)

            manager.stop()
            // Must not throw RejectedExecutionException (or anything else) - see CallManager.stop's
            // own doc comment: "Safe to call more than once; this manager is not usable again
            // afterward." Before this fix, this second call threw RejectedExecutionException because
            // the first call's stateExecutor.shutdownNow() had already run.
            manager.stop()
            manager.stop()
        }

        test(
            "hangUp racing a still-in-flight newSession() does not leak the media session it eventually returns",
        ) {
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            // Simulates mediaEngine.newSession(...) still being mid-flight (a real
            // WebRtcCallMediaEngine spends real wall-clock time here) when the local user hangs up
            // before it ever returns.
            val newSessionGate = CountDownLatch(1)
            engineA.blockNewSessionUntil = newSessionGate

            val callId = managerA.placeCall(identityB)
            // placeCall()'s own admission (adding callId to the tracked-calls map) and this hangUp()
            // are both merely ENQUEUED onto the same single-threaded stateExecutor, in that order -
            // its FIFO ordering (not any sleep here) is what guarantees the call is admitted, then
            // ended, in exactly that order, regardless of how long newSession() blocks on the media
            // thread meanwhile.
            managerA.hangUp(callId)
            awaitCondition { managerA.activeCalls().isEmpty() }

            // Only now does the in-flight newSession() call return the fake session -
            // runOutgoingMediaSetup then tries to attach it to a call that no longer exists.
            newSessionGate.countDown()

            awaitCondition { engineA.sessions.isNotEmpty() }
            val session = engineA.sessions.single()
            // Before this fix: calls[callId]?.mediaSession = session was a silent no-op (calls[callId]
            // was already null) - the session was recorded nowhere and closeQuietly() was never
            // called on it, leaking it (a real WebRtcCallMediaSession: an RTCPeerConnection plus its
            // audio source/track and bound UDP port) for the rest of the process's lifetime.
            awaitCondition { session.closed.get() }

            managerA.stop()
        }

        test(
            "stop() lets a queued session close behind a slow in-flight send finish before " +
                "force-closing the media executor",
        ) {
            // Regression coverage for the MAJOR review-round finding (2026-09-02): stop() used to
            // call mediaExecutor.shutdownNow() unconditionally, which DISCARDS a still-queued
            // session.closeQuietly() task if the media thread happens to be blocked inside a slow
            // transport.send at that moment - see CallManager.stop's own doc comment on its
            // mediaExecutor shutdown ordering for the full mechanism.
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            // Set BEFORE placeCall() so there is no race between the test thread setting this field
            // and the media thread reading it: the very first send this manager ever makes (the
            // outgoing INVITE, at the tail of runOutgoingMediaSetup, after the session has already
            // been created and attached) blocks on it too - harmless here since identityB is never
            // registered with the network, so nothing depends on that INVITE actually arriving.
            val releaseSend = CountDownLatch(1)
            transportA.blockSendUntil = releaseSend

            val callId = managerA.placeCall(identityB)
            awaitCondition { engineA.sessions.isNotEmpty() }
            val session = engineA.sessions.single()

            // hangUp() enqueues its own HANGUP send, then (synchronously right after, on the state
            // thread) the session's own close - both queued behind the still-blocked INVITE send
            // above, in that order, on the single-threaded media executor. Mirrors a real
            // DmCallSignalTransport.send blocking for up to DmSessionManager.DIAL_TIMEOUT.
            managerA.hangUp(callId)
            awaitCondition { managerA.activeCalls().isEmpty() }

            // Released well within CallManager's own MEDIA_SHUTDOWN_TIMEOUT bound, simulating the
            // send eventually completing rather than hanging forever.
            Thread {
                Thread.sleep(200)
                releaseSend.countDown()
            }.start()

            managerA.stop()

            // Before this fix: stop()'s unconditional mediaExecutor.shutdownNow() would have
            // discarded the queued session.closeQuietly() task the instant it ran (well before the
            // 200ms release above), leaving this false and the session's native resources leaked
            // out from under the immediately-following mediaEngine.close().
            session.closed.get() shouldBe true
        }

        test(
            "a second call's media-setup task, still queued behind the first call's slow send when " +
                "stop() runs, does not leak the session it creates once stateExecutor is already shut down",
        ) {
            // Regression coverage for the MAJOR review-round finding this same wave's PREVIOUS fix
            // (the "queued session close" test just above) itself introduced: stop() shuts
            // stateExecutor down (shutdownNow()) strictly BEFORE it drains mediaExecutor - required
            // for that other fix's own ordering guarantee. A second call's runOutgoingMediaSetup,
            // still sitting in mediaExecutor's queue behind the first call's blocked transport.send
            // when stop() runs, therefore only starts running AFTER stateExecutor has already
            // terminated - its own "attach this session back onto the state thread" submission used
            // to throw an uncaught RejectedExecutionException straight out of the media thread,
            // abandoning the session mediaEngine.newSession() had just created (never closed, never
            // recorded on any ActiveCall) - see CallManager.executeOnStateThreadIfRunning's own doc
            // comment for the mechanism that fix closed. A LATER finding (2026-09-02, part (b) of the
            // "state -> media/scheduler hand-offs" MINOR) closed this same window even more tightly:
            // runOutgoingMediaSetup now checks CallManager's own `stopped` flag before ever calling
            // mediaEngine.newSession() at all - see that check's own doc comment - so this second
            // call's session is no longer created-then-abandoned, it is simply never created.
            val config = CallConfig(maxConcurrentCalls = 2)
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA, config)
            network.register(identityA, managerA)

            // Blocks EVERY send on managerA's single-threaded media executor - in particular the
            // first call's own outgoing INVITE send, which is what keeps the second call's
            // runOutgoingMediaSetup queued behind it instead of running immediately.
            val releaseSend = CountDownLatch(1)
            transportA.blockSendUntil = releaseSend

            managerA.placeCall(identityB)
            awaitCondition { engineA.sessions.size == 1 }

            // Admitted into `calls` (maxConcurrentCalls = 2 allows a second concurrent call) - its
            // own runOutgoingMediaSetup is merely QUEUED behind the first call's still-blocked send,
            // not yet running, and so has not called mediaEngine.newSession() yet either.
            managerA.placeCall(identityB)
            awaitCondition { managerA.activeCalls().size == 2 }

            // Released from a background thread WHILE stop() (below) is synchronously blocked
            // awaiting mediaExecutor's graceful drain - mirrors the previous test's own release
            // timing, well within CallManager's MEDIA_SHUTDOWN_TIMEOUT bound.
            Thread {
                Thread.sleep(200)
                releaseSend.countDown()
            }.start()

            managerA.stop()

            // Before the original MAJOR fix: the second call's session was created (added to
            // engineA.sessions) but then abandoned mid-setup by the uncaught
            // RejectedExecutionException. Before the LATER `stopped`-check fix: the session WAS
            // created and closed cleanly by then (attach failing gracefully via
            // executeOnStateThreadIfRunning), so engineA.sessions grew to 2 either way. With the
            // `stopped` check in place, the second call's runOutgoingMediaSetup returns before ever
            // calling mediaEngine.newSession() - engineA.sessions never grows past the first call's
            // own session at all.
            engineA.sessions shouldHaveSize 1
        }

        test(
            "an attach task queued behind a slow listener when stop() gives up waiting is still " +
                "closed via the liveMediaSessions safety-net sweep, even though " +
                "stateExecutor.shutdownNow() discards the still-queued attach task itself",
        ) {
            // Regression coverage for the MAJOR review-round finding (2026-09-02):
            // executeOnStateThreadIfRunning only closes a session whose stateExecutor hand-off was
            // REJECTED (the executor already terminated at submission time) - it does nothing for one
            // that was ACCEPTED (successfully enqueued while the state thread was merely busy, not yet
            // shut down) but then DISCARDED, still unexecuted, by stop()'s own
            // stateExecutor.shutdownNow(). Reproduced here exactly like the review round's own probe: a
            // listener blocks the state thread for the WHOLE duration of stop()'s own QUERY_TIMEOUT
            // snapshot wait, so the attach task submitted while it was blocked is guaranteed to still be
            // sitting - queued, never started - in stateExecutor's queue at the moment shutdownNow()
            // drains it. See CallManager.liveMediaSessions's own doc comment for the fix this asserts.
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            // Blocks mediaEngine.newSession() so this call's own media setup does not even create a
            // session until released below - well AFTER the state thread is already stuck.
            val newSessionGate = CountDownLatch(1)
            engineA.blockNewSessionUntil = newSessionGate

            // Blocks the STATE thread itself - inside the listener callback emit() invokes
            // synchronously for CallEvent.Ended, mirroring stop()'s own "the state thread is stuck
            // behind a slow listener" scenario exactly. The 30s bound is purely a safety net against
            // this test hanging the whole suite if the fix ever regresses - well past every timeout
            // (QUERY_TIMEOUT, ~5s) this test itself relies on; the real unblock, on a passing run,
            // comes from stateExecutor.shutdownNow()'s own interrupt() of the running worker.
            val listenerEntered = CountDownLatch(1)
            val listenerGate = CountDownLatch(1)
            managerA.addCallListener { event ->
                if (event is CallEvent.Ended) {
                    listenerEntered.countDown()
                    try {
                        listenerGate.await(30, TimeUnit.SECONDS)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                }
            }

            val callId = managerA.placeCall(identityB)
            // hangUp()'s own endCallOnStateThread removes the call and emits CallEvent.Ended BEFORE
            // mediaEngine.newSession() below has even been called - what gets the state thread stuck is
            // this emission's listener callback, entirely independent of the still-blocked media-setup
            // task sitting on the media thread meanwhile.
            managerA.hangUp(callId)
            listenerEntered.await(2, TimeUnit.SECONDS) shouldBe true

            // Only now does newSession() return - runOutgoingMediaSetup registers the session (this
            // fix) and submits its attach action onto stateExecutor. The submission SUCCEEDS (the
            // executor is merely busy, not yet shut down) and the task is queued BEHIND the
            // still-blocked listener above; it cannot run while that listener keeps blocking.
            newSessionGate.countDown()
            awaitCondition { engineA.sessions.isNotEmpty() }
            val session = engineA.sessions.single()
            // Lets runOutgoingMediaSetup's own createOffer()/transport.send() calls (both fast,
            // non-blocking fakes, running on the media thread independently of the stuck state thread)
            // finish and submit the attach action, before stop() below races it.
            Thread.sleep(300)

            // stop()'s own snapshot task is queued behind both the still-blocked listener and the
            // attach task above; snapshot.get() blocks for the full QUERY_TIMEOUT (~5s) before giving
            // up, at which point stateExecutor.shutdownNow() discards the still-queued (never started)
            // attach task - reproducing the exact race this fix closes.
            managerA.stop()

            // Before this fix: the attach task was discarded, attachMediaSessionOrCloseIfEnded never
            // ran, and this session was neither attached to any ActiveCall NOR closed by anything else
            // - leaked for the remainder of the process's lifetime. The liveMediaSessions safety-net
            // sweep (queued as stop()'s own last mediaExecutor task) closes it regardless.
            session.closed.get() shouldBe true
            managerA.liveMediaSessionCountForTesting() shouldBe 0

            listenerGate.countDown()
        }

        test("onMediaConnected/onMediaFailed arriving after stop() do not throw an uncaught exception") {
            // Regression coverage for the MEDIUM review-round finding (2026-09-02): unlike every other
            // stateExecutor hand-off in CallManager, mediaObserverFor's two callbacks are invoked
            // directly from mediaEngine's OWN thread (for the real WebRtcCallMediaEngine, libwebrtc's
            // native signaling thread, from inside a JNI callback) - a bare stateExecutor.execute(...)
            // there used to throw an uncaught RejectedExecutionException straight back into that
            // caller once stop() had shut stateExecutor down, which for the real engine is undefined
            // behavior for the JNI bridge, not just a log line.
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            managerA.placeCall(identityB)
            awaitCondition { engineA.sessions.isNotEmpty() }
            val observer = engineA.sessions.single().observer

            managerA.stop()

            // Before this fix, either of these threw RejectedExecutionException straight out of this
            // call - exactly as it would have out of a real native callback thread - failing this test.
            observer.onMediaConnected()
            observer.onMediaFailed("simulated failure arriving after stop()")
        }

        test("stop() closes a session's media on the media thread, never on stop()'s own caller thread") {
            // Regression coverage for a review-round MINOR finding (2026-09-02): the round-3 fix that
            // moved this close off stop()'s own caller thread and onto mediaExecutor (see
            // CallManager.stop's own doc comment on that ordering) shipped with no dedicated test of
            // its own - only the four scenarios above, none of which assert WHICH thread actually
            // called CallMediaSession.close().
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            managerA.placeCall(identityB)
            awaitCondition { engineA.sessions.isNotEmpty() }
            val session = engineA.sessions.single()

            managerA.stop()

            session.closed.get() shouldBe true
            session.closedOnThread shouldBe "lapis-net-call-media"
        }

        test(
            "a state-thread task still mid-execution when stop() has already shut every other " +
                "executor down does not kill the state thread on its own hand-off to mediaExecutor",
        ) {
            // Regression coverage for the MINOR review-round finding (2026-09-02, "state -> media/
            // scheduler hand-offs, in der Gegenrichtung"): every OTHER stateExecutor hand-off in this
            // class was already guarded (executeOnStateThreadIfRunning) for the media/scheduler-thread
            // -> stateExecutor direction, but the reverse - stateExecutor -> mediaExecutor/scheduler -
            // was entirely unguarded. Reproduced exactly like the finding's own probe: a listener
            // blocks INSIDE emit() for CallEvent.OutgoingRinging - placeCallOnStateThread's own
            // mediaExecutor hand-off (this test's target) sits right after that emit() call, so it
            // cannot run until the listener releases, by which point stop() has already shut
            // mediaExecutor down too (its own queue was empty, so its graceful shutdown()+
            // awaitTermination() finishes almost immediately).
            val uncaught = CopyOnWriteArrayList<Throwable>()
            val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
                if (thread.name.startsWith("lapis-net-call-")) {
                    uncaught.add(throwable)
                } else {
                    previousHandler?.uncaughtException(thread, throwable)
                }
            }
            try {
                val network = FakeCallNetwork()
                val identityA = Secp256k1KeyPair.generate().publicKey
                val identityB = Secp256k1KeyPair.generate().publicKey
                val transportA = FakeCallSignalTransport(identityA, network)
                val engineA = FakeCallMediaEngine()
                val managerA = CallManager.attachToTransport(transportA, engineA)
                network.register(identityA, managerA)

                val listenerEntered = CountDownLatch(1)
                val listenerGate = CountDownLatch(1)
                managerA.addCallListener { event ->
                    if (event is CallEvent.OutgoingRinging) {
                        listenerEntered.countDown()
                        try {
                            // Ignoring the interrupt deliberately - mirrors real, non-interruptible
                            // work (file I/O, a slow logger, a UI dialog) that swallows stop()'s own
                            // shutdownNow() interrupt rather than reacting to it, exactly like the
                            // review round's own probe.
                            listenerGate.await(30, TimeUnit.SECONDS)
                        } catch (e: InterruptedException) {
                            Thread.currentThread().interrupt()
                        }
                    }
                }

                managerA.placeCall(identityB)
                listenerEntered.await(2, TimeUnit.SECONDS) shouldBe true

                // stop()'s own snapshot task is queued behind the still-blocked listener; its
                // QUERY_TIMEOUT (~5s) wait gives up, and every executor - mediaExecutor included, via
                // its own graceful shutdown()+awaitTermination(), near-instant here since nothing else
                // is queued on it - is shut down while the listener keeps blocking.
                managerA.stop()

                // Only now does the listener return - placeCallOnStateThread resumes on the
                // already-interrupted, already-torn-down state thread and reaches its own
                // executeOnMediaThreadIfRunning call with mediaExecutor already terminated. Before
                // this fix, the bare mediaExecutor.execute(...) there threw an uncaught
                // RejectedExecutionException straight out of lapis-net-call-state.
                listenerGate.countDown()
                Thread.sleep(300)

                uncaught shouldHaveSize 0
            } finally {
                Thread.setDefaultUncaughtExceptionHandler(previousHandler)
            }
        }

        test(
            "a connect-timeout scheduling call that only resumes after stop() has already shut " +
                "the scheduler down does not throw an uncaught exception (scheduleOnTimerIfRunning " +
                "guard, scheduling-call-site half)",
        ) {
            // Regression coverage for a round-4 MINOR guard (2026-09-02: scheduleTimeout's own
            // scheduler.schedule(...) call wrapped in scheduleOnTimerIfRunning) - and, per the round-6
            // finding on THIS test's own predecessor ("a ring timeout that only fires after stop() has
            // shut every executor down..."), empirically verified to never actually reach that guard
            // (a temporary probe replacing it with a raw call plus a counter fired zero times across
            // the whole suite): scheduler.shutdownNow() cancels a not-yet-due ring timeout outright, so
            // "stop() before the timeout fires" - what the predecessor test did - can never race
            // anything. This version blocks the STATE thread itself (via a listener stuck in
            // emit(CallEvent.Connecting), the exact call site scheduleTimeout(config.connectTimeout)
            // sits right behind in both acceptCallOnStateThread and handleInboundAccept - here reached
            // via handleInboundAccept) so that when it resumes, [stop] is GUARANTEED to have already
            // run scheduler.shutdownNow() - deterministic, no timing luck required.
            val uncaught = CopyOnWriteArrayList<Throwable>()
            val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
                if (thread.name.startsWith("lapis-net-call-")) {
                    uncaught.add(throwable)
                } else {
                    previousHandler?.uncaughtException(thread, throwable)
                }
            }
            try {
                val network = FakeCallNetwork()
                val identityA = Secp256k1KeyPair.generate().publicKey
                val identityB = Secp256k1KeyPair.generate().publicKey
                val transportA = FakeCallSignalTransport(identityA, network)
                val engineA = FakeCallMediaEngine()
                val managerA = CallManager.attachToTransport(transportA, engineA)
                network.register(identityA, managerA)

                val listenerEntered = CountDownLatch(1)
                val listenerGate = CountDownLatch(1)
                managerA.addCallListener { event ->
                    if (event is CallEvent.Connecting) {
                        listenerEntered.countDown()
                        // Ignoring the interrupt deliberately, same as every sibling test's identical
                        // pattern - mirrors real, non-interruptible work swallowing stop()'s own
                        // shutdownNow() interrupt rather than reacting to it.
                        try {
                            listenerGate.await(30, TimeUnit.SECONDS)
                        } catch (e: InterruptedException) {
                            Thread.currentThread().interrupt()
                        }
                    }
                }

                // Blocks the outgoing INVITE send - attach happens BEFORE createOffer/this send in
                // runOutgoingMediaSetup, so the call still reaches OUTGOING_RINGING with a live,
                // attached session despite the send itself never completing until released below.
                val releaseSend = CountDownLatch(1)
                transportA.blockSendUntil = releaseSend

                val callId = managerA.placeCall(identityB)
                awaitCondition { engineA.sessions.isNotEmpty() }

                // Injects the ACCEPT directly - handleInboundAccept runs on managerA's still-live
                // state thread, emits CallEvent.Connecting (blocking in the listener above) BEFORE
                // its own scheduleTimeout(config.connectTimeout) call ever runs.
                val now = System.currentTimeMillis()
                val acceptSignal = CallSignal.accept(callId, fakeAudioSdp(), now, now + 60_000)
                managerA.onInboundCallSignal(
                    DmInboundCallSignal(identityB, CallSignalCodec.encode(acceptSignal), false, now / 1000),
                )
                listenerEntered.await(2, TimeUnit.SECONDS) shouldBe true

                // stop()'s own snapshot task is queued behind the still-blocked listener; its
                // QUERY_TIMEOUT (~5s) wait gives up, and scheduler.shutdownNow() + stateExecutor
                // .shutdownNow() both run - interrupting the listener, which gives up per the pattern
                // above - well before this call returns.
                managerA.stop()

                // Only now does the listener return - handleInboundAccept resumes on the
                // already-torn-down state thread and reaches its own scheduleTimeout(connectTimeout)
                // call, whose scheduler.schedule(...) is guaranteed to be rejected (scheduler was
                // already shut down by the completed stop() call above). Before the round-4 fix, this
                // threw an uncaught RejectedExecutionException straight out of lapis-net-call-state.
                listenerGate.countDown()
                Thread.sleep(300)

                uncaught shouldHaveSize 0
            } finally {
                Thread.setDefaultUncaughtExceptionHandler(previousHandler)
            }
        }

        test(
            "a scheduled timeout callback that only reaches its stateExecutor hand-off after stop() " +
                "has already shut every executor down is rejected without throwing " +
                "(executeOnStateThreadIfRunning guard, scheduler-callback half)",
        ) {
            // Regression coverage for the SAME round-4 MINOR guard's other half - the scheduled
            // callback's own hand-off back onto stateExecutor via executeOnStateThreadIfRunning - and
            // for the round-6 finding that the predecessor test covering both halves never actually
            // exercised either one. Unlike the scheduling-call-site guard above, this half cannot be
            // pinned deterministically through real wall-clock timing at all: scheduler.shutdownNow()
            // and stateExecutor.shutdownNow() run back to back inside stop(), so the window in which a
            // fired timeout's callback could still be executing (already dequeued, ignoring the
            // scheduler's own shutdown) while stateExecutor has ALREADY terminated is nanoseconds
            // wide - not something any amount of Duration/sleep tuning can guarantee. This uses
            // CallManager.scheduleGuardedTimeoutHandoffForTesting (see its own doc comment) to pin
            // that moment directly: the scheduler thread blocks on a latch this test only releases
            // once it has independently confirmed - by stop() having already returned - that
            // stateExecutor is guaranteed to be terminated.
            val uncaught = CopyOnWriteArrayList<Throwable>()
            val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
                if (thread.name.startsWith("lapis-net-call-")) {
                    uncaught.add(throwable)
                } else {
                    previousHandler?.uncaughtException(thread, throwable)
                }
            }
            try {
                val network = FakeCallNetwork()
                val identityA = Secp256k1KeyPair.generate().publicKey
                val identityB = Secp256k1KeyPair.generate().publicKey
                val transportA = FakeCallSignalTransport(identityA, network)
                val engineA = FakeCallMediaEngine()
                val managerA = CallManager.attachToTransport(transportA, engineA)
                network.register(identityA, managerA)

                val handoffAttempted = CountDownLatch(1)
                val releaseHandoff = CountDownLatch(1)
                val result = CompletableFuture<Boolean>()
                managerA.scheduleGuardedTimeoutHandoffForTesting(Duration.ofMillis(10), result) {
                    handoffAttempted.countDown()
                    // Loops rather than giving up on the first interrupt (unlike every OTHER blocked-
                    // listener test in this file): stop() below interrupts this very thread as part of
                    // its own scheduler.shutdownNow(), but the whole point of this test is to attempt
                    // the hand-off strictly AFTER stop() has fully RETURNED, not the instant it merely
                    // starts tearing down - giving up here like those other tests do would let the
                    // hand-off race stop()'s own remaining teardown steps, reintroducing exactly the
                    // nanosecond-wide, non-deterministic window this hook exists to avoid.
                    // Thread.interrupted() (not currentThread().interrupt()) clears the interrupt
                    // status so the next await() call actually blocks instead of throwing immediately.
                    val deadlineMillis = System.currentTimeMillis() + 30_000
                    var released = false
                    while (!released && System.currentTimeMillis() < deadlineMillis) {
                        val remainingMillis = deadlineMillis - System.currentTimeMillis()
                        try {
                            released = releaseHandoff.await(remainingMillis, TimeUnit.MILLISECONDS)
                        } catch (e: InterruptedException) {
                            Thread.interrupted()
                        }
                    }
                }
                handoffAttempted.await(2, TimeUnit.SECONDS) shouldBe true

                // No active calls exist, so stop()'s own snapshot resolves immediately; it proceeds
                // through scheduler.shutdownNow() (interrupting the blocked scheduler thread above,
                // ignored per the retry loop) and stateExecutor.shutdownNow(), then returns - by
                // which point stateExecutor is unconditionally terminated.
                managerA.stop()

                // Only now released - the scheduler thread's hand-off attempt below is therefore
                // guaranteed to run against an already-terminated stateExecutor.
                releaseHandoff.countDown()

                // Before the round-4 fix: a bare stateExecutor.execute(...) here threw an uncaught
                // RejectedExecutionException straight out of the scheduler thread. The guard instead
                // catches it and completes [result] with `false`.
                result.get(2, TimeUnit.SECONDS) shouldBe false
                uncaught shouldHaveSize 0
            } finally {
                Thread.setDefaultUncaughtExceptionHandler(previousHandler)
            }
        }

        test(
            "an ACCEPT's applyAnswer failure whose own state-ending fallback only runs once stop() " +
                "has already shut stateExecutor down does not throw an uncaught exception",
        ) {
            // Regression coverage for a round-4 MINOR guard (2026-09-02: handleInboundAccept's own
            // applyAnswer-failure fallback via executeOnStateThreadIfRunning) that shipped with no
            // dedicated test of its own.
            val uncaught = CopyOnWriteArrayList<Throwable>()
            val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
                if (thread.name.startsWith("lapis-net-call-")) {
                    uncaught.add(throwable)
                } else {
                    previousHandler?.uncaughtException(thread, throwable)
                }
            }
            try {
                val network = FakeCallNetwork()
                val identityA = Secp256k1KeyPair.generate().publicKey
                val identityB = Secp256k1KeyPair.generate().publicKey
                val transportA = FakeCallSignalTransport(identityA, network)
                val engineA = FakeCallMediaEngine()
                engineA.configureSession = { it.failApplyAnswer = true }
                val managerA = CallManager.attachToTransport(transportA, engineA)
                network.register(identityA, managerA)

                // Blocks the outgoing INVITE send - attach happens BEFORE createOffer/this send in
                // runOutgoingMediaSetup, so the call still reaches OUTGOING_RINGING with a live,
                // attached session despite the send itself never completing until released below.
                val releaseSend = CountDownLatch(1)
                transportA.blockSendUntil = releaseSend

                val callId = managerA.placeCall(identityB)
                awaitCondition { engineA.sessions.isNotEmpty() }
                val session = engineA.sessions.single()

                // Injects the ACCEPT directly - no real identityB manager needed.
                // handleInboundAccept runs on managerA's still-live state thread, finds the
                // already-attached session, and submits its own applyAnswer task onto mediaExecutor -
                // accepted (mediaExecutor is merely busy with the still-blocked INVITE send above, not
                // yet shut down), so it queues up BEHIND that send.
                val now = System.currentTimeMillis()
                val acceptSignal = CallSignal.accept(callId, fakeAudioSdp(), now, now + 60_000)
                managerA.onInboundCallSignal(
                    DmInboundCallSignal(identityB, CallSignalCodec.encode(acceptSignal), false, now / 1000),
                )
                awaitCondition { managerA.activeCalls().singleOrNull()?.state == CallState.CONNECTING }

                // Released from a background thread WHILE stop() (below) is synchronously blocked
                // awaiting mediaExecutor's graceful drain - by the time the INVITE send (and, right
                // behind it, the applyAnswer task) actually run, stop() has already shut stateExecutor
                // down (scheduler.shutdownNow() and stateExecutor.shutdownNow() both run well before
                // mediaExecutor.shutdown()'s own awaitTermination starts blocking on this release).
                Thread {
                    Thread.sleep(200)
                    releaseSend.countDown()
                }.start()

                managerA.stop()

                // Before the round-4 fix this test covers: the applyAnswer task's own fallback threw
                // an uncaught RejectedExecutionException straight out of the media thread at this
                // point.
                session.closed.get() shouldBe true
                uncaught shouldHaveSize 0
            } finally {
                Thread.setDefaultUncaughtExceptionHandler(previousHandler)
            }
        }

        test(
            "a media-session close whose stateExecutor -> mediaExecutor hand-off is rejected after " +
                "stop() is never leaked and never closed anywhere but the media thread (round-6 " +
                "MAJOR fix: inline close-on-rejection fallbacks removed from endCallOnStateThread " +
                "and handleInboundAccept)",
        ) {
            // Regression coverage for the MAJOR review-round finding (2026-09-02, round 6):
            // endCallOnStateThread and handleInboundAccept each used to fall back to an inline
            // `closeAndUntrack(session)` call, right there on the state thread, whenever their own
            // `executeOnMediaThreadIfRunning` submission was rejected - reasoning that a rejection
            // proved nothing else could be concurrently touching the session. That reasoning was
            // wrong: stop()'s own mediaExecutor.shutdown() is deliberately GRACEFUL (see stop()'s own
            // doc comment on that ordering), so a rejection there only proves mediaExecutor has
            // stopped accepting NEW work - not that every task already queued or executing on it
            // (in particular stop()'s own liveMediaSessions safety-net sweep, enqueued strictly
            // before that shutdown() call) has finished. Closing inline raced that work directly on
            // the same session - empirically reproduced as a native double-free (see
            // WebRtcCallMediaSession.close's own doc comment) that can crash the whole JVM. The fix
            // removes both fallbacks outright, relying on the safety-net sweep alone.
            //
            // Both call sites share the identical `executeOnMediaThreadIfRunning { closeAndUntrack
            // (session) }` shape post-fix (handleInboundAccept's own applyAnswer-failure path reaches
            // the very same closeAndUntrack too - see that function's own doc comment), and pinning
            // the exact moment either one's submission is attempted relative to stop()'s
            // mediaExecutor.shutdown() cannot be done through real wall-clock timing alone (the
            // reachable window is wide - mediaExecutor.shutdown() rejects immediately, before its own
            // up-to-MEDIA_SHUTDOWN_TIMEOUT drain even starts - but nothing observable marks the exact
            // instant it happens without a hook). This exercises the shared mechanism directly via
            // CallManager.scheduleGuardedMediaCloseForTesting (see its own doc comment).
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            managerA.placeCall(identityB)
            awaitCondition { engineA.sessions.isNotEmpty() }
            val session = engineA.sessions.single()

            val handoffAttempted = CountDownLatch(1)
            val releaseHandoff = CountDownLatch(1)
            val result = CompletableFuture<Boolean>()
            managerA.scheduleGuardedMediaCloseForTesting(session, result) {
                handoffAttempted.countDown()
                // Loops rather than giving up on the first interrupt - see the identical pattern (and
                // rationale) in the scheduleGuardedTimeoutHandoffForTesting-based test above.
                val deadlineMillis = System.currentTimeMillis() + 30_000
                var released = false
                while (!released && System.currentTimeMillis() < deadlineMillis) {
                    val remainingMillis = deadlineMillis - System.currentTimeMillis()
                    try {
                        released = releaseHandoff.await(remainingMillis, TimeUnit.MILLISECONDS)
                    } catch (e: InterruptedException) {
                        Thread.interrupted()
                    }
                }
            }
            handoffAttempted.await(2, TimeUnit.SECONDS) shouldBe true

            // stop() closes nothing for this call via its own toClose loop (the call was never ended
            // and is still tracked), but its liveMediaSessions safety-net sweep - enqueued on
            // mediaExecutor strictly before mediaExecutor.shutdown() - is queued regardless and is
            // what this test relies on to eventually close [session].
            managerA.stop()

            // Only now released - the state thread's hand-off attempt is therefore guaranteed to run
            // against an already-shutdown mediaExecutor, exercising the exact rejection branch the
            // removed fallbacks used to mishandle.
            releaseHandoff.countDown()

            result.get(2, TimeUnit.SECONDS) shouldBe false
            // Before the round-6 fix: the old inline fallback would have closed [session] itself,
            // right here on the state thread, racing stop()'s own safety-net sweep (already running
            // or about to run on the media thread) closing the SAME session concurrently - the
            // empirically-reproduced native double-free. The fix leaves it un-closed at this call
            // site entirely; the sweep is the only closer, so this must always land on the media
            // thread, and the session must never end up leaked.
            awaitCondition { session.closed.get() }
            session.closedOnThread shouldBe "lapis-net-call-media"
            managerA.liveMediaSessionCountForTesting() shouldBe 0
        }

        test(
            "every public entry point stays a safe no-op after stop() - never throws " +
                "RejectedExecutionException (MEDIUM review-round finding, 2026-09-02)",
        ) {
            // placeCall/acceptCall/rejectCall/hangUp each submitted to stateExecutor unguarded, unlike
            // every OTHER stateExecutor.execute call site in this class - after stop() has already run
            // stateExecutor.shutdownNow(), every one of them used to throw RejectedExecutionException
            // straight out of a public API method, contradicting acceptCall's own doc comment ("a
            // no-op (logged, not thrown)... mirrors DmSessionManager's own public-data-rejection, never
            // a crash discipline") and activeCalls()/stop()'s own identical "safe to call during
            // shutdown" contract. onInboundCallSignal had the same gap, invoked directly from a Netty
            // callback in production - this class's own doc comment already promises it "must never
            // let anything escape" (see CallManagerAbuseTest's own assertion of that exact contract).
            // All five are now guarded via executeOnStateThreadIfRunning, exactly like every other
            // hand-off in this class.
            val network = FakeCallNetwork()
            val identityA = Secp256k1KeyPair.generate().publicKey
            val identityB = Secp256k1KeyPair.generate().publicKey
            val transportA = FakeCallSignalTransport(identityA, network)
            val engineA = FakeCallMediaEngine()
            val managerA = CallManager.attachToTransport(transportA, engineA)
            network.register(identityA, managerA)

            managerA.stop()

            val callId = managerA.placeCall(identityB)
            managerA.acceptCall(callId)
            managerA.rejectCall(callId)
            managerA.hangUp(callId)
            val now = System.currentTimeMillis()
            managerA.onInboundCallSignal(
                DmInboundCallSignal(
                    identityB,
                    CallSignalCodec.encode(CallSignal.invite(callId, fakeAudioSdp(), now, now + 60_000)),
                    false,
                    now / 1000,
                ),
            )

            // Nothing above threw - and, being genuinely post-stop(), none of it was ever admitted
            // into calls() either.
            managerA.activeCalls().isEmpty() shouldBe true
        }
    })
