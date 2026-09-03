package net.lapisphilosophorum.lapisnet.call

import net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/** A structurally CallSdpPolicy-valid, host-only audio SDP - what every `FakeCallMediaSession`
 * returns from `createOffer`/`acceptOfferAndCreateAnswer`, so `CallManagerStateMachineTest`/
 * `CallManagerAbuseTest` exercise the REAL `CallSdpPolicy.validateRemote` call `CallManager` makes on
 * every inbound INVITE/ACCEPT, not a shortcut around it. */
internal fun fakeAudioSdp(): String =
    "v=0\r\n" +
        "o=- 1 1 IN IP4 192.168.1.5\r\n" +
        "s=-\r\n" +
        "t=0 0\r\n" +
        "m=audio 54321 UDP/TLS/RTP/SAVPF 111\r\n" +
        "c=IN IP4 192.168.1.5\r\n" +
        "a=setup:actpass\r\n" +
        "a=fingerprint:sha-256 " + (1..32).joinToString(":") { "AB" } + "\r\n" +
        "a=candidate:1 1 udp 2122260223 192.168.1.5 54321 typ host\r\n"

/** A test double for [CallMediaSession] - never touches `dev.onvoid.webrtc.*` or a real network
 * interface. [failCreateOrAccept]/[failApplyAnswer] simulate a media-layer failure;
 * [autoConnectOnAcceptSide]/[autoConnectOnApplyAnswer] control whether/when this session fires
 * [CallMediaObserver.onMediaConnected] - `false` on either lets a test exercise
 * [CallConfig.connectTimeout] deterministically (the observer is simply never told). */
internal class FakeCallMediaSession(
    /** Exposed (not `private`) so a test can invoke a connection-state callback directly, simulating
     * the real [CallMediaObserver] being called from an arbitrary native thread at a time of the
     * test's own choosing - e.g. after [CallManager.stop] has already torn its state thread down. */
    val observer: CallMediaObserver,
) : CallMediaSession {
    val closed = AtomicBoolean(false)

    /** Set by [close] to the name of whichever thread actually called it - `null` until then. Lets a
     * test assert CLOSE happened on the correct executor (`"lapis-net-call-media"`) rather than just
     * that it happened at all - see [CallManager.stop]'s own doc comment on why every session close
     * must run on the media thread, never inline on an arbitrary caller thread. */
    @Volatile
    var closedOnThread: String? = null
    var failCreateOrAccept = false
    var failApplyAnswer = false
    var autoConnectOnAcceptSide = true
    var autoConnectOnApplyAnswer = true

    override fun createOffer(timeout: Duration): String {
        if (failCreateOrAccept) throw CallMediaException("simulated createOffer failure")
        return fakeAudioSdp()
    }

    override fun acceptOfferAndCreateAnswer(
        remoteSdp: String,
        timeout: Duration,
    ): String {
        if (failCreateOrAccept) throw CallMediaException("simulated acceptOfferAndCreateAnswer failure")
        if (autoConnectOnAcceptSide) observer.onMediaConnected()
        return fakeAudioSdp()
    }

    override fun applyAnswer(remoteSdp: String) {
        if (failApplyAnswer) throw CallMediaException("simulated applyAnswer failure")
        if (autoConnectOnApplyAnswer) observer.onMediaConnected()
    }

    override fun close() {
        closedOnThread = Thread.currentThread().name
        closed.set(true)
    }
}

internal class FakeCallMediaEngine : CallMediaEngine {
    val sessions = CopyOnWriteArrayList<FakeCallMediaSession>()
    var failNewSession = false
    var configureSession: (FakeCallMediaSession) -> Unit = {}

    /** When set, [newSession] blocks on this latch before returning - simulates
     * `mediaEngine.newSession(...)` still being mid-flight (a real `WebRtcCallMediaEngine` can spend
     * real wall-clock time here) while a local `hangUp`/`rejectCall` races ahead of it on the state
     * thread, exactly the race `CallManager.attachMediaSessionOrCloseIfEnded` exists to close. */
    var blockNewSessionUntil: java.util.concurrent.CountDownLatch? = null

    override fun newSession(observer: CallMediaObserver): CallMediaSession {
        blockNewSessionUntil?.await(5, java.util.concurrent.TimeUnit.SECONDS)
        if (failNewSession) throw CallMediaException("simulated newSession failure")
        val session = FakeCallMediaSession(observer)
        configureSession(session)
        sessions.add(session)
        return session
    }

    override fun close() {}
}

/** A shared directory of `identity -> CallManager`, so any number of [FakeCallSignalTransport]s can
 * route to EACH OTHER by destination peer identity - not just a fixed, single hardcoded pen pal.
 * Needed as soon as a test wires up more than two nodes (e.g. `CallManagerStateMachineTest`'s own
 * "busy" scenario: a third node calling into an already-occupied pair). */
internal class FakeCallNetwork {
    // ConcurrentHashMap, not mutableMapOf: MINOR round-8-verification finding (2026-09-03) - most
    // tests only register() during single-threaded setup, but at least one now registers a third
    // node mid-test (CallManagerStateMachineTest's own busy-triad scenario) while other nodes'
    // media threads may concurrently be reading this map via deliver() - a plain HashMap racing a
    // write against reads is undefined behavior even if no test has flaked on it yet.
    private val managers = java.util.concurrent.ConcurrentHashMap<Secp256k1PublicKey, CallManager>()

    fun register(
        identity: Secp256k1PublicKey,
        manager: CallManager,
    ) {
        managers[identity] = manager
    }

    fun deliver(
        sender: Secp256k1PublicKey,
        peer: Secp256k1PublicKey,
        payload: ByteArray,
        quarantined: Boolean,
    ) {
        val target = managers[peer] ?: return
        target.onInboundCallSignal(DmInboundCallSignal(sender, payload, quarantined, System.currentTimeMillis() / 1000))
    }
}

/** Routes [CallManager.placeCall]'s/etc. outbound signals through a shared [FakeCallNetwork] to
 * whichever [CallManager] is registered under the destination `peer` identity - no `DmSessionManager`,
 * no real network, in the loop. */
internal class FakeCallSignalTransport(
    private val selfIdentity: Secp256k1PublicKey,
    private val network: FakeCallNetwork,
) : CallSignalTransport {
    var failSends = false
    var quarantinedFromSelf = false
    val sentSignals = CopyOnWriteArrayList<CallSignal>()

    /** Parallel to [sentSignals] (same index = same [send] call) - the `marksAcceptance` flag
     * `CallManager` passed for that signal. Lets a regression test pin which outbound signals are
     * (and are not) allowed to promote their peer to accepted contact - see
     * [CallSignalTransport.send]'s own doc comment, SECURITY round-11 review finding (2026-09-03). */
    val sentMarksAcceptance = CopyOnWriteArrayList<Boolean>()

    /** When set, [send] blocks on this latch before doing anything else - simulates a real
     * `DmCallSignalTransport.send` still mid-dial (up to `DmSessionManager.DIAL_TIMEOUT`) on
     * `CallManager`'s own single-threaded media executor, exactly the race
     * `CallManager.stop`'s own doc comment on its `mediaExecutor` shutdown ordering describes. */
    var blockSendUntil: java.util.concurrent.CountDownLatch? = null

    override fun send(
        peer: Secp256k1PublicKey,
        payload: ByteArray,
        marksAcceptance: Boolean,
    ) {
        blockSendUntil?.await(5, java.util.concurrent.TimeUnit.SECONDS)
        if (failSends) throw RuntimeException("simulated transport failure")
        sentSignals.add(CallSignalCodec.decode(payload))
        sentMarksAcceptance.add(marksAcceptance)
        network.deliver(selfIdentity, peer, payload, quarantinedFromSelf)
    }
}

/** Polls [condition] until it returns `true` or [timeoutMs] elapses - this module's own tiny
 * `eventually` helper (no Kotest extension dependency added just for this). Fails the test with
 * [message] if the timeout is reached first. */
internal fun awaitCondition(
    timeoutMs: Long = 2_000,
    message: String = "condition not met within ${timeoutMs}ms",
    condition: () -> Boolean,
) {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (condition()) return
        Thread.sleep(10)
    }
    if (!condition()) throw AssertionError(message)
}
