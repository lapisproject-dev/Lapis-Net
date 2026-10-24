package net.lapisphilosophorum.lapisnet.browser

import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import net.lapisphilosophorum.lapisnet.call.CallEndReason
import net.lapisphilosophorum.lapisnet.call.CallEvent
import net.lapisphilosophorum.lapisnet.call.CallId
import net.lapisphilosophorum.lapisnet.call.CallLogEntry
import net.lapisphilosophorum.lapisnet.call.CallMediaEngine
import net.lapisphilosophorum.lapisnet.call.CallMediaObserver
import net.lapisphilosophorum.lapisnet.call.CallMediaPolicy
import net.lapisphilosophorum.lapisnet.call.CallMediaSession
import net.lapisphilosophorum.lapisnet.call.CallSnapshot
import net.lapisphilosophorum.lapisnet.call.CallState
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.SecureRandom
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** A structurally valid, host-only audio SDP (accepted by lapis-net-call's real SDP policy). */
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

/** Media engine double: never touches webrtc natives; sessions "connect" immediately. */
internal class FakeBrowserCallMediaEngine : CallMediaEngine {
    val sessionCount =
        java.util.concurrent.atomic
            .AtomicInteger(0)

    override fun newSession(observer: CallMediaObserver): CallMediaSession {
        sessionCount.incrementAndGet()
        return object : CallMediaSession {
            override fun createOffer(timeout: Duration): String = fakeAudioSdp()

            override fun acceptOfferAndCreateAnswer(
                remoteSdp: String,
                timeout: Duration,
            ): String {
                observer.onMediaConnected()
                return fakeAudioSdp()
            }

            override fun applyAnswer(remoteSdp: String) {
                observer.onMediaConnected()
            }

            override fun close() {}
        }
    }

    override fun close() {}
}

/** Records every call; events are delivered on a dedicated single thread, simulating the call
 * state thread that real [CallEvent]s arrive on. */
internal class FakeCallRemote : CallRemote {
    val placed = CopyOnWriteArrayList<Secp256k1PublicKey>()
    val accepted = CopyOnWriteArrayList<CallId>()
    val rejected = CopyOnWriteArrayList<CallId>()
    val hungUp = CopyOnWriteArrayList<CallId>()
    val listeners = CopyOnWriteArrayList<(CallEvent) -> Unit>()
    val listenerCount: Int get() = listeners.size

    @Volatile var active: List<CallSnapshot> = emptyList()

    @Volatile var history: List<CallLogEntry> = emptyList()
    private val random = SecureRandom()
    private val stateThread =
        Executors.newSingleThreadExecutor {
            Thread(
                it,
                "fake-call-state",
            ).apply { isDaemon = true }
        }

    val totalMutatingCalls: Int get() = placed.size + accepted.size + rejected.size + hungUp.size

    /** Parallel to [placed]/[accepted]: the exposure confirmation each call carried. */
    val placedConfirmed = CopyOnWriteArrayList<Boolean>()
    val acceptedConfirmed = CopyOnWriteArrayList<Boolean>()

    override fun placeCall(
        peer: Secp256k1PublicKey,
        mediaExposureConfirmed: Boolean,
    ): CallId {
        placed.add(peer)
        placedConfirmed.add(mediaExposureConfirmed)
        return CallId.random(random)
    }

    override fun acceptCall(
        callId: CallId,
        mediaExposureConfirmed: Boolean,
    ) {
        accepted.add(callId)
        acceptedConfirmed.add(mediaExposureConfirmed)
    }

    override fun rejectCall(callId: CallId) {
        rejected.add(callId)
    }

    override fun hangUp(callId: CallId) {
        hungUp.add(callId)
    }

    override fun activeCalls(): List<CallSnapshot> = active

    override fun callHistory(): List<CallLogEntry> = history

    override fun addCallListener(listener: (CallEvent) -> Unit) {
        listeners.add(listener)
    }

    /** Delivers [event] to every listener on the simulated state thread and waits for completion. */
    fun emit(event: CallEvent) {
        stateThread.submit { listeners.forEach { it(event) } }.get(10, TimeUnit.SECONDS)
    }

    fun snapshot(
        id: CallId,
        peer: Secp256k1PublicKey,
        state: CallState = CallState.INCOMING_RINGING,
    ) = CallSnapshot(id, peer, state)
}

internal fun randomPeer(): Secp256k1PublicKey = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

internal fun randomCallId(): CallId = CallId.random(SecureRandom())

internal fun ended(
    id: CallId,
    peer: Secp256k1PublicKey,
    reason: CallEndReason = CallEndReason.REMOTE_HANGUP,
) = CallEvent.Ended(id, peer, reason)

internal const val TEST_PORT = 45678

internal fun testCallDeps(
    remote: CallRemote?,
    hub: CallEventHub? = remote?.let { CallEventHub(it, autoRejectQuarantined = true) },
    token: CallSessionToken = CallSessionToken.generate(),
    own: Secp256k1PublicKey = randomPeer(),
    port: Int = TEST_PORT,
    callMedia: CallMediaPolicy = CallMediaPolicy.DIRECT,
) = CallApiDependencies(
    remote = remote,
    hub = hub,
    ownPublicKey = own,
    sessionToken = token,
    expectedPort = { port },
    callMedia = callMedia,
)

/** Installs only the call routes, with the same ContentNegotiation + catch-all StatusPages the real
 * [installBrowserApi] has - so a parse error that is NOT handled locally would surface as the same 500. */
internal fun Application.installCallOnly(deps: CallApiDependencies) {
    install(ContentNegotiation) { json() }
    install(StatusPages) {
        exception<Throwable> {
            call,
            _,
            ->
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal server error"))
        }
    }
    routing { installCallRoutes(deps) }
}
