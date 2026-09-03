package net.lapisphilosophorum.lapisnet.call

import dev.onvoid.webrtc.CreateSessionDescriptionObserver
import dev.onvoid.webrtc.PeerConnectionFactory
import dev.onvoid.webrtc.PeerConnectionObserver
import dev.onvoid.webrtc.PortAllocatorConfig
import dev.onvoid.webrtc.RTCAnswerOptions
import dev.onvoid.webrtc.RTCConfiguration
import dev.onvoid.webrtc.RTCIceCandidate
import dev.onvoid.webrtc.RTCIceGatheringState
import dev.onvoid.webrtc.RTCOfferOptions
import dev.onvoid.webrtc.RTCPeerConnection
import dev.onvoid.webrtc.RTCPeerConnectionState
import dev.onvoid.webrtc.RTCSdpType
import dev.onvoid.webrtc.RTCSessionDescription
import dev.onvoid.webrtc.SetSessionDescriptionObserver
import dev.onvoid.webrtc.media.MediaDevices
import dev.onvoid.webrtc.media.audio.AudioDeviceModule
import dev.onvoid.webrtc.media.audio.AudioOptions
import dev.onvoid.webrtc.media.audio.AudioTrack
import dev.onvoid.webrtc.media.audio.AudioTrackSource
import dev.onvoid.webrtc.media.audio.HeadlessAudioDeviceModule
import io.github.oshai.kotlinlogging.KotlinLogging
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/** What [WebRtcCallMediaSession]'s `onConnectionChange` does for a given [RTCPeerConnectionState] -
 * pulled out into its own top-level, testable function purely so a test can assert this mapping
 * table directly. `onConnectionChange` itself lives inside a private anonymous
 * `PeerConnectionObserver` on a real `RTCPeerConnection`, unreachable from a test with no live
 * native connection driving actual state transitions through it - a gap the review-fix round's own
 * MINOR finding (2026-09-02) flagged for the DISCONNECTED-is-not-terminal change specifically:
 * that change touched this file but added no test for it. This function has no dependency on
 * [RTCPeerConnection]/[PeerConnectionObserver]/anything else that needs the native library loaded -
 * only the plain [RTCPeerConnectionState] enum - so it is callable from any test regardless of
 * [WebRtcCallMediaEngine.isNativeAvailable]. */
internal enum class CallConnectionAction { CONNECTED, TRANSIENT_DISCONNECT, FAILED, CLOSED, IGNORE }

internal fun callConnectionActionFor(state: RTCPeerConnectionState): CallConnectionAction =
    when (state) {
        RTCPeerConnectionState.CONNECTED -> CallConnectionAction.CONNECTED
        // Only FAILED is a terminal WebRTC connection state. DISCONNECTED is explicitly transient
        // in the spec (a transport dropped its most recently pinged connection - e.g. brief packet
        // loss or a Wi-Fi roam) and routinely recovers back to CONNECTED within a second or two
        // without any application action; libwebrtc itself keeps ICE alive and only moves on to
        // FAILED if it never recovers. Treating DISCONNECTED as a hard failure here previously tore
        // down the whole call (CallManager.onMediaFailedOnStateThread sends a HANGUP and ends it)
        // for exactly the transient blips this state exists to describe, with nothing left to
        // reconnect once that HANGUP reaches the peer.
        RTCPeerConnectionState.DISCONNECTED -> CallConnectionAction.TRANSIENT_DISCONNECT
        RTCPeerConnectionState.FAILED -> CallConnectionAction.FAILED
        RTCPeerConnectionState.CLOSED -> CallConnectionAction.CLOSED
        else -> CallConnectionAction.IGNORE
    }

/**
 * The **sole file in this module** (and in `lapis-net-call`'s entire dependency graph) that imports
 * `dev.onvoid.webrtc.*` - mirrors `lapis-net-dm`'s own `DmFirstContactDepositVerifier.kt` "sole
 * consumer" discipline for `fr.acinq.*` exactly. Every other class in this module (`CallManager`,
 * `CallSignalCodec`, `CallSdpPolicy`, ...) only ever sees [CallMediaEngine]/[CallMediaSession]/
 * [CallMediaObserver].
 *
 * **This node's own ICE gathering is deliberately restricted to `typ host` UDP candidates, with NO
 * STUN or TURN server ever contacted and NO local TCP candidate gathered either** -
 * `RTCConfiguration.iceServers` stays an empty list AND `PortAllocatorConfig`'s
 * `PORTALLOCATOR_DISABLE_STUN`/`PORTALLOCATOR_DISABLE_RELAY`/`PORTALLOCATOR_DISABLE_TCP` flags are all
 * set. The TCP flag mirrors, on this node's OWN gathering side, the identical `udp`-only restriction
 * `CallSdpPolicy.validateCandidateLine` enforces on a REMOTE peer's candidates (MINOR review-round
 * finding, 2026-09-02) - symmetric, not merely one-sided. Multiple independent mechanisms enforcing
 * the SAME restriction, deliberately: an empty
 * `iceServers` list alone only means "no server WAS configured" - it does not, by itself, prove
 * libwebrtc's port allocator could never be steered toward contacting one by some other path (e.g. a
 * future code change that populates `iceServers` for an unrelated reason). The `PortAllocatorConfig`
 * flags are the actual, structural guarantee: "reasoning through the empty list" is a form of
 * confirmation this codec's own security-checklist discipline treats as insufficient by itself (see
 * `CallSdpPolicy`'s own class doc comment for the identical reasoning applied to a REMOTE peer's
 * SDP). Together, this is exactly the design goal "reines P2P, keine dritte Partei" states: no STUN
 * server sees this node's public IP, no TURN server ever relays media - a call either connects
 * directly or does not connect at all this wave (see `docs/architecture.adoc`'s own "explicit,
 * deliberate scope cuts" section for the direct-dialable-peers-only consequence this implies).
 */
class WebRtcCallMediaEngine private constructor(
    private val factory: PeerConnectionFactory,
    private val mediaPortRange: IntRange?,
) : CallMediaEngine {
    @Volatile
    private var closed = false

    override fun newSession(observer: CallMediaObserver): CallMediaSession {
        check(!closed) { "WebRtcCallMediaEngine is already closed" }
        return WebRtcCallMediaSession(factory, mediaPortRange, observer)
    }

    /** Disposes the underlying `PeerConnectionFactory` - releases the audio device module and every
     * native thread the factory owns. Idempotent. Does NOT close any [CallMediaSession] this engine
     * already handed out - `CallManager` owns each session's own lifecycle and is responsible for
     * closing every session before closing the engine that created it (mirrors `DmSessionManager
     * .stop()`'s own "children stopped before the parent that owns their lifecycle" ordering). */
    override fun close() {
        if (closed) return
        closed = true
        factory.dispose()
    }

    companion object {
        /**
         * Creates a [WebRtcCallMediaEngine] backed by a fresh `PeerConnectionFactory`.
         *
         * [headlessAudio]: `true` forces [HeadlessAudioDeviceModule] (CI, a server with no audio
         * hardware); `false` forces the platform [AudioDeviceModule] (a real microphone/speaker);
         * `null` (the default) auto-detects via [MediaDevices.getAudioCaptureDevices] - an empty
         * device list means headless, a non-empty list means a real device is present.
         *
         * [mediaPortRange] optionally restricts the local UDP/TCP port range libwebrtc's port
         * allocator draws from - useful behind a firewall that only forwards a known range. `null`
         * (the default) means unrestricted (ephemeral OS-assigned ports).
         */
        fun create(
            headlessAudio: Boolean? = null,
            mediaPortRange: IntRange? = null,
        ): WebRtcCallMediaEngine {
            val useHeadless =
                headlessAudio ?: run {
                    val devices = runCatching { MediaDevices.getAudioCaptureDevices() }.getOrDefault(emptyList())
                    devices.isEmpty()
                }
            val adm = if (useHeadless) HeadlessAudioDeviceModule() else AudioDeviceModule()
            val factory = PeerConnectionFactory(adm)
            return WebRtcCallMediaEngine(factory, mediaPortRange)
        }

        /** `true` iff `webrtc-java`'s native library is loadable on this platform - gates every test
         * that needs a REAL engine: `WebRtcCallMediaEngineTest` (the engine alone, two sessions in
         * one JVM, no `CallManager`/`DmSessionManager` in the loop) and `TwoNodeCallIntegrationTest`
         * (the full production stack - `CallManager.attach` over a real `DmSessionManager`/two real
         * `LapisNode`s, both sides reaching `CallEvent.Active` against this real engine, closing the
         * gap this comment used to flag as untested). See this module's
         * `CallManagerStateMachineTest`/`CallManagerAbuseTest` for the state-machine coverage against
         * a `FakeCallMediaEngine` instead, `DmSessionManagerCallSignalTest` in `lapis-net-dm` for the
         * opaque-bytes DM-transport coverage, and `CallManagerDmWiringIntegrationTest` for the
         * `CallManager.attach` DM-listener wiring against that same `FakeCallMediaEngine` -
         * `TwoNodeCallIntegrationTest` is the one test in this constellation that replaces the fake
         * with this real engine end to end.
         * Constructs and immediately disposes a throwaway [HeadlessAudioDeviceModule] - the cheapest
         * operation that forces the native library to load, without needing an actual audio device or
         * network interface. Never throws - catches [LinkageError] (the superclass of both
         * `UnsatisfiedLinkError` and `NoClassDefFoundError`, either of which `System.load`'s
         * "restricted method" JDK 25 behavior, or a genuinely missing native binary, could raise). */
        fun isNativeAvailable(): Boolean =
            try {
                HeadlessAudioDeviceModule().dispose()
                true
            } catch (e: LinkageError) {
                logger.warn(e) { "webrtc-java native library is not available on this platform" }
                false
            }
    }
}

/** [CallMediaSession] implementation - the sole class in this file besides its outer
 * [WebRtcCallMediaEngine] that touches `dev.onvoid.webrtc.*` directly. One instance per call, created
 * fresh by [WebRtcCallMediaEngine.newSession]. */
private class WebRtcCallMediaSession(
    factory: PeerConnectionFactory,
    mediaPortRange: IntRange?,
    private val observer: CallMediaObserver,
) : CallMediaSession {
    /** [AtomicBoolean], not `@Volatile var` + check-then-act - MAJOR review-round finding
     * (2026-09-02, round 6), empirically reproduced: a plain `if (closed) return; closed = true`
     * lets two threads both observe `closed == false` and both proceed to call
     * `peerConnection.close()` below - two `close()` calls racing this class's own [close] override
     * is exactly the native double-free this class's own doc comment on that method already
     * describes ("Native object was not deleted") for a SINGLE thread calling both `close()` and
     * `audioTrack.dispose()`; two THREADS calling `peerConnection.close()` concurrently hits the same
     * failure mode from a different angle. [CallManager] (this class's only production caller) no
     * longer has any call site that can reach [close] concurrently from two threads at once (see
     * `CallManager.endCallOnStateThread`/`handleInboundAccept`'s own doc comments on the inline
     * close-on-rejection fallbacks removed by that same finding) - `compareAndSet` here is defense
     * in depth, making a double-close structurally impossible rather than merely unlikely. */
    private val closed = AtomicBoolean(false)

    /** Counts down the instant `onIceGatheringChange(COMPLETE)` fires - see
     * [awaitIceGatheringComplete]'s own doc comment for why this is bounded, never awaited
     * unconditionally. */
    private val gatheringComplete = CountDownLatch(1)

    private val pcObserver =
        object : PeerConnectionObserver {
            override fun onIceCandidate(candidate: RTCIceCandidate) {
                // Non-Trickle (see CallMediaSession's own class doc comment): individual candidates
                // are never forwarded anywhere - libwebrtc folds every gathered host candidate
                // straight into getLocalDescription()'s own SDP by the time gathering completes
                // below, which is the only copy this class ever reads.
            }

            override fun onIceGatheringChange(state: RTCIceGatheringState) {
                if (state == RTCIceGatheringState.COMPLETE) gatheringComplete.countDown()
            }

            override fun onConnectionChange(state: RTCPeerConnectionState) {
                // See callConnectionActionFor's own doc comment - the mapping itself lives there,
                // pulled out to be independently testable.
                when (callConnectionActionFor(state)) {
                    CallConnectionAction.CONNECTED -> observer.onMediaConnected()
                    CallConnectionAction.TRANSIENT_DISCONNECT ->
                        logger.debug {
                            "peer connection transiently disconnected - not failing the call, " +
                                "waiting to see whether it recovers to CONNECTED or degrades to FAILED"
                        }
                    CallConnectionAction.FAILED -> observer.onMediaFailed("ICE/DTLS connection failed")
                    CallConnectionAction.CLOSED -> observer.onMediaClosed()
                    CallConnectionAction.IGNORE -> Unit
                }
            }
        }

    private val configuration =
        RTCConfiguration().apply {
            // See WebRtcCallMediaEngine's own class doc comment - the two-mechanism no-STUN/no-TURN
            // guarantee. iceServers stays this class's default (an empty list) - never populated.
            portAllocatorConfig =
                PortAllocatorConfig(
                    mediaPortRange?.first ?: 0,
                    mediaPortRange?.last ?: 0,
                    PortAllocatorConfig.PORTALLOCATOR_DISABLE_STUN or
                        PortAllocatorConfig.PORTALLOCATOR_DISABLE_RELAY or
                        // MINOR review-round finding (2026-09-02) - see this class's own class doc
                        // comment: mirrors CallSdpPolicy's remote-side udp-only restriction on this
                        // node's own local gathering too, symmetrically.
                        PortAllocatorConfig.PORTALLOCATOR_DISABLE_TCP,
                )
        }

    private val peerConnection: RTCPeerConnection
    private val audioSource: AudioTrackSource
    private val audioTrack: AudioTrack

    /** MINOR review-round finding (2026-09-02, resource-leaks): the four construction steps below
     * (`createPeerConnection`, `createAudioSource`, `createAudioTrack`, `addTrack`) used to run as
     * separate property initializers with no error handling. If any step after
     * `createPeerConnection` threw, the already-created native `RTCPeerConnection` was never
     * assigned to a property and never closed - this class's own constructor never returned an
     * instance, so `CallManager.runOutgoingMediaSetup`/`runIncomingMediaSetup` only saw the
     * exception out of `mediaEngine.newSession(...)`, never added anything to
     * `liveMediaSessions`, and the safety-net sweep in `CallManager.stop()` had no session to find.
     * Leaked native `RTCPeerConnection`s left alive past `WebRtcCallMediaEngine.close()`'s
     * `factory.dispose()` call are exactly the "Native object was not deleted" SIGSEGV this file's
     * own [close] doc comment describes - hence closing `pc` here on any failure, before
     * rethrowing, rather than leaving it for the GC/native finalizer to (never) reach. */
    init {
        val pc = factory.createPeerConnection(configuration, pcObserver)
        try {
            val source = factory.createAudioSource(AudioOptions())
            val track = factory.createAudioTrack(AUDIO_TRACK_ID, source)
            pc.addTrack(track, listOf(AUDIO_STREAM_ID))
            peerConnection = pc
            audioSource = source
            audioTrack = track
        } catch (e: Exception) {
            pc.close()
            throw CallMediaException("failed to initialize WebRTC media pipeline", e)
        }
    }

    override fun createOffer(timeout: Duration): String {
        val offer = createSessionDescription(offer = true, timeout)
        setLocalDescription(offer, timeout)
        awaitIceGatheringComplete(timeout)
        return requireLocalSdp()
    }

    override fun acceptOfferAndCreateAnswer(
        remoteSdp: String,
        timeout: Duration,
    ): String {
        setRemoteDescription(RTCSessionDescription(RTCSdpType.OFFER, remoteSdp), timeout)
        val answer = createSessionDescription(offer = false, timeout)
        setLocalDescription(answer, timeout)
        awaitIceGatheringComplete(timeout)
        return requireLocalSdp()
    }

    override fun applyAnswer(remoteSdp: String) {
        setRemoteDescription(RTCSessionDescription(RTCSdpType.ANSWER, remoteSdp), DEFAULT_SET_REMOTE_ANSWER_TIMEOUT)
    }

    /** **Deliberately does NOT call `audioTrack.dispose()`** - verified empirically (2026-09-02) to be
     * actively dangerous, not merely redundant: `RTCPeerConnection.close()` already releases every
     * track it holds a sender reference to (this track was `addTrack`'d in `init{}` above), and a
     * subsequent explicit `audioTrack.dispose()` crashes the JVM with a native-level
     * `java.lang.Error: Native object was not deleted. A reference is still around somewhere` -
     * SIGSEGV, not a catchable exception, observed taking down the ENTIRE test JVM (not just this
     * test) the first time this method was written to call both. `peerConnection.close()` is the
     * complete, correct teardown for a track that was ever `addTrack`'d - manually disposing it
     * afterward is a double-free, not a hygiene improvement. The audio SOURCE/track objects are
     * ultimately reclaimed when [WebRtcCallMediaEngine.close] disposes the whole
     * `PeerConnectionFactory` they were created from. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        peerConnection.close()
    }

    private fun requireLocalSdp(): String =
        peerConnection.localDescription?.sdp
            ?: throw CallMediaException("local description was unexpectedly null after set+gather")

    private fun createSessionDescription(
        offer: Boolean,
        timeout: Duration,
    ): RTCSessionDescription {
        val future = CompletableFuture<RTCSessionDescription>()
        val sdpObserver =
            object : CreateSessionDescriptionObserver {
                override fun onSuccess(description: RTCSessionDescription) {
                    future.complete(description)
                }

                override fun onFailure(error: String) {
                    future.completeExceptionally(CallMediaException(error))
                }
            }
        if (offer) {
            peerConnection.createOffer(RTCOfferOptions(), sdpObserver)
        } else {
            peerConnection.createAnswer(RTCAnswerOptions(), sdpObserver)
        }
        return await(future, timeout, "create ${if (offer) "offer" else "answer"}")
    }

    private fun setLocalDescription(
        description: RTCSessionDescription,
        timeout: Duration,
    ) {
        val future = CompletableFuture<Void>()
        peerConnection.setLocalDescription(
            description,
            object : SetSessionDescriptionObserver {
                override fun onSuccess() {
                    future.complete(null)
                }

                override fun onFailure(error: String) {
                    future.completeExceptionally(CallMediaException(error))
                }
            },
        )
        await(future, timeout, "set local description")
    }

    private fun setRemoteDescription(
        description: RTCSessionDescription,
        timeout: Duration,
    ) {
        val future = CompletableFuture<Void>()
        peerConnection.setRemoteDescription(
            description,
            object : SetSessionDescriptionObserver {
                override fun onSuccess() {
                    future.complete(null)
                }

                override fun onFailure(error: String) {
                    future.completeExceptionally(CallMediaException(error))
                }
            },
        )
        await(future, timeout, "set remote description")
    }

    /** Bounded wait for ICE gathering to reach COMPLETE - NEVER unbounded, even though gathering with
     * no STUN/TURN configured is normally near-instantaneous (only host candidates to enumerate).
     * Proceeds with whatever [peerConnection] already gathered if [timeout] elapses first - a
     * genuinely stalled gathering pass (e.g. no usable network interface at all) must never hang a
     * call attempt forever. */
    private fun awaitIceGatheringComplete(timeout: Duration) {
        if (peerConnection.iceGatheringState == RTCIceGatheringState.COMPLETE) return
        if (!gatheringComplete.await(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            logger.debug {
                "ICE gathering did not reach COMPLETE within $timeout - proceeding with whatever " +
                    "host candidates were gathered so far"
            }
        }
    }

    private fun <T> await(
        future: CompletableFuture<T>,
        timeout: Duration,
        action: String,
    ): T =
        try {
            future.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw CallMediaException("timed out waiting to $action", e)
        } catch (e: ExecutionException) {
            throw CallMediaException("failed to $action", e.cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw CallMediaException("interrupted while waiting to $action", e)
        }

    private companion object {
        const val AUDIO_TRACK_ID = "lapis-net-call-audio"
        const val AUDIO_STREAM_ID = "lapis-net-call"
        val DEFAULT_SET_REMOTE_ANSWER_TIMEOUT: Duration = Duration.ofSeconds(10)
    }
}
