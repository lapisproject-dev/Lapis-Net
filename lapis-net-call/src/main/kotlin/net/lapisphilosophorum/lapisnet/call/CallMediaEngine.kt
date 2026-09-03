package net.lapisphilosophorum.lapisnet.call

import java.time.Duration

/** Thrown by a [CallMediaSession] operation that fails - a `webrtc-java` `onFailure` callback, or a
 * timeout waiting for one. Deliberately the ONE exception type every [CallMediaEngine]/
 * [CallMediaSession] implementation throws, so `CallManager` never needs to know which concrete
 * engine (`WebRtcCallMediaEngine` in production, a test fake in `CallManagerStateMachineTest`) is
 * behind the interface. */
class CallMediaException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Callback interface [CallManager] implements to learn about a [CallMediaSession]'s connection
 * lifecycle - the media-layer analogue of `PeerConnectionObserver`'s connection-state callbacks,
 * abstracted so `CallManager` never imports `dev.onvoid.webrtc.*` directly (see
 * `WebRtcCallMediaEngine`'s own doc comment on this module's "sole consumer" discipline). Every
 * method may be called from the implementing [CallMediaEngine]'s OWN internal thread(s) - an
 * implementation MUST NOT assume it runs on any particular thread, and `CallManager`'s own
 * implementation immediately posts every callback onto its state thread rather than acting on it
 * inline (see that class's own doc comment on its three-executor concurrency model). */
interface CallMediaObserver {
    fun onMediaConnected()

    fun onMediaFailed(cause: String)

    fun onMediaClosed()
}

/** One side of one call's WebRTC media path - created fresh per call via
 * [CallMediaEngine.newSession]. Every method here is BLOCKING (bounded by its own [timeout]
 * parameter) - `CallManager` always calls these from its dedicated media thread, never from its
 * state thread or from a `DmSessionManager` callback (see that class's own doc comment for why this
 * is load-bearing, not a style preference).
 *
 * **Non-Trickle**: [createOffer]/[acceptOfferAndCreateAnswer] both block until ICE gathering
 * completes (or [timeout] elapses) before returning - the returned SDP already has every gathered
 * host candidate folded in, so no separate `CallSignalType.ICE_CANDIDATE` exchange is ever needed
 * this wave (see that enum's own doc comment on why it is reserved, not implemented). */
interface CallMediaSession : AutoCloseable {
    /** Creates and sets a local offer, waits for ICE gathering to finish (bounded by [timeout]), and
     * returns the resulting SDP text.
     *
     * @throws CallMediaException on failure or timeout.
     */
    fun createOffer(timeout: Duration): String

    /** Sets [remoteSdp] as the remote offer, creates and sets a local answer, waits for ICE
     * gathering to finish (bounded by [timeout]), and returns the resulting answer SDP text.
     *
     * @throws CallMediaException on failure or timeout.
     */
    fun acceptOfferAndCreateAnswer(
        remoteSdp: String,
        timeout: Duration,
    ): String

    /** Sets [remoteSdp] as the remote answer, completing this side's offer/answer exchange.
     *
     * @throws CallMediaException on failure or timeout.
     */
    fun applyAnswer(remoteSdp: String)
}

/** Produces [CallMediaSession]s - one instance is shared across every call `CallManager` drives in
 * this process (see [CallManager.attach]'s own `mediaEngine` parameter). Abstracted so
 * `CallManagerStateMachineTest`/`CallManagerAbuseTest` can drive the FULL state machine with a fake
 * that never touches `dev.onvoid.webrtc.*` or a real network interface. */
interface CallMediaEngine : AutoCloseable {
    fun newSession(observer: CallMediaObserver): CallMediaSession
}
