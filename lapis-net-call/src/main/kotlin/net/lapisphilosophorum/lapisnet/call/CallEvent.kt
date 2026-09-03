package net.lapisphilosophorum.lapisnet.call

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/** The local state of one call, as observed by a [CallManager] listener - a simplified projection of
 * `CallManager`'s own internal per-call state machine, exposed for a future UI (V0.8.7b, not this
 * wave - see `docs/architecture.adoc`'s own "explicit, deliberate scope cuts" section) to render. */
enum class CallState {
    OUTGOING_RINGING,
    INCOMING_RINGING,
    CONNECTING,
    ACTIVE,
    ENDED,
}

/** Emitted by [CallManager.addCallListener] on every call-state transition - ALWAYS posted from
 * [CallManager]'s own dedicated state thread (see that class's own doc comment on its three-executor
 * concurrency model), so a listener never needs its own synchronization to reason about ordering
 * across events for the SAME [callId]. */
sealed class CallEvent {
    abstract val callId: CallId
    abstract val peer: Secp256k1PublicKey

    /** An inbound `INVITE` arrived. [quarantined] mirrors `DmInboundCallSignal.quarantined` - it
     * reflects `DmSessionManager`'s acceptance-policy classification of the SENDER only, and says
     * nothing by itself about whether this event is actionable: whether
     * [CallConfig.autoRejectQuarantined] is `true` (the default) decides that separately (see that
     * field's own doc comment). With it `true`, a `quarantined = true` call IS emitted here (so a
     * listener can still log/audit the attempt) but is NOT admitted into this call's tracking - it
     * never actually rings, [CallManager.acceptCall]/[CallManager.rejectCall] for its [callId] are
     * silent no-ops, and this [IncomingCall] is the ONLY event this manager will ever emit for that
     * [callId] (no [Connecting]/[Active]/[Ended] follows - see [CallManager.onInboundCallSignal]'s
     * own silent-drop branch). With [CallConfig.autoRejectQuarantined] `false`, EVERY [IncomingCall],
     * quarantined or not, is a real, ringing call a listener MUST offer accept/reject for, and DOES
     * emit its normal follow-up [Connecting]/[Active]/[Ended] events. A listener must therefore
     * branch on [quarantined] (in light of its own [CallConfig.autoRejectQuarantined] setting)
     * before deciding whether to treat this event as actionable or as terminal for [callId]. */
    data class IncomingCall(
        override val callId: CallId,
        override val peer: Secp256k1PublicKey,
        val quarantined: Boolean,
    ) : CallEvent()

    /** [CallManager.placeCall] sent its `INVITE` and is now waiting for the peer to `ACCEPT`/
     * `REJECT`, or for [CallConfig.ringTimeout] to elapse. */
    data class OutgoingRinging(
        override val callId: CallId,
        override val peer: Secp256k1PublicKey,
    ) : CallEvent()

    /** Both sides have exchanged offer/answer; [CallManager] is now waiting for the underlying
     * [CallMediaSession] to report [CallMediaObserver.onMediaConnected], bounded by
     * [CallConfig.connectTimeout]. */
    data class Connecting(
        override val callId: CallId,
        override val peer: Secp256k1PublicKey,
    ) : CallEvent()

    /** The underlying [CallMediaSession] reported [CallMediaObserver.onMediaConnected] - audio is
     * flowing. */
    data class Active(
        override val callId: CallId,
        override val peer: Secp256k1PublicKey,
    ) : CallEvent()

    /** Terminal for this [callId] - no further event for it will ever be emitted. */
    data class Ended(
        override val callId: CallId,
        override val peer: Secp256k1PublicKey,
        val reason: CallEndReason,
    ) : CallEvent()
}

/** A snapshot of one call [CallManager.activeCalls] can return - deliberately NOT the same type as
 * [CallEvent] (a snapshot is queried state, an event is a transition notification; conflating the two
 * would force every snapshot consumer to also handle transition-only semantics like [CallEvent
 * .IncomingCall]'s `quarantined` flag, which a snapshot of an ALREADY-admitted call has no use for). */
data class CallSnapshot(
    val callId: CallId,
    val peer: Secp256k1PublicKey,
    val state: CallState,
)
