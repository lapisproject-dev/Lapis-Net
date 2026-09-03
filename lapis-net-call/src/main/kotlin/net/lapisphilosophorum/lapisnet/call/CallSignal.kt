package net.lapisphilosophorum.lapisnet.call

/** Thrown when decoding a [CallSignal]'s canonical byte encoding ([CallSignalCodec.decode]) fails
 * structurally. Never thrown for AEAD/ratchet failures - by the time these bytes reach
 * [CallSignalCodec.decode], `DoubleRatchetSession.decrypt` has already succeeded (this is the ratchet
 * plaintext of a `DmMessageType.CALL_SIGNAL` envelope - see `DmInboundCallSignal`'s own doc comment).
 * Mirrors `MalformedDmContentException`'s identical "structural-only, post-AEAD" contract exactly. */
class MalformedCallSignalException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * One 1:1 call-control message, carried as the ratchet plaintext of a `DmMessageType.CALL_SIGNAL`
 * envelope (see [CallSignalCodec] for the exact byte layout `CallManager` exchanges through
 * `DmCallSignalTransport`).
 *
 * **`internal` constructor - only [CallSignalCodec.decode] and this file's own factory functions
 * ([invite]/[accept]/[reject]/[hangUp]) build one** - mirrors `DmEnvelope`'s own internal-ctor
 * discipline: a caller outside this module can never hand-construct a [CallSignal] that skipped
 * [CallSignalCodec]'s own field-consistency invariants.
 *
 * [sdp] is non-null if and only if [type] is [CallSignalType.INVITE] or [CallSignalType.ACCEPT] -
 * every other type carries no SDP (there is nothing to negotiate in a reject/hang-up). [reason] MUST
 * be [CallEndReason.NONE] unless [type] is [CallSignalType.REJECT] or [CallSignalType.HANGUP] - an
 * `INVITE`/`ACCEPT` has not ended anything yet.
 */
class CallSignal internal constructor(
    val type: CallSignalType,
    val callId: CallId,
    val createdAtEpochMillis: Long,
    val notValidAfterEpochMillis: Long,
    val mediaKind: CallMediaKind,
    val reason: CallEndReason,
    val sdp: String?,
) {
    init {
        require((type == CallSignalType.INVITE || type == CallSignalType.ACCEPT) == (sdp != null)) {
            "sdp must be present iff type is INVITE or ACCEPT"
        }
        require((type == CallSignalType.REJECT || type == CallSignalType.HANGUP) || reason == CallEndReason.NONE) {
            "reason must be NONE unless type is REJECT or HANGUP"
        }
        require(notValidAfterEpochMillis > createdAtEpochMillis) {
            "notValidAfterEpochMillis must be after createdAtEpochMillis"
        }
    }

    /** **NEVER logs [sdp]** - an SDP carries this node's LAN-local ICE host candidates (see
     * `CallSdpPolicy`'s own class doc comment on why that is an accepted, deliberate leak to an
     * ALREADY-AUTHENTICATED call peer, not to a log file) and, on `webrtc-java`'s default
     * `RTCConfiguration.certificates`, a fresh-per-session DTLS certificate fingerprint. Mirrors
     * `DmContent.toString`'s identical "shape only, never payload content" discipline. */
    override fun toString(): String =
        "CallSignal(type=$type, callId=${callId.fingerprint()}, mediaKind=$mediaKind, reason=$reason, " +
            "hasSdp=${sdp != null})"

    companion object {
        fun invite(
            callId: CallId,
            sdp: String,
            createdAtEpochMillis: Long,
            notValidAfterEpochMillis: Long,
        ): CallSignal =
            CallSignal(
                CallSignalType.INVITE,
                callId,
                createdAtEpochMillis,
                notValidAfterEpochMillis,
                CallMediaKind.AUDIO,
                CallEndReason.NONE,
                sdp,
            )

        fun accept(
            callId: CallId,
            sdp: String,
            createdAtEpochMillis: Long,
            notValidAfterEpochMillis: Long,
        ): CallSignal =
            CallSignal(
                CallSignalType.ACCEPT,
                callId,
                createdAtEpochMillis,
                notValidAfterEpochMillis,
                CallMediaKind.AUDIO,
                CallEndReason.NONE,
                sdp,
            )

        fun reject(
            callId: CallId,
            reason: CallEndReason,
            createdAtEpochMillis: Long,
            notValidAfterEpochMillis: Long,
        ): CallSignal =
            CallSignal(
                CallSignalType.REJECT,
                callId,
                createdAtEpochMillis,
                notValidAfterEpochMillis,
                CallMediaKind.AUDIO,
                reason,
                null,
            )

        fun hangUp(
            callId: CallId,
            reason: CallEndReason,
            createdAtEpochMillis: Long,
            notValidAfterEpochMillis: Long,
        ): CallSignal =
            CallSignal(
                CallSignalType.HANGUP,
                callId,
                createdAtEpochMillis,
                notValidAfterEpochMillis,
                CallMediaKind.AUDIO,
                reason,
                null,
            )
    }
}
