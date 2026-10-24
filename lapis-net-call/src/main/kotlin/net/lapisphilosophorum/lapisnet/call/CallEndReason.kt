package net.lapisphilosophorum.lapisnet.call

/**
 * Why a call ended, or - for [NONE] - that it has not (yet). Carried on the wire only by
 * [CallSignal.REJECT]/[CallSignal.HANGUP] (see [CallSignalCodec]'s own class doc comment: `reason`
 * MUST be [NONE] for every other [CallSignalType]), and locally by [CallEvent.Ended] for reasons that
 * never cross the wire at all ([RING_TIMEOUT], [CONNECT_TIMEOUT], [UNSUPPORTED_MEDIA],
 * [MALFORMED_SIGNAL], [LOCAL_ERROR] are all things ONE side observed locally, never a value the OTHER
 * side would encode into a signal it sends).
 */
enum class CallEndReason(
    val wireValue: Byte,
) {
    NONE(0),
    DECLINED(1),
    BUSY(2),
    RING_TIMEOUT(3),
    CONNECT_TIMEOUT(4),
    UNSUPPORTED_MEDIA(5),
    MALFORMED_SIGNAL(6),
    LOCAL_ERROR(7),
    REMOTE_HANGUP(8),
    LOCAL_HANGUP(9),

    /**
     * V0.10.0-G: the signal path over circuits was lost (anonymity mode). LOCAL ONLY: never encoded
     * ([CallSignalCodec.encode] refuses it) and never decoded ([fromWireValue] does not know it).
     */
    CIRCUIT_LOST(10),
    ;

    companion object {
        /** Values that may appear on the wire; [CIRCUIT_LOST] is local-only and therefore excluded. */
        fun fromWireValue(value: Byte): CallEndReason? =
            entries.firstOrNull { it.wireValue == value && it != CIRCUIT_LOST }
    }
}
