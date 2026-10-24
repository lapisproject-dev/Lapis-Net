package net.lapisphilosophorum.lapisnet.onion

/** Opaque handle of a circuit owned by a hidden-service state machine; the host maps it to a real circuit. */
@JvmInline
value class CircuitRef(
    val value: Long,
)

/** Why a circuit is built; the host uses it to choose a path whose LAST hop is the given relay. */
enum class CircuitPurpose {
    INTRO,
    RENDEZVOUS_SENDER,
    RENDEZVOUS_RECEIVER,
    INTRODUCE,
    DIRECTORY_PUBLISH,
    MAILBOX_PUBLISH,
}

/** Input of the pure hidden-service state machines. */
sealed interface HsEvent {
    class CircuitBuilt(
        val ref: CircuitRef,
    ) : HsEvent

    /** The circuit failed to build, was destroyed, or its link was lost. */
    class CircuitFailed(
        val ref: CircuitRef,
    ) : HsEvent

    class RelayReceived(
        val ref: CircuitRef,
        val message: RelayMessage,
    ) : HsEvent {
        override fun toString(): String = "RelayReceived(command=${message.command})"
    }

    data object Tick : HsEvent
}
