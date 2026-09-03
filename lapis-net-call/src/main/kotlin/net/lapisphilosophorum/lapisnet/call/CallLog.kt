package net.lapisphilosophorum.lapisnet.call

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Instant

/** One finished call, as recorded by [CallLog]. */
data class CallLogEntry(
    val callId: CallId,
    val peer: Secp256k1PublicKey,
    val reason: CallEndReason,
    val endedAtEpochSecond: Long,
)

/**
 * A bounded, in-memory-only call history - exactly `DmStore`'s own "nothing persisted to disk"
 * discipline (see that class's own doc comment), applied to calls: a call log is at least as
 * sensitive as a message history (it reveals WHO this node talks to and WHEN, even with no content),
 * so this wave makes the same deliberate choice `DmStore` already made for DM history rather than
 * introducing a new persistence surface this wave's own security review would then need to cover.
 *
 * FIFO-capped at [maxEntries] - oldest entry evicted first once the cap is reached, same "generous
 * headroom, provisional magnitude" framing as every other bounded structure in this codebase.
 *
 * [clockSeconds] defaults to the real wall clock but is injectable - [CallManager] passes its own
 * `clock` through (see that class's constructor) rather than letting this class read
 * [Instant.now] independently. Review-fix finding (2026-09-02): `CallManagerStateMachineTest` and
 * friends set a fixed fake clock on `CallManager` for its skew/expiry assertions
 * (`signalTtl`/`maxClockSkew`/rate-limiter windows all read through it) - a [CallLog] that kept
 * reading the real system clock independently would stamp `endedAtEpochSecond` with a value
 * inconsistent with those same signals' `createdAtEpochMillis`/`notValidAfterEpochMillis` whenever a
 * test (or a future caller) compares them.
 */
class CallLog(
    private val maxEntries: Int = 256,
    private val clockSeconds: () -> Long = { Instant.now().epochSecond },
) {
    private val entries = ArrayDeque<CallLogEntry>()

    @Synchronized
    fun record(event: CallEvent.Ended) {
        entries.addLast(
            CallLogEntry(event.callId, event.peer, event.reason, clockSeconds()),
        )
        while (entries.size > maxEntries) entries.removeFirst()
    }

    /** Oldest first. A defensive copy - the caller cannot mutate this log's own internal state
     * through the returned list. */
    @Synchronized
    fun entries(): List<CallLogEntry> = entries.toList()
}
