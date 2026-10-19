package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.call.CallEvent
import net.lapisphilosophorum.lapisnet.call.CallId
import net.lapisphilosophorum.lapisnet.call.CallLogEntry
import net.lapisphilosophorum.lapisnet.call.CallManager
import net.lapisphilosophorum.lapisnet.call.CallSnapshot
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * V0.8.7b - the narrow slice of [CallManager] the browser call remote control needs.
 *
 * A dedicated facade (instead of using [CallManager] directly) because [CallManager.attachToTransport]
 * and the fakes of `lapis-net-call` are `internal` to that module: with this interface, [CallApi]
 * routes and [CallEventHub] can be exercised in this module's tests without a real
 * `DmSessionManager`. Production uses [CallManagerRemote], a pure 1:1 delegation.
 */
interface CallRemote {
    /** Places an outgoing call; returns the freshly minted [CallId] immediately. */
    fun placeCall(peer: Secp256k1PublicKey): CallId

    /** Accepts a currently ringing incoming call (a no-op for an unknown/finished call). */
    fun acceptCall(callId: CallId)

    /** Rejects an incoming call with `DECLINED`. */
    fun rejectCall(callId: CallId)

    /** Hangs up a call with `LOCAL_HANGUP`. */
    fun hangUp(callId: CallId)

    /** Snapshot of every tracked call. Blocks for up to 5 s on the call state thread - only call
     * this from `Dispatchers.IO`, never from a Netty event-loop thread. */
    fun activeCalls(): List<CallSnapshot>

    /** Ended calls, oldest first (in-memory only, capped by `lapis-net-call`). */
    fun callHistory(): List<CallLogEntry>

    /** Registers a listener; invoked from the call state thread, which must never be blocked. */
    fun addCallListener(listener: (CallEvent) -> Unit)
}

/** Production [CallRemote]: delegates 1:1 to [manager]. */
class CallManagerRemote(
    private val manager: CallManager,
) : CallRemote {
    override fun placeCall(peer: Secp256k1PublicKey): CallId = manager.placeCall(peer)

    override fun acceptCall(callId: CallId) = manager.acceptCall(callId)

    override fun rejectCall(callId: CallId) = manager.rejectCall(callId)

    override fun hangUp(callId: CallId) = manager.hangUp(callId)

    override fun activeCalls(): List<CallSnapshot> = manager.activeCalls()

    override fun callHistory(): List<CallLogEntry> = manager.callHistory()

    override fun addCallListener(listener: (CallEvent) -> Unit) = manager.addCallListener(listener)
}
