package net.lapisphilosophorum.lapisnet.call

import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmCallReplyRoute
import net.lapisphilosophorum.lapisnet.dm.DmCallSignalPathLostException
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/** The channel [CallManager] sends encoded [CallSignal] bytes over - an interface purely so
 * `CallManagerStateMachineTest`/`CallManagerAbuseTest` can drive the full state machine against a
 * `FakeCallSignalTransport`, with no real network stack or `DmSessionManager` in the loop. */
fun interface CallSignalTransport {
    /**
     * [marksAcceptance] MUST be `true` only when this send is a direct response to a LOCAL user
     * decision to COMMUNICATE with [peer] - an outgoing INVITE/ACCEPT, or a HANGUP for a call [peer]
     * already placed with/for us and this node already accepted (an OUTGOING call, or an INCOMING
     * call already past ringing) - `false` for every automatic, protocol-driven send `CallManager`
     * emits on its own (a BUSY/SDP-policy auto-reject, a ring/connect timeout, or a media-failure
     * hangup) AND for a REJECT or a HANGUP-while-still-ringing, both of which are a decision NOT to
     * communicate with [peer] (round-12 review finding, 2026-09-03 - REJECT/an unanswered HANGUP
     * were wrongly `true` before this fix, letting a REJECT alone promote the sender to accepted
     * contact). See [DmSessionManager.sendCallSignal]'s own doc comment on this same parameter for
     * the full SECURITY reasoning - every caller here must pass it through unchanged, never hardcode
     * either value.
     *
     * [replyRoute] is only an address fallback (V0.9.19); it never changes whether a signal is
     * sent. `null` for an INVITE and whenever no inbound signal from [peer] supplied one; ALWAYS `null` in
     * anonymity mode (V0.10.0-G).
     *
     * @throws RuntimeException on any send failure - `CallManager` catches this generically (it
     * never needs to distinguish transport failure modes, only that a send did or did not succeed)
     * and reports [CallEndReason.LOCAL_ERROR] to any local listener.
     */
    fun send(
        peer: Secp256k1PublicKey,
        payload: ByteArray,
        marksAcceptance: Boolean,
        replyRoute: DmCallReplyRoute?,
    )
}

/**
 * V0.10.0-G: the signal path over circuits failed (recipient not reachable anonymously, or the delivery attempt
 * failed). Fixed text, no cause chain: it carries no address and no circuit id.
 */
class CallSignalPathLostException : RuntimeException("call-signal-path-lost")

/** The production [CallSignalTransport] - a thin adapter over [DmSessionManager.sendCallSignal].
 * Deliberately this thin: all of [DmSessionManager]'s own `@throws` taxonomy
 * (`DmUnknownRecipientException`/`DmNoSessionException`/`DmSessionException`) already extends
 * `RuntimeException`, satisfying [CallSignalTransport.send]'s own contract with no translation
 * needed. */
class DmCallSignalTransport(
    private val dm: DmSessionManager,
) : CallSignalTransport {
    override fun send(
        peer: Secp256k1PublicKey,
        payload: ByteArray,
        marksAcceptance: Boolean,
        replyRoute: DmCallReplyRoute?,
    ) {
        try {
            dm.sendCallSignal(peer, payload, marksAcceptance, replyRoute)
        } catch (e: DmCallSignalPathLostException) {
            throw CallSignalPathLostException()
        } catch (e: DmAnonymousDeliveryException) {
            throw CallSignalPathLostException()
        }
    }
}
