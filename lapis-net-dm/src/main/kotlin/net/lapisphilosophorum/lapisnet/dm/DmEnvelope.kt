package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessage
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader

/** Thrown when decoding a [DmEnvelope]'s canonical byte encoding fails structurally. Never thrown
 * for AEAD/ratchet-decryption failures - those are
 * [net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetException]/
 * [net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageRejectedException], raised one layer up in
 * [DmSessionManager] once a structurally-valid envelope's embedded [RatchetMessage] is actually
 * decrypted. Mirrors [net.lapisphilosophorum.lapisnet.ratchet.MalformedRatchetMessageException]'s
 * identical structural-only contract. */
class MalformedDmEnvelopeException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * The outer wire frame for one 1:1 direct message sent over [DmProtocol]'s
 * `/lapis/dm/1.1.0` stream: a [messageType] discriminator, the claimed [senderIdentity], an
 * optional [x3dhInitialHeader] (present iff this is a first-contact handshake message), and the
 * [RatchetMessage] that actually carries the encrypted application payload.
 *
 * **`internal` constructor - only [DmEnvelopeCodec.decode] and [DmSessionManager]'s own outbound-
 * send path build one** - mirrors [RatchetMessage]'s own internal-ctor discipline: a caller outside
 * this module can never hand-construct an envelope that skipped either codec's validation.
 *
 * **CRITICAL IDENTITY-AUTHORITY NOTE, stated here because this is the type where the claim
 * originates.** [senderIdentity] is an UNTRUSTED CLAIM the moment this envelope arrives off the
 * wire (see [DmEnvelopeCodec.decode]) - it selects which session [DmSessionManager] attempts to
 * decrypt under, nothing more. It is NEVER the same thing as the libp2p `PeerId` the transport
 * connection that carried these bytes authenticated (via Noise) - a `PeerId` and a secp256k1
 * identity are two completely separate identity spaces in this codebase, and [DmProtocol]/
 * [DmSessionManager] never let the two be confused. [senderIdentity] only becomes trustworthy once
 * [DmSessionManager.handleInboundEnvelope]'s [RatchetMessage] decryption succeeds under a session
 * that was itself bootstrapped, via a real X3DH exchange, with THIS exact identity - see that
 * function's own doc comment for the full argument.
 */
class DmEnvelope internal constructor(
    val messageType: DmMessageType,
    val senderIdentity: Secp256k1PublicKey,
    val x3dhInitialHeader: X3dhPreKeyMessageHeader?,
    val ratchetMessage: RatchetMessage,
) {
    init {
        require(messageType != DmMessageType.RECEIPT) {
            "messageType RECEIPT is reserved and rejected outright"
        }
        require((messageType == DmMessageType.X3DH_INITIAL) == (x3dhInitialHeader != null)) {
            "x3dhInitialHeader must be present iff messageType is X3DH_INITIAL"
        }
        // No separate x3dhInitiatorIdentity wire field exists (see DmEnvelopeCodec's class doc
        // comment) - the X3DH initiator IS this envelope's own senderIdentity by construction. This
        // check keeps that invariant true for every DmEnvelope this module ever constructs, not just
        // ones that survived a round trip through the codec.
        require(x3dhInitialHeader == null || x3dhInitialHeader.initiatorIdentity == senderIdentity) {
            "x3dhInitialHeader.initiatorIdentity must equal senderIdentity"
        }
        // V0.8.7: a CALL_SIGNAL envelope never carries an X3DH header - a call signal is only ever
        // sent over an ALREADY-established session (see DmSessionManager.sendCallSignal, which never
        // bootstraps one). This is already implied by the x3dhInitialHeader-iff-X3DH_INITIAL check
        // above (CALL_SIGNAL != X3DH_INITIAL, so x3dhInitialHeader must be null), stated here
        // explicitly rather than left as an inference: a call never begins a first contact.
    }

    override fun toString(): String =
        "DmEnvelope(messageType=$messageType, senderIdentity=${senderIdentity.fingerprint()}, " +
            "hasX3dhInitialHeader=${x3dhInitialHeader != null})"
}
