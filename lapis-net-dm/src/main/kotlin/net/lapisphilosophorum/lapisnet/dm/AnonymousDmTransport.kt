package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.time.Instant

/**
 * V0.10.0-F1: the transport seam of anonymity-mode direct messages. `lapis-net-dm` knows nothing
 * about onion circuits; the `lapis-net-dm-onion` adapter implements this interface on top of the
 * anonymity runtime. [DmSessionManager] drives it in a fixed order (see
 * [DmSessionManager.sendAuto]): [resolve] first - before any session work, so a refusal can never
 * leave a phantom session behind - then [deliverOnline] or, on failure, [depositOffline] with the
 * SAME already-encrypted envelope.
 */
interface AnonymousDmTransport {
    /** Resolves [recipient] to an opaque target, or throws [DmAnonymousDeliveryException]. */
    fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget

    /**
     * Online delivery through an introduction point and a rendezvous stream. Returns `true` only
     * after a transport-level acknowledgement; `false` means "online failed". Never throws.
     */
    fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean

    /**
     * Seals and queues the envelope for repeated announcement through circuits. Does not throw after
     * a successful [resolve]; a throttled governor only delays the announcement.
     */
    fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    )

    fun close()
}

/**
 * Opaque resolution result. [sealingKey] is the recipient's X25519 identity key from its prekey
 * bundle, used to seal offline mailbox items; [online] says whether a service descriptor was found.
 * [toString] is redacted.
 */
class AnonymousDmTarget(
    val recipient: Secp256k1PublicKey,
    val sealingKey: X25519PublicKey,
    val handle: Any?,
    val online: Boolean,
) {
    override fun toString(): String = "AnonymousDmTarget(REDACTED)"
}

/**
 * V0.10.0-F1: the only inbound doors of anonymity-mode DMs. Both funnel into the single
 * `processInboundDmEnvelope` pipeline (dedup, X3DH replay register, prekey rate limiter, ratchet
 * AEAD, acceptance policy). Neither ever throws.
 */
interface DmInboundSink {
    /** An envelope that arrived on a rendezvous stream. */
    fun acceptCircuitEnvelope(envelopeBytes: ByteArray)

    /** A sealed mailbox item announced on the shared topic; silently dropped unless it opens. */
    fun acceptSealedMailboxItem(itemBytes: ByteArray)
}
