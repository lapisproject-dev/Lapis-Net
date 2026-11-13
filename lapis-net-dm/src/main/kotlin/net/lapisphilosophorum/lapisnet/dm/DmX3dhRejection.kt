package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey

/** Why a responder refused a first-contact `X3DH_INITIAL` (wire byte in [DmX3dhRejectionCodec]'s layout). */
enum class DmX3dhRejectionReason(
    val wireValue: Byte,
) {
    ONE_TIME_PREKEY_CONSUMED(1),
    ONE_TIME_PREKEY_UNKNOWN(2),
    SIGNED_PREKEY_MISMATCH(3),
    ;

    companion object {
        fun fromWireValue(value: Byte): DmX3dhRejectionReason? = entries.firstOrNull { it.wireValue == value }
    }
}

/**
 * An authenticated refusal of one specific `X3DH_INITIAL` (wire type [DmMessageType.X3DH_REJECTED]): the responder
 * [rejecterIdentity] tells the initiator that the handshake with ephemeral key [rejectedEphemeralPublicKey] could not
 * be accepted for [reason]. The [tag] is an HMAC-SHA256 under a key derived from the static X25519 identity DH of the
 * two parties (see [DmX3dhRejectionCodec.computeTag]): deniable (either party could have computed it), unforgeable
 * for anyone holding neither identity key.
 *
 * Structural validity only - a decoded instance is NOT yet authenticated; the receiver must call
 * [DmX3dhRejectionCodec.verifyTag] (after its cheaper state checks) before acting on it.
 */
class DmX3dhRejection internal constructor(
    val rejecterIdentity: Secp256k1PublicKey,
    val rejectedEphemeralPublicKey: X25519PublicKey,
    val signedPrekeyId: Int,
    val oneTimePrekeyId: Int?,
    val reason: DmX3dhRejectionReason,
    val issuedAtEpochSecond: Long,
    tag: ByteArray,
) {
    private val storedTag = tag.copyOf()

    /** Fresh copy on every access. */
    val tag: ByteArray get() = storedTag.copyOf()

    init {
        require(
            storedTag.size == DmX3dhRejectionCodec.TAG_SIZE,
        ) { "tag must be ${DmX3dhRejectionCodec.TAG_SIZE} bytes" }
        require(signedPrekeyId >= 0) { "signedPrekeyId must be >= 0" }
        require(oneTimePrekeyId == null || oneTimePrekeyId >= 0) { "oneTimePrekeyId must be null or >= 0" }
    }

    /** Never prints keys, the tag or the identity. */
    override fun toString(): String = "DmX3dhRejection(reason=$reason, otkPresent=${oneTimePrekeyId != null})"
}
