package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/** Sizes of the fixed-width fields in an [EciesWrap]'s wire encoding. */
internal const val EPHEMERAL_PUBLIC_KEY_SIZE = 33
internal const val CONTENT_KEY_SIZE = 32
internal const val GCM_TAG_SIZE = 16
internal const val WRAPPED_KEY_SIZE = CONTENT_KEY_SIZE + GCM_TAG_SIZE // 48, fixed
internal const val ECIES_WRAP_SIZE = EPHEMERAL_PUBLIC_KEY_SIZE + WRAPPED_KEY_SIZE // 81

/**
 * One recipient's (or the sender's own) AES-256-GCM-wrapped copy of a [HybridEcies]-sealed
 * message's content key.
 *
 * **`wrappedKey` is fixed-width (48 bytes = 32-byte content key + 16-byte GCM tag) - there is no
 * length field for it.** The plaintext being wrapped is always exactly the 32-byte content key, so
 * the ciphertext+tag length is a compile-time constant. This codec has zero attacker-controlled
 * length fields at the wrap level, strictly stronger than the check-then-allocate discipline a
 * variable-length field would require - it follows the `sender(33)`/`signature(64)` fixed-field
 * precedent in [MessageEnvelopeCodec].
 *
 * **The wrap's AES-GCM nonce is deliberately absent from this type and from the wire.** It is
 * HKDF-derived (see [HybridEcies]'s class doc comment for the exact construction) rather than
 * transmitted - so there are zero attacker-controlled nonce bytes here to defend against at the
 * codec level.
 *
 * **`ephemeralPublicKey` is deliberately repeated identically across every wrap in one envelope.**
 * [HybridEcies.seal] generates exactly one ephemeral keypair per call and reuses it for all
 * `recipients.size + 1` slots (see that class's doc comment), so an N-recipient envelope's wrap
 * section carries the same 33-byte value N+1 times rather than storing it once at the envelope
 * level. This is not an oversight: keeping the field per-wrap makes [EciesWrap] self-contained -
 * [EciesWrapCodec.decodeFrom] and [MessageEnvelope]'s constructor impose no rule that every wrap in
 * a list share one ephemeral key, which leaves room for a future per-recipient-ephemeral variant
 * without a wire-format change to this type. It is not a security concern either: [aadForWrap]
 * binds each slot to its own `wrap.ephemeralPublicKey`, so a list mixing keys simply fails to open,
 * it does not open incorrectly. The cost is real, though - at [MessageEnvelopeCodec.MAX_RECIPIENTS]
 * (64) this repeats one 33-byte value 65 times, 2,145 of the 5,267-byte wrap section (~41%). Any
 * byte-budget arithmetic derived from the 81-byte per-wrap record (docs/architecture.adoc,
 * [MessageEnvelopeCodec]'s class doc comment) should keep this redundancy in mind.
 */
class EciesWrap(
    val ephemeralPublicKey: Secp256k1PublicKey,
    wrappedKey: ByteArray,
) {
    private val storedWrappedKey: ByteArray = wrappedKey.copyOf()

    /** Returns a fresh copy on every access. Never log these bytes at any log level. */
    val wrappedKey: ByteArray get() = storedWrappedKey.copyOf()

    init {
        require(storedWrappedKey.size == WRAPPED_KEY_SIZE) {
            "wrappedKey must be exactly $WRAPPED_KEY_SIZE bytes (content key + GCM tag), " +
                "was ${storedWrappedKey.size}"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is EciesWrap &&
            ephemeralPublicKey == other.ephemeralPublicKey &&
            storedWrappedKey.contentEquals(other.storedWrappedKey)

    override fun hashCode(): Int {
        var result = ephemeralPublicKey.hashCode()
        result = 31 * result + storedWrappedKey.contentHashCode()
        return result
    }

    /** Never includes wrappedKey bytes - only the ephemeral key's fingerprint. */
    override fun toString(): String = "EciesWrap(ephemeral=${ephemeralPublicKey.fingerprint()})"
}
