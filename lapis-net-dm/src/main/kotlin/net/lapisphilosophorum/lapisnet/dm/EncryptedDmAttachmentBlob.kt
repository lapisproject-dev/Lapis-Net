package net.lapisphilosophorum.lapisnet.dm

/** GCM nonce size, bytes - `lapis-net-ratchet`'s identically-named constant is `internal` and
 * invisible across the module boundary, so duplicated here, mirroring how `lapis-net-mail`'s
 * `SealedBody.kt` does the identical thing for its own module. */
internal const val DM_GCM_NONCE_SIZE = 12

/** GCM authentication tag size, bytes - see [DM_GCM_NONCE_SIZE]'s doc comment for why this is
 * duplicated rather than imported. */
internal const val DM_GCM_TAG_SIZE = 16

/**
 * The AES-256-GCM-encrypted form of one DM attachment's raw bytes, stored as its OWN Nabu blob under
 * its OWN CID - never gossiped, never embedded in [DmEnvelopeCodec]'s frame. Produced by
 * [DmAttachmentCipher.encrypt], consumed by [DmAttachmentCipher.decrypt]. Structurally identical to
 * `lapis-net-mail`'s `EncryptedAttachmentBlob` - see [EncryptedDmAttachmentBlobCodec]'s class doc
 * comment for why this is a deliberately separate type (`"LNDA"` magic, distinct AAD domain), not a
 * reuse of the mail one.
 */
class EncryptedDmAttachmentBlob(
    nonce: ByteArray,
    ciphertext: ByteArray,
) {
    private val storedNonce: ByteArray = nonce.copyOf()
    private val storedCiphertext: ByteArray = ciphertext.copyOf()

    /** Returns a fresh copy on every access. */
    val nonce: ByteArray get() = storedNonce.copyOf()

    /** Returns a fresh copy on every access. Includes the trailing 16-byte GCM tag. */
    val ciphertext: ByteArray get() = storedCiphertext.copyOf()

    init {
        require(
            storedNonce.size == DM_GCM_NONCE_SIZE,
        ) { "encrypted DM-attachment nonce must be $DM_GCM_NONCE_SIZE bytes" }
        require(storedCiphertext.size in (DM_GCM_TAG_SIZE + 1)..EncryptedDmAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES) {
            "encrypted DM-attachment ciphertext must be ${DM_GCM_TAG_SIZE + 1}.." +
                "${EncryptedDmAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES} bytes, was ${storedCiphertext.size}"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is EncryptedDmAttachmentBlob &&
            storedNonce.contentEquals(other.storedNonce) &&
            storedCiphertext.contentEquals(other.storedCiphertext)

    override fun hashCode(): Int {
        var result = storedNonce.contentHashCode()
        result = 31 * result + storedCiphertext.contentHashCode()
        return result
    }

    /** Never includes nonce or ciphertext content - lengths only. */
    override fun toString(): String = "EncryptedDmAttachmentBlob(ciphertextBytes=${storedCiphertext.size})"
}
