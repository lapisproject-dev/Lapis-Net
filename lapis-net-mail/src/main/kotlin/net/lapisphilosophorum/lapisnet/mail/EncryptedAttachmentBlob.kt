package net.lapisphilosophorum.lapisnet.mail

/**
 * The AES-256-GCM-encrypted form of one attachment's raw bytes, stored as its OWN Nabu blob under
 * its OWN CID - unlike [SealedBody], which rides inside the [MailFrameCodec] gossip frame, this
 * blob is never gossiped and never embedded in a frame (see [EncryptedAttachmentBlobCodec]'s class
 * doc comment for why it therefore uses a 32-bit, not 16-bit, ciphertext-length field). Produced by
 * [MailAttachmentCipher.encrypt], consumed by [MailAttachmentCipher.decrypt].
 */
class EncryptedAttachmentBlob(
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
        require(storedNonce.size == GCM_NONCE_SIZE) { "encrypted-attachment nonce must be $GCM_NONCE_SIZE bytes" }
        require(storedCiphertext.size in (GCM_TAG_SIZE + 1)..EncryptedAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES) {
            "encrypted-attachment ciphertext must be ${GCM_TAG_SIZE + 1}.." +
                "${EncryptedAttachmentBlobCodec.MAX_CIPHERTEXT_BYTES} bytes, was ${storedCiphertext.size}"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is EncryptedAttachmentBlob &&
            storedNonce.contentEquals(other.storedNonce) &&
            storedCiphertext.contentEquals(other.storedCiphertext)

    override fun hashCode(): Int {
        var result = storedNonce.contentHashCode()
        result = 31 * result + storedCiphertext.contentHashCode()
        return result
    }

    /** Never includes nonce or ciphertext content - lengths only. */
    override fun toString(): String = "EncryptedAttachmentBlob(ciphertextBytes=${storedCiphertext.size})"
}
