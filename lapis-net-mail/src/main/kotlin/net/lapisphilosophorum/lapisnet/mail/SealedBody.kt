package net.lapisphilosophorum.lapisnet.mail

/** GCM nonce size for the sealed-body AEAD - 96 bits, matching [KeystoreEncryption]'s
 * `NONCE_SIZE` precedent in `lapis-net-identity`. */
internal const val GCM_NONCE_SIZE = 12

/**
 * The AES-256-GCM-encrypted form of a [MessageBody], stored as its own Nabu blob and carried in
 * the [MailFrameCodec] frame's body section - exactly where the plaintext `MessageBody` blob sits
 * for [EncryptionMode.NONE], so [MessageEnvelope.contentCid] and [InboxGossip]'s CID-binding check
 * work unchanged for both modes: `cidFor` is a pure function of raw bytes, sealed or not.
 *
 * Unlike [EciesWrap]'s wrap nonce (HKDF-derived, never transmitted - see [HybridEcies]'s class doc
 * comment for why that asymmetry is deliberate), [nonce] here IS an explicit, random, transmitted
 * field: the content key is chosen by the sender and is not tied to any freshly-generated
 * asymmetric key, so an explicit per-message random nonce is the belt-and-braces choice for this
 * layer.
 */
class SealedBody(
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
        require(storedNonce.size == GCM_NONCE_SIZE) { "sealed-body nonce must be $GCM_NONCE_SIZE bytes" }
        require(storedCiphertext.size in (GCM_TAG_SIZE + 1)..SealedBodyCodec.MAX_CIPHERTEXT_BYTES) {
            "sealed-body ciphertext must be ${GCM_TAG_SIZE + 1}..${SealedBodyCodec.MAX_CIPHERTEXT_BYTES} bytes, " +
                "was ${storedCiphertext.size}"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is SealedBody &&
            storedNonce.contentEquals(other.storedNonce) &&
            storedCiphertext.contentEquals(other.storedCiphertext)

    override fun hashCode(): Int {
        var result = storedNonce.contentHashCode()
        result = 31 * result + storedCiphertext.contentHashCode()
        return result
    }

    /** Never includes nonce or ciphertext content - lengths only. */
    override fun toString(): String = "SealedBody(ciphertextBytes=${storedCiphertext.size})"
}
