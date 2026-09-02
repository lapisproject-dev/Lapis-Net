package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid

/**
 * A reference to one direct-message attachment: [cid] identifies the content-addressed,
 * AES-256-GCM-encrypted [EncryptedDmAttachmentBlob] stored in Nabu under its own key ([DmAttachmentCipher]
 * / [EncryptedDmAttachmentBlobCodec]), [name]/[mime] are display metadata, [size] is the PLAINTEXT
 * size (checked against the actually-decrypted plaintext at fetch time by
 * [DmAttachmentFetcher.fetchAndDecrypt] - unlike `lapis-net-mail`'s `AttachmentRef.size`, which is
 * declared-only, never verified this wave), and [encryptionKey] is the fresh, per-attachment
 * AES-256 key [DmAttachmentCipher.encrypt] minted for this specific blob.
 *
 * **[encryptionKey] is NON-NULLABLE, unlike `lapis-net-mail`'s `AttachmentRef.encryptionKey`** - a
 * deliberate V0.8.6 design decision (Tesler: one obvious way to do it, no `encrypt: Boolean` toggle
 * for the caller to get wrong). Every DM attachment blob is always encrypted; there is no
 * unencrypted-attachment escape hatch this wave, mirroring the fact that DM messages themselves are
 * always end-to-end encrypted (there is no `EncryptionMode.NONE` equivalent in this module). One
 * accepted, documented consequence: a genuinely empty (0-byte) attachment is not representable this
 * wave (see [DmAttachmentCipher.encrypt]'s own doc comment on why an empty AES-GCM plaintext cannot
 * be stored).
 */
class DmAttachmentRef(
    val cid: Cid,
    val name: String,
    val mime: String,
    val size: Long,
    encryptionKey: ByteArray,
) {
    private val storedEncryptionKey: ByteArray = encryptionKey.copyOf()

    /** Returns a fresh copy on every access. NEVER log this at any log level. */
    val encryptionKey: ByteArray get() = storedEncryptionKey.copyOf()

    init {
        val cidBytes = cid.toBytes()
        require(cidBytes.size in 1..DmContentCodec.MAX_CID_BYTES) {
            "attachment cid must encode to 1..${DmContentCodec.MAX_CID_BYTES} bytes, was ${cidBytes.size}"
        }
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        require(nameBytes.size in 1..DmContentCodec.MAX_ATTACHMENT_NAME_BYTES) {
            "attachment name must be 1..${DmContentCodec.MAX_ATTACHMENT_NAME_BYTES} UTF-8 bytes, was ${nameBytes.size}"
        }
        val mimeBytes = mime.toByteArray(Charsets.UTF_8)
        require(mimeBytes.size in 1..DmContentCodec.MAX_ATTACHMENT_MIME_BYTES) {
            "attachment mime must be 1..${DmContentCodec.MAX_ATTACHMENT_MIME_BYTES} UTF-8 bytes, was ${mimeBytes.size}"
        }
        require(size in 1..DmContentCodec.MAX_DM_ATTACHMENT_BYTES) {
            "attachment size must be 1..${DmContentCodec.MAX_DM_ATTACHMENT_BYTES}, was $size"
        }
        require(storedEncryptionKey.size == DmContentCodec.ATTACHMENT_KEY_SIZE) {
            "attachment encryptionKey must be exactly ${DmContentCodec.ATTACHMENT_KEY_SIZE} bytes"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is DmAttachmentRef &&
            cid == other.cid &&
            name == other.name &&
            mime == other.mime &&
            size == other.size &&
            storedEncryptionKey.contentEquals(other.storedEncryptionKey)

    override fun hashCode(): Int {
        var result = cid.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + mime.hashCode()
        result = 31 * result + size.hashCode()
        result = 31 * result + storedEncryptionKey.contentHashCode()
        return result
    }

    /** Deliberately contains NEITHER [name] (nutzer-/angreifer-kontrollierter Text - a display
     * filename is message content, same "never log message content" rule as [DmContent]'s own
     * `toString`) NOR [encryptionKey]. Diverges from `lapis-net-mail`'s `AttachmentRef.toString()`,
     * which does include the name - see this module's logging-discipline convention. */
    override fun toString(): String = "DmAttachmentRef(cid=$cid, mime=$mime, size=$size)"
}
