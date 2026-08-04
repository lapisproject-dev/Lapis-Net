package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import java.util.SortedMap
import java.util.TreeMap

/**
 * A reference to an attachment blob. [size] is a DECLARED value that is never checked against the
 * referenced blob (V0.9.1 scope cut, still true in V0.9.3).
 *
 * **[encryptionKey] (V0.9.3).** `null` for an unencrypted attachment; a 32-byte AES-256 key for one
 * independently encrypted via [MailAttachmentCipher] - see that object's class doc comment for the
 * "always a fresh key, never the body's HYBRID_ECIES content key" design decision and why it holds
 * regardless of the enclosing [MessageBody]'s own [EncryptionMode]. This is what makes "an
 * unencrypted newsletter with one encrypted PDF attachment" representable: attachment encryption is
 * orthogonal to body encryption, not derived from it.
 */
class AttachmentRef(
    val cid: Cid,
    val name: String,
    val mime: String,
    val size: Long,
    encryptionKey: ByteArray? = null,
) {
    private val storedEncryptionKey: ByteArray? = encryptionKey?.copyOf()

    /** 32-byte AES-256 key for this attachment's independently-encrypted blob (see
     * [MailAttachmentCipher]), or `null` if unencrypted. Returns a fresh copy on every access -
     * never log this at any log level. */
    val encryptionKey: ByteArray? get() = storedEncryptionKey?.copyOf()

    init {
        val cidBytes = cid.toBytes()
        require(cidBytes.size in 1..MessageBodyCodec.MAX_CID_BYTES) {
            "attachment cid must be 1..${MessageBodyCodec.MAX_CID_BYTES} bytes, was ${cidBytes.size}"
        }
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        require(nameBytes.size in 1..MessageBodyCodec.MAX_ATTACHMENT_NAME_BYTES) {
            "attachment name must be 1..${MessageBodyCodec.MAX_ATTACHMENT_NAME_BYTES} UTF-8 bytes, " +
                "was ${nameBytes.size}"
        }
        val mimeBytes = mime.toByteArray(Charsets.UTF_8)
        require(mimeBytes.size in 1..MessageBodyCodec.MAX_ATTACHMENT_MIME_BYTES) {
            "attachment mime must be 1..${MessageBodyCodec.MAX_ATTACHMENT_MIME_BYTES} UTF-8 bytes, " +
                "was ${mimeBytes.size}"
        }
        require(size in 0..MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES) {
            "attachment size must be 0..${MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES}, was $size"
        }
        storedEncryptionKey?.let {
            require(it.size == MessageBodyCodec.ATTACHMENT_KEY_SIZE) {
                "attachment encryptionKey must be exactly ${MessageBodyCodec.ATTACHMENT_KEY_SIZE} bytes " +
                    "(AES-256), was ${it.size}"
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (other !is AttachmentRef) return false
        val keysEqual =
            when {
                storedEncryptionKey == null && other.storedEncryptionKey == null -> true
                storedEncryptionKey != null && other.storedEncryptionKey != null ->
                    storedEncryptionKey.contentEquals(other.storedEncryptionKey)
                else -> false
            }
        return cid == other.cid && name == other.name && mime == other.mime && size == other.size && keysEqual
    }

    override fun hashCode(): Int {
        var result = cid.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + mime.hashCode()
        result = 31 * result + size.hashCode()
        result = 31 * result + (storedEncryptionKey?.contentHashCode() ?: 0)
        return result
    }

    /** Never includes the key bytes themselves - only whether one is present. */
    override fun toString(): String =
        "AttachmentRef(cid=$cid, name=$name, mime=$mime, size=$size, encrypted=${storedEncryptionKey != null})"
}

/**
 * The payload half of a mail message, stored as its own Nabu blob. [MessageEnvelope.contentCid] is
 * this blob's CID and is covered by the envelope signature - so this type carries NO signature of
 * its own: it is authenticated transitively, through the CID binding, by whoever signed the
 * envelope. [body] is Markdown and is stored verbatim: it is NOT rendered, sanitized, or otherwise
 * interpreted here - that is a browser-UI concern for a later wave (V0.9.3).
 */
class MessageBody(
    val subject: String,
    val body: String,
    attachments: List<AttachmentRef> = emptyList(),
    headers: Map<String, String> = emptyMap(),
) {
    /** Immutable snapshot - safe from later mutation of any list the caller passed in. */
    val attachments: List<AttachmentRef> = attachments.toList()

    /** Canonicalized: sorted by key's UTF-8 byte order, so the encoding - and therefore the CID
     * the envelope signs - is a pure function of the logical content, independent of the caller's
     * map insertion order. */
    val headers: SortedMap<String, String> =
        TreeMap<String, String>(Comparator { a, b -> compareUnsignedBytes(a, b) }).apply { putAll(headers) }

    init {
        require(subject.toByteArray(Charsets.UTF_8).size <= MessageBodyCodec.MAX_SUBJECT_BYTES) {
            "subject must be at most ${MessageBodyCodec.MAX_SUBJECT_BYTES} UTF-8 bytes"
        }
        require(body.toByteArray(Charsets.UTF_8).size <= MessageBodyCodec.MAX_MARKDOWN_BYTES) {
            "body must be at most ${MessageBodyCodec.MAX_MARKDOWN_BYTES} UTF-8 bytes"
        }
        require(this.attachments.size <= MessageBodyCodec.MAX_ATTACHMENTS) {
            "at most ${MessageBodyCodec.MAX_ATTACHMENTS} attachments allowed, was ${this.attachments.size}"
        }
        require(this.headers.size <= MessageBodyCodec.MAX_HEADERS) {
            "at most ${MessageBodyCodec.MAX_HEADERS} headers allowed, was ${this.headers.size}"
        }
        this.headers.forEach { (key, value) ->
            val keyBytes = key.toByteArray(Charsets.UTF_8)
            require(keyBytes.size in 1..MessageBodyCodec.MAX_HEADER_KEY_BYTES) {
                "header key must be 1..${MessageBodyCodec.MAX_HEADER_KEY_BYTES} UTF-8 bytes, was ${keyBytes.size}"
            }
            val valueBytes = value.toByteArray(Charsets.UTF_8)
            require(valueBytes.size <= MessageBodyCodec.MAX_HEADER_VALUE_BYTES) {
                "header value must be at most ${MessageBodyCodec.MAX_HEADER_VALUE_BYTES} UTF-8 bytes, " +
                    "was ${valueBytes.size}"
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is MessageBody &&
            subject == other.subject &&
            body == other.body &&
            attachments == other.attachments &&
            headers == other.headers

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + body.hashCode()
        result = 31 * result + attachments.hashCode()
        result = 31 * result + headers.hashCode()
        return result
    }

    /** Deliberately does NOT include [subject] or [body] content, only their lengths - this type
     * is routinely logged/debugged and its content is user-authored message text. */
    override fun toString(): String =
        "MessageBody(subjectBytes=${subject.toByteArray(Charsets.UTF_8).size}, " +
            "bodyBytes=${body.toByteArray(Charsets.UTF_8).size}, attachments=${attachments.size}, " +
            "headers=${headers.size})"
}

/** Unsigned-byte-array lexicographic comparison of two strings' UTF-8 encodings - matches how
 * [MessageBodyCodec.decode] validates header ordering byte-for-byte. */
internal fun compareUnsignedBytes(
    a: String,
    b: String,
): Int {
    val aBytes = a.toByteArray(Charsets.UTF_8)
    val bBytes = b.toByteArray(Charsets.UTF_8)
    val minLength = minOf(aBytes.size, bBytes.size)
    for (i in 0 until minLength) {
        val diff = (aBytes[i].toInt() and 0xFF) - (bBytes[i].toInt() and 0xFF)
        if (diff != 0) return diff
    }
    return aBytes.size - bBytes.size
}
