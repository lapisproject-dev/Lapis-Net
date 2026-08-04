package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [MessageBody]'s canonical byte encoding fails structurally (bad magic,
 * unsupported version, truncated/overrun buffer, out-of-range field, non-canonical header
 * ordering).
 */
class MalformedMessageBodyException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [MessageBody]. Follows the same length-prefixed
 * sequential layout discipline as [MessageEnvelopeCodec] (magic, version, reserved flags, every
 * variable-length field length-validated BEFORE allocation). All integers are big-endian.
 *
 * There is no `encodeSignedBody`/`contentId` here, unlike [MessageEnvelopeCodec] - a body is not
 * independently signed. It is authenticated transitively: [MessageEnvelope.contentCid] is this
 * blob's CID (see [cidFor]) and is itself covered by the envelope's signature. This is not an
 * omission - see [MessageBody]'s own doc comment.
 *
 * Layout of [encode]'s output: `magic(4) | version(1) | flags(1, bit0 = FLAG_ATTACHMENTS_MAY_HAVE_KEY,
 * all other bits reserved) | subjectLen(2) | subject(subjectLen) | bodyLen(2) | body(bodyLen) |
 * attachmentCount(2) | (cidLen(2) | cid(cidLen) | nameLen(2) | name(nameLen) | mimeLen(2) |
 * mime(mimeLen) | size(8) | [keyPresent(1) | key(32) if keyPresent - ONLY present at all when
 * flags bit0 is set]) * attachmentCount | headerCount(2) | (keyLen(2) | key(keyLen) | valueLen(2)
 * | value(valueLen)) * headerCount`, headers in strictly increasing unsigned-byte key order.
 *
 * **`VERSION` stays `1` for the V0.9.3 attachment-key addition**, mirroring
 * [MessageEnvelopeCodec]'s identical V0.9.2 wrap-section justification: (1) a body with zero keyed
 * attachments encodes byte-identical to V0.9.1/V0.9.2 - [FLAG_ATTACHMENTS_MAY_HAVE_KEY] is only set
 * when at least one attachment carries a key; (2) the new per-attachment `keyPresent`/`key`
 * sub-fields are gated by that already-reserved, now-used flag bit, never silent structural drift;
 * (3) a pre-V0.9.3 decoder cleanly rejects a body that sets the bit via its own pre-existing
 * `if (flags != 0) throw ...` check - a typed rejection, never a misparse.
 */
object MessageBodyCodec {
    private val MAGIC = "LNMB".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val FLAG_ATTACHMENTS_MAY_HAVE_KEY = 0x01

    const val MAX_SUBJECT_BYTES = 512
    const val MAX_MARKDOWN_BYTES = 32_768
    const val MAX_ATTACHMENTS = 16
    const val MAX_ATTACHMENT_NAME_BYTES = 128
    const val MAX_ATTACHMENT_MIME_BYTES = 64

    /** 1 GiB - declared-only, never verified against the actual blob this wave (see
     * [AttachmentRef]'s doc comment). */
    const val MAX_ATTACHMENT_SIZE_BYTES = 1_073_741_824L
    const val MAX_CID_BYTES = 128
    const val MAX_HEADERS = 16
    const val MAX_HEADER_KEY_BYTES = 64
    const val MAX_HEADER_VALUE_BYTES = 512

    /** AES-256 key size for an independently-encrypted attachment (V0.9.3) - see
     * [AttachmentRef.encryptionKey] and [MailAttachmentCipher]. */
    const val ATTACHMENT_KEY_SIZE = 32

    /**
     * Cap on a fully-encoded [MessageBody] blob. Worst-case arithmetic (why the sub-caps above are
     * sized the way they are - a naive choice would overflow this):
     * `512 (subject) + 32768 (markdown) + 16 * (2+128 cid + 2+128 name + 2+64 mime + 8 size + 1
     * keyPresent + 32 key = 367) = 5,872 + 16 * (2+64 key + 2+512 value = 580) = 9,280` → total ≈
     * 48 KB (delta of +528 bytes over the pre-V0.9.3 arithmetic, from the attachment key
     * sub-fields), comfortably under this limit and far under
     * [net.lapisphilosophorum.lapisnet.networking.GossipPubSub]'s 256 KiB gossip message-size
     * ceiling.
     */
    const val MAX_BODY_BLOB_SIZE = 0xFFFF

    fun encode(body: MessageBody): ByteArray {
        val subjectBytes = body.subject.toByteArray(Charsets.UTF_8)
        val bodyBytes = body.body.toByteArray(Charsets.UTF_8)
        val anyKeyed = body.attachments.any { it.encryptionKey != null }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(if (anyKeyed) FLAG_ATTACHMENTS_MAY_HAVE_KEY else 0)
            writeShort(subjectBytes.size)
            write(subjectBytes)
            writeShort(bodyBytes.size)
            write(bodyBytes)
            writeShort(body.attachments.size)
            body.attachments.forEach { attachment ->
                val cidBytes = attachment.cid.toBytes()
                writeShort(cidBytes.size)
                write(cidBytes)
                val nameBytes = attachment.name.toByteArray(Charsets.UTF_8)
                writeShort(nameBytes.size)
                write(nameBytes)
                val mimeBytes = attachment.mime.toByteArray(Charsets.UTF_8)
                writeShort(mimeBytes.size)
                write(mimeBytes)
                writeLong(attachment.size)
                if (anyKeyed) {
                    val key = attachment.encryptionKey
                    writeByte(if (key != null) 1 else 0)
                    // Fixed ATTACHMENT_KEY_SIZE bytes, no length prefix needed - mirrors the
                    // sender(33)/signature(64) fixed-field precedent in MessageEnvelopeCodec.
                    if (key != null) write(key)
                }
            }
            writeShort(body.headers.size)
            body.headers.forEach { (key, value) ->
                val keyBytes = key.toByteArray(Charsets.UTF_8)
                writeShort(keyBytes.size)
                write(keyBytes)
                val valueBytes = value.toByteArray(Charsets.UTF_8)
                writeShort(valueBytes.size)
                write(valueBytes)
            }
        }
        val bytes = out.toByteArray()
        require(
            bytes.size <= MAX_BODY_BLOB_SIZE,
        ) { "encoded body blob exceeds $MAX_BODY_BLOB_SIZE bytes: ${bytes.size}" }
        return bytes
    }

    /**
     * @throws MalformedMessageBodyException if the bytes are structurally invalid, including
     * non-canonical (non-strictly-increasing, unsigned-byte-lexicographic) header key ordering -
     * which also rejects a duplicate key.
     */
    fun decode(bytes: ByteArray): MessageBody {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedMessageBodyException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedMessageBodyException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags and FLAG_ATTACHMENTS_MAY_HAVE_KEY.inv() != 0) {
                throw MalformedMessageBodyException("reserved flag bits must be zero: $flags")
            }
            val attachmentsMayHaveKey = flags and FLAG_ATTACHMENTS_MAY_HAVE_KEY != 0

            val subjectLen = input.readUnsignedShort()
            if (subjectLen > MAX_SUBJECT_BYTES) throw MalformedMessageBodyException("subject too long: $subjectLen")
            val subjectBytes = ByteArray(subjectLen).also { input.readFully(it) }

            val bodyLen = input.readUnsignedShort()
            if (bodyLen > MAX_MARKDOWN_BYTES) throw MalformedMessageBodyException("body too long: $bodyLen")
            val bodyBytes = ByteArray(bodyLen).also { input.readFully(it) }

            val attachmentCount = input.readUnsignedShort()
            if (attachmentCount > MAX_ATTACHMENTS) {
                throw MalformedMessageBodyException("too many attachments: $attachmentCount")
            }
            val attachments =
                (0 until attachmentCount).map {
                    val cidLen = input.readUnsignedShort()
                    if (cidLen !in 1..MAX_CID_BYTES) {
                        throw MalformedMessageBodyException("invalid attachment cid length: $cidLen")
                    }
                    val cidBytes = ByteArray(cidLen).also { buf -> input.readFully(buf) }
                    // Field-length caps above bound the WIRE bytes for this field, not the
                    // multihash length declared INSIDE those bytes - see CidBytesValidation's
                    // class doc comment for why Cid.cast() must never see bytes that fail this.
                    if (!CidBytesValidation.isSafeToCast(cidBytes)) {
                        throw MalformedMessageBodyException("attachment cid declares an unsafe multihash length")
                    }

                    val nameLen = input.readUnsignedShort()
                    if (nameLen !in 1..MAX_ATTACHMENT_NAME_BYTES) {
                        throw MalformedMessageBodyException("invalid attachment name length: $nameLen")
                    }
                    val nameBytes = ByteArray(nameLen).also { buf -> input.readFully(buf) }

                    val mimeLen = input.readUnsignedShort()
                    if (mimeLen !in 1..MAX_ATTACHMENT_MIME_BYTES) {
                        throw MalformedMessageBodyException("invalid attachment mime length: $mimeLen")
                    }
                    val mimeBytes = ByteArray(mimeLen).also { buf -> input.readFully(buf) }

                    val size = input.readLong()
                    if (size !in 0..MAX_ATTACHMENT_SIZE_BYTES) {
                        throw MalformedMessageBodyException("invalid attachment size: $size")
                    }

                    val encryptionKey =
                        if (attachmentsMayHaveKey) {
                            val present = input.readUnsignedByte()
                            if (present !in 0..1) {
                                throw MalformedMessageBodyException("invalid attachment key-present flag: $present")
                            }
                            if (present == 1) {
                                ByteArray(ATTACHMENT_KEY_SIZE).also { buf -> input.readFully(buf) }
                            } else {
                                null
                            }
                        } else {
                            null
                        }

                    AttachmentRef(
                        cid = Cid.cast(cidBytes),
                        name = String(nameBytes, Charsets.UTF_8),
                        mime = String(mimeBytes, Charsets.UTF_8),
                        size = size,
                        encryptionKey = encryptionKey,
                    )
                }

            val headerCount = input.readUnsignedShort()
            if (headerCount > MAX_HEADERS) throw MalformedMessageBodyException("too many headers: $headerCount")
            var previousKey: String? = null
            val headers = LinkedHashMap<String, String>()
            repeat(headerCount) {
                val keyLen = input.readUnsignedShort()
                if (keyLen !in 1..MAX_HEADER_KEY_BYTES) {
                    throw MalformedMessageBodyException("invalid header key length: $keyLen")
                }
                val keyBytes = ByteArray(keyLen).also { buf -> input.readFully(buf) }
                val key = String(keyBytes, Charsets.UTF_8)

                val valueLen = input.readUnsignedShort()
                if (valueLen > MAX_HEADER_VALUE_BYTES) {
                    throw MalformedMessageBodyException("invalid header value length: $valueLen")
                }
                val valueBytes = ByteArray(valueLen).also { buf -> input.readFully(buf) }
                val value = String(valueBytes, Charsets.UTF_8)

                val previous = previousKey
                if (previous != null && compareUnsignedBytes(previous, key) >= 0) {
                    throw MalformedMessageBodyException("headers must be in strictly increasing key order")
                }
                previousKey = key
                headers[key] = value
            }

            if (input.available() > 0) throw MalformedMessageBodyException("trailing bytes after headers")

            return MessageBody(
                subject = String(subjectBytes, Charsets.UTF_8),
                body = String(bodyBytes, Charsets.UTF_8),
                attachments = attachments,
                headers = headers,
            )
        } catch (e: EOFException) {
            throw MalformedMessageBodyException("truncated body bytes", e)
        } catch (e: IOException) {
            throw MalformedMessageBodyException("failed to decode body", e)
        } catch (e: MalformedMessageBodyException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, independent of CidBytesValidation.isSafeToCast's guard above: if
            // some other unforeseen path ever attempts an oversized allocation while decoding a
            // body, this must still surface as a clean malformed-input rejection, never an Error
            // escaping to InboxGossip.onGossipMessage's caller. Deliberately narrow - only
            // OutOfMemoryError, not a blanket Throwable/Error catch, which would risk masking a
            // real JVM problem unrelated to this decode call.
            throw MalformedMessageBodyException("body field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from MessageBody's/AttachmentRef's own init
            // requirements and io.ipfs.cid.Cid.CidEncodingException from Cid.cast() on malformed
            // CID bytes - decode() must never leak an arbitrary third-party exception type.
            throw MalformedMessageBodyException("invalid body field", e)
        }
    }

    /**
     * The [Cid] `NabuStorage.put(bytes)` would return for these exact bytes, computed locally with
     * zero I/O: CIDv1 / raw codec / sha2-256 - exactly what Nabu's `FileBlockstore.put` constructs
     * (`new Cid(1, codec, Multihash.Type.sha2_256, Hash.sha256(block))`). This is what makes
     * [MessageEnvelope.contentCid]'s binding checkable inside a network-free GossipSub validator
     * (see [InboxGossip]'s class doc comment for why the validator must never call
     * `NabuStorage.get()`).
     */
    fun cidFor(bodyBytes: ByteArray): Cid =
        Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, MessageDigest.getInstance("SHA-256").digest(bodyBytes))
}
