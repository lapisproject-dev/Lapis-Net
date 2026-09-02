package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/** Thrown when decoding a [DmContent]'s canonical byte encoding fails structurally. Never thrown
 * for AEAD/ratchet failures - by the time these bytes are ever decoded, `DoubleRatchetSession.decrypt`
 * has already succeeded (see [DmSessionManager.processInboundDmEnvelope]'s own doc comment on
 * ordering: session persistence happens BEFORE this decode is even attempted). */
class MalformedDmContentException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [DmContent] - V0.8.6. This is what
 * `DoubleRatchetSession.encrypt`/`decrypt` treat as an opaque plaintext payload: [encode]'s output
 * IS the ratchet plaintext, [decode] runs on the plaintext `session.decrypt` already returned.
 *
 * **No [DmEnvelopeCodec]/wire-format-version bump was needed for this addition** - the ratchet
 * plaintext was already an opaque byte string as far as [DmEnvelopeCodec]/[DmMessageType] are
 * concerned (`messageType` stays `TEXT`/`X3DH_INITIAL`); this codec's own framing lives entirely
 * INSIDE that opaque plaintext, invisible to every layer below it. `docs/roadmap.adoc` documents the
 * one wire-level change this wave DOES make: the OUTER stream-protocol id bumped to
 * `/lapis/dm/1.1.0` (see [DmProtocol.DM_PROTOCOL_ID]) - a deliberate, breaking, undocumented-fallback
 * cut, not a codec concern.
 *
 * Layout (big-endian, same check-before-allocate discipline as every other codec in this codebase):
 * ```
 * magic(4) "LNDC" | version(1)=0x01 | kind(1) | flags(1) |
 * bodyLen(2) | body(bodyLen) |
 * [ attachmentCount(2) | ( cidLen(2)|cid | nameLen(2)|name | mimeLen(2)|mime | size(8) | key(32) ) * count ]
 *   -- only present when kind == TEXT_WITH_ATTACHMENTS
 * [ preimage(32) | paymentHash(32) | amountMsat(8) | invoiceLen(2) | invoice(invoiceLen) ]
 *   -- only present when flags bit0 (FLAG_FIRST_CONTACT_DEPOSIT) is set
 * ```
 *
 * **`MAGIC` is NOT a security boundary here** - unlike every codec whose `decode()` is reachable
 * directly off an untrusted wire (e.g. [DmEnvelopeCodec], `MessageBodyCodec`), this codec only ever
 * runs on bytes a real AEAD has already authenticated. The magic/version bytes exist purely for
 * consistency with this codebase's other codecs and to fail LOUDLY (a clean, typed exception) on a
 * version/kind mismatch rather than silently misparsing, never as a tamper-detection mechanism.
 */
object DmContentCodec {
    private val MAGIC = "LNDC".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 0x01
    private const val FLAG_FIRST_CONTACT_DEPOSIT = 0x01

    const val MAX_DM_BODY_BYTES = 32_768
    const val MAX_DM_ATTACHMENTS = 4
    const val MAX_DM_ATTACHMENT_BYTES = 16_777_216L // 16 MiB
    const val MAX_DM_ATTACHMENT_TOTAL_BYTES = 33_554_432L // 32 MiB
    const val MAX_ATTACHMENT_NAME_BYTES = 128
    const val MAX_ATTACHMENT_MIME_BYTES = 64
    const val MAX_CID_BYTES = 128
    const val ATTACHMENT_KEY_SIZE = 32
    const val MAX_SIGNED_INVOICE_BYTES = 2048

    /** Hard ceiling: what [encode] produces must fit through `DoubleRatchetSession.encrypt` - see
     * this object's class doc comment. Worst case: `4+1+1+1 (header) + 2+32768 (body) + 2 +
     * 4*(2+128+2+128+2+64+8+32=366)=1464 (attachments) + (32+32+8+2+2048=2122) (deposit) ≈ 36,390`
     * bytes - comfortably under [RatchetMessageCodec.MAX_PLAINTEXT_BYTES] (65,459). */
    const val MAX_CONTENT_BYTES = RatchetMessageCodec.MAX_PLAINTEXT_BYTES

    fun encode(content: DmContent): ByteArray {
        val bodyBytes = content.body.toByteArray(Charsets.UTF_8)
        val deposit = content.firstContactDeposit
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(content.kind.wireValue.toInt())
            writeByte(if (deposit != null) FLAG_FIRST_CONTACT_DEPOSIT else 0)
            writeShort(bodyBytes.size)
            write(bodyBytes)
            if (content.kind == DmContentKind.TEXT_WITH_ATTACHMENTS) {
                writeShort(content.attachments.size)
                content.attachments.forEach { attachment ->
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
                    write(attachment.encryptionKey)
                }
            }
            if (deposit != null) {
                write(deposit.preimage)
                write(deposit.paymentHash)
                writeLong(deposit.requiredAmountMsat)
                val invoiceBytes = deposit.signedInvoice.toByteArray(Charsets.US_ASCII)
                writeShort(invoiceBytes.size)
                write(invoiceBytes)
            }
        }
        val bytes = out.toByteArray()
        require(bytes.size <= MAX_CONTENT_BYTES) {
            "encoded DmContent (${bytes.size} bytes) exceeds the $MAX_CONTENT_BYTES-byte ratchet plaintext budget"
        }
        return bytes
    }

    /** @throws MalformedDmContentException if the bytes are structurally invalid. */
    fun decode(bytes: ByteArray): DmContent {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedDmContentException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedDmContentException("unsupported version $version")

            val kindByte = input.readByte()
            val kind =
                DmContentKind.fromWireValue(kindByte)
                    ?: throw MalformedDmContentException("unknown DmContent kind $kindByte")

            val flags = input.readUnsignedByte()
            if (flags and FLAG_FIRST_CONTACT_DEPOSIT.inv() != 0) {
                throw MalformedDmContentException("reserved flag bits must be zero: $flags")
            }
            val hasDeposit = flags and FLAG_FIRST_CONTACT_DEPOSIT != 0

            val bodyLen = input.readUnsignedShort()
            if (bodyLen > MAX_DM_BODY_BYTES) throw MalformedDmContentException("body too long: $bodyLen")
            val bodyBytes = ByteArray(bodyLen).also { input.readFully(it) }

            val attachments = mutableListOf<DmAttachmentRef>()
            if (kind == DmContentKind.TEXT_WITH_ATTACHMENTS) {
                val attachmentCount = input.readUnsignedShort()
                if (attachmentCount > MAX_DM_ATTACHMENTS) {
                    throw MalformedDmContentException("too many attachments: $attachmentCount")
                }
                repeat(attachmentCount) {
                    val cidLen = input.readUnsignedShort()
                    if (cidLen !in 1..MAX_CID_BYTES) {
                        throw MalformedDmContentException("invalid attachment cid length: $cidLen")
                    }
                    val cidBytes = ByteArray(cidLen).also { buf -> input.readFully(buf) }
                    if (!CidBytesValidation.isSafeToCast(cidBytes)) {
                        throw MalformedDmContentException("attachment cid declares an unsafe multihash length")
                    }

                    val nameLen = input.readUnsignedShort()
                    if (nameLen !in 1..MAX_ATTACHMENT_NAME_BYTES) {
                        throw MalformedDmContentException("invalid attachment name length: $nameLen")
                    }
                    val nameBytes = ByteArray(nameLen).also { buf -> input.readFully(buf) }

                    val mimeLen = input.readUnsignedShort()
                    if (mimeLen !in 1..MAX_ATTACHMENT_MIME_BYTES) {
                        throw MalformedDmContentException("invalid attachment mime length: $mimeLen")
                    }
                    val mimeBytes = ByteArray(mimeLen).also { buf -> input.readFully(buf) }

                    val size = input.readLong()
                    if (size !in 1..MAX_DM_ATTACHMENT_BYTES) {
                        throw MalformedDmContentException("invalid attachment size: $size")
                    }

                    val key = ByteArray(ATTACHMENT_KEY_SIZE).also { buf -> input.readFully(buf) }

                    attachments +=
                        DmAttachmentRef(
                            cid = Cid.cast(cidBytes),
                            name = String(nameBytes, Charsets.UTF_8),
                            mime = String(mimeBytes, Charsets.UTF_8),
                            size = size,
                            encryptionKey = key,
                        )
                }
            }

            val deposit =
                if (hasDeposit) {
                    val preimage = ByteArray(DmFirstContactDeposit.PREIMAGE_SIZE).also { input.readFully(it) }
                    val paymentHash = ByteArray(DmFirstContactDeposit.PAYMENT_HASH_SIZE).also { input.readFully(it) }
                    val amountMsat = input.readLong()
                    val invoiceLen = input.readUnsignedShort()
                    if (invoiceLen !in 1..MAX_SIGNED_INVOICE_BYTES) {
                        throw MalformedDmContentException("invalid signed invoice length: $invoiceLen")
                    }
                    val invoiceBytes = ByteArray(invoiceLen).also { buf -> input.readFully(buf) }
                    DmFirstContactDeposit(
                        preimage = preimage,
                        paymentHash = paymentHash,
                        signedInvoice = String(invoiceBytes, Charsets.US_ASCII),
                        requiredAmountMsat = amountMsat,
                    )
                } else {
                    null
                }

            if (input.available() > 0) throw MalformedDmContentException("trailing bytes after DmContent")

            return DmContent(
                body = String(bodyBytes, Charsets.UTF_8),
                attachments = attachments,
                firstContactDeposit = deposit,
            )
        } catch (e: EOFException) {
            throw MalformedDmContentException("truncated DmContent bytes", e)
        } catch (e: IOException) {
            throw MalformedDmContentException("failed to decode DmContent", e)
        } catch (e: MalformedDmContentException) {
            throw e
        } catch (e: OutOfMemoryError) {
            throw MalformedDmContentException("DmContent field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            throw MalformedDmContentException("invalid DmContent field", e)
        }
    }
}
