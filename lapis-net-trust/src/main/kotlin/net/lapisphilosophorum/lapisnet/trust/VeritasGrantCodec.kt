package net.lapisphilosophorum.lapisnet.trust

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [VeritasGrant]'s canonical byte encoding fails structurally (bad magic,
 * unsupported version, truncated/overrun buffer, out-of-range field). Never thrown for signature
 * verification failures - [VeritasGrantCodec.decode] does not verify signatures, see its doc
 * comment.
 */
class MalformedVeritasGrantException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [VeritasGrant] - used both to build the digest that
 * gets signed and to compute a grant's content id (what a successor's backward-hash link points
 * to). Unlike [net.lapisphilosophorum.lapisnet.identity.KeystoreFileFormat]'s fixed-offset binary
 * layout, a grant has variable-length fields (comment, occasion references, optional predecessor
 * link), so this uses a sequential length-prefixed layout instead. All integers are big-endian.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4) | version(1) | flags(1) | truster(33) |
 * target(33) | trustMicros(4) | previousGrantId(32, only if flags bit0 set) | commentLen(2) |
 * comment(commentLen) | occasionCount(2) | (cidLen(2) | cid(cidLen)) * occasionCount`.
 * [encode] appends the 64-byte signature after that.
 */
object VeritasGrantCodec {
    private val MAGIC = "LNVG".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val FLAG_HAS_PREVIOUS = 0x01
    private const val CONTENT_ID_SIZE = 32
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64

    /** Cap on the comment's UTF-8 byte length - see [MAX_BODY_SIZE] for why this exists. */
    const val MAX_COMMENT_BYTES = 8192

    /** Cap on the number of occasion references per grant - see [MAX_BODY_SIZE]. */
    const val MAX_OCCASION_REFERENCES = 256
    private const val MAX_CID_BYTES = 128

    /** [domainSeparatedDigest][net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]
     * treats the whole signed body as a single part, capped at this size. [MAX_COMMENT_BYTES] and
     * [MAX_OCCASION_REFERENCES] are chosen so a body can never exceed it (worst case: ~8 KB
     * comment + 256 * ~130 B references ≈ 41 KB, well under the limit). */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see [VeritasGrant.create]. */
    fun encodeSignedBody(
        truster: Secp256k1PublicKey,
        target: Secp256k1PublicKey,
        trustMicros: Int,
        previousGrantId: ByteArray?,
        comment: String,
        occasionReferences: List<Cid>,
    ): ByteArray {
        require(trustMicros in MIN_TRUST_MICROS..MAX_TRUST_MICROS) {
            "trustMicros must be in $MIN_TRUST_MICROS..$MAX_TRUST_MICROS, was $trustMicros"
        }
        require(previousGrantId == null || previousGrantId.size == CONTENT_ID_SIZE) {
            "previousGrantId must be a $CONTENT_ID_SIZE-byte content id or null"
        }
        val commentBytes = comment.toByteArray(Charsets.UTF_8)
        require(commentBytes.size <= MAX_COMMENT_BYTES) { "comment must be at most $MAX_COMMENT_BYTES UTF-8 bytes" }
        require(occasionReferences.size <= MAX_OCCASION_REFERENCES) {
            "at most $MAX_OCCASION_REFERENCES occasion references allowed"
        }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(if (previousGrantId != null) FLAG_HAS_PREVIOUS else 0)
            write(truster.bytes)
            write(target.bytes)
            writeInt(trustMicros)
            if (previousGrantId != null) write(previousGrantId)
            writeShort(commentBytes.size)
            write(commentBytes)
            writeShort(occasionReferences.size)
            occasionReferences.forEach { cid ->
                val cidBytes = cid.toBytes()
                require(cidBytes.size in 1..MAX_CID_BYTES) {
                    "occasion reference CID must be 1..$MAX_CID_BYTES bytes, was ${cidBytes.size}"
                }
                writeShort(cidBytes.size)
                write(cidBytes)
            }
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded grant body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [grant]. */
    fun encodeSignedBody(grant: VeritasGrant): ByteArray =
        encodeSignedBody(
            truster = grant.truster,
            target = grant.target,
            trustMicros = grant.trustMicros,
            previousGrantId = grant.previousGrantId,
            comment = grant.comment,
            occasionReferences = grant.occasionReferences,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. This is what a
     * future wave hands to `NabuStorage.put()`, and the preimage of [contentId]. */
    fun encode(grant: VeritasGrant): ByteArray = encodeSignedBody(grant) + grant.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - a content identifier / lookup key, not
     * itself a signed value. A successor grant embeds this as its `previousGrantId`. */
    fun contentId(grant: VeritasGrant): ByteArray = sha256(encode(grant))

    /**
     * Structural decode only - does **not** verify the signature, unlike
     * [net.lapisphilosophorum.lapisnet.identity.KeystoreFileFormat.decode] (which does, because a
     * keystore must be trustworthy to load at all). A grant typically arrives from an untrusted
     * peer over the network; callers must explicitly call [VeritasGrant.verify] (or the
     * [VeritasGrant.Companion.verify] overload with an expected truster) before trusting it.
     *
     * @throws MalformedVeritasGrantException if the bytes are structurally invalid.
     */
    fun decode(bytes: ByteArray): VeritasGrant {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedVeritasGrantException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedVeritasGrantException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags and FLAG_HAS_PREVIOUS.inv() != 0) {
                throw MalformedVeritasGrantException("reserved flag bits must be zero: $flags")
            }
            val trusterBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val targetBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val trustMicros = input.readInt()
            if (trustMicros !in MIN_TRUST_MICROS..MAX_TRUST_MICROS) {
                throw MalformedVeritasGrantException("trustMicros out of range: $trustMicros")
            }
            val previousGrantId =
                if (flags and FLAG_HAS_PREVIOUS != 0) {
                    ByteArray(CONTENT_ID_SIZE).also { input.readFully(it) }
                } else {
                    null
                }

            val commentLen = input.readUnsignedShort()
            if (commentLen > MAX_COMMENT_BYTES) throw MalformedVeritasGrantException("comment too long: $commentLen")
            val commentBytes = ByteArray(commentLen).also { input.readFully(it) }

            val occasionCount = input.readUnsignedShort()
            if (occasionCount > MAX_OCCASION_REFERENCES) {
                throw MalformedVeritasGrantException("too many occasion references: $occasionCount")
            }
            val occasionReferences =
                (0 until occasionCount).map {
                    val cidLen = input.readUnsignedShort()
                    if (cidLen !in 1..MAX_CID_BYTES) throw MalformedVeritasGrantException("invalid CID length: $cidLen")
                    val cidBytes = ByteArray(cidLen).also { buf -> input.readFully(buf) }
                    // Field-length cap above bounds the WIRE bytes for this field, not the multihash length
                    // declared INSIDE those bytes - see CidBytesValidation's class doc comment for why
                    // Cid.cast() must never see bytes that fail this check.
                    if (!CidBytesValidation.isSafeToCast(cidBytes)) {
                        throw MalformedVeritasGrantException(
                            "occasion reference CID declares an unsafe multihash length",
                        )
                    }
                    Cid.cast(cidBytes)
                }

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedVeritasGrantException("trailing bytes after signature")

            return VeritasGrant.fromDecoded(
                truster = Secp256k1PublicKey(trusterBytes),
                target = Secp256k1PublicKey(targetBytes),
                trustMicros = trustMicros,
                previousGrantId = previousGrantId,
                comment = String(commentBytes, Charsets.UTF_8),
                occasionReferences = occasionReferences,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedVeritasGrantException("truncated grant bytes", e)
        } catch (e: IOException) {
            throw MalformedVeritasGrantException("failed to decode grant", e)
        } catch (e: MalformedVeritasGrantException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, independent of CidBytesValidation.isSafeToCast's guard above: if
            // some other unforeseen path ever attempts an oversized allocation while decoding a
            // grant, this must still surface as a clean malformed-input rejection, never an Error
            // escaping to VeritasGossip.onGossipMessage's caller. Deliberately narrow - only
            // OutOfMemoryError, not a blanket Throwable/Error catch, which would risk masking a
            // real JVM problem unrelated to this decode call.
            throw MalformedVeritasGrantException("grant field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from VeritasGrant's own constructor validation and
            // io.ipfs.cid.Cid.CidEncodingException from Cid.cast() on malformed CID bytes - decode()
            // must never leak an arbitrary third-party exception type to callers.
            throw MalformedVeritasGrantException("invalid grant field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
