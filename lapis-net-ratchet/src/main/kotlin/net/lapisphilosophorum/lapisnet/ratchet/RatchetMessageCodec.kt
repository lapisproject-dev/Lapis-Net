package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/** Thrown when decoding a [RatchetMessage]'s canonical byte encoding fails structurally. Never
 * thrown for AEAD/decryption failures - those are [DoubleRatchetException], see that type's doc
 * comment. Mirrors [MalformedPrekeyBundleException]'s identical structural-only contract. */
class MalformedRatchetMessageException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [RatchetMessage]. Mirrors [PrekeyBundleCodec]'s and
 * `PeerRecordCodec`'s layout discipline exactly: magic, version, reserved-flag-bits-must-be-zero,
 * every variable-length field's declared size validated BEFORE the corresponding allocation. All
 * integers are big-endian.
 *
 * Exact wire layout, byte by byte:
 * ```
 * off   len   field
 *   0     4   magic  "LNDR"  (Lapis Net Double Ratchet)
 *   4     1   version = 1
 *   5     1   flags   - all bits reserved, must be zero
 *   6    32   ratchetPublicKey     (X25519, sender's current DHs public half)
 *  38     4   previousChainLength  (PN, Int, 0..MAX_CHAIN_LENGTH)
 *  42     4   messageNumber        (N,  Int, 0..MAX_CHAIN_LENGTH)
 *  46    12   nonce                (AES-256-GCM, random per message)
 *  58     2   ciphertextLength     (unsigned short, 17..MAX_CIPHERTEXT_BYTES)
 * --- HEADER_SIZE = 60. Bytes [0, 60) VERBATIM are the AAD prefix. ---
 *  60     N   ciphertext           (AES-256-GCM output, includes the trailing 16-byte tag)
 * ```
 *
 * **The AAD, verbatim, never reconstructed.** `AAD = headerBytes[0..59] || associatedData[0..70]`
 * (131 bytes) - both parts fixed length, so the concatenation is injective with no length prefix,
 * the same argument [X3dh]'s and `HybridEcies`'s own `HKDF_INFO_LABEL` doc comments already make
 * for their own concatenations. The header bytes [DoubleRatchetSession] hands the AEAD come off the
 * wire (or are freshly assembled by [encodeHeader]) VERBATIM - never re-serialised from
 * [RatchetMessageHeader]'s parsed fields. See [RatchetMessage]'s own doc comment for why
 * `headerBytes` is a field on that type rather than a discipline callers must remember.
 *
 * **No `io.ipfs.cid.Cid` field anywhere in this layout - deliberately**, mirroring
 * [PrekeyBundleCodec]'s and [PrekeyStoreFileFormat]'s own equivalent notes: there is nothing here
 * for `net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation` to guard.
 */
object RatchetMessageCodec {
    private val MAGIC = "LNDR".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val X25519_KEY_SIZE = 32

    /** Bytes `[0, HEADER_SIZE)` of an encoded message - this exact byte range, read verbatim off
     * the wire, is what [DoubleRatchetSession] hands the AEAD as the first half of its AAD. */
    const val HEADER_SIZE = 4 + 1 + 1 + 32 + 4 + 4 + 12 + 2 // 60

    /** `0xFFFF - HEADER_SIZE`. Chosen so a COMPLETE encoded message still fits a 16-bit outer frame
     * length, mirroring `SealedBodyCodec.MAX_CIPHERTEXT_BYTES`'s identical reasoning against
     * `MailFrameCodec`'s own 16-bit body-length field - a future online DM stream will need exactly
     * that. */
    const val MAX_CIPHERTEXT_BYTES = 0xFFFF - HEADER_SIZE // 65_475
    const val MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - GCM_TAG_SIZE // 65_459
    const val MAX_MESSAGE_BYTES = HEADER_SIZE + MAX_CIPHERTEXT_BYTES // 65_535

    /** Hard cap on `messageNumber`/`previousChainLength` as WIRE values, rejected at [decode]
     * **before any allocation and before any key-derivation loop can be reached**. One million
     * messages in a single chain means one party sent a million messages without the other ever
     * replying once - already absurd for a 1:1 chat, with generous headroom above any realistic
     * burst. The number is deliberately NOT derived from a protocol requirement (mirroring
     * `PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS`'s identical "generous headroom ... not derived from
     * any protocol requirement" framing).
     *
     * **This is the FIRST of two independent gates against the skipped-key DoS, and it is the
     * cheaper one.** It rejects `Int.MAX_VALUE` (and every other absurd claim) during structural
     * decoding, before [DoubleRatchetSession.decrypt] is ever entered. It is NOT sufficient on its
     * own - a header claiming `messageNumber = 999_999` passes this gate and would still drive a
     * ~1M-iteration derivation loop - which is why `decrypt` applies a second, tighter `MAX_SKIP`
     * gate computed against the session's own position, also before any derivation. This codebase's
     * CID-length OOM history (`Fix CID multihash-length OOM DoS`, commit `0c56dbb`) is why both
     * gates exist rather than one.
     */
    const val MAX_CHAIN_LENGTH = 1_000_000

    /** Assembles the 60-byte header FIRST, so it can be handed to the AEAD as AAD before the
     * ciphertext exists - resolving the same circular dependency `KeystoreEncryption`'s class doc
     * comment describes and `KeystoreFileFormat.encodeEncrypted`/`PrekeyStoreFileFormat.encodeEncrypted`
     * both solve the same way. [ciphertextLength] must be the length the ciphertext WILL have
     * (`plaintext.size + GCM_TAG_SIZE`, which AES-GCM makes deterministic);
     * [DoubleRatchetSession.encrypt] `check`s the actual output matches after encrypting. */
    internal fun encodeHeader(
        header: RatchetMessageHeader,
        ciphertextLength: Int,
    ): ByteArray {
        require(ciphertextLength in (GCM_TAG_SIZE + 1)..MAX_CIPHERTEXT_BYTES) {
            "ciphertextLength must be in ${GCM_TAG_SIZE + 1}..$MAX_CIPHERTEXT_BYTES, was $ciphertextLength"
        }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(0) // flags: all bits reserved, must be zero
            write(header.ratchetPublicKey.bytes)
            writeInt(header.previousChainLength)
            writeInt(header.messageNumber)
            write(header.nonce)
            writeShort(ciphertextLength)
        }
        val bytes = out.toByteArray()
        check(bytes.size == HEADER_SIZE) { "header assembly produced an unexpected size: ${bytes.size}" }
        return bytes
    }

    /** `message.headerBytes + message.ciphertext`. Never re-serialises `message.header` - so a
     * [decode]/[encode] round trip is byte-exact by construction, not merely by test. */
    fun encode(message: RatchetMessage): ByteArray = message.headerBytes + message.ciphertext

    /**
     * Structural decode only - does **not** perform any AEAD operation. In exactly this order:
     *
     * 1. `bytes.size > MAX_MESSAGE_BYTES` rejected on the FIRST LINE, before any stream is opened -
     *    so an oversized frame costs nothing (`DoubleRatchetAdversarialTest` case (h)).
     * 2. Too-short-to-be-valid rejected next.
     * 3. Magic, version, reserved flags.
     * 4. `ratchetPublicKey`: [X25519PublicKey]'s own canonical-encoding + low-order-point rejections
     *    fire here, funnelled by the blanket `catch (e: RuntimeException)` below (same path
     *    [PrekeyBundleCodec.decode] documents) - so a low-order X25519 value in this slot is
     *    rejected structurally, before any DH ever runs.
     * 5. `previousChainLength`/`messageNumber`: range-checked against [MAX_CHAIN_LENGTH] - the
     *    first, cheaper of the two DoS gates, see that constant's doc comment.
     * 6. `nonce`: 12 bytes, no further validation (any 12 bytes are a structurally valid nonce).
     * 7. `ciphertextLength`: range-checked BEFORE the corresponding allocation.
     * 8. The declared length must match the actual frame size EXACTLY - no trailing bytes, no
     *    truncation.
     * 9. A canonicalization `check`: re-encoding the parsed header must reproduce `headerBytes`
     *    exactly. Cannot fail today (every field is fixed-width with a validated range, so
     *    re-encoding necessarily reproduces the input), kept so a future variable-length header
     *    field cannot silently introduce a non-canonical encoding that would make `headerBytes` and
     *    `header` disagree - which would in turn make the AAD depend on which of the two a future
     *    call site happened to use.
     *
     * @throws MalformedRatchetMessageException if the bytes are structurally invalid.
     */
    fun decode(bytes: ByteArray): RatchetMessage {
        if (bytes.size > MAX_MESSAGE_BYTES) {
            throw MalformedRatchetMessageException(
                "ratchet message exceeds $MAX_MESSAGE_BYTES bytes: ${bytes.size}",
            )
        }
        if (bytes.size < HEADER_SIZE + GCM_TAG_SIZE + 1) {
            throw MalformedRatchetMessageException("ratchet message too short to be valid: ${bytes.size} bytes")
        }
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedRatchetMessageException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedRatchetMessageException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedRatchetMessageException("reserved flag bits must be zero: $flags")

            val ratchetPublicKeyBytes = ByteArray(X25519_KEY_SIZE).also { input.readFully(it) }

            val previousChainLength = input.readInt()
            if (previousChainLength !in 0..MAX_CHAIN_LENGTH) {
                throw MalformedRatchetMessageException(
                    "previousChainLength must be in 0..$MAX_CHAIN_LENGTH, was $previousChainLength",
                )
            }
            val messageNumber = input.readInt()
            if (messageNumber !in 0..MAX_CHAIN_LENGTH) {
                throw MalformedRatchetMessageException(
                    "messageNumber must be in 0..$MAX_CHAIN_LENGTH, was $messageNumber",
                )
            }

            val nonce = ByteArray(GCM_NONCE_SIZE).also { input.readFully(it) }

            val ciphertextLength = input.readUnsignedShort()
            if (ciphertextLength !in (GCM_TAG_SIZE + 1)..MAX_CIPHERTEXT_BYTES) {
                throw MalformedRatchetMessageException(
                    "ciphertextLength must be in ${GCM_TAG_SIZE + 1}..$MAX_CIPHERTEXT_BYTES, was $ciphertextLength",
                )
            }
            if (bytes.size != HEADER_SIZE + ciphertextLength) {
                throw MalformedRatchetMessageException(
                    "declared ciphertextLength $ciphertextLength does not match actual frame size " +
                        "${bytes.size - HEADER_SIZE}",
                )
            }

            val ciphertext = ByteArray(ciphertextLength).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedRatchetMessageException("trailing bytes after ciphertext")

            val headerBytes = bytes.copyOfRange(0, HEADER_SIZE)
            val header =
                RatchetMessageHeader(
                    ratchetPublicKey = X25519PublicKey(ratchetPublicKeyBytes),
                    previousChainLength = previousChainLength,
                    messageNumber = messageNumber,
                    nonce = nonce,
                )
            // Canonicalization guard - see this object's class doc comment for why this is
            // structurally unreachable today but kept as a forward guard.
            check(encodeHeader(header, ciphertextLength).contentEquals(headerBytes)) {
                "decoded header does not re-encode to the original bytes - non-canonical encoding"
            }
            return RatchetMessage(header, headerBytes, ciphertext)
        } catch (e: EOFException) {
            throw MalformedRatchetMessageException("truncated ratchet message bytes", e)
        } catch (e: IOException) {
            throw MalformedRatchetMessageException("failed to decode ratchet message", e)
        } catch (e: MalformedRatchetMessageException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, kept for structural consistency with every sibling codec - every
            // allocation in this function is already bounded by an explicit cap checked BEFORE
            // allocation. Never thrown by a known path today.
            throw MalformedRatchetMessageException("ratchet message field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers X25519PublicKey's canonical-encoding/low-order-point checks and
            // RatchetMessageHeader's own range checks - decode() must never leak an arbitrary
            // third-party/internal exception type to callers. This is also the exact path that
            // rejects a low-order X25519 public key at decode time, before any DH ever runs.
            throw MalformedRatchetMessageException("invalid ratchet message field", e)
        }
    }
}
