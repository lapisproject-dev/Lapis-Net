package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.MalformedRatchetMessageException
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer

/**
 * Canonical, deterministic byte encoding for [DmEnvelope] - the outer frame carried on a
 * [DmProtocol] `/lapis/dm/1.0.0` stream. **This is the FIRST codec in this codebase parsing bytes
 * arriving directly off a raw libp2p stream, with no GossipSub message-size ceiling backstopping
 * it** - every check below is ordered cheapest/most-selective first and, above all, EVERY variable-
 * length field's declared size is validated BEFORE the corresponding allocation, mirroring
 * [RatchetMessageCodec.decode]'s/`PeerRecordCodec.decode`'s established discipline, now applied
 * where nothing upstream of this parser bounds frame size at all.
 *
 * Exact wire layout, byte by byte, all integers big-endian:
 * ```
 * off    len   field
 *   0      4   magic "LNDM"  (Lapis Net Direct Message)
 *   4      1   version = 1
 *   5      1   flags - reserved, must be zero
 *   6      1   messageType  (wire byte: 0=TEXT, 1=X3DH_INITIAL, 2=RECEIPT reserved, 3=CALL_SIGNAL reserved)
 *   7     33   senderIdentity              (secp256k1 compressed public key)
 *  40      1   x3dhInitialHeaderPresent    (0 or 1; MUST equal 1 iff messageType == X3DH_INITIAL)
 *  41     32   x3dhInitiatorX25519PublicKey            (all-zero when absent)
 *  73     64   x3dhInitiatorEncryptionBindingSignature (all-zero when absent)
 * 137     32   x3dhEphemeralPublicKey                  (all-zero when absent)
 * 169      4   x3dhSignedPrekeyId                      (0 when absent)
 * 173      1   x3dhOneTimePrekeyIdPresent              (0 or 1; MUST be 0 when x3dhInitialHeaderPresent==0)
 * 174      4   x3dhOneTimePrekeyId                     (0 when absent)
 * --- DM_ENVELOPE_FIXED_PREFIX_SIZE = 178 ---
 * 178      2   ratchetMessageLength   (unsigned short, 1..RatchetMessageCodec.MAX_MESSAGE_BYTES)
 * 180      N   ratchetMessageBytes    (a RatchetMessageCodec.encode()'d blob, N = ratchetMessageLength)
 * --- total size = 180 + N; MAX_ENVELOPE_BYTES = 180 + RatchetMessageCodec.MAX_MESSAGE_BYTES ---
 * ```
 *
 * **No separate `x3dhInitiatorIdentity` field.** The X3DH initiator IS this envelope's own
 * [DmEnvelope.senderIdentity] by construction ([DmSessionManager] only ever emits `X3DH_INITIAL`
 * for a message it itself originates as initiator) - encoding it twice would be a redundant field
 * an attacker could make disagree with `senderIdentity`, the exact anti-pattern
 * `PrekeyBundle.x25519IdentityKey`'s "read-through alias, never a second copy" discipline exists to
 * prevent. `X3dhPreKeyMessageHeader.initiatorIdentity` is reconstructed on [decode] as
 * `= envelope.senderIdentity`, never carried separately on the wire.
 *
 * **The X3DH section is always present in the fixed layout, gated by a presence byte, not
 * conditional placement** - exactly `DoubleRatchetSessionCodec`'s own established idiom for
 * "sometimes-present" fields. Costs 137 extra bytes on every `TEXT` envelope (negligible relative to
 * a <=65 KB ratchet payload) in exchange for zero offset arithmetic to get wrong.
 *
 * Decode order (cheapest/most-selective first):
 * 1. `bytes.size > MAX_ENVELOPE_BYTES` - rejected on the first line, before any stream is opened.
 * 2. Too-short-to-be-structurally-valid - rejected next.
 * 3. magic/version/flags.
 * 4. `messageType` - if `RECEIPT`/`CALL_SIGNAL`/unrecognized wire byte, rejected immediately,
 *    BEFORE parsing `senderIdentity` or anything downstream (cheapest possible rejection point).
 * 5. `senderIdentity` - [Secp256k1PublicKey]'s own constructor throws for a non-curve-point,
 *    funnelled by the blanket catch below.
 * 6. `x3dhInitialHeaderPresent` - cross-checked against `messageType`; mismatch is rejected.
 * 7. If present: every X3DH sub-field constructor (`X25519PublicKey`, `EncryptionKeyBinding`,
 *    `X3dhPreKeyMessageHeader`) independently validates its own input. If absent: every one of the
 *    137-byte section's sub-fields must be exactly all-zero/0 - a non-zero "absent" slot is tamper
 *    evidence, rejected.
 * 8. `ratchetMessageLength` - range-checked (`1..RatchetMessageCodec.MAX_MESSAGE_BYTES`) BEFORE the
 *    corresponding `ByteArray(ratchetMessageLength)` allocation, for the one genuinely
 *    variable-length field in this format. **Tightened doc, follow-up hardening item 4
 *    (2026-08-11): this check's UPPER bound is not what actually caps the allocation size, and
 *    calling it "the load-bearing gate" (an earlier revision of this comment did) overstated what it
 *    does.** `ratchetMessageLength` comes from `readUnsignedShort()`, whose result range is
 *    `0..65535` by construction (a fixed 2-byte wire field) - and
 *    `RatchetMessageCodec.MAX_MESSAGE_BYTES` is exactly `65_535`, so
 *    `ratchetMessageLength > RatchetMessageCodec.MAX_MESSAGE_BYTES` can NEVER be true; that half of
 *    the comparison is dead code, not a genuinely reachable rejection. The real, load-bearing reason
 *    the `ByteArray(ratchetMessageLength)` allocation below can never run away is STRUCTURAL, not
 *    this explicit check: a 2-byte length field can only ever encode a value up to 65,535 in the
 *    first place, and 65,535 bytes is itself a small, unconditionally safe allocation size regardless
 *    of whether anything explicitly gates it (this codec's actual defense against a genuinely
 *    attacker-controlled oversized declared length lives one layer OUT, in
 *    [net.lapisphilosophorum.lapisnet.dm.MAX_ENVELOPE_BYTES]'s own frame-level ceiling in `decode`'s
 *    first line and, redundantly, in `DmProtocolHandler`'s Netty `LengthFieldBasedFrameDecoder` - see
 *    that class's own doc comment). What this specific comparison DOES genuinely, reachably enforce
 *    is the LOWER bound: `ratchetMessageLength >= 1`, rejecting a declared length of exactly `0` (an
 *    empty, meaningless ratchet-message body) that `readUnsignedShort()` could otherwise legitimately
 *    produce.
 * 9. Declared length must match actual remaining frame size exactly - no trailing bytes, no
 *    truncation.
 * 10. [RatchetMessageCodec.decode] - its OWN independent size/range/canonical-encoding checks run
 *     here too (defense in depth: even if a future bug ever let an oversized `ratchetMessageLength`
 *     slip past step 8, `RatchetMessageCodec.decode`'s own first-line size check catches it again).
 */
object DmEnvelopeCodec {
    private val MAGIC = "LNDM".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1

    private const val SENDER_IDENTITY_SIZE = 33
    private const val X3DH_X25519_SIZE = 32
    private const val X3DH_BINDING_SIGNATURE_SIZE = 64
    private const val X3DH_EPHEMERAL_SIZE = 32

    /** `32 (x25519 pubkey) + 64 (binding signature) + 32 (ephemeral) + 4 (signedPrekeyId) +
     * 1 (oneTimePrekeyIdPresent) + 4 (oneTimePrekeyId) = 137`. */
    private const val X3DH_SECTION_SIZE =
        X3DH_X25519_SIZE + X3DH_BINDING_SIGNATURE_SIZE + X3DH_EPHEMERAL_SIZE + 4 + 1 + 4

    /** `4 (magic) + 1 (version) + 1 (flags) + 1 (messageType) + 33 (senderIdentity) +
     * 1 (x3dhInitialHeaderPresent) + 137 (X3DH section) = 178`. */
    const val DM_ENVELOPE_FIXED_PREFIX_SIZE = 4 + 1 + 1 + 1 + SENDER_IDENTITY_SIZE + 1 + X3DH_SECTION_SIZE

    private const val RATCHET_LENGTH_FIELD_SIZE = 2

    /** `180 + RatchetMessageCodec.MAX_MESSAGE_BYTES = 65_715`. The hard frame-size cap enforced
     * BEFORE any read of the frame body - both here (the first line of [decode]) and, redundantly,
     * as [DmProtocol]'s `LengthFieldBasedFrameDecoder` `maxFrameLength`, so an oversized frame is
     * rejected at the Netty layer before it ever reaches this codec at all. */
    const val MAX_ENVELOPE_BYTES =
        DM_ENVELOPE_FIXED_PREFIX_SIZE + RATCHET_LENGTH_FIELD_SIZE + RatchetMessageCodec.MAX_MESSAGE_BYTES

    /** A conservative, cheap-to-check lower bound: [DM_ENVELOPE_FIXED_PREFIX_SIZE] + the length
     * field + at least [RatchetMessageCodec.HEADER_SIZE] + 1 byte of ciphertext. Not the TIGHT
     * minimum (this codec has no visibility into `lapis-net-ratchet`'s internal GCM-tag-size
     * constant, which is `internal` to that module) - [RatchetMessageCodec.decode] itself enforces
     * the tight bound as a second, independent layer, per this class's own decode-order doc comment
     * step 10. */
    private const val MIN_ENVELOPE_BYTES =
        DM_ENVELOPE_FIXED_PREFIX_SIZE + RATCHET_LENGTH_FIELD_SIZE + RatchetMessageCodec.HEADER_SIZE + 1

    private val ZERO_X3DH_SECTION = ByteArray(X3DH_SECTION_SIZE)

    /** `DmEnvelope.x3dhInitialHeader`'s `initiatorEncryptionBinding.x25519PublicKey.bytes ||
     * .signature || ephemeralPublicKey.bytes || signedPrekeyId || oneTimePrekeyIdPresent ||
     * oneTimePrekeyId` (or [ZERO_X3DH_SECTION] when absent), plus the ratchet message length +
     * bytes - assembled with [ByteBuffer] rather than a `ByteArrayOutputStream`, mirroring
     * `DoubleRatchetSessionCodec.encodeBody`'s identical "write straight into the buffer that
     * becomes the returned array" reasoning (nothing here is secret key material the way that
     * function's is, but the discipline of avoiding an abandoned intermediate buffer copy is cheap
     * to keep anyway). */
    fun encode(envelope: DmEnvelope): ByteArray {
        val ratchetBytes = RatchetMessageCodec.encode(envelope.ratchetMessage)
        check(ratchetBytes.size <= RatchetMessageCodec.MAX_MESSAGE_BYTES) {
            "encoded ratchet message unexpectedly exceeds ${RatchetMessageCodec.MAX_MESSAGE_BYTES} bytes"
        }
        val totalSize = DM_ENVELOPE_FIXED_PREFIX_SIZE + RATCHET_LENGTH_FIELD_SIZE + ratchetBytes.size
        val buffer = ByteBuffer.allocate(totalSize)
        buffer.put(MAGIC)
        buffer.put(VERSION)
        buffer.put(0) // flags: reserved, must be zero
        buffer.put(envelope.messageType.wireValue)
        buffer.put(envelope.senderIdentity.bytes)

        val header = envelope.x3dhInitialHeader
        if (header != null) {
            buffer.put(1)
            buffer.put(header.initiatorEncryptionBinding.x25519PublicKey.bytes)
            buffer.put(header.initiatorEncryptionBinding.signature)
            buffer.put(header.ephemeralPublicKey.bytes)
            buffer.putInt(header.signedPrekeyId)
            val oneTimePrekeyId = header.oneTimePrekeyId
            if (oneTimePrekeyId != null) {
                buffer.put(1)
                buffer.putInt(oneTimePrekeyId)
            } else {
                buffer.put(0)
                buffer.putInt(0)
            }
        } else {
            buffer.put(0)
            buffer.put(ZERO_X3DH_SECTION)
        }

        buffer.putShort(ratchetBytes.size.toShort())
        buffer.put(ratchetBytes)
        check(
            !buffer.hasRemaining(),
        ) { "dm envelope assembly under-filled the buffer: ${buffer.remaining()} bytes left" }
        val out = buffer.array()
        check(out.size == totalSize) { "dm envelope assembly produced an unexpected size: ${out.size}" }
        return out
    }

    /** @throws MalformedDmEnvelopeException on any structural problem - see this object's class doc
     *   comment for the exact, ordered set of checks. Never throws for a ratchet-message AEAD
     *   failure - [RatchetMessageCodec.decode] is a structural decode only, never an AEAD operation
     *   (see that function's own doc comment); actual decryption happens one layer up, in
     *   [DmSessionManager]. */
    fun decode(bytes: ByteArray): DmEnvelope {
        if (bytes.size > MAX_ENVELOPE_BYTES) {
            throw MalformedDmEnvelopeException("dm envelope exceeds $MAX_ENVELOPE_BYTES bytes: ${bytes.size}")
        }
        if (bytes.size < MIN_ENVELOPE_BYTES) {
            throw MalformedDmEnvelopeException("dm envelope too short to be structurally valid: ${bytes.size} bytes")
        }
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedDmEnvelopeException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedDmEnvelopeException("unsupported version $version")

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedDmEnvelopeException("reserved flag bits must be zero: $flags")

            // messageType is checked - and RECEIPT/CALL_SIGNAL/unknown rejected - BEFORE
            // senderIdentity or anything downstream is even parsed: the cheapest possible rejection
            // point, and what the CALL_SIGNAL adversarial test asserts the ordering of.
            val messageTypeByte = input.readByte()
            val messageType =
                DmMessageType.fromWireValue(messageTypeByte)
                    ?: throw MalformedDmEnvelopeException("unknown dm messageType wire value $messageTypeByte")
            if (messageType == DmMessageType.RECEIPT || messageType == DmMessageType.CALL_SIGNAL) {
                throw MalformedDmEnvelopeException("messageType $messageType is reserved and rejected outright")
            }

            val senderIdentityBytes = ByteArray(SENDER_IDENTITY_SIZE).also { input.readFully(it) }
            val senderIdentity = Secp256k1PublicKey(senderIdentityBytes)

            val x3dhPresent =
                when (val b = input.readUnsignedByte()) {
                    0 -> false
                    1 -> true
                    else -> throw MalformedDmEnvelopeException("x3dhInitialHeaderPresent must be 0 or 1, was $b")
                }
            if (x3dhPresent != (messageType == DmMessageType.X3DH_INITIAL)) {
                throw MalformedDmEnvelopeException(
                    "x3dhInitialHeaderPresent ($x3dhPresent) is inconsistent with messageType ($messageType)",
                )
            }

            val x3dhX25519Bytes = ByteArray(X3DH_X25519_SIZE).also { input.readFully(it) }
            val x3dhBindingSignature = ByteArray(X3DH_BINDING_SIGNATURE_SIZE).also { input.readFully(it) }
            val x3dhEphemeralBytes = ByteArray(X3DH_EPHEMERAL_SIZE).also { input.readFully(it) }
            val x3dhSignedPrekeyId = input.readInt()
            val x3dhOneTimePrekeyIdPresent =
                when (val b = input.readUnsignedByte()) {
                    0 -> false
                    1 -> true
                    else -> throw MalformedDmEnvelopeException("x3dhOneTimePrekeyIdPresent must be 0 or 1, was $b")
                }
            val x3dhOneTimePrekeyId = input.readInt()

            val x3dhInitialHeader: X3dhPreKeyMessageHeader?
            if (x3dhPresent) {
                if (!x3dhOneTimePrekeyIdPresent && x3dhOneTimePrekeyId != 0) {
                    throw MalformedDmEnvelopeException(
                        "x3dhOneTimePrekeyId must be 0 when x3dhOneTimePrekeyIdPresent is false",
                    )
                }
                val binding = EncryptionKeyBinding(X25519PublicKey(x3dhX25519Bytes), x3dhBindingSignature)
                x3dhInitialHeader =
                    X3dhPreKeyMessageHeader(
                        initiatorIdentity = senderIdentity,
                        initiatorEncryptionBinding = binding,
                        ephemeralPublicKey = X25519PublicKey(x3dhEphemeralBytes),
                        signedPrekeyId = x3dhSignedPrekeyId,
                        oneTimePrekeyId = if (x3dhOneTimePrekeyIdPresent) x3dhOneTimePrekeyId else null,
                    )
            } else {
                // Tamper evidence: every sub-field of an "absent" X3DH section must be exactly
                // all-zero/0 - a non-zero slot here means the frame was hand-crafted, not produced
                // by this codec's own encode().
                val allZero =
                    x3dhX25519Bytes.all { it == 0.toByte() } &&
                        x3dhBindingSignature.all { it == 0.toByte() } &&
                        x3dhEphemeralBytes.all { it == 0.toByte() } &&
                        x3dhSignedPrekeyId == 0 &&
                        !x3dhOneTimePrekeyIdPresent &&
                        x3dhOneTimePrekeyId == 0
                if (!allZero) {
                    throw MalformedDmEnvelopeException(
                        "absent X3DH section must be entirely all-zero/0 - tamper evidence",
                    )
                }
                x3dhInitialHeader = null
            }

            // ratchetMessageLength is range-checked BEFORE the ByteArray(ratchetMessageLength)
            // allocation below - see this object's class doc comment step 8 (follow-up hardening item
            // 4, 2026-08-11) for exactly what this check does and does not enforce: the reachable part
            // is the >= 1 lower bound; the <= MAX_MESSAGE_BYTES upper bound can never actually fire,
            // since readUnsignedShort()'s own 2-byte width already structurally caps this value at
            // 65,535 (== MAX_MESSAGE_BYTES), which is itself a small, safe allocation size regardless.
            val ratchetMessageLength = input.readUnsignedShort()
            if (ratchetMessageLength !in 1..RatchetMessageCodec.MAX_MESSAGE_BYTES) {
                throw MalformedDmEnvelopeException(
                    "ratchetMessageLength must be in 1..${RatchetMessageCodec.MAX_MESSAGE_BYTES}, was $ratchetMessageLength",
                )
            }
            val expectedSize = DM_ENVELOPE_FIXED_PREFIX_SIZE + RATCHET_LENGTH_FIELD_SIZE + ratchetMessageLength
            if (bytes.size != expectedSize) {
                throw MalformedDmEnvelopeException(
                    "declared ratchetMessageLength $ratchetMessageLength does not match actual frame size " +
                        "${bytes.size - DM_ENVELOPE_FIXED_PREFIX_SIZE - RATCHET_LENGTH_FIELD_SIZE}",
                )
            }
            val ratchetMessageBytes = ByteArray(ratchetMessageLength).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedDmEnvelopeException("trailing bytes after ratchet message")

            // RatchetMessageCodec.decode's OWN independent checks run here too - defense in depth,
            // see this object's class doc comment step 10.
            val ratchetMessage = RatchetMessageCodec.decode(ratchetMessageBytes)

            return DmEnvelope(messageType, senderIdentity, x3dhInitialHeader, ratchetMessage)
        } catch (e: EOFException) {
            throw MalformedDmEnvelopeException("truncated dm envelope bytes", e)
        } catch (e: IOException) {
            throw MalformedDmEnvelopeException("failed to decode dm envelope", e)
        } catch (e: MalformedDmEnvelopeException) {
            throw e
        } catch (e: MalformedRatchetMessageException) {
            throw MalformedDmEnvelopeException("invalid embedded ratchet message: ${e.message}", e)
        } catch (e: OutOfMemoryError) {
            throw MalformedDmEnvelopeException("dm envelope field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers Secp256k1PublicKey's/X25519PublicKey's canonical-encoding/curve-point checks,
            // EncryptionKeyBinding's/X3dhPreKeyMessageHeader's own range checks, etc. - decode() must
            // never leak an arbitrary third-party/internal exception type to callers.
            throw MalformedDmEnvelopeException("invalid dm envelope field", e)
        }
    }
}
