package net.lapisphilosophorum.lapisnet.call

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/**
 * Canonical, deterministic byte encoding for [CallSignal] - V0.8.7. This is what
 * `DoubleRatchetSession.encrypt`/`decrypt` treat as an opaque plaintext payload for a
 * `DmMessageType.CALL_SIGNAL` envelope, exactly the role `DmContentCodec` plays for `TEXT`/
 * `X3DH_INITIAL` (see that object's own class doc comment for the identical "IS the ratchet
 * plaintext" framing) - but this codec lives in `lapis-net-call`, not `lapis-net-dm`, since
 * `lapis-net-dm` must never learn this shape (see `DmInboundCallSignal`'s own doc comment).
 *
 * **No `DmEnvelopeCodec`/wire-format-version bump was needed to introduce this** - `DmMessageType
 * .CALL_SIGNAL`'s wire value (3) has been reserved since V0.8.4 specifically so this moment would not
 * need one (see that enum's own doc comment).
 *
 * Exact wire layout, byte by byte, all integers big-endian:
 * ```
 * off   len  field
 *   0     4  magic "LNCS"           (Lapis Net Call Signal)
 *   4     1  version = 0x01
 *   5     1  type                   (0=INVITE, 1=ACCEPT, 2=REJECT, 3=HANGUP;
 *                                    4=ICE_CANDIDATE, 5=RINGING, 6=RENEGOTIATE - reserved, rejected)
 *   6     1  flags                  reserved, MUST be zero
 *   7    16  callId                 128 bit, MUST NOT be all-zero
 *  23     8  createdAtEpochMillis
 *  31     8  notValidAfterEpochMillis
 *  39     1  mediaKind              (0=AUDIO; 1=AUDIO_VIDEO - reserved, rejected)
 *  40     1  reason                 (CallEndReason wire value; MUST be 0/NONE unless type is
 *                                    REJECT/HANGUP)
 *  41     2  sdpLen                 (0..MAX_SDP_BYTES)
 *  43     N  sdp                    US-ASCII; N>0 iff type is INVITE/ACCEPT, else N==0
 * --- FIXED_PREFIX_SIZE = 43; MAX_CALL_SIGNAL_BYTES = 43 + MAX_SDP_BYTES ---
 * ```
 *
 * **`MAGIC` is NOT a security boundary here** - exactly `DmContentCodec`'s own established caveat:
 * these bytes have already been authenticated by a real AEAD (`DoubleRatchetSession.decrypt`) before
 * this codec ever runs. The magic/version bytes exist purely for consistency with this codebase's
 * other codecs and to fail LOUDLY on a version/type mismatch rather than silently misparsing.
 *
 * Decode order (cheapest/most-selective first, same discipline as every codec in this codebase):
 * 1. `bytes.size > MAX_CALL_SIGNAL_BYTES` / `< FIXED_PREFIX_SIZE` - rejected before any stream opens.
 * 2. magic/version.
 * 3. `type` - unrecognized or reserved ([CallSignalType.ICE_CANDIDATE]/[CallSignalType.RINGING]/
 *    [CallSignalType.RENEGOTIATE]) wire bytes rejected immediately.
 * 4. `flags` - must be zero.
 * 5. `callId` - must not be all-zero ([CallId.of]'s own check, funnelled through the blanket catch).
 * 6. `notValidAfterEpochMillis > createdAtEpochMillis` (funnelled through [CallSignal]'s own init
 *    check via the blanket catch) - a signal cannot expire before it was created.
 * 7. `mediaKind` - unrecognized or reserved ([CallMediaKind.AUDIO_VIDEO]) rejected.
 * 8. `reason` - unrecognized rejected; consistency with `type` funnelled through [CallSignal]'s own
 *    init check.
 * 9. `sdpLen` - range-checked (`0..MAX_SDP_BYTES`) BEFORE the corresponding `ByteArray(sdpLen)`
 *    allocation.
 * 10. Declared `sdpLen` must match actual remaining frame size exactly - no trailing bytes, no
 *     truncation.
 * 11. SDP presence-vs-`type` consistency, and non-ASCII rejection - both funnelled through
 *     [CallSignal]'s own init check / this function's own explicit ASCII check respectively.
 */
object CallSignalCodec {
    private val MAGIC = "LNCS".toByteArray(Charsets.US_ASCII)
    const val VERSION: Byte = 0x01

    const val MAX_SDP_BYTES = 16_384
    private const val CALL_ID_SIZE = CallId.SIZE

    /** `4 (magic) + 1 (version) + 1 (type) + 1 (flags) + 16 (callId) + 8 (createdAt) +
     * 8 (notValidAfter) + 1 (mediaKind) + 1 (reason) + 2 (sdpLen) = 43`. */
    const val FIXED_PREFIX_SIZE = 4 + 1 + 1 + 1 + CALL_ID_SIZE + 8 + 8 + 1 + 1 + 2

    const val MAX_CALL_SIGNAL_BYTES = FIXED_PREFIX_SIZE + MAX_SDP_BYTES

    fun encode(signal: CallSignal): ByteArray {
        val sdpBytes = signal.sdp?.toByteArray(Charsets.US_ASCII) ?: ByteArray(0)
        require(sdpBytes.size <= MAX_SDP_BYTES) {
            "encoded sdp (${sdpBytes.size} bytes) exceeds $MAX_SDP_BYTES bytes"
        }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            writeByte(signal.type.wireValue.toInt())
            writeByte(0) // flags: reserved, must be zero
            write(signal.callId.bytes)
            writeLong(signal.createdAtEpochMillis)
            writeLong(signal.notValidAfterEpochMillis)
            writeByte(signal.mediaKind.wireValue.toInt())
            writeByte(signal.reason.wireValue.toInt())
            writeShort(sdpBytes.size)
            write(sdpBytes)
        }
        val bytes = out.toByteArray()
        check(bytes.size <= MAX_CALL_SIGNAL_BYTES) {
            "encoded CallSignal (${bytes.size} bytes) unexpectedly exceeds $MAX_CALL_SIGNAL_BYTES bytes"
        }
        return bytes
    }

    /** @throws MalformedCallSignalException if the bytes are structurally invalid. */
    fun decode(bytes: ByteArray): CallSignal {
        if (bytes.size > MAX_CALL_SIGNAL_BYTES) {
            throw MalformedCallSignalException("call signal exceeds $MAX_CALL_SIGNAL_BYTES bytes: ${bytes.size}")
        }
        if (bytes.size < FIXED_PREFIX_SIZE) {
            throw MalformedCallSignalException(
                "call signal too short to be structurally valid: ${bytes.size} bytes",
            )
        }
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedCallSignalException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedCallSignalException("unsupported version $version")

            // type is checked - and reserved/unknown rejected - BEFORE anything else downstream is
            // parsed, the cheapest possible rejection point, mirroring DmEnvelopeCodec's own
            // messageType-first-rejection discipline.
            val typeByte = input.readByte()
            val type =
                CallSignalType.fromWireValue(typeByte)
                    ?: throw MalformedCallSignalException("unknown CallSignal type wire value $typeByte")
            if (type == CallSignalType.ICE_CANDIDATE ||
                type == CallSignalType.RINGING ||
                type == CallSignalType.RENEGOTIATE
            ) {
                throw MalformedCallSignalException("CallSignal type $type is reserved and rejected outright")
            }

            val flags = input.readUnsignedByte()
            if (flags != 0) throw MalformedCallSignalException("reserved flag bits must be zero: $flags")

            val callIdBytes = ByteArray(CALL_ID_SIZE).also { input.readFully(it) }
            val callId = CallId.of(callIdBytes)

            val createdAtEpochMillis = input.readLong()
            val notValidAfterEpochMillis = input.readLong()

            val mediaKindByte = input.readByte()
            val mediaKind =
                CallMediaKind.fromWireValue(mediaKindByte)
                    ?: throw MalformedCallSignalException("unknown CallSignal mediaKind wire value $mediaKindByte")
            if (mediaKind == CallMediaKind.AUDIO_VIDEO) {
                throw MalformedCallSignalException("CallSignal mediaKind $mediaKind is reserved and rejected outright")
            }

            val reasonByte = input.readByte()
            val reason =
                CallEndReason.fromWireValue(reasonByte)
                    ?: throw MalformedCallSignalException("unknown CallSignal reason wire value $reasonByte")

            val sdpLen = input.readUnsignedShort()
            if (sdpLen !in 0..MAX_SDP_BYTES) {
                throw MalformedCallSignalException("sdpLen must be in 0..$MAX_SDP_BYTES, was $sdpLen")
            }
            val expectedSize = FIXED_PREFIX_SIZE + sdpLen
            if (bytes.size != expectedSize) {
                throw MalformedCallSignalException(
                    "declared sdpLen $sdpLen does not match actual frame size ${bytes.size - FIXED_PREFIX_SIZE}",
                )
            }
            val sdpBytes = ByteArray(sdpLen).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedCallSignalException("trailing bytes after CallSignal")

            if (!sdpBytes.all { it in 0..127 }) {
                throw MalformedCallSignalException("sdp must be pure US-ASCII")
            }
            val sdp = if (sdpBytes.isEmpty()) null else String(sdpBytes, Charsets.US_ASCII)

            return CallSignal(
                type = type,
                callId = callId,
                createdAtEpochMillis = createdAtEpochMillis,
                notValidAfterEpochMillis = notValidAfterEpochMillis,
                mediaKind = mediaKind,
                reason = reason,
                sdp = sdp,
            )
        } catch (e: EOFException) {
            throw MalformedCallSignalException("truncated call signal bytes", e)
        } catch (e: IOException) {
            throw MalformedCallSignalException("failed to decode call signal", e)
        } catch (e: MalformedCallSignalException) {
            throw e
        } catch (e: OutOfMemoryError) {
            throw MalformedCallSignalException("call signal field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers CallId.of's/CallSignal's own init { } range/consistency checks (e.g. an
            // all-zero callId, notValidAfter <= createdAt, sdp-presence-vs-type mismatch,
            // reason-vs-type mismatch) - decode() must never leak an arbitrary exception type.
            throw MalformedCallSignalException("invalid call signal field", e)
        }
    }
}
