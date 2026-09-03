package net.lapisphilosophorum.lapisnet.call

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.security.SecureRandom

private val random = SecureRandom()

private fun validInviteBytes(): ByteArray {
    val callId = CallId.random(random)
    val signal = CallSignal.invite(callId, "v=0\r\nm=audio 9 x 0\r\n", 1_000L, 61_000L)
    return CallSignalCodec.encode(signal)
}

class CallSignalCodecAdversarialTest :
    FunSpec({
        test("reserved type ICE_CANDIDATE (4) is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[5] = CallSignalType.ICE_CANDIDATE.wireValue
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("reserved type RINGING (5) is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[5] = CallSignalType.RINGING.wireValue
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("reserved type RENEGOTIATE (6) is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[5] = CallSignalType.RENEGOTIATE.wireValue
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("unknown type wire byte is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[5] = 99
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("non-zero flags are rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[6] = 1
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("mediaKind AUDIO_VIDEO (1) is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[39] = CallMediaKind.AUDIO_VIDEO.wireValue
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("unknown mediaKind wire byte is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[39] = 99
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("unknown reason wire byte is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[40] = 99
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("all-zero callId is rejected") {
            val bytes = validInviteBytes().copyOf()
            for (i in 7 until 23) bytes[i] = 0
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("sdpLen exceeding MAX_SDP_BYTES is rejected before any allocation") {
            val bytes = validInviteBytes().copyOf()
            // Overwrite the 2-byte sdpLen field (offset 41) with a value larger than MAX_SDP_BYTES.
            val oversized = (CallSignalCodec.MAX_SDP_BYTES + 1)
            bytes[41] = ((oversized ushr 8) and 0xFF).toByte()
            bytes[42] = (oversized and 0xFF).toByte()
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("truncated frame is rejected") {
            val bytes = validInviteBytes()
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes.copyOf(bytes.size - 5)) }
        }

        test("trailing bytes after the declared frame are rejected") {
            val bytes = validInviteBytes()
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes + byteArrayOf(1, 2, 3)) }
        }

        test("bad magic is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[0] = 'X'.code.toByte()
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("unsupported version is rejected") {
            val bytes = validInviteBytes().copyOf()
            bytes[4] = 99
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
        }

        test("REJECT with sdp present is rejected (sdp must be absent for REJECT)") {
            // Build a REJECT frame by hand: FIXED_PREFIX_SIZE bytes + a non-empty declared sdp.
            val callId = CallId.random(random)
            val reject = CallSignal.reject(callId, CallEndReason.DECLINED, 1_000L, 61_000L)
            val rejectBytes = CallSignalCodec.encode(reject)
            // rejectBytes has sdpLen == 0 at offset 41/42 - splice in a fake non-zero sdpLen plus
            // matching sdp bytes to simulate a tampered/hand-crafted frame.
            val fakeSdp = "m=audio\r\n".toByteArray(Charsets.US_ASCII)
            val tampered = rejectBytes.copyOf(rejectBytes.size + fakeSdp.size)
            fakeSdp.copyInto(tampered, rejectBytes.size)
            tampered[41] = ((fakeSdp.size ushr 8) and 0xFF).toByte()
            tampered[42] = (fakeSdp.size and 0xFF).toByte()
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(tampered) }
        }

        test("10,000 random byte arrays never produce anything but MalformedCallSignalException") {
            val rng = SecureRandom()
            repeat(10_000) {
                val length = rng.nextInt(300)
                val garbage = ByteArray(length).also(rng::nextBytes)
                try {
                    CallSignalCodec.decode(garbage)
                } catch (e: MalformedCallSignalException) {
                    // expected
                } catch (e: Throwable) {
                    throw AssertionError("decode() threw ${e::class} instead of MalformedCallSignalException", e)
                }
            }
        }

        test("oversized frame (> MAX_CALL_SIGNAL_BYTES) is rejected on the first line") {
            val oversized = ByteArray(CallSignalCodec.MAX_CALL_SIGNAL_BYTES + 1)
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(oversized) }
        }

        test("too-short frame is rejected") {
            shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(ByteArray(5)) }
        }

        test("decode ordering: type is checked before callId - a bad type with a corrupted callId still throws") {
            val bytes = validInviteBytes().copyOf()
            bytes[5] = 100 // unknown type
            for (i in 7 until 23) bytes[i] = 0 // ALSO corrupt callId to all-zero
            val exception = shouldThrow<MalformedCallSignalException> { CallSignalCodec.decode(bytes) }
            exception.message shouldBe "unknown CallSignal type wire value 100"
        }
    })
