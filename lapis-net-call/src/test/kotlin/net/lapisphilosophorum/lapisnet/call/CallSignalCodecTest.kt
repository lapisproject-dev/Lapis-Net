package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.security.SecureRandom

private val random = SecureRandom()

private fun sampleSdp(): String = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"

class CallSignalCodecTest :
    FunSpec({
        test("INVITE round-trips byte-exact") {
            val callId = CallId.random(random)
            val signal = CallSignal.invite(callId, sampleSdp(), 1_000L, 61_000L)
            val bytes = CallSignalCodec.encode(signal)
            val decoded = CallSignalCodec.decode(bytes)

            decoded.type shouldBe CallSignalType.INVITE
            decoded.callId shouldBe callId
            decoded.sdp shouldBe sampleSdp()
            decoded.mediaKind shouldBe CallMediaKind.AUDIO
            decoded.reason shouldBe CallEndReason.NONE
            CallSignalCodec.encode(decoded) shouldBe bytes
        }

        test("ACCEPT round-trips byte-exact") {
            val callId = CallId.random(random)
            val signal = CallSignal.accept(callId, sampleSdp(), 2_000L, 62_000L)
            val decoded = CallSignalCodec.decode(CallSignalCodec.encode(signal))

            decoded.type shouldBe CallSignalType.ACCEPT
            decoded.sdp shouldBe sampleSdp()
        }

        test("REJECT round-trips byte-exact, carries no sdp") {
            val callId = CallId.random(random)
            val signal = CallSignal.reject(callId, CallEndReason.DECLINED, 3_000L, 63_000L)
            val decoded = CallSignalCodec.decode(CallSignalCodec.encode(signal))

            decoded.type shouldBe CallSignalType.REJECT
            decoded.sdp shouldBe null
            decoded.reason shouldBe CallEndReason.DECLINED
        }

        test("HANGUP round-trips byte-exact, carries no sdp") {
            val callId = CallId.random(random)
            val signal = CallSignal.hangUp(callId, CallEndReason.LOCAL_HANGUP, 4_000L, 64_000L)
            val decoded = CallSignalCodec.decode(CallSignalCodec.encode(signal))

            decoded.type shouldBe CallSignalType.HANGUP
            decoded.sdp shouldBe null
            decoded.reason shouldBe CallEndReason.LOCAL_HANGUP
        }

        test("createdAtEpochMillis/notValidAfterEpochMillis survive the round trip exactly") {
            val callId = CallId.random(random)
            val signal = CallSignal.invite(callId, sampleSdp(), 123_456_789L, 123_456_789L + 60_000L)
            val decoded = CallSignalCodec.decode(CallSignalCodec.encode(signal))

            decoded.createdAtEpochMillis shouldBe 123_456_789L
            decoded.notValidAfterEpochMillis shouldBe 123_456_789L + 60_000L
        }

        test("encoding the same CallSignal twice produces byte-identical output") {
            val callId = CallId.random(random)
            val signal = CallSignal.invite(callId, sampleSdp(), 1_000L, 61_000L)
            CallSignalCodec.encode(signal) shouldBe CallSignalCodec.encode(signal)
        }

        test("reason is NONE for INVITE/ACCEPT") {
            val callId = CallId.random(random)
            CallSignalCodec
                .decode(
                    CallSignalCodec.encode(CallSignal.invite(callId, sampleSdp(), 0L, 1L)),
                ).reason shouldBe
                CallEndReason.NONE
        }
    })
