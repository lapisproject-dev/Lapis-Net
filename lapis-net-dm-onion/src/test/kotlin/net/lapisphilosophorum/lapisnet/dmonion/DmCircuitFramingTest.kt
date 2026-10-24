package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec
import java.nio.ByteBuffer

class DmCircuitFramingTest :
    FunSpec({
        fun reader(type: Int = DmCircuitFraming.TYPE_ENVELOPE) = DmFrameReader(type, { 0L })

        test("an envelope frame split into 910-byte chunks is reassembled exactly once") {
            val envelope = ByteArray(5_000) { it.toByte() }
            val chunks = DmCircuitFraming.chunks(DmCircuitFraming.envelopeFrame(envelope), 910)
            chunks.all { it.size <= 910 } shouldBe true
            val got = ArrayList<ByteArray>()
            val r = reader()
            for (c in chunks) r.feed(c) { _, p -> got += p }
            got.size shouldBe 1
            got[0].contentEquals(envelope) shouldBe true
            r.inFrame shouldBe false
        }

        test("two frames in one chunk and a frame split across the header are both handled") {
            val a = ByteArray(10) { 1 }
            val b = ByteArray(20) { 2 }
            val joined = DmCircuitFraming.envelopeFrame(a) + DmCircuitFraming.envelopeFrame(b)
            val got = ArrayList<ByteArray>()
            val r = reader()
            r.feed(joined.copyOfRange(0, 3)) { _, p -> got += p }
            r.inFrame shouldBe true
            r.feed(joined.copyOfRange(3, joined.size)) { _, p -> got += p }
            got.map { it.size } shouldBe listOf(10, 20)
        }

        test("a length above the envelope maximum or zero is refused before anything is allocated") {
            val tooBig =
                ByteBuffer
                    .allocate(5)
                    .put(DmCircuitFraming.TYPE_ENVELOPE.toByte())
                    .putInt(
                        DmEnvelopeCodec.MAX_ENVELOPE_BYTES + 1,
                    ).array()
            shouldThrow<DmFramingException> { reader().feed(tooBig) { _, _ -> } }
            val zero =
                ByteBuffer
                    .allocate(5)
                    .put(DmCircuitFraming.TYPE_ENVELOPE.toByte())
                    .putInt(0)
                    .array()
            shouldThrow<DmFramingException> { reader().feed(zero) { _, _ -> } }
            val negative =
                ByteBuffer
                    .allocate(5)
                    .put(DmCircuitFraming.TYPE_ENVELOPE.toByte())
                    .putInt(-1)
                    .array()
            shouldThrow<DmFramingException> { reader().feed(negative) { _, _ -> } }
            val huge =
                ByteBuffer
                    .allocate(5)
                    .put(DmCircuitFraming.TYPE_ENVELOPE.toByte())
                    .putInt(Int.MAX_VALUE)
                    .array()
            shouldThrow<DmFramingException> { reader().feed(huge) { _, _ -> } }
        }

        test("each side accepts only its own frame type") {
            shouldThrow<DmFramingException> { reader().feed(DmCircuitFraming.ackFrame()) { _, _ -> } }
            shouldThrow<DmFramingException> {
                reader(DmCircuitFraming.TYPE_ACK).feed(DmCircuitFraming.envelopeFrame(ByteArray(3) { 1 })) { _, _ -> }
            }
            shouldThrow<DmFramingException> { reader().feed(byteArrayOf(9, 0, 0, 0, 1, 0)) { _, _ -> } }
        }

        test("an acknowledgement is exactly one byte") {
            val got = ArrayList<ByteArray>()
            reader(DmCircuitFraming.TYPE_ACK).feed(DmCircuitFraming.ackFrame()) { _, p -> got += p }
            got.single().toList() shouldBe listOf(DmCircuitFraming.ACK_BYTE)
            shouldThrow<DmFramingException> {
                reader(
                    DmCircuitFraming.TYPE_ACK,
                ).feed(DmCircuitFraming.frame(DmCircuitFraming.TYPE_ACK, ByteArray(2))) { _, _ -> }
            }
        }
    })
