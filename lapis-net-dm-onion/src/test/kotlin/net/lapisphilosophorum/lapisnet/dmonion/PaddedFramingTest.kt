package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

/** Padded frames: roundtrip, tamper cases and the order of frame completion and acknowledgement (wave V0.10.0-H). */
class PaddedFramingTest :
    FunSpec({
        val maxPayload = 910
        val dmMax = DmEnvelopeCodec.MAX_ENVELOPE_BYTES

        fun reader(
            clock: () -> Long = { 0L },
            admit: (Int) -> Boolean = { true },
        ) = DmFrameReader(
            setOf(DmCircuitFraming.TYPE_ENVELOPE, DmCircuitFraming.TYPE_ENVELOPE_PADDED),
            clock,
            dmMax,
            admit,
            maxPayload,
            mapOf(DmCircuitFraming.TYPE_ENVELOPE_PADDED to DmCircuitFraming.TYPE_ENVELOPE),
        )

        fun feedAll(
            r: DmFrameReader,
            chunks: List<ByteArray>,
        ): List<Pair<Int, ByteArray>> {
            val out = ArrayList<Pair<Int, ByteArray>>()
            chunks.forEach { c -> r.feed(c) { t, p -> out += t to p } }
            return out
        }

        test("an envelope of every tested length survives padding and its chunk count equals its size class") {
            val cap = FrameSizeClasses.maxChunks(dmMax, maxPayload)
            for (len in listOf(1, 2, 100, 800, 905, 906, 910, 1000, 1700, 1815, 1816, 5000, 30_000, dmMax)) {
                val envelope = ByteArray(len) { (it * 31 + len).toByte() }
                val frame = DmCircuitFraming.paddedEnvelopeFrame(envelope, maxPayload)
                (frame.size % maxPayload) shouldBe 0
                val chunks = DmCircuitFraming.chunks(frame, maxPayload)
                chunks.size shouldBe FrameSizeClasses.classChunks(FrameSizeClasses.realChunks(len, maxPayload), cap)
                chunks.all { it.size == maxPayload } shouldBe true
                val got = feedAll(reader(), chunks)
                got.size shouldBe 1
                // handlers see the base type and exactly the original bytes
                got.single().first shouldBe DmCircuitFraming.TYPE_ENVELOPE
                got.single().second.contentEquals(envelope) shouldBe true
            }
        }

        test("two lengths of one class give the same number of chunks, different classes do not") {
            fun chunksOf(len: Int) =
                DmCircuitFraming
                    .chunks(
                        DmCircuitFraming.paddedEnvelopeFrame(ByteArray(len), maxPayload),
                        maxPayload,
                    ).size
            chunksOf(100) shouldBe chunksOf(800)
            chunksOf(1000) shouldBe chunksOf(1700)
            (chunksOf(1000) > chunksOf(100)) shouldBe true
        }

        test("an unpadded frame is still accepted (a sender with padding off)") {
            val envelope = ByteArray(1234) { 7 }
            val got = feedAll(reader(), DmCircuitFraming.chunks(DmCircuitFraming.envelopeFrame(envelope), maxPayload))
            got.single().first shouldBe DmCircuitFraming.TYPE_ENVELOPE
            got.single().second.contentEquals(envelope) shouldBe true
        }

        test("the frame is reported only after the last padding byte: the acknowledgement follows the whole class") {
            val frame = DmCircuitFraming.paddedEnvelopeFrame(ByteArray(3000), maxPayload) // 4 chunks
            val chunks = DmCircuitFraming.chunks(frame, maxPayload)
            chunks.size shouldBe 4
            val r = reader()
            var reported = 0
            for ((i, c) in chunks.withIndex()) {
                r.feed(c) { _, _ -> reported++ }
                // the real data ends inside chunk 4 (3000 + 5 bytes = 3.3 chunks): nothing may be reported earlier
                reported shouldBe (if (i == chunks.lastIndex) 1 else 0)
            }
        }

        test("the padding is counted, never inspected: non-zero padding is accepted without effect (no oracle)") {
            val envelope = ByteArray(10) { 9 }
            val frame = DmCircuitFraming.paddedEnvelopeFrame(envelope, maxPayload)
            for (i in 15 until frame.size) frame[i] = (i * 13).toByte()
            val got = feedAll(reader(), DmCircuitFraming.chunks(frame, maxPayload))
            got.single().second.contentEquals(envelope) shouldBe true
        }

        test("too little padding: nothing is reported, the stream stays in the frame and the idle sweep can close it") {
            val now = AtomicLong(0)
            val frame = DmCircuitFraming.paddedEnvelopeFrame(ByteArray(3000), maxPayload)
            val short = frame.copyOf(frame.size - 1)
            val r = reader({ now.get() })
            var reported = 0
            DmCircuitFraming.chunks(short, maxPayload).forEach { r.feed(it) { _, _ -> reported++ } }
            reported shouldBe 0
            r.inFrame shouldBe true
            now.set(11_000)
            // exactly what OnionDmInboundHandler.sweep checks
            (r.inFrame && now.get() - r.lastProgressMillis >= 10_000L) shouldBe true
        }

        test("too much padding: the next bytes form a header, which is rejected as a framing violation") {
            val frame = DmCircuitFraming.paddedEnvelopeFrame(ByteArray(3000), maxPayload)
            val longer = frame + ByteArray(maxPayload) // one extra chunk of zeros
            val r = reader()
            shouldThrow<DmFramingException> {
                DmCircuitFraming.chunks(longer, maxPayload).forEach { r.feed(it) { _, _ -> } }
            }
        }

        test("a declared length above the maximum is refused before any buffer is allocated") {
            var admitted = false
            val r =
                reader(admit = {
                    admitted = true
                    true
                })
            val header =
                ByteBuffer
                    .allocate(5)
                    .put(DmCircuitFraming.TYPE_ENVELOPE_PADDED.toByte())
                    .putInt(dmMax + 1)
                    .array()
            shouldThrow<DmFramingException> { r.feed(header) { _, _ -> } }
            admitted shouldBe false
        }

        test("a padded type the reader does not allow is refused") {
            val r = DmFrameReader(DmCircuitFraming.TYPE_ENVELOPE, { 0L })
            shouldThrow<DmFramingException> {
                r.feed(DmCircuitFraming.paddedEnvelopeFrame(ByteArray(5), maxPayload)) { _, _ -> }
            }
        }

        test("admit sees the real length, not the padded one, and bodyTooSlow counts the padding as part of the body") {
            val seen = ArrayList<Int>()
            val r =
                reader(admit = {
                    seen += it
                    true
                })
            val frame = DmCircuitFraming.paddedEnvelopeFrame(ByteArray(2000), maxPayload) // 3 real chunks, class 4
            r.feed(frame.copyOfRange(0, 5)) { _, _ -> }
            seen shouldBe listOf(2000)
            r.headerComplete shouldBe true
            r.bodyLength shouldBe (4 * maxPayload - 5)
            r.feed(frame.copyOfRange(5, maxPayload)) { _, _ -> }
            r.bodyReceived shouldBe (maxPayload - 5)
        }

        test("an oversized payload is refused when the frame is built") {
            shouldThrow<IllegalArgumentException> {
                DmCircuitFraming.paddedEnvelopeFrame(ByteArray(dmMax + 1), maxPayload)
            }
        }
    })
