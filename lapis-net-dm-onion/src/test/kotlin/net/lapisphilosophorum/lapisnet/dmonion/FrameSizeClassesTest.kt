package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec

/** The size classes of padded frames (wave V0.10.0-H). */
class FrameSizeClassesTest :
    FunSpec({
        val maxPayload = 910
        val dmMax = DmEnvelopeCodec.MAX_ENVELOPE_BYTES
        val mailMax = 1_048_576 + 16

        test("the DM classes are the powers of two up to the chunk count of the largest envelope (8 classes)") {
            FrameSizeClasses.classes(dmMax, maxPayload) shouldBe listOf(1, 2, 4, 8, 16, 32, 64, 73)
        }

        test("the mail classes are the powers of two up to 1024 plus the largest frame (12 classes)") {
            val classes = FrameSizeClasses.classes(mailMax, maxPayload)
            classes shouldBe listOf(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1153)
        }

        test("the class is monotone, at least the real chunk count, and capped at the class of the maximum") {
            for ((max, name) in listOf(dmMax to "dm", mailMax to "mail")) {
                val cap = FrameSizeClasses.maxChunks(max, maxPayload)
                var previous = 0
                for (len in generateSequence(1) { if (it < 5000) it + 7 else it + 997 }.takeWhile { it <= max }) {
                    val real = FrameSizeClasses.realChunks(len, maxPayload)
                    val cls = FrameSizeClasses.classChunks(real, cap)
                    (cls >= real) shouldBe true
                    (cls <= cap) shouldBe true
                    (cls >= previous) shouldBe true
                    previous = cls
                    // never more than twice the real size, except for the cap
                    (cls < 2 * real || cls == cap) shouldBe true
                }
                FrameSizeClasses.classChunks(FrameSizeClasses.realChunks(max, maxPayload), cap) shouldBe cap
                name.isNotEmpty() shouldBe true
            }
        }

        test(
            "boundary lengths: a 905 byte payload fills one chunk, 906 needs two, 1815 fills two, 1816 needs three (class 4)",
        ) {
            FrameSizeClasses.realChunks(905, maxPayload) shouldBe 1
            FrameSizeClasses.realChunks(906, maxPayload) shouldBe 2
            FrameSizeClasses.realChunks(910, maxPayload) shouldBe 2
            FrameSizeClasses.realChunks(911, maxPayload) shouldBe 2
            FrameSizeClasses.realChunks(1815, maxPayload) shouldBe 2
            FrameSizeClasses.realChunks(1816, maxPayload) shouldBe 3
            FrameSizeClasses.paddedFrameBytes(1816, maxPayload, dmMax) shouldBe 4L * maxPayload
            FrameSizeClasses.paddedFrameBytes(1, maxPayload, dmMax) shouldBe 1L * maxPayload
            FrameSizeClasses.paddingBytes(905, maxPayload, dmMax) shouldBe 0L
            FrameSizeClasses.paddingBytes(100, maxPayload, dmMax) shouldBe (910L - 5 - 100)
        }

        test("the padded size of the largest legal frame is exactly its class: no padding beyond the cap") {
            val cap = FrameSizeClasses.maxChunks(dmMax, maxPayload)
            FrameSizeClasses.paddedFrameBytes(dmMax, maxPayload, dmMax) shouldBe cap.toLong() * maxPayload
        }

        test("a length above the maximum or a huge length is refused before any allocation, without overflow") {
            shouldThrow<IllegalArgumentException> { FrameSizeClasses.paddedFrameBytes(dmMax + 1, maxPayload, dmMax) }
            shouldThrow<IllegalArgumentException> {
                FrameSizeClasses.paddedFrameBytes(Int.MAX_VALUE, maxPayload, dmMax)
            }
            // the chunk count of the largest Int length fits an Int
            FrameSizeClasses.realChunks(Int.MAX_VALUE, maxPayload) shouldBe
                ((Int.MAX_VALUE.toLong() + 5 + maxPayload - 1) / maxPayload).toInt()
            shouldThrow<IllegalArgumentException> { FrameSizeClasses.realChunks(-1, maxPayload) }
            shouldThrow<IllegalArgumentException> { FrameSizeClasses.realChunks(1, 0) }
        }
    })
