package net.lapisphilosophorum.lapisnet.mailonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dmonion.DmFramingException
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizing
import java.nio.ByteBuffer

class MailCircuitBundleCodecTest :
    FunSpec({
        val frame = ByteArray(300) { it.toByte() }

        fun refused(bytes: ByteArray) {
            shouldThrow<MalformedMailBundleException> { MailCircuitBundleCodec.decode(bytes) }
        }

        test("round trip with and without blobs") {
            val blobs = listOf(ByteArray(10) { 1 }, ByteArray(0), ByteArray(5000) { 2 })
            val decoded = MailCircuitBundleCodec.decode(MailCircuitBundleCodec.encode(frame, blobs))
            decoded.frame.contentEquals(frame) shouldBe true
            decoded.blobs.size shouldBe 3
            decoded.blobs.zip(blobs).all { (a, b) -> a.contentEquals(b) } shouldBe true
            MailCircuitBundleCodec.decode(MailCircuitBundleCodec.encode(frame, emptyList())).blobs.size shouldBe 0
        }

        test("a frame length larger than the rest, zero, or negative is refused") {
            val good = MailCircuitBundleCodec.encode(frame, emptyList())
            for (len in listOf(0, -1, frame.size + 2, Int.MAX_VALUE)) {
                val bad = good.copyOf()
                ByteBuffer.wrap(bad).position(1).putInt(len)
                refused(bad)
            }
        }

        test("a blob length larger than the rest or negative is refused") {
            val good = MailCircuitBundleCodec.encode(frame, listOf(ByteArray(20) { 4 }))
            val lenOffset = 1 + 4 + frame.size + 1
            for (len in listOf(-1, 21, Int.MAX_VALUE)) {
                val bad = good.copyOf()
                ByteBuffer.wrap(bad).position(lenOffset).putInt(len)
                refused(bad)
            }
        }

        test("more than 16 blobs, trailing bytes, truncation, a wrong version and an oversize bundle are refused") {
            val good = MailCircuitBundleCodec.encode(frame, listOf(ByteArray(8)))
            refused(good + byteArrayOf(0))
            refused(good.copyOf(good.size - 1))
            refused(good.copyOf().also { it[0] = 2 })
            refused(ByteArray(0))
            val countOffset = 1 + 4 + frame.size
            refused(good.copyOf().also { it[countOffset] = 17 })
            refused(ByteArray(AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES + 1))
            shouldThrow<IllegalArgumentException> { MailCircuitBundleCodec.encode(frame, List(17) { ByteArray(1) }) }
            shouldThrow<IllegalArgumentException> {
                MailCircuitBundleCodec.encode(frame, listOf(ByteArray(AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES)))
            }
        }

        test("the framing accepts exactly the bundle type and bounds the declared length") {
            val reader = MailCircuitFraming.bundleReader({ 0L }) { true }
            val bundle = MailCircuitBundleCodec.encode(frame, emptyList())
            var got: ByteArray? = null
            MailCircuitFraming.chunks(MailCircuitFraming.bundleFrame(bundle), 910).forEach {
                reader.feed(it) { type, payload ->
                    type shouldBe MailCircuitFraming.TYPE_MAIL_BUNDLE
                    got = payload
                }
            }
            got!!.contentEquals(bundle) shouldBe true
            // a DM envelope frame (type 1) and an ack frame (type 2) are not accepted by the bundle reader
            shouldThrow<DmFramingException> {
                MailCircuitFraming.bundleReader({ 0L }) { true }.feed(byteArrayOf(1, 0, 0, 0, 5)) { _, _ -> }
            }
            shouldThrow<DmFramingException> {
                MailCircuitFraming.bundleReader({ 0L }) { true }.feed(MailCircuitFraming.ackFrame()) { _, _ -> }
            }
            // length beyond the bound is refused from the header alone
            shouldThrow<DmFramingException> {
                MailCircuitFraming
                    .bundleReader({ 0L }) { true }
                    .feed(
                        ByteBuffer
                            .allocate(5)
                            .put(3)
                            .putInt(MailCircuitFraming.MAX_FRAME_BYTES + 1)
                            .array(),
                    ) { _, _ -> }
            }
        }

        test("the admit hook is asked before the body is allocated and can end the stream") {
            var asked = -1
            val reader =
                MailCircuitFraming.bundleReader({ 0L }) {
                    asked = it
                    false
                }
            shouldThrow<DmFramingException> {
                reader.feed(
                    ByteBuffer
                        .allocate(5)
                        .put(3)
                        .putInt(1234)
                        .array(),
                ) { _, _ -> }
            }
            asked shouldBe 1234
        }
    })
