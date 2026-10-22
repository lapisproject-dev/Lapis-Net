package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.DeterministicSecureRandom
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import java.security.SecureRandom
import java.util.Random

class RelayMessageCodecTest :
    FunSpec({
        val rnd = SecureRandom()

        test("golden header with a deterministic padding stream") {
            val msg = RelayMessage(RelayCommand.DATA, 0x0102.toShort(), byteArrayOf(9, 8, 7))
            val out = RelayMessageCodec.encode(msg, 20, DeterministicSecureRandom(5))
            out.size shouldBe 20
            hex(out.copyOfRange(0, 8)) shouldBe "0101020003" + "090807"
        }

        test("capacity per hop count") {
            for (hops in 1..5) {
                RelayMessageCodec.capacity(hops) shouldBe 1019 - 17 * hops
                RelayMessageCodec.maxData(hops) shouldBe 1019 - 17 * hops - 5
            }
            shouldThrow<IllegalArgumentException> { RelayMessageCodec.maxData(0) }
            shouldThrow<IllegalArgumentException> { RelayMessageCodec.maxData(6) }
        }

        test("roundtrip at the exact payload boundary, one more is refused") {
            for (hops in 1..5) {
                val max = RelayMessageCodec.maxData(hops)
                val cap = RelayMessageCodec.capacity(hops)
                val data = ByteArray(max) { it.toByte() }
                val msg = RelayMessage(RelayCommand.DATA, -2, data)
                val back = RelayMessageCodec.decode(RelayMessageCodec.encode(msg, cap, rnd))
                back.command shouldBe RelayCommand.DATA
                back.streamId shouldBe (-2).toShort()
                back.data.contentEquals(data) shouldBe true
                shouldThrow<IllegalArgumentException> {
                    RelayMessageCodec.encode(RelayMessage(RelayCommand.DATA, 0, ByteArray(max + 1)), cap, rnd)
                }
            }
        }

        test("hostile length fields") {
            val ok = RelayMessageCodec.encode(RelayMessage(RelayCommand.DATA, 1, ByteArray(10)), 100, rnd)
            RelayMessageCodec.decode(ok).data.size shouldBe 10
            // length = 0xFFFF, a "negative short" (0x8000), exact edge +-1
            for (len in listOf(0xFFFF, 0x8000, 96, 100, 1000)) {
                val bad = ok.copyOf()
                bad[3] = (len ushr 8).toByte()
                bad[4] = len.toByte()
                shouldThrow<CellFormatException> { RelayMessageCodec.decode(bad) }
            }
            val edge =
                ok.copyOf().also {
                    it[3] = 0
                    it[4] = 95
                }
            RelayMessageCodec.decode(edge).data.size shouldBe 95
            val over =
                ok.copyOf().also {
                    it[3] = 0
                    it[4] = 96
                }
            shouldThrow<CellFormatException> { RelayMessageCodec.decode(over) }
            shouldThrow<CellFormatException> { RelayMessageCodec.decode(ByteArray(4)) }
            shouldThrow<CellFormatException> { RelayMessageCodec.decode(ByteArray(100).also { it[0] = 77 }) }
        }

        test("fuzz: 10000 random buffers never produce anything but CellFormatException") {
            val r = Random(42)
            repeat(10_000) {
                val buf = ByteArray(r.nextInt(1100))
                r.nextBytes(buf)
                try {
                    RelayMessageCodec.decode(buf)
                } catch (e: CellFormatException) {
                    // expected
                }
            }
        }

        test("extend payload roundtrip and boundaries") {
            val x = X25519KeyPair.generate(DeterministicSecureRandom(3)).publicKey
            for (specLen in listOf(0, 1, 127, 128)) {
                val p = ExtendPayload(3, ByteArray(32) { 1 }, ByteArray(32) { 2 }, x, ByteArray(specLen) { 5 })
                val enc = ExtendPayloadCodec.encode(p)
                val d = ExtendPayloadCodec.decode(enc)
                d.hopIndex shouldBe 3
                d.linkSpecifier.size shouldBe specLen
                d.clientEphemeral shouldBe x
            }
            shouldThrow<IllegalArgumentException> { ExtendPayload(3, ByteArray(32), ByteArray(32), x, ByteArray(129)) }
        }

        test("extend payload: truncation at every offset and length mismatches") {
            val x = X25519KeyPair.generate(DeterministicSecureRandom(4)).publicKey
            val enc =
                ExtendPayloadCodec.encode(
                    ExtendPayload(2, ByteArray(32) { 1 }, ByteArray(32) { 2 }, x, ByteArray(10)),
                )
            for (cut in 0 until enc.size) {
                shouldThrow<CellFormatException> { ExtendPayloadCodec.decode(enc.copyOf(cut)) }
            }
            shouldThrow<CellFormatException> { ExtendPayloadCodec.decode(enc + byteArrayOf(0)) }
            // specifier length byte larger than 128 and larger than the remainder
            val big = enc.copyOf().also { it[97] = 200.toByte() }
            shouldThrow<CellFormatException> { ExtendPayloadCodec.decode(big) }
            shouldThrow<CellFormatException> { ExtendPayloadCodec.decode(enc.copyOf().also { it[0] = 0 }) }
            // low-order client ephemeral
            val low = enc.copyOf().also { ByteArray(32).also { z -> z[0] = 1 }.copyInto(it, 65) }
            shouldThrow<CellFormatException> { ExtendPayloadCodec.decode(low) }
        }
    })
