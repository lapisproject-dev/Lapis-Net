package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.DeterministicSecureRandom
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import java.security.SecureRandom

class CellCodecTest :
    FunSpec({
        val body = ByteArray(OnionConstants.BODY_SIZE) { (it % 251).toByte() }

        test("golden header bytes for every command") {
            val expected =
                mapOf(
                    CellCommand.CREATE to "0102030401",
                    CellCommand.CREATED to "0102030402",
                    CellCommand.RELAY to "0102030403",
                    CellCommand.DESTROY to "0102030404",
                )
            for ((cmd, header) in expected) {
                val bytes = CellCodec.encode(Cell(0x01020304, cmd, body))
                bytes.size shouldBe 1024
                hex(bytes.copyOfRange(0, 5)) shouldBe header
                hex(bytes.copyOfRange(5, 10)) shouldBe "0001020304"
            }
            val padding = CellCodec.encode(Cell(0, CellCommand.PADDING, body))
            hex(padding.copyOfRange(0, 5)) shouldBe "0000000000"
        }

        test("roundtrip for every command") {
            for (cmd in CellCommand.entries) {
                val id = if (cmd == CellCommand.PADDING) 0 else -123456
                val cell = Cell(id, cmd, body)
                CellCodec.decode(CellCodec.encode(cell)) shouldBe cell
            }
        }

        test("decoding at an offset") {
            val cell = Cell(7, CellCommand.RELAY, body)
            val buf = ByteArray(3000)
            CellCodec.encode(cell).copyInto(buf, 500)
            CellCodec.decode(buf, 500) shouldBe cell
            shouldThrow<CellFormatException> { CellCodec.decode(buf, 2977) }
            shouldThrow<CellFormatException> { CellCodec.decode(buf, -1) }
        }

        test("every size other than 1024 is rejected before any copy") {
            for (size in listOf(0, 1, 5, 1023, 1025, 2048, 10_000_000)) {
                shouldThrow<CellFormatException> { CellCodec.decode(ByteArray(size)) }
            }
        }

        test("unknown command and circuit id rules") {
            val ok = CellCodec.encode(Cell(1, CellCommand.RELAY, body))
            for (code in listOf(5, 9, 0x7F, 0xFF)) {
                val bad = ok.copyOf().also { it[4] = code.toByte() }
                shouldThrow<CellFormatException> { CellCodec.decode(bad) }
            }
            // circuit id 0 on a non-PADDING cell
            shouldThrow<CellFormatException> { CellCodec.decode(ok.copyOf().also { for (i in 0..3) it[i] = 0 }) }
            // PADDING with a non-zero circuit id
            shouldThrow<CellFormatException> { CellCodec.decode(ok.copyOf().also { it[4] = 0 }) }
            shouldThrow<IllegalArgumentException> { Cell(0, CellCommand.RELAY, body) }
            shouldThrow<IllegalArgumentException> { Cell(1, CellCommand.RELAY, ByteArray(10)) }
        }

        test("cell toString never prints body bytes") {
            Cell(1, CellCommand.RELAY, body).toString() shouldBe "Cell(circuitId=1, command=RELAY)"
        }

        test("create body: roundtrip, golden layout, low-order key rejected") {
            val x = X25519KeyPair.generate(DeterministicSecureRandom(1)).publicKey
            val id = ByteArray(32) { 1 }
            val fp = ByteArray(32) { 2 }
            val encoded = CreateBody(2, id, fp, x).encode(SecureRandom())
            encoded.size shouldBe OnionConstants.BODY_SIZE
            hex(encoded.copyOfRange(0, 3)) shouldBe "000102"
            val decoded = CreateBody.decode(encoded)
            decoded.hopIndex shouldBe 2
            decoded.clientEphemeral shouldBe x
            hex(decoded.relayIdDigest) shouldBe hex(id)
            // low-order point (u = 1) rejected structurally
            val lowOrder = encoded.copyOf()
            ByteArray(32).also { it[0] = 1 }.copyInto(lowOrder, 3 + 64)
            shouldThrow<CellFormatException> { CreateBody.decode(lowOrder) }
            // wrong handshake type / hop index
            shouldThrow<CellFormatException> { CreateBody.decode(encoded.copyOf().also { it[1] = 9 }) }
            shouldThrow<CellFormatException> { CreateBody.decode(encoded.copyOf().also { it[2] = 0 }) }
            shouldThrow<CellFormatException> { CreateBody.decode(encoded.copyOf().also { it[2] = 6 }) }
            shouldThrow<CellFormatException> { CreateBody.decode(ByteArray(10)) }
        }

        test("created and destroy bodies") {
            val y = X25519KeyPair.generate(DeterministicSecureRandom(2)).publicKey
            val created = CreatedBody(y, ByteArray(32) { 7 })
            val back = CreatedBody.decode(created.encode(SecureRandom()))
            back.serverEphemeral shouldBe y
            hex(back.auth) shouldBe "07".repeat(32)
            shouldThrow<CellFormatException> { CreatedBody.fromExtendedPayload(ByteArray(63)) }
            for (r in DestroyReason.entries) DestroyBody.decode(DestroyBody.encode(r)) shouldBe r
            DestroyBody.decode(ByteArray(OnionConstants.BODY_SIZE).also { it[0] = 99 }) shouldBe DestroyReason.PROTOCOL
        }

        test("unused body space is random, not zero") {
            val a = DestroyBody.encode(DestroyReason.NONE)
            val b = DestroyBody.encode(DestroyReason.NONE)
            (a.copyOfRange(1, 40).contentEquals(b.copyOfRange(1, 40))) shouldBe false
        }
    })
