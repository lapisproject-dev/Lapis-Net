package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private fun hex(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

class HolePunchCodecTest :
    FunSpec({
        test("golden vector: CONNECT without addresses is 08 64") {
            HolePunchCodec.encode(HolePunchMessage(HolePunchType.CONNECT)).toList() shouldBe hex(0x08, 0x64).toList()
        }

        test("golden vector: SYNC (300) is 08 ac 02") {
            HolePunchCodec.encode(HolePunchMessage(HolePunchType.SYNC)).toList() shouldBe hex(0x08, 0xAC, 0x02).toList()
        }

        test("golden vector: CONNECT with one address is 08 64 12 03 aa bb cc") {
            val bytes = HolePunchCodec.encode(HolePunchMessage(HolePunchType.CONNECT, listOf(hex(0xAA, 0xBB, 0xCC))))
            bytes.toList() shouldBe hex(0x08, 0x64, 0x12, 0x03, 0xAA, 0xBB, 0xCC).toList()
        }

        test("round trip") {
            val m = HolePunchMessage(HolePunchType.CONNECT, listOf(ByteArray(10) { it.toByte() }, ByteArray(64) { 1 }))
            HolePunchCodec.decode(HolePunchCodec.encode(m)) shouldBe m
        }

        test("unknown fields of a skippable wire type are ignored") {
            // field 3 varint 7, then the type
            HolePunchCodec.decode(hex(0x18, 0x07, 0x08, 0x64)) shouldBe HolePunchMessage(HolePunchType.CONNECT)
        }

        fun rejects(
            bytes: ByteArray,
            fragment: String,
        ) {
            shouldThrow<HolePunchProtocolException> { HolePunchCodec.decode(bytes) }.message shouldContain fragment
        }

        test("missing type") { rejects(hex(0x12, 0x01, 0x01), "missing") }
        test("empty message") { rejects(ByteArray(0), "missing") }
        test("unknown type") { rejects(hex(0x08, 0x65), "unknown message type") }
        test("duplicate type") { rejects(hex(0x08, 0x64, 0x08, 0x64), "duplicate") }
        test("nine addresses") {
            val bytes =
                hex(0x08, 0x64) + (0 until 9).flatMap { listOf(0x12, 0x01, 0x01) }.map { it.toByte() }.toByteArray()
            rejects(bytes, "too many")
        }
        test("an address of 65 bytes") {
            rejects(hex(0x08, 0x64, 0x12, 65) + ByteArray(65), "too long")
        }
        test("a message over 4 KiB") { rejects(hex(0x08, 0x64) + ByteArray(4100), "larger") }
        test("a truncated varint") { rejects(hex(0x08, 0xAC), "malformed") }
        test("a truncated length-delimited field") { rejects(hex(0x08, 0x64, 0x12, 0x05, 0x01), "malformed") }
        test("a group wire type") { rejects(hex(0x08, 0x64, 0x1B), "wire type") }
        test("trailing garbage after the message") { rejects(hex(0x08, 0x64, 0xFF), "malformed") }

        test("encode refuses oversized input") {
            shouldThrow<IllegalArgumentException> {
                HolePunchCodec.encode(HolePunchMessage(HolePunchType.CONNECT, List(9) { ByteArray(1) }))
            }
            shouldThrow<IllegalArgumentException> {
                HolePunchCodec.encode(HolePunchMessage(HolePunchType.CONNECT, listOf(ByteArray(65))))
            }
        }
    })
