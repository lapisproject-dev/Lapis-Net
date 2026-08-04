package net.lapisphilosophorum.lapisnet.core.cid

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class CidBytesValidationTest :
    FunSpec({
        test("rejects a declared multihash length that overruns the remaining bytes") {
            // version=1, codec=0x55, type=0x12, declared length=0x7FFFFFFF, no hash bytes follow
            val bytes = byteArrayOf(1, 0x55, 0x12, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x07)
            CidBytesValidation.isSafeToCast(bytes) shouldBe false
        }

        test("rejects a declared multihash length exceeding the 127-byte cap even if enough bytes follow") {
            val header = byteArrayOf(1, 0x55, 0x12, 128.toByte(), 1) // declares length 128
            val bytes = header + ByteArray(128)
            CidBytesValidation.isSafeToCast(bytes) shouldBe false
        }

        test("accepts a well-formed CIDv1 sha2-256 encoding") {
            val header = byteArrayOf(1, 0x55, 0x12, 32) // version 1, raw codec, sha2-256, length 32
            val bytes = header + ByteArray(32)
            CidBytesValidation.isSafeToCast(bytes) shouldBe true
        }

        test("accepts the CIDv0 34-byte fast path") {
            val bytes = byteArrayOf(18, 32) + ByteArray(32)
            CidBytesValidation.isSafeToCast(bytes) shouldBe true
        }

        // isSafeToDeserializeMultihash: the same guard, but for candidates positioned at the
        // multihash's own type varint (no leading version/codec pair) - the shape
        // `io.ipfs.cid.Cid.decode(String)`'s legacy CIDv0 shortcut (`Multihash.fromBase58(v)`)
        // hands to `Multihash.deserialize` directly, bypassing `Cid.cast`/[isSafeToCast] entirely.
        // See `lapis-net-browser`'s `parseCidOrNull` for the guarded call site.

        test("isSafeToDeserializeMultihash rejects a declared length that overruns the remaining bytes") {
            // type=0x12, declared length=0x7FFFFFFF, no hash bytes follow
            val bytes = byteArrayOf(0x12, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x07)
            CidBytesValidation.isSafeToDeserializeMultihash(bytes) shouldBe false
        }

        test("isSafeToDeserializeMultihash rejects a declared length exceeding the 127-byte cap") {
            val header = byteArrayOf(0x12, 128.toByte(), 1) // declares length 128
            val bytes = header + ByteArray(128)
            CidBytesValidation.isSafeToDeserializeMultihash(bytes) shouldBe false
        }

        test("isSafeToDeserializeMultihash accepts a well-formed sha2-256 multihash encoding") {
            val header = byteArrayOf(0x12, 32) // sha2-256, length 32
            val bytes = header + ByteArray(32)
            CidBytesValidation.isSafeToDeserializeMultihash(bytes) shouldBe true
        }
    })
