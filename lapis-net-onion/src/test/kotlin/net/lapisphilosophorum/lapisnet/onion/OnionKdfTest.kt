package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import net.lapisphilosophorum.lapisnet.onion.fake.unhex

class OnionKdfTest :
    FunSpec({
        test("HKDF-SHA256, RFC 5869 test case 1") {
            val okm =
                OnionKdf.hkdfSha256(
                    ByteArray(22) { 0x0b },
                    unhex("000102030405060708090a0b0c"),
                    unhex("f0f1f2f3f4f5f6f7f8f9"),
                    42,
                )
            hex(okm) shouldBe
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        }

        test("HKDF-SHA256 with an empty salt equals a zero-filled salt (RFC 5869 test case 3)") {
            val okm = OnionKdf.hkdfSha256(ByteArray(22) { 0x0b }, ByteArray(0), ByteArray(0), 42)
            hex(okm) shouldBe
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        }

        test("HMAC-SHA256, RFC 4231 test case 1") {
            hex(OnionKdf.hmacSha256(ByteArray(20) { 0x0b }, "Hi There".toByteArray())) shouldBe
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        }
    })
