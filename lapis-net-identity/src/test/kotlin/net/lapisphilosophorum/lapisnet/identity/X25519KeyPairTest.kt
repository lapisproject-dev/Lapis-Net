package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

private fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        (
            (Character.digit(s[i * 2], 16) shl 4) +
                Character.digit(s[i * 2 + 1], 16)
        ).toByte()
    }

/** The seven classically published canonical small-order Curve25519 u-coordinates. */
private val CANONICAL_LOW_ORDER_POINTS =
    listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ).map { hex(it) }

/** The five non-canonical (bit-255-set) re-encodings that reduce to full-order points after RFC
 * 7748's mandatory bit-255 masking - NOT caught by BouncyCastle's own all-zero-agreement check. */
private val NON_CANONICAL_LOW_ORDER_POINTS =
    listOf(
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "d9" + "ff".repeat(31),
        "da" + "ff".repeat(31),
        "db" + "ff".repeat(31),
    ).map { hex(it) }

class X25519KeyPairTest :
    FunSpec({
        test("generate produces different private keys across calls") {
            val a = X25519KeyPair.generate()
            val b = X25519KeyPair.generate()
            a.privateKey shouldNotBe b.privateKey
        }

        test("generated public key has bit 255 clear (canonical encoding)") {
            repeat(20) {
                val keyPair = X25519KeyPair.generate()
                (keyPair.publicKey.bytes[31].toInt() and 0x80) shouldBe 0
            }
        }

        test("fromPrivateKeyBytes round-trips: derived public key equals the generated one") {
            val generated = X25519KeyPair.generate()
            val derived = X25519KeyPair.fromPrivateKeyBytes(generated.privateKey.bytes)
            derived.publicKey shouldBe generated.publicKey
        }

        test("X25519PrivateKey rejects an all-zero seed") {
            shouldThrow<IllegalArgumentException> { X25519PrivateKey(ByteArray(32)) }
        }

        test("X25519PrivateKey rejects an all-ones seed") {
            shouldThrow<IllegalArgumentException> { X25519PrivateKey(ByteArray(32) { 0xFF.toByte() }) }
        }

        test("X25519PrivateKey rejects 31 and 33 bytes") {
            shouldThrow<IllegalArgumentException> { X25519PrivateKey(ByteArray(31)) }
            shouldThrow<IllegalArgumentException> { X25519PrivateKey(ByteArray(33)) }
        }

        test("X25519PublicKey rejects 31 and 33 bytes") {
            shouldThrow<IllegalArgumentException> { X25519PublicKey(ByteArray(31)) }
            shouldThrow<IllegalArgumentException> { X25519PublicKey(ByteArray(33)) }
        }

        test("X25519PublicKey rejects all seven canonical small-order points") {
            CANONICAL_LOW_ORDER_POINTS.forEach { point ->
                shouldThrow<IllegalArgumentException> { X25519PublicKey(point) }
            }
        }

        test("X25519PublicKey rejects all five non-canonical (bit-255-set) low-order re-encodings") {
            NON_CANONICAL_LOW_ORDER_POINTS.forEach { point ->
                shouldThrow<IllegalArgumentException> { X25519PublicKey(point) }
            }
        }

        test("X25519PublicKey rejects a non-blacklisted u >= p value via the canonical-encoding rule alone") {
            // Not one of the twelve blacklisted values - proves the u < p rule is independently
            // exercised, not merely redundant with the blacklist.
            val nonCanonical = hex("f0" + "ff".repeat(31))
            shouldThrow<IllegalArgumentException> { X25519PublicKey(nonCanonical) }
        }

        test("X25519PublicKey accepts both RFC 7748 section 6.1 public keys unchanged") {
            shouldNotThrowAny {
                X25519PublicKey(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
            }
            shouldNotThrowAny {
                X25519PublicKey(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
            }
        }

        test("a genuinely generated public key round-trips through validation") {
            val keyPair = X25519KeyPair.generate()
            shouldNotThrowAny { X25519PublicKey(keyPair.publicKey.bytes) }
        }

        test(
            "BouncyCastle pinning regression: canonical small-order points fail agreement (IllegalStateException), " +
                "non-canonical ones do not - this pins the exact dependency behaviour the low-order rejection design " +
                "depends on, so a future BouncyCastle bump that changes it fails loudly rather than silently",
        ) {
            val scalar = X25519PrivateKeyParameters(java.security.SecureRandom())
            CANONICAL_LOW_ORDER_POINTS.forEach { point ->
                val out = ByteArray(32)
                shouldThrow<IllegalStateException> {
                    scalar.generateSecret(X25519PublicKeyParameters(point, 0), out, 0)
                }
            }
            NON_CANONICAL_LOW_ORDER_POINTS.forEach { point ->
                val out = ByteArray(32)
                shouldNotThrowAny {
                    scalar.generateSecret(X25519PublicKeyParameters(point, 0), out, 0)
                }
                out.all { it == 0.toByte() } shouldBe false
            }
        }
    })
