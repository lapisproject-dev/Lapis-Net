package net.lapisphilosophorum.lapisnet.identity

import fr.acinq.secp256k1.Secp256k1
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.MessageDigest

class EcdhAgreementTest :
    FunSpec({
        test("ecdhSharedSecret is symmetric: ecdh(a, B) == ecdh(b, A)") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()

            ecdhSharedSecret(a.privateKey, b.publicKey) shouldBe ecdhSharedSecret(b.privateKey, a.publicKey)
        }

        test("ecdhSharedSecret is always exactly 32 bytes") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()

            ecdhSharedSecret(a.privateKey, b.publicKey).size shouldBe 32
        }

        test("ecdhSharedSecret differs for different keypairs") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val c = Secp256k1KeyPair.generate()

            ecdhSharedSecret(a.privateKey, b.publicKey) shouldNotBe ecdhSharedSecret(a.privateKey, c.publicKey)
        }

        // The pinning regression this module's doc comment promises: independently recompute the
        // shared point via this same jar's own pubKeyTweakMul/pubKeyCompress primitives (NOT via
        // ecdhSharedSecret itself) and SHA-256 the compressed result, then assert it equals
        // ecdhSharedSecret's output byte-for-byte. This is what makes the claim "ecdh returns
        // SHA-256(compressed shared point), not the raw X coordinate" an empirically verified fact
        // rather than documentation copied from elsewhere - and it is the tripwire if a future
        // secp256k1-kmp bump ever changes the default hash function: without it, such a bump would
        // silently and undetectably change every key this codebase derives.
        test("ecdhSharedSecret == SHA-256(compressed shared point) - pins the exact output shape") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()

            val actual = ecdhSharedSecret(a.privateKey, b.publicKey)

            val uncompressedSharedPoint = Secp256k1.pubKeyTweakMul(b.publicKey.bytes, a.privateKey.bytes)
            val compressedSharedPoint = Secp256k1.pubKeyCompress(uncompressedSharedPoint)
            val expected = MessageDigest.getInstance("SHA-256").digest(compressedSharedPoint)

            actual shouldBe expected
        }

        test("ecdhSharedSecret is NOT the raw X coordinate of the shared point") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()

            val actual = ecdhSharedSecret(a.privateKey, b.publicKey)

            val uncompressedSharedPoint = Secp256k1.pubKeyTweakMul(b.publicKey.bytes, a.privateKey.bytes)
            // Uncompressed point layout: 0x04 || X(32) || Y(32).
            val rawX = uncompressedSharedPoint.copyOfRange(1, 33)

            actual shouldNotBe rawX
        }

        test("ecdhSharedSecret throws for an off-curve public key rather than reaching the native call") {
            // Cannot construct a Secp256k1PublicKey from off-curve bytes at all - the constructor's
            // own pubkeyParse guard rejects it first. This is the assertion that guard exists and
            // is load-bearing for this function's "unreachable with invalid input" claim.
            val offCurveBytes = byteArrayOf(0x02) + ByteArray(32) { 0xFF.toByte() }

            shouldThrow<IllegalArgumentException> { Secp256k1PublicKey(offCurveBytes) }
        }

        test("does not mutate the private key's own byte accessor after use") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val before = a.privateKey.bytes

            ecdhSharedSecret(a.privateKey, b.publicKey)

            a.privateKey.bytes shouldBe before
        }
    })
