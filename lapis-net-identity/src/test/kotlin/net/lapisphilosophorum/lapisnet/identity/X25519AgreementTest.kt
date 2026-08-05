package net.lapisphilosophorum.lapisnet.identity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        (
            (Character.digit(s[i * 2], 16) shl 4) +
                Character.digit(s[i * 2 + 1], 16)
        ).toByte()
    }

// RFC 7748 section 6.1 published test vector.
private val ALICE_PRIVATE = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
private val ALICE_PUBLIC = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
private val BOB_PRIVATE = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
private val BOB_PUBLIC = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
private val EXPECTED_SHARED = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

class X25519AgreementTest :
    FunSpec({
        test("symmetric: both directions produce the same shared secret") {
            val a = X25519KeyPair.generate()
            val b = X25519KeyPair.generate()
            x25519SharedSecret(a.privateKey, b.publicKey) shouldBe x25519SharedSecret(b.privateKey, a.publicKey)
        }

        test("RFC 7748 section 6.1 known-answer vector, both directions") {
            val alicePrivateKey = X25519PrivateKey(ALICE_PRIVATE)
            val bobPublicKey = X25519PublicKey(BOB_PUBLIC)
            x25519SharedSecret(alicePrivateKey, bobPublicKey) shouldBe EXPECTED_SHARED

            val bobPrivateKey = X25519PrivateKey(BOB_PRIVATE)
            val alicePublicKey = X25519PublicKey(ALICE_PUBLIC)
            x25519SharedSecret(bobPrivateKey, alicePublicKey) shouldBe EXPECTED_SHARED
        }

        test("both RFC private keys derive their published public keys") {
            X25519KeyPair.fromPrivateKeyBytes(ALICE_PRIVATE).publicKey shouldBe X25519PublicKey(ALICE_PUBLIC)
            X25519KeyPair.fromPrivateKeyBytes(BOB_PRIVATE).publicKey shouldBe X25519PublicKey(BOB_PUBLIC)
        }

        test("the shared secret is the raw RFC value, not SHA-256 of anything - proving it is not hashed") {
            val alicePrivateKey = X25519PrivateKey(ALICE_PRIVATE)
            val bobPublicKey = X25519PublicKey(BOB_PUBLIC)
            val shared = x25519SharedSecret(alicePrivateKey, bobPublicKey)
            shared shouldBe EXPECTED_SHARED
            val sha256OfShared =
                java.security.MessageDigest
                    .getInstance("SHA-256")
                    .digest(shared)
            shared.contentEquals(sha256OfShared) shouldBe false
        }

        test("the caller's private key is not mutated by the call") {
            val privateKey = X25519PrivateKey(ALICE_PRIVATE)
            val before = privateKey.bytes
            x25519SharedSecret(privateKey, X25519PublicKey(BOB_PUBLIC))
            privateKey.bytes shouldBe before
        }
    })
