package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class Ed25519KeyPairTest :
    FunSpec({
        val message = "lapis net identity binding".toByteArray()

        test("generate produces different private keys across calls") {
            val a = Ed25519KeyPair.generate()
            val b = Ed25519KeyPair.generate()
            a.privateKey shouldNotBe b.privateKey
        }

        test("verify succeeds for a matching signature, message, and public key") {
            val keyPair = Ed25519KeyPair.generate()
            val signature = keyPair.sign(message)
            keyPair.publicKey.verify(message, signature) shouldBe true
        }

        test("verify fails when the message is tampered") {
            val keyPair = Ed25519KeyPair.generate()
            val signature = keyPair.sign(message)
            val tamperedMessage = message.copyOf().also { it[0] = (it[0] + 1).toByte() }
            keyPair.publicKey.verify(tamperedMessage, signature) shouldBe false
        }

        test("verify fails when the signature is tampered") {
            val keyPair = Ed25519KeyPair.generate()
            val signature = keyPair.sign(message)
            val tamperedSignature = signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
            keyPair.publicKey.verify(message, tamperedSignature) shouldBe false
        }

        test("verify fails against a different public key") {
            val keyPair = Ed25519KeyPair.generate()
            val otherKeyPair = Ed25519KeyPair.generate()
            val signature = keyPair.sign(message)
            otherKeyPair.publicKey.verify(message, signature) shouldBe false
        }

        test("rejects an all-zero seed") {
            shouldThrow<IllegalArgumentException> {
                Ed25519PrivateKey(ByteArray(32))
            }
        }

        test("rejects an all-ones seed") {
            shouldThrow<IllegalArgumentException> {
                Ed25519PrivateKey(ByteArray(32) { 0xFF.toByte() })
            }
        }

        test("rejects a seed of the wrong length") {
            shouldThrow<IllegalArgumentException> {
                Ed25519PrivateKey(ByteArray(31))
            }
        }

        test("rejects a public key of the wrong length") {
            shouldThrow<IllegalArgumentException> {
                Ed25519PublicKey(ByteArray(31))
            }
        }

        // Security fix (V0.8.1 sub-wave audit round 1, major finding 1): bytes of the right length
        // are not necessarily a valid point on the curve. Before this fix, ByteArray(32){0xFF}
        // constructed successfully and only failed LATER at a completely different call site
        // (jvm-libp2p's unmarshalEd25519PublicKey, transitively PeerRecord.peerId/toString) with an
        // uncaught IllegalArgumentException - see PeerRecordCodecTest's and
        // PeerRecordSpoofingTest's companion regression tests for the end-to-end attack this closed.
        test("rejects an all-0xFF public key - right length, not a valid point on the curve") {
            shouldThrow<IllegalArgumentException> {
                Ed25519PublicKey(ByteArray(32) { 0xFF.toByte() })
            }
        }

        test("a genuinely generated public key round-trips through the curve-point validation") {
            val keyPair = Ed25519KeyPair.generate()
            shouldNotThrowAny { Ed25519PublicKey(keyPair.publicKey.bytes) }
        }
    })
