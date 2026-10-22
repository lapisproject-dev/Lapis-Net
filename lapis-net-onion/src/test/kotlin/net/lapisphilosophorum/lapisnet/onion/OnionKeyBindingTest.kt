package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

class OnionKeyBindingTest :
    FunSpec({
        val identity = Secp256k1KeyPair.generate()
        val onion = X25519KeyPair.generate().publicKey

        test("create and verify") {
            val b = OnionKeyBinding.create(identity, onion, 1000)
            OnionKeyBinding.verify(b, 999) shouldBe true
            OnionKeyBinding.verify(b, 1000) shouldBe true
            b.relayIdDigest().size shouldBe 32
            b.onionKeyFingerprint().size shouldBe 32
        }

        test("expired binding fails") {
            OnionKeyBinding.verify(OnionKeyBinding.create(identity, onion, 1000), 1001) shouldBe false
        }

        test("signature by a different key fails") {
            val other = Secp256k1KeyPair.generate()
            val forged = OnionKeyBinding.create(other, onion, 1000)
            val reattributed = OnionKeyBinding(identity.publicKey, onion, 1000, forged.signature)
            OnionKeyBinding.verify(reattributed, 1) shouldBe false
        }

        test("tampered fields fail verification") {
            val b = OnionKeyBinding.create(identity, onion, 1000)
            OnionKeyBinding.verify(
                OnionKeyBinding(identity.publicKey, X25519KeyPair.generate().publicKey, 1000, b.signature),
                1,
            ) shouldBe
                false
            OnionKeyBinding.verify(OnionKeyBinding(identity.publicKey, onion, 2000, b.signature), 1) shouldBe false
            val sig = b.signature.also { it[10] = (it[10].toInt() xor 1).toByte() }
            OnionKeyBinding.verify(OnionKeyBinding(identity.publicKey, onion, 1000, sig), 1) shouldBe false
            // an all-zero (malformed r,s) signature must return false, never throw
            OnionKeyBinding.verify(OnionKeyBinding(identity.publicKey, onion, 1000, ByteArray(64)), 1) shouldBe false
        }

        test("domain separation: an EncryptionKeyBinding signature is not an OnionKeyBinding") {
            val enc = EncryptionKeyBinding.create(identity, onion)
            OnionKeyBinding.verify(OnionKeyBinding(identity.publicKey, onion, 1000, enc.signature), 1) shouldBe false
            OnionKeyBinding.DOMAIN_TAG shouldBe "LapisNet:onion-key:v1"
        }
    })
