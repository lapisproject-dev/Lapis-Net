package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import java.security.MessageDigest

class EncryptionKeyBindingTest :
    FunSpec({
        test("create then verify round-trips successfully") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val x25519PublicKey = X25519KeyPair.generate().publicKey
            val binding = EncryptionKeyBinding.create(secp256k1KeyPair, x25519PublicKey)
            EncryptionKeyBinding.verify(secp256k1KeyPair.publicKey, binding) shouldBe true
        }

        test(
            "verify fails when the bound X25519 public key differs from the one actually signed",
        ) {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val x25519PublicKey = X25519KeyPair.generate().publicKey
            val binding = EncryptionKeyBinding.create(secp256k1KeyPair, x25519PublicKey)

            // A genuinely different, independently-generated X25519 public key - substituting it for
            // the one actually signed must fail verification. Deliberately NOT a byte-flipped
            // mutation of x25519PublicKey: X25519PublicKey's own constructor rejects low-order/
            // non-canonical byte patterns (see that class's doc comment), so flipping an arbitrary
            // byte risks constructing an invalid key for an UNRELATED reason - a former version of
            // this test caught that with `runCatching { X25519PublicKey(tamperedBytes) }.getOrNull()
            // ?: return@test`, an escape hatch that would have silently skipped this test entirely,
            // exercising nothing, the one time the flip happened to land on a rejected byte pattern.
            // X25519KeyPair.generate() is guaranteed to construct successfully (see X25519PublicKey's
            // own "why this can never reject a legitimate key" doc comment), so this test always
            // actually exercises verify()'s tamper-detection path.
            val differentKey = X25519KeyPair.generate().publicKey
            differentKey shouldNotBe x25519PublicKey

            val tamperedBinding = EncryptionKeyBinding(differentKey, binding.signature)
            EncryptionKeyBinding.verify(secp256k1KeyPair.publicKey, tamperedBinding) shouldBe false
        }

        test("verify fails against a different secp256k1 identity") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val otherSecp256k1KeyPair = Secp256k1KeyPair.generate()
            val x25519PublicKey = X25519KeyPair.generate().publicKey
            val binding = EncryptionKeyBinding.create(secp256k1KeyPair, x25519PublicKey)

            EncryptionKeyBinding.verify(otherSecp256k1KeyPair.publicKey, binding) shouldBe false
        }

        test("a signature over a plain, non-domain-tagged digest of the same bytes is not the binding signature") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val x25519PublicKey = X25519KeyPair.generate().publicKey
            val binding = EncryptionKeyBinding.create(secp256k1KeyPair, x25519PublicKey)

            val plainDigest = MessageDigest.getInstance("SHA-256").digest(x25519PublicKey.bytes)
            val plainSignature = secp256k1KeyPair.sign(plainDigest)

            plainDigest.contentEquals(
                domainSeparatedDigest("LapisNet:x25519-encryption-key:v1", x25519PublicKey.bytes),
            ) shouldBe false
            plainSignature.contentEquals(binding.signature) shouldBe false
        }

        test(
            "an IdentityBinding-tagged signature is not accepted as an EncryptionKeyBinding signature, and vice versa",
        ) {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val x25519PublicKey = X25519KeyPair.generate().publicKey
            val ed25519PublicKey = Ed25519KeyPair.generate().publicKey

            // Sign the X25519 public key bytes under IdentityBinding's OWN domain tag, then try to
            // pass that signature off as an EncryptionKeyBinding signature over the same bytes.
            val crossTaggedDigest = domainSeparatedDigest("LapisNet:identity-binding:v1", x25519PublicKey.bytes)
            val crossTaggedSignature = secp256k1KeyPair.sign(crossTaggedDigest)
            val forgedBinding = EncryptionKeyBinding(x25519PublicKey, crossTaggedSignature)
            EncryptionKeyBinding.verify(secp256k1KeyPair.publicKey, forgedBinding) shouldBe false

            // And the reverse: an EncryptionKeyBinding signature must not verify as an IdentityBinding.
            val encBinding = EncryptionKeyBinding.create(secp256k1KeyPair, x25519PublicKey)
            val forgedIdentityBinding = IdentityBinding(ed25519PublicKey, encBinding.signature)
            IdentityBinding.verify(secp256k1KeyPair.publicKey, forgedIdentityBinding) shouldBe false
        }

        test("constructor rejects a signature that is not exactly 64 bytes") {
            val x25519PublicKey = X25519KeyPair.generate().publicKey
            shouldThrow<IllegalArgumentException> { EncryptionKeyBinding(x25519PublicKey, ByteArray(63)) }
            shouldThrow<IllegalArgumentException> { EncryptionKeyBinding(x25519PublicKey, ByteArray(65)) }
        }
    })
