package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

private fun freshBundle(
    identity: DualKeyIdentity = DualKeyIdentity.generate(),
    oneTimePrekeys: List<OneTimePrekey> = listOf(OneTimePrekey(0, X25519KeyPair.generate().publicKey)),
    sequenceNumber: Long = 1,
    notValidAfterEpochSecond: Long = 500_000L,
    nowEpochSecond: Long = 0L,
): PrekeyBundle {
    val x25519Identity = X25519KeyPair.generate()
    val binding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, x25519Identity.publicKey)
    val signedPrekey = X25519KeyPair.generate()
    return PrekeyBundle.create(
        identity = identity,
        encryptionBinding = binding,
        signedPrekeyId = 0,
        signedPrekey = signedPrekey.publicKey,
        oneTimePrekeys = oneTimePrekeys,
        sequenceNumber = sequenceNumber,
        notValidAfterEpochSecond = notValidAfterEpochSecond,
        nowEpochSecond = nowEpochSecond,
    )
}

class PrekeyBundleTest :
    FunSpec({
        test("create then all three verifies pass") {
            val identity = DualKeyIdentity.generate()
            val bundle = freshBundle(identity)
            PrekeyBundle.verify(bundle) shouldBe true
            bundle.verifyEncryptionBinding() shouldBe true
            bundle.verifySignedPrekey() shouldBe true
        }

        test("verify(expectedIdentity) is false for a different identity") {
            val bundle = freshBundle()
            val otherIdentity = DualKeyIdentity.generate()
            PrekeyBundle.verify(otherIdentity.secp256k1KeyPair.publicKey, bundle) shouldBe false
        }

        test("create refuses a binding that does not verify against the identity") {
            val identity = DualKeyIdentity.generate()
            val otherIdentity = DualKeyIdentity.generate()
            val x25519Identity = X25519KeyPair.generate()
            val brokenBinding = EncryptionKeyBinding.create(otherIdentity.secp256k1KeyPair, x25519Identity.publicKey)
            shouldThrow<IllegalArgumentException> {
                PrekeyBundle.create(
                    identity = identity,
                    encryptionBinding = brokenBinding,
                    signedPrekeyId = 0,
                    signedPrekey = X25519KeyPair.generate().publicKey,
                    oneTimePrekeys = emptyList(),
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 1000,
                )
            }
        }

        test("create refuses notValidAfterEpochSecond beyond MAX_TTL_WINDOW_SECONDS") {
            val identity = DualKeyIdentity.generate()
            val x25519Identity = X25519KeyPair.generate()
            val binding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, x25519Identity.publicKey)
            shouldThrow<IllegalArgumentException> {
                PrekeyBundle.create(
                    identity = identity,
                    encryptionBinding = binding,
                    signedPrekeyId = 0,
                    signedPrekey = X25519KeyPair.generate().publicKey,
                    oneTimePrekeys = emptyList(),
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = PrekeyBundle.MAX_TTL_WINDOW_SECONDS + 1000,
                    nowEpochSecond = 0,
                )
            }
        }

        test("constructor rejects duplicate one-time prekey ids") {
            val identity = DualKeyIdentity.generate()
            val duplicateKey1 = X25519KeyPair.generate().publicKey
            val duplicateKey2 = X25519KeyPair.generate().publicKey
            shouldThrow<IllegalArgumentException> {
                freshBundle(
                    identity,
                    oneTimePrekeys = listOf(OneTimePrekey(5, duplicateKey1), OneTimePrekey(5, duplicateKey2)),
                )
            }
        }

        test("constructor rejects duplicate one-time prekey public keys") {
            val identity = DualKeyIdentity.generate()
            val sameKey = X25519KeyPair.generate().publicKey
            shouldThrow<IllegalArgumentException> {
                freshBundle(identity, oneTimePrekeys = listOf(OneTimePrekey(1, sameKey), OneTimePrekey(2, sameKey)))
            }
        }

        test("toString contains no signature bytes") {
            val bundle = freshBundle()
            val text = bundle.toString()
            text.contains(String(bundle.signature)) shouldBe false
            text.contains(String(bundle.signedPrekeySignature)) shouldBe false
        }

        test("contentId differs for bundles differing in any single field") {
            val identity = DualKeyIdentity.generate()
            val base = freshBundle(identity, sequenceNumber = 1)
            val differentSequence = freshBundle(identity, sequenceNumber = 2)
            base.contentId() shouldNotBe differentSequence.contentId()

            val differentTtl = freshBundle(identity, notValidAfterEpochSecond = 550_000L)
            base.contentId() shouldNotBe differentTtl.contentId()

            val differentOneTime = freshBundle(identity, oneTimePrekeys = emptyList())
            base.contentId() shouldNotBe differentOneTime.contentId()

            val otherIdentity = DualKeyIdentity.generate()
            val differentIdentity = freshBundle(otherIdentity)
            base.contentId() shouldNotBe differentIdentity.contentId()
        }
    })
