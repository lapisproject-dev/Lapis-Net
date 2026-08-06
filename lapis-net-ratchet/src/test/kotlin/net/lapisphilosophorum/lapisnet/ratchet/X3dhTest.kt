package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import java.nio.file.Files

private class Party(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    val store: PrekeyStore =
        PrekeyStore.create(
            Files.createTempDirectory("x3dh-test"),
            identity,
            oneTimePrekeyCount = 3,
        ),
) {
    val encryptionBinding: EncryptionKeyBinding =
        EncryptionKeyBinding.create(
            identity.secp256k1KeyPair,
            store.x25519IdentityPublicKey,
        )

    fun publishBundle(): PrekeyBundle =
        store.publishBundle(
            identity,
            notValidAfterEpochSecond = 500_000L,
            nowEpochSecond = 0,
        )
}

class X3dhTest :
    FunSpec({
        test("initiator and responder derive byte-identical sharedSecret and associatedData, with a one-time prekey") {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()

            val initiation =
                X3dh.initiate(
                    initiatorIdentity = alice.identity.secp256k1KeyPair.publicKey,
                    initiatorEncryptionBinding = alice.encryptionBinding,
                    initiatorX25519IdentityPrivateKey = alice.store.x25519IdentityPrivateKey(),
                    bundle = bundle,
                    nowEpochSecond = 0,
                )
            (initiation.header.oneTimePrekeyId in 0..2) shouldBe true

            val consumedPrivateKey = bob.store.consumeOneTimePrekey(initiation.header.oneTimePrekeyId!!)
            val responderSession =
                X3dh.respond(
                    responderIdentity = bob.identity.secp256k1KeyPair.publicKey,
                    responderEncryptionBinding = bob.encryptionBinding,
                    responderX25519IdentityPrivateKey = bob.store.x25519IdentityPrivateKey(),
                    responderSignedPrekeyId = bob.store.signedPrekeyId,
                    responderSignedPrekeyPublicKey = bob.store.signedPrekeyPublicKey,
                    responderSignedPrekeyPrivateKey = bob.store.signedPrekeyPrivateKey(),
                    header = initiation.header,
                    consumedOneTimePrekey = consumedPrivateKey,
                )

            responderSession.sharedSecret.contentEquals(initiation.session.sharedSecret) shouldBe true
            responderSession.associatedData.contentEquals(initiation.session.associatedData) shouldBe true
        }

        test("initiator and responder derive byte-identical secrets without a one-time prekey (exhausted bundle)") {
            val alice = Party()
            val bobIdentity = DualKeyIdentity.generate()
            val bob =
                Party(
                    bobIdentity,
                    PrekeyStore.create(Files.createTempDirectory("x3dh-test"), bobIdentity, oneTimePrekeyCount = 0),
                )
            val bundle = bob.publishBundle()
            bundle.oneTimePrekeys shouldBe emptyList()

            val initiation =
                X3dh.initiate(
                    initiatorIdentity = alice.identity.secp256k1KeyPair.publicKey,
                    initiatorEncryptionBinding = alice.encryptionBinding,
                    initiatorX25519IdentityPrivateKey = alice.store.x25519IdentityPrivateKey(),
                    bundle = bundle,
                    nowEpochSecond = 0,
                )
            initiation.header.oneTimePrekeyId shouldBe null

            val responderSession =
                X3dh.respond(
                    responderIdentity = bob.identity.secp256k1KeyPair.publicKey,
                    responderEncryptionBinding = bob.encryptionBinding,
                    responderX25519IdentityPrivateKey = bob.store.x25519IdentityPrivateKey(),
                    responderSignedPrekeyId = bob.store.signedPrekeyId,
                    responderSignedPrekeyPublicKey = bob.store.signedPrekeyPublicKey,
                    responderSignedPrekeyPrivateKey = bob.store.signedPrekeyPrivateKey(),
                    header = initiation.header,
                    consumedOneTimePrekey = null,
                )
            responderSession.sharedSecret.contentEquals(initiation.session.sharedSecret) shouldBe true
        }

        test("the with-one-time-prekey and without-one-time-prekey secrets differ (DH4 changes derivation)") {
            val alice = Party()
            val bob = Party()
            val bundleWithOtp = bob.publishBundle()
            val bundleWithoutOtp =
                bob.store.publishBundle(
                    bob.identity,
                    notValidAfterEpochSecond = 500_000L,
                    nowEpochSecond = 0,
                    maxOneTimePrekeys = 0,
                )

            val withOtp =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundleWithOtp,
                    nowEpochSecond = 0,
                )
            val withoutOtp =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundleWithoutOtp,
                    nowEpochSecond = 0,
                )
            withOtp.session.sharedSecret.contentEquals(withoutOtp.session.sharedSecret) shouldBe false
        }

        test(
            "associatedData is exactly 71 bytes, begins with the magic+version, and contains both identities in order",
        ) {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )
            val ad = initiation.session.associatedData
            ad.size shouldBe 71
            val expected =
                byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'X'.code.toByte(), '3'.code.toByte(), 1) +
                    alice.identity.secp256k1KeyPair.publicKey.bytes +
                    bob.identity.secp256k1KeyPair.publicKey.bytes
            ad.contentEquals(expected) shouldBe true
        }

        test("swapping the two identities produces a different AD - asymmetry is intentional") {
            val alice = Party()
            val bob = Party()
            val ad1 =
                X3dh.associatedData(
                    alice.identity.secp256k1KeyPair.publicKey,
                    bob.identity.secp256k1KeyPair.publicKey,
                )
            val ad2 =
                X3dh.associatedData(
                    bob.identity.secp256k1KeyPair.publicKey,
                    alice.identity.secp256k1KeyPair.publicKey,
                )
            ad1.contentEquals(ad2) shouldBe false
        }

        test(
            "two initiate calls against the same bundle produce different shared secrets (fresh ephemeral each time)",
        ) {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            val first =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                    preferredOneTimePrekeyId = 0,
                )
            val second =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                    preferredOneTimePrekeyId = 1,
                )
            (first.header.ephemeralPublicKey == second.header.ephemeralPublicKey) shouldBe false
            first.session.sharedSecret.contentEquals(second.session.sharedSecret) shouldBe false
        }

        test("respond fails when header.signedPrekeyId does not match the responder's") {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                    preferredOneTimePrekeyId = 0,
                )
            val consumed = bob.store.consumeOneTimePrekey(0)
            shouldThrow<X3dhException> {
                X3dh.respond(
                    bob.identity.secp256k1KeyPair.publicKey,
                    bob.encryptionBinding,
                    bob.store.x25519IdentityPrivateKey(),
                    responderSignedPrekeyId = 999,
                    responderSignedPrekeyPublicKey = bob.store.signedPrekeyPublicKey,
                    responderSignedPrekeyPrivateKey = bob.store.signedPrekeyPrivateKey(),
                    header = initiation.header,
                    consumedOneTimePrekey = consumed,
                )
            }
        }

        test("respond fails when exactly one of oneTimePrekeyId / consumedOneTimePrekey is null") {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                    preferredOneTimePrekeyId = 0,
                )
            // header names a one-time prekey but we pass null for the consumed key.
            shouldThrow<X3dhException> {
                X3dh.respond(
                    bob.identity.secp256k1KeyPair.publicKey,
                    bob.encryptionBinding,
                    bob.store.x25519IdentityPrivateKey(),
                    bob.store.signedPrekeyId,
                    bob.store.signedPrekeyPublicKey,
                    bob.store.signedPrekeyPrivateKey(),
                    header = initiation.header,
                    consumedOneTimePrekey = null,
                )
            }
        }

        test("initiate rejects an expired bundle") {
            val alice = Party()
            val bob = Party()
            val bundle =
                bob.store.publishBundle(
                    bob.identity,
                    notValidAfterEpochSecond = 100L,
                    nowEpochSecond = 0,
                )
            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 200L,
                )
            }
        }

        test("initiate rejects a self-handshake") {
            val alice = Party()
            val bundle = alice.publishBundle()
            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )
            }
        }

        test("initiate rejects a mismatched initiatorX25519IdentityPrivateKey") {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            val wrongPrivateKey = X25519KeyPair.generate().privateKey
            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    wrongPrivateKey,
                    bundle,
                    nowEpochSecond = 0,
                )
            }
        }

        test("preferredOneTimePrekeyId naming an id absent from the bundle throws") {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                    preferredOneTimePrekeyId = 999,
                )
            }
        }

        test(
            "end-to-end with a real PrekeyStore: publishBundle -> initiate -> consume -> respond yields identical secrets",
        ) {
            val alice = Party()
            val bob = Party()
            val bundle = bob.publishBundle()
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )
            val consumed = bob.store.consumeOneTimePrekey(initiation.header.oneTimePrekeyId!!)
            val responderSession =
                X3dh.respond(
                    bob.identity.secp256k1KeyPair.publicKey,
                    bob.encryptionBinding,
                    bob.store.x25519IdentityPrivateKey(),
                    bob.store.signedPrekeyId,
                    bob.store.signedPrekeyPublicKey,
                    bob.store.signedPrekeyPrivateKey(),
                    initiation.header,
                    consumed,
                )
            responderSession.sharedSecret.contentEquals(initiation.session.sharedSecret) shouldBe true
        }
    })
