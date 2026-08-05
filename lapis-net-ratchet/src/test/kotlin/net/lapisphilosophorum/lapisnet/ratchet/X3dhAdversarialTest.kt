package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.nio.file.Files

private fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        (
            (Character.digit(s[i * 2], 16) shl 4) +
                Character.digit(s[i * 2 + 1], 16)
        ).toByte()
    }

/** All twelve published low-order/degenerate X25519 u-coordinates - see [X25519PublicKey]'s doc
 * comment for the full measured evidence behind this list. */
private val ALL_LOW_ORDER_POINTS =
    listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "d9" + "ff".repeat(31),
        "da" + "ff".repeat(31),
        "db" + "ff".repeat(31),
    ).map { hex(it) }

private class AdversarialParty(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    val store: PrekeyStore =
        PrekeyStore.create(
            Files.createTempDirectory("x3dh-adversarial"),
            identity,
            oneTimePrekeyCount = 3,
        ),
) {
    val encryptionBinding: EncryptionKeyBinding =
        EncryptionKeyBinding.create(
            identity.secp256k1KeyPair,
            store.x25519IdentityPublicKey,
        )

    fun publishBundle(
        sequenceNumber: Long = 1,
        notValidAfterEpochSecond: Long = 500_000L,
    ): PrekeyBundle = store.publishBundle(identity, sequenceNumber, notValidAfterEpochSecond, nowEpochSecond = 0)
}

/**
 * The mandatory adversarial spec for this wave, applying the same rigor as `PeerRecordSpoofingTest`
 * (V0.8.1) and `HybridEciesAdversarialTest` (V0.9.2). Case letters match the SPEC's own lettering.
 */
class X3dhAdversarialTest :
    FunSpec({
        test("(a) a tampered signed-prekey signature is rejected before any DH runs") {
            val alice = AdversarialParty()
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            val tamperedSignature = bundle.signedPrekeySignature.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val tamperedBundle =
                PrekeyBundle.fromDecoded(
                    identity = bundle.identity,
                    encryptionBinding = bundle.encryptionBinding,
                    signedPrekeyId = bundle.signedPrekeyId,
                    signedPrekey = bundle.signedPrekey,
                    signedPrekeySignature = tamperedSignature,
                    oneTimePrekeys = bundle.oneTimePrekeys,
                    sequenceNumber = bundle.sequenceNumber,
                    notValidAfterEpochSecond = bundle.notValidAfterEpochSecond,
                    signature = bundle.signature,
                )
            // The outer signature covers the WHOLE encoded body, including signedPrekeySignature's own
            // bytes (see PrekeyBundleCodec's layout) - so tampering it invalidates BOTH the outer
            // signature and the signed-prekey signature itself. Both checks independently reject it;
            // either alone is sufficient to stop initiate() before any DH runs.
            PrekeyBundle.verify(tamperedBundle) shouldBe false
            tamperedBundle.verifySignedPrekey() shouldBe false
            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    tamperedBundle,
                    nowEpochSecond = 0,
                )
            }
        }

        test(
            "(a) a signed prekey swapped for a different (but validly-encoded) key, keeping the original signature, is rejected",
        ) {
            val alice = AdversarialParty()
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            val swappedBundle =
                PrekeyBundle.fromDecoded(
                    identity = bundle.identity,
                    encryptionBinding = bundle.encryptionBinding,
                    signedPrekeyId = bundle.signedPrekeyId,
                    signedPrekey = X25519KeyPair.generate().publicKey,
                    signedPrekeySignature = bundle.signedPrekeySignature,
                    oneTimePrekeys = bundle.oneTimePrekeys,
                    sequenceNumber = bundle.sequenceNumber,
                    notValidAfterEpochSecond = bundle.notValidAfterEpochSecond,
                    signature = bundle.signature,
                )
            swappedBundle.verifySignedPrekey() shouldBe false
            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    swappedBundle,
                    nowEpochSecond = 0,
                )
            }
        }

        test(
            "(b) every one of the twelve low-order X25519 values is rejected by the X25519PublicKey constructor " +
                "itself - which is what makes it structurally impossible to ever pass one into " +
                "PrekeyBundle.create's signedPrekey parameter: that parameter is TYPED as X25519PublicKey, so a " +
                "caller cannot even construct the argument to hand it, let alone reach PrekeyBundle.create's own " +
                "body, with a low-order value. (This duplicates X25519KeyPairTest's identical constructor-level " +
                "assertion - kept here too so this file's own low-order coverage for the signed-prekey ROLE is " +
                "self-contained and doesn't require cross-referencing that file. The genuine WIRE-slot coverage, " +
                "for bytes that bypass the constructor via decode(), lives in the three sibling " +
                "'... rejected at decode()' tests below.)",
        ) {
            ALL_LOW_ORDER_POINTS.forEach { lowOrder ->
                shouldThrow<IllegalArgumentException> { X25519PublicKey(lowOrder) }
            }
        }

        test("(b) a low-order X25519 key in the signed-prekey wire slot is rejected at decode() - before any DH runs") {
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            val bytes = PrekeyBundleCodec.encode(bundle).copyOf()
            val signedPrekeyOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4
            ALL_LOW_ORDER_POINTS.forEach { lowOrder ->
                val tampered = bytes.copyOf()
                lowOrder.copyInto(tampered, signedPrekeyOffset)
                shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(tampered) }
            }
        }

        test("(b) a low-order X25519 key in a one-time-prekey wire slot is rejected at decode() - before any DH runs") {
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            bundle.oneTimePrekeys.size shouldBe 3
            val bytes = PrekeyBundleCodec.encode(bundle).copyOf()
            val firstOneTimeKeyOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32 + 64 + 2 + 4
            ALL_LOW_ORDER_POINTS.forEach { lowOrder ->
                val tampered = bytes.copyOf()
                lowOrder.copyInto(tampered, firstOneTimeKeyOffset)
                shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(tampered) }
            }
        }

        test("(b) a low-order X25519 key as the X25519 identity key wire slot is rejected at decode()") {
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            val bytes = PrekeyBundleCodec.encode(bundle).copyOf()
            val x25519IdentityOffset = 4 + 1 + 1 + 33
            ALL_LOW_ORDER_POINTS.forEach { lowOrder ->
                val tampered = bytes.copyOf()
                lowOrder.copyInto(tampered, x25519IdentityOffset)
                shouldThrow<MalformedPrekeyBundleException> { PrekeyBundleCodec.decode(tampered) }
            }
        }

        test("(c) one-time prekey reuse is refused by PrekeyStore - consuming the same id twice fails cleanly") {
            val bob = AdversarialParty()
            bob.store.consumeOneTimePrekey(0)
            shouldThrow<PrekeyConsumptionException> { bob.store.consumeOneTimePrekey(0) }
        }

        test("(c) consume, reopen the store, consume again - still throws") {
            val identity = DualKeyIdentity.generate()
            val dir = Files.createTempDirectory("x3dh-adversarial")
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 2)
            store.consumeOneTimePrekey(0)
            val reopened = PrekeyStore.open(dir)!!
            shouldThrow<PrekeyConsumptionException> { reopened.consumeOneTimePrekey(0) }
        }

        test(
            "(c) the security consequence, not just the API contract: a replay of an identical initiation " +
                "whose one-time prekey was already consumed cannot obtain the private key at all, so respond() " +
                "is never reached",
        ) {
            val alice = AdversarialParty()
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )
            val id = initiation.header.oneTimePrekeyId!!
            bob.store.consumeOneTimePrekey(id) // first (legitimate) consumption
            // A replay of the identical initiation - the responder must refuse to consume again.
            shouldThrow<PrekeyConsumptionException> { bob.store.consumeOneTimePrekey(id) }
            // respond() is simply never called in the replay path - there is no private key to call it with.
        }

        test("(d) prekey exhaustion falls back safely to signed-prekey-only X3DH, no crash") {
            val alice = AdversarialParty()
            val bobIdentity = DualKeyIdentity.generate()
            val bobStore =
                PrekeyStore.create(
                    Files.createTempDirectory("x3dh-adversarial"),
                    bobIdentity,
                    oneTimePrekeyCount = 0,
                )
            val bundle =
                bobStore.publishBundle(
                    bobIdentity,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                    nowEpochSecond = 0,
                )
            bundle.oneTimePrekeys shouldBe emptyList()

            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )
            initiation.header.oneTimePrekeyId shouldBe null

            val responderSession =
                X3dh.respond(
                    bobIdentity.secp256k1KeyPair.publicKey,
                    bobStore.x25519IdentityPrivateKey(),
                    bobStore.signedPrekeyId,
                    bobStore.signedPrekeyPrivateKey(),
                    initiation.header,
                    consumedOneTimePrekey = null,
                )
            responderSession.sharedSecret.contentEquals(initiation.session.sharedSecret) shouldBe true

            // Differs from a WITH-one-time-prekey derivation between the same two identities.
            val bobWithOtpIdentity = DualKeyIdentity.generate()
            val bobWithOtpStore =
                PrekeyStore.create(
                    Files.createTempDirectory("x3dh-adversarial"),
                    bobWithOtpIdentity,
                    oneTimePrekeyCount = 1,
                )
            val bobWithOtpBundle =
                bobWithOtpStore.publishBundle(
                    bobWithOtpIdentity,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                    nowEpochSecond = 0,
                )
            val withOtpInitiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bobWithOtpBundle,
                    nowEpochSecond = 0,
                )
            (withOtpInitiation.header.oneTimePrekeyId != null) shouldBe true
            responderSession.sharedSecret.contentEquals(withOtpInitiation.session.sharedSecret) shouldBe false
        }

        test(
            "(e1) unknown key share, verbatim binding transplant - rejected before any DH, even though the outer signature is valid",
        ) {
            val alice = AdversarialParty()
            val bob = AdversarialParty()
            val mallory = DualKeyIdentity.generate()
            val bobBundle = bob.publishBundle()

            // Mallory copies Bob's binding object verbatim into a bundle she signs (genuinely, with
            // her OWN identity, over the actual forged body - not merely reusing an old signature).
            val malloryStore =
                PrekeyStore.create(
                    Files.createTempDirectory("x3dh-adversarial"),
                    mallory,
                    oneTimePrekeyCount = 1,
                )
            val malloryBundleTemplate =
                malloryStore.publishBundle(
                    mallory,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                    nowEpochSecond = 0,
                )
            val forgedBody =
                PrekeyBundleCodec.encodeSignedBody(
                    identity = mallory.secp256k1KeyPair.publicKey,
                    encryptionBinding = bobBundle.encryptionBinding, // Bob's binding, verbatim
                    signedPrekeyId = malloryBundleTemplate.signedPrekeyId,
                    signedPrekey = malloryBundleTemplate.signedPrekey,
                    signedPrekeySignature = malloryBundleTemplate.signedPrekeySignature,
                    oneTimePrekeys = malloryBundleTemplate.oneTimePrekeys,
                    sequenceNumber = malloryBundleTemplate.sequenceNumber,
                    notValidAfterEpochSecond = malloryBundleTemplate.notValidAfterEpochSecond,
                )
            val forgedOuterSignature =
                mallory.secp256k1KeyPair.sign(
                    net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest(
                        "LapisNet:x3dh-prekey-bundle:v1",
                        forgedBody,
                    ),
                )
            val forgedBundle =
                PrekeyBundle.fromDecoded(
                    identity = mallory.secp256k1KeyPair.publicKey,
                    encryptionBinding = bobBundle.encryptionBinding, // Bob's binding, verbatim
                    signedPrekeyId = malloryBundleTemplate.signedPrekeyId,
                    signedPrekey = malloryBundleTemplate.signedPrekey,
                    signedPrekeySignature = malloryBundleTemplate.signedPrekeySignature,
                    oneTimePrekeys = malloryBundleTemplate.oneTimePrekeys,
                    sequenceNumber = malloryBundleTemplate.sequenceNumber,
                    notValidAfterEpochSecond = malloryBundleTemplate.notValidAfterEpochSecond,
                    signature = forgedOuterSignature,
                )
            // Outer signature is genuinely valid (Mallory signed the whole body including Bob's binding bytes).
            PrekeyBundle.verify(forgedBundle) shouldBe true
            // But the binding itself does not verify against Mallory's identity - it was signed by Bob.
            forgedBundle.verifyEncryptionBinding() shouldBe false

            shouldThrow<X3dhException> {
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    forgedBundle,
                    nowEpochSecond = 0,
                )
            }
        }

        test(
            "(e2) unknown key share, FRESHLY RE-SIGNED binding - the wave's most important test. All three " +
                "cryptographic checks genuinely pass, but the AD-in-info construction still closes the attack: " +
                "Alice's and Bob's derived shared secrets differ, because their views of the AD (built from the " +
                "secp256k1 identities) genuinely disagree.",
        ) {
            val alice = AdversarialParty()
            val bob = AdversarialParty()
            val bobBundle = bob.publishBundle()
            val mallory = DualKeyIdentity.generate()

            // Mallory mints a FRESH, self-consistent EncryptionKeyBinding over Bob's public X25519 identity
            // key, and re-signs Bob's signed prekey (and offers Bob's one-time prekeys), all under HER OWN
            // secp256k1 identity.
            val malloryEncryptionBinding =
                EncryptionKeyBinding.create(
                    mallory.secp256k1KeyPair,
                    bobBundle.x25519IdentityKey,
                )
            val signedPrekeyDigest =
                PrekeyBundle.signedPrekeyDigest(
                    mallory.secp256k1KeyPair.publicKey,
                    bobBundle.x25519IdentityKey,
                    bobBundle.signedPrekey,
                    bobBundle.signedPrekeyId,
                )
            val mallorySignedPrekeySignature = mallory.secp256k1KeyPair.sign(signedPrekeyDigest)
            val forgedBundleBody =
                PrekeyBundleCodec.encodeSignedBody(
                    identity = mallory.secp256k1KeyPair.publicKey,
                    encryptionBinding = malloryEncryptionBinding,
                    signedPrekeyId = bobBundle.signedPrekeyId,
                    signedPrekey = bobBundle.signedPrekey,
                    signedPrekeySignature = mallorySignedPrekeySignature,
                    oneTimePrekeys = bobBundle.oneTimePrekeys,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                )
            val forgedOuterSignature =
                mallory.secp256k1KeyPair.sign(
                    net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest(
                        "LapisNet:x3dh-prekey-bundle:v1",
                        forgedBundleBody,
                    ),
                )
            val forgedBundle =
                PrekeyBundle.fromDecoded(
                    identity = mallory.secp256k1KeyPair.publicKey,
                    encryptionBinding = malloryEncryptionBinding,
                    signedPrekeyId = bobBundle.signedPrekeyId,
                    signedPrekey = bobBundle.signedPrekey,
                    signedPrekeySignature = mallorySignedPrekeySignature,
                    oneTimePrekeys = bobBundle.oneTimePrekeys,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                    signature = forgedOuterSignature,
                )

            // (i)-(iii): all three cryptographic checks genuinely pass.
            PrekeyBundle.verify(forgedBundle) shouldBe true
            forgedBundle.verifyEncryptionBinding() shouldBe true
            forgedBundle.verifySignedPrekey() shouldBe true

            // (iv): Alice's initiate() therefore succeeds - nothing here can detect the forgery at
            // bundle-validation time.
            val aliceInitiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    forgedBundle,
                    nowEpochSecond = 0,
                )

            // (v)+(vi): Bob, using his REAL private keys, can reproduce the same DH values (since the
            // X25519 keys in the header/bundle really are his), but Bob's own AD names HIMSELF as
            // responder, not Mallory - so his AD, and therefore his derived shared secret, DIFFER from
            // Alice's, even though every DH term matches.
            val consumed = bob.store.consumeOneTimePrekey(aliceInitiation.header.oneTimePrekeyId!!)
            val bobSession =
                X3dh.respond(
                    bob.identity.secp256k1KeyPair.publicKey,
                    bob.store.x25519IdentityPrivateKey(),
                    bob.store.signedPrekeyId,
                    bob.store.signedPrekeyPrivateKey(),
                    aliceInitiation.header,
                    consumed,
                )
            bobSession.associatedData.contentEquals(aliceInitiation.session.associatedData) shouldBe false
            bobSession.sharedSecret.contentEquals(aliceInitiation.session.sharedSecret) shouldBe false
        }

        test("(f) replay of an identical initial message - with a one-time prekey, refused at PrekeyStore") {
            val alice = AdversarialParty()
            val bob = AdversarialParty()
            val bundle = bob.publishBundle()
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )
            val id = initiation.header.oneTimePrekeyId!!
            bob.store.consumeOneTimePrekey(id)
            // The exact same initial message, replayed - refused at the PrekeyStore layer.
            shouldThrow<PrekeyConsumptionException> { bob.store.consumeOneTimePrekey(id) }
        }

        test(
            "(f) replay of an identical initial message - WITHOUT a one-time prekey, X3dh.respond() itself " +
                "accepts the replay and derives the same secret. This residual gap is DELIBERATELY DEFERRED " +
                "to V0.8.3's Double Ratchet session layer, which owns per-session replay state; X3dh is a " +
                "stateless pure function by design and this wave does not close this case - stated explicitly.",
        ) {
            val alice = AdversarialParty()
            val bobIdentity = DualKeyIdentity.generate()
            val bobStore =
                PrekeyStore.create(
                    Files.createTempDirectory("x3dh-adversarial"),
                    bobIdentity,
                    oneTimePrekeyCount = 0,
                )
            val bundle =
                bobStore.publishBundle(
                    bobIdentity,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                    nowEpochSecond = 0,
                )
            val initiation =
                X3dh.initiate(
                    alice.identity.secp256k1KeyPair.publicKey,
                    alice.encryptionBinding,
                    alice.store.x25519IdentityPrivateKey(),
                    bundle,
                    nowEpochSecond = 0,
                )

            val firstResponse =
                X3dh.respond(
                    bobIdentity.secp256k1KeyPair.publicKey,
                    bobStore.x25519IdentityPrivateKey(),
                    bobStore.signedPrekeyId,
                    bobStore.signedPrekeyPrivateKey(),
                    initiation.header,
                    consumedOneTimePrekey = null,
                )
            // The identical header, replayed - respond() has no per-call state and accepts it again,
            // deriving the identical secret. This is the explicitly-deferred gap.
            val secondResponse =
                X3dh.respond(
                    bobIdentity.secp256k1KeyPair.publicKey,
                    bobStore.x25519IdentityPrivateKey(),
                    bobStore.signedPrekeyId,
                    bobStore.signedPrekeyPrivateKey(),
                    initiation.header,
                    consumedOneTimePrekey = null,
                )
            firstResponse.sharedSecret.contentEquals(secondResponse.sharedSecret) shouldBe true
        }
    })
