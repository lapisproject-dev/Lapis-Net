package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.ratchet.OneTimePrekey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey

private fun bundle(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
): PrekeyBundle {
    val x25519Identity = X25519KeyPair.generate()
    val binding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, x25519Identity.publicKey)
    val signedPrekey = X25519KeyPair.generate()
    return PrekeyBundle.create(
        identity = identity,
        encryptionBinding = binding,
        signedPrekeyId = 0,
        signedPrekey = signedPrekey.publicKey,
        oneTimePrekeys = listOf(OneTimePrekey(0, X25519KeyPair.generate().publicKey)),
        sequenceNumber = sequenceNumber,
        notValidAfterEpochSecond = 500_000L,
        nowEpochSecond = 0,
    )
}

/** As [bundle], but genuinely self-signed by [signingIdentity] while embedding a DIFFERENT
 * identity's [EncryptionKeyBinding] - a verbatim binding transplant, mirroring
 * `PeerRecordIndexTest`'s identical `spoofedRecord` helper shape.
 *
 * **The signed-prekey signature is a GENUINE signature, not a placeholder** - computed by
 * [signingIdentity]'s own secp256k1 key over the correct [PrekeyBundleCodec] digest for the
 * TRANSPLANTED (victim's) X25519 identity key, exactly the shape a real attacker who controls their
 * own signing key would produce. This is deliberate: an all-zero placeholder signature would make
 * `verifySignedPrekey()` fail too, for an unrelated reason, so a caller could never tell from the
 * test alone whether `verifyEncryptionBinding()` specifically is what index.add rejects on - the
 * same isolation technique the sibling "signed-prekey-signature-invalid" test below already applies
 * to `verifySignedPrekey`, applied here to the OTHER binding-transplant scenario. */
private fun spoofedBundle(
    signingIdentity: DualKeyIdentity,
    victimBinding: EncryptionKeyBinding,
): PrekeyBundle {
    val signedPrekey = X25519KeyPair.generate()
    val signedPrekeyId = 0
    val signedPrekeyDigest =
        domainSeparatedDigest(
            "LapisNet:x3dh-signed-prekey:v1",
            signingIdentity.secp256k1KeyPair.publicKey.bytes,
            victimBinding.x25519PublicKey.bytes,
            signedPrekey.publicKey.bytes,
            intToBigEndian4(signedPrekeyId),
        )
    val signedPrekeySignature = signingIdentity.secp256k1KeyPair.sign(signedPrekeyDigest)
    val body =
        PrekeyBundleCodec.encodeSignedBody(
            identity = signingIdentity.secp256k1KeyPair.publicKey,
            encryptionBinding = victimBinding,
            signedPrekeyId = signedPrekeyId,
            signedPrekey = signedPrekey.publicKey,
            signedPrekeySignature = signedPrekeySignature,
            oneTimePrekeys = emptyList(),
            sequenceNumber = 0,
            notValidAfterEpochSecond = 500_000L,
        )
    val signature =
        signingIdentity.secp256k1KeyPair.sign(
            domainSeparatedDigest("LapisNet:x3dh-prekey-bundle:v1", body),
        )
    // PrekeyBundle.fromDecoded is internal to lapis-net-ratchet (a different Gradle module from
    // this test), so this test - like PrekeyBundleGossip's own gossip validator - constructs the
    // hand-forged bundle via the PUBLIC wire-decode path instead, exactly as an attacker on the
    // real network would have to.
    return PrekeyBundleCodec.decode(body + signature)
}

/** Big-endian 4-byte encoding, mirroring `PrekeyBundle`'s own private `intToBigEndian4` helper
 * (internal to `lapis-net-ratchet`, not visible from this module) - needed to reproduce
 * [PrekeyBundle.signedPrekeyDigest]'s exact byte layout from outside that module. */
private fun intToBigEndian4(value: Int): ByteArray =
    byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

class PrekeyBundleIndexTest :
    FunSpec({
        test("latest-wins by sequence number") {
            val identity = DualKeyIdentity.generate()
            val index = PrekeyBundleIndex()
            val first = bundle(identity, 1)
            val second = bundle(identity, 2)
            index.add(first) shouldBe true
            index.add(second) shouldBe true
            index.current(identity.secp256k1KeyPair.publicKey) shouldBe second
        }

        test("a rollback (lower sequence number) is rejected outright") {
            val identity = DualKeyIdentity.generate()
            val index = PrekeyBundleIndex()
            val newer = bundle(identity, 5)
            index.add(newer) shouldBe true
            val staler = bundle(identity, 3)
            index.add(staler) shouldBe false
            index.current(identity.secp256k1KeyPair.publicKey) shouldBe newer
        }

        test("rollback rejection survives tracking-cap eviction, via the separate high-water mark") {
            val index = PrekeyBundleIndex(maxTracked = 2, maxPersisted = 100, maxHighWaterMarks = 100)
            val victim = DualKeyIdentity.generate()
            index.add(bundle(victim, 10)) shouldBe true

            // Flood past the tracking cap with unrelated identities, evicting the victim from the
            // tracking map (but NOT from the separate, larger high-water-mark map).
            repeat(5) { index.add(bundle(DualKeyIdentity.generate(), 1)) }

            // A replayed OLDER bundle for the victim must still be rejected.
            index.add(bundle(victim, 5)) shouldBe false
        }

        test("deterministic tie-break: same sequence number, higher content id wins, order-independent") {
            val identity = DualKeyIdentity.generate()
            val index1 = PrekeyBundleIndex()
            val index2 = PrekeyBundleIndex()
            val a = bundle(identity, 1)
            val b = bundle(identity, 1)

            index1.add(a)
            index1.add(b)
            index2.add(b)
            index2.add(a)

            index1.current(identity.secp256k1KeyPair.publicKey) shouldBe
                index2.current(identity.secp256k1KeyPair.publicKey)
        }

        test("a flood of many distinct fabricated identities is bounded by the tracking cap") {
            val index = PrekeyBundleIndex(maxTracked = 10, maxPersisted = 100, maxHighWaterMarks = 100)
            repeat(50) { index.add(bundle(DualKeyIdentity.generate(), 1)) }
            index.size() shouldBe 10
        }

        test("persistence-cap decoupling: tracking succeeds even after the persistence cap is exhausted") {
            val index = PrekeyBundleIndex(maxTracked = 100, maxPersisted = 1, maxHighWaterMarks = 100)
            val first = bundle(DualKeyIdentity.generate(), 1)
            val second = bundle(DualKeyIdentity.generate(), 1)
            index.tryReservePersistence(first) shouldBe true
            index.tryReservePersistence(second) shouldBe false
            // Tracking is unaffected by the persistence cap being full.
            index.add(first) shouldBe true
            index.add(second) shouldBe true
            index.size() shouldBe 2
        }

        // Security regression backport (V0.8.5 finding, originally fixed in
        // MailboxPointerIndex.releaseReservedPersistence, mirrored from PeerRecordIndex's identical
        // backport): releaseReservedPersistence must free a reservation for reuse rather than
        // burning it permanently. maxPersisted = 1 is the tightest possible window to prove RELEASE,
        // not merely non-exhaustion - a single successful reservation would otherwise permanently
        // exhaust a cap of 1 forever if release() were a no-op.
        test(
            "releaseReservedPersistence frees a reservation for reuse rather than burning it " +
                "permanently - V0.8.5 security fix backport regression",
        ) {
            val index = PrekeyBundleIndex(maxTracked = 100, maxPersisted = 1, maxHighWaterMarks = 100)
            val a = bundle(DualKeyIdentity.generate(), 0)
            val b = bundle(DualKeyIdentity.generate(), 0)

            // Mirrors what PrekeyBundleGossip.onGossipMessage does on a storage.put() failure: call
            // tryReservePersistence (which unconditionally inserts into the never-evicting
            // persistedContentIds the moment it is called), THEN releaseReservedPersistence when the
            // actual durable write never went through.
            index.tryReservePersistence(a) shouldBe true
            index.releaseReservedPersistence(a)

            // THE CENTRAL ASSERTION: a wholly different, later bundle can still claim the cap's ONE
            // slot - proving `a`'s failed/released reservation did not permanently burn it. Without
            // releaseReservedPersistence (or if it were a no-op), this would fail: the cap would
            // already be exhausted by `a` alone.
            index.tryReservePersistence(b) shouldBe true

            // releaseReservedPersistence is a no-op for a content id that was never reserved (or was
            // already released) - safe to call defensively.
            index.releaseReservedPersistence(a) // already released above - must not throw or corrupt state
            index.tryReservePersistence(bundle(DualKeyIdentity.generate(), 0)) shouldBe false // cap still enforced
        }

        test("evictExpired removes bundles whose TTL has passed, without touching the high-water mark") {
            val index = PrekeyBundleIndex()
            val identity = DualKeyIdentity.generate()
            val expiring =
                PrekeyBundle.create(
                    identity = identity,
                    encryptionBinding =
                        EncryptionKeyBinding.create(
                            identity.secp256k1KeyPair,
                            X25519KeyPair.generate().publicKey,
                        ),
                    signedPrekeyId = 0,
                    signedPrekey = X25519KeyPair.generate().publicKey,
                    oneTimePrekeys = emptyList(),
                    sequenceNumber = 10,
                    notValidAfterEpochSecond = 100L,
                    nowEpochSecond = 0,
                )
            index.add(expiring) shouldBe true
            index.evictExpired(200L) shouldBe 1
            index.size() shouldBe 0
            // The high-water mark survives - a replayed OLDER bundle for the same identity is still rejected.
            index.add(bundle(identity, 5)) shouldBe false
        }

        test("add rejects a bundle failing verify, verifyEncryptionBinding, or verifySignedPrekey") {
            val index = PrekeyBundleIndex()
            val victim = DualKeyIdentity.generate()
            val attacker = DualKeyIdentity.generate()
            val victimBundle = bundle(victim, 1)

            // (1) signature-invalid.
            val victimBytes = PrekeyBundleCodec.encode(victimBundle).copyOf()
            victimBytes[victimBytes.size - 1] = (victimBytes[victimBytes.size - 1] + 1).toByte()
            val tampered = PrekeyBundleCodec.decode(victimBytes)
            index.add(tampered) shouldBe false

            // (2) encryption-binding-invalid: verbatim transplant of the victim's binding into an
            // attacker-signed bundle. Both verify() and verifySignedPrekey() are proven to PASS
            // below, isolating verifyEncryptionBinding() as the specific check that rejects this
            // bundle - see spoofedBundle's own doc comment for why its signed-prekey signature is a
            // genuine one, not a placeholder that would fail verifySignedPrekey() too and leave this
            // isolation unproven.
            val spoofed = spoofedBundle(signingIdentity = attacker, victimBinding = victimBundle.encryptionBinding)
            PrekeyBundle.verify(spoofed) shouldBe true // genuinely signed - proves this isn't caught by signature alone
            spoofed.verifySignedPrekey() shouldBe true // genuinely signed too - not a signed-prekey failure either
            spoofed.verifyEncryptionBinding() shouldBe false // THIS is the check that actually rejects it
            index.add(spoofed) shouldBe false

            // Confirm the genuine bundle is still accepted for comparison.
            index.add(victimBundle) shouldBe true
        }

        test(
            "add rejects a signed-prekey-signature-invalid bundle even when the outer signature is freshly " +
                "RE-SIGNED over the tampered body - isolates verifySignedPrekey as the failing check, since " +
                "neither verify() nor verifyEncryptionBinding() fail first",
        ) {
            val index = PrekeyBundleIndex()
            val identity = DualKeyIdentity.generate()
            val genuine = bundle(identity, 1)

            val body = PrekeyBundleCodec.encodeSignedBody(genuine).copyOf()
            // Signed-prekey signature offset: magic(4)+version(1)+flags(1)+identity(33)+
            // x25519Key(32)+bindingSig(64)+signedPrekeyId(4)+signedPrekey(32) = 171
            val signedPrekeySignatureOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32
            body[signedPrekeySignatureOffset] = (body[signedPrekeySignatureOffset] + 1).toByte()
            val signature =
                identity.secp256k1KeyPair.sign(
                    domainSeparatedDigest("LapisNet:x3dh-prekey-bundle:v1", body),
                )
            val bytes = body + signature
            val tampered = PrekeyBundleCodec.decode(bytes)

            // Re-signed over the tampered body - not an outer-signature failure.
            PrekeyBundle.verify(tampered) shouldBe true
            // Binding untouched - not a binding failure either.
            tampered.verifyEncryptionBinding() shouldBe true

            index.add(tampered) shouldBe false
        }
    })
