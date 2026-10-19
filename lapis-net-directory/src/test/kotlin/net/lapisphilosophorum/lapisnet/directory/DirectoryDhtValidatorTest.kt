package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import java.time.Instant

class DirectoryDhtValidatorTest :
    FunSpec({
        val now = Instant.now().epochSecond

        fun validate(
            publisher: DirectoryPublisher,
            value: DirectoryDhtValue,
            expected: DirectoryPublisher = publisher,
            signedBy: DirectoryPublisher = publisher,
        ) = DirectoryDhtValidator.validate(
            ipnsValueOf(signedBy.peerId, DirectoryDhtValueCodec.encode(value)),
            expected.key,
            now,
        )

        fun flip(
            bytes: ByteArray,
            fromEnd: Int,
        ): ByteArray = bytes.copyOf().also { it[it.size - fromEnd] = (it[it.size - fromEnd].toInt() xor 1).toByte() }

        test("a valid value with both parts is accepted and yields both parts verbatim") {
            val a = DirectoryPublisher()
            val value = a.value()
            val entry = validate(a, value)!!
            entry.identity shouldBe a.key
            entry.peerRecord shouldBe PeerRecordCodec.decode(value.peerRecordBytes!!)
            entry.prekeyBundle shouldBe PrekeyBundleCodec.decode(value.prekeyBundleBytes!!)
            entry.peerRecordBytes!!.contentEquals(value.peerRecordBytes) shouldBe true
        }

        test("a value with only a peer record, or only a bundle, is accepted") {
            val a = DirectoryPublisher()
            validate(a, a.value(bundle = null))!!.prekeyBundle shouldBe null
            validate(a, a.value(peerRecord = null))!!.peerRecord shouldBe null
        }

        test("the IPNS publisher must be the transport key the binding names") {
            val a = DirectoryPublisher()
            val other = DirectoryPublisher()
            validate(a, a.value(), signedBy = other) shouldBe null
        }

        test("a binding made by another identity is rejected") {
            val a = DirectoryPublisher()
            val mallory = DirectoryPublisher()
            val foreignBinding =
                IdentityBinding.create(
                    mallory.identity.secp256k1KeyPair,
                    a.identity.ed25519KeyPair.publicKey,
                )
            val value = DirectoryDhtValue(a.key, foreignBinding, PeerRecordCodec.encode(a.peerRecord()), null)
            validate(a, value) shouldBe null
        }

        test("a value for another identity than the one asked for is rejected") {
            val a = DirectoryPublisher()
            val b = DirectoryPublisher()
            validate(a, a.value(), expected = b) shouldBe null
        }

        test("a peer record of another identity inside a valid envelope is rejected") {
            val a = DirectoryPublisher()
            val b = DirectoryPublisher()
            val value = DirectoryDhtValue(a.key, a.identity.binding, PeerRecordCodec.encode(b.peerRecord()), null)
            validate(a, value) shouldBe null
        }

        test("a peer record whose binding differs from the envelope's is rejected") {
            val a = DirectoryPublisher()
            val a2 = DirectoryPublisher() // holds the Ed25519 key a second binding of A's identity points at
            val secondBinding =
                IdentityBinding.create(
                    a.identity.secp256k1KeyPair,
                    a2.identity.ed25519KeyPair.publicKey,
                )
            val value = DirectoryDhtValue(a.key, secondBinding, PeerRecordCodec.encode(a.peerRecord()), null)
            // the envelope itself is perfectly valid for key a2 ...
            DirectoryDhtValidator.validate(
                ipnsValueOf(
                    a2.peerId,
                    DirectoryDhtValueCodec.encode(
                        DirectoryDhtValue(a.key, secondBinding, null, a.value().prekeyBundleBytes),
                    ),
                ),
                a.key,
                now,
            ) shouldNotBe null
            // ... but the record inside names the first binding
            DirectoryDhtValidator.validate(
                ipnsValueOf(a2.peerId, DirectoryDhtValueCodec.encode(value)),
                a.key,
                now,
            ) shouldBe
                null
        }

        test("a forged peer record signature is rejected") {
            val a = DirectoryPublisher()
            val value =
                DirectoryDhtValue(a.key, a.identity.binding, flip(PeerRecordCodec.encode(a.peerRecord()), 1), null)
            validate(a, value) shouldBe null
        }

        test(
            "case (h): a record whose fresh binding covers the victim's transport key but lacks a possession proof is rejected",
        ) {
            val attacker = DirectoryPublisher()
            val victim = DirectoryPublisher()
            val forgedBinding =
                IdentityBinding.create(
                    attacker.identity.secp256k1KeyPair,
                    victim.identity.ed25519KeyPair.publicKey,
                )
            val body =
                PeerRecordCodec.encodeSignedBody(
                    identity = attacker.key,
                    binding = forgedBinding,
                    possessionProof = ByteArray(64),
                    addresses = emptyList(),
                    capabilities = setOf(PeerCapability.DM),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = now + 3600,
                )
            val signature =
                attacker.identity.secp256k1KeyPair.sign(
                    domainSeparatedDigest("LapisNet:peer-record:v1", body),
                )
            val forged =
                PeerRecord.fromDecoded(
                    attacker.key,
                    forgedBinding,
                    emptyList(),
                    setOf(PeerCapability.DM),
                    0,
                    now + 3600,
                    signature,
                )
            PeerRecord.verify(forged) shouldBe true
            forged.verifyBinding() shouldBe true
            val value = DirectoryDhtValue(attacker.key, forgedBinding, PeerRecordCodec.encode(forged), null)
            // even if somebody could sign IPNS as the victim, the possession proof still fails
            validate(attacker, value, signedBy = victim) shouldBe null
        }

        test("a bundle of another identity is rejected") {
            val a = DirectoryPublisher()
            val b = DirectoryPublisher()
            val value = DirectoryDhtValue(a.key, a.identity.binding, null, PrekeyBundleCodec.encode(b.bundle()))
            validate(a, value) shouldBe null
        }

        test("a bundle with a broken outer signature, signed prekey signature or encryption binding is rejected") {
            val a = DirectoryPublisher()
            val encoded = PrekeyBundleCodec.encode(a.bundle(oneTimePrekeys = 0))
            // layout: ... encryptionBinding sig, signed prekey sig, one-time prekeys (none), seq(8), expiry(8), outer sig(64)
            val outerSig = flip(encoded, 1)
            val signedPrekeySig = flip(encoded, 64 + 8 + 8 + 2 + 1 + 10)
            val encryptionBindingSig = flip(encoded, 64 + 8 + 8 + 2 + 1 + 64 + 10)
            for (tampered in listOf(outerSig, signedPrekeySig, encryptionBindingSig)) {
                validate(a, DirectoryDhtValue(a.key, a.identity.binding, null, tampered)) shouldBe null
            }
        }

        test("an expired peer record or bundle is rejected") {
            val a = DirectoryPublisher()
            validate(a, a.value(peerRecord = a.peerRecord(expiresInSeconds = -10), bundle = null)) shouldBe null
            validate(a, a.value(peerRecord = null, bundle = a.bundle(expiresInSeconds = -10))) shouldBe null
        }

        test("an expired part is dropped while the other valid part is kept") {
            val a = DirectoryPublisher()
            val onlyBundle =
                validate(
                    a,
                    a.value(
                        peerRecord = a.peerRecord(expiresInSeconds = -10),
                        bundle = a.bundle(expiresInSeconds = 1000),
                    ),
                )
            onlyBundle shouldNotBe null
            onlyBundle!!.peerRecord shouldBe null
            onlyBundle.peerRecordBytes shouldBe null
            onlyBundle.prekeyBundle shouldNotBe null
        }

        test("one valid part plus one manipulated part rejects the whole value") {
            val a = DirectoryPublisher()
            val badBundle = flip(PrekeyBundleCodec.encode(a.bundle()), 1)
            val value = DirectoryDhtValue(a.key, a.identity.binding, PeerRecordCodec.encode(a.peerRecord()), badBundle)
            validate(a, value) shouldBe null
            val badRecord = flip(PeerRecordCodec.encode(a.peerRecord()), 1)
            val value2 = DirectoryDhtValue(a.key, a.identity.binding, badRecord, PrekeyBundleCodec.encode(a.bundle()))
            validate(a, value2) shouldBe null
        }

        test("malformed envelopes and parts never throw, they are rejected") {
            val a = DirectoryPublisher()
            DirectoryDhtValidator.validate(ipnsValueOf(a.peerId, ByteArray(40) { 3 }), a.key, now) shouldBe null
            DirectoryDhtValidator.validate(ipnsValueOf(a.peerId, ByteArray(6000)), a.key, now) shouldBe null
            val garbageParts = DirectoryDhtValue(a.key, a.identity.binding, ByteArray(50) { 1 }, ByteArray(50) { 2 })
            validate(a, garbageParts) shouldBe null
        }
    })
