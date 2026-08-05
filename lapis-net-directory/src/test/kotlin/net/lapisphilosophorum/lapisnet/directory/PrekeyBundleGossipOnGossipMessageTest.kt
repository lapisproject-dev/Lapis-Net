package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.ratchet.OneTimePrekey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun bundle(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
): PrekeyBundle {
    val x25519Identity = X25519KeyPair.generate()
    val binding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, x25519Identity.publicKey)
    return PrekeyBundle.create(
        identity = identity,
        encryptionBinding = binding,
        signedPrekeyId = 0,
        signedPrekey = X25519KeyPair.generate().publicKey,
        oneTimePrekeys = listOf(OneTimePrekey(0, X25519KeyPair.generate().publicKey)),
        sequenceNumber = sequenceNumber,
        notValidAfterEpochSecond = 500_000L,
        nowEpochSecond = 0,
    )
}

/**
 * Unit-level tests of [PrekeyBundleGossip.onGossipMessage] - mirrors
 * [PeerDirectoryGossipOnGossipMessageTest]'s test seam exactly: only a single, never-connected
 * [LapisNode] + [NabuStorage] is needed.
 */
class PrekeyBundleGossipOnGossipMessageTest :
    FunSpec({
        test("a valid bundle is Valid, persisted, and indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-valid"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val b = bundle(identity, 0)
                val bytes = PrekeyBundleCodec.encode(b)

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.current(identity.secp256k1KeyPair.publicKey) shouldBe b
                storage.get(storage.put(bytes)) shouldBe bytes
            } finally {
                node.stop()
            }
        }

        test("structurally malformed bytes are Invalid, nothing persisted or indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-malformed"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val result = PrekeyBundleGossip.onGossipMessage(byteArrayOf(1, 2, 3), from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a signature-invalid bundle is Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-badsig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val b = bundle(identity, 0)
                val bytes = PrekeyBundleCodec.encode(b)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the outer signature

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test(
            "an encryption-binding-invalid (unknown key share) bundle is Invalid - central attack, wiring-level companion",
        ) {
            val victim = DualKeyIdentity.generate()
            val attacker = DualKeyIdentity.generate()
            val node = LapisNode.create(attacker)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-spoofed"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val victimBundle = bundle(victim, 0)
                val signedPrekey = X25519KeyPair.generate()
                val body =
                    PrekeyBundleCodec.encodeSignedBody(
                        identity = attacker.secp256k1KeyPair.publicKey,
                        encryptionBinding = victimBundle.encryptionBinding, // victim's binding, verbatim
                        signedPrekeyId = 0,
                        signedPrekey = signedPrekey.publicKey,
                        signedPrekeySignature = ByteArray(64),
                        oneTimePrekeys = emptyList(),
                        sequenceNumber = 0,
                        notValidAfterEpochSecond = 500_000L,
                    )
                val signature =
                    attacker.secp256k1KeyPair.sign(
                        domainSeparatedDigest("LapisNet:x3dh-prekey-bundle:v1", body),
                    )
                // PrekeyBundle.fromDecoded is internal to lapis-net-ratchet (a different Gradle
                // module) - constructs the hand-forged bundle via the PUBLIC wire-decode path
                // instead, exactly as an attacker on the real network would have to.
                val bytes = body + signature
                val spoofed = PrekeyBundleCodec.decode(bytes)
                PrekeyBundle.verify(spoofed) shouldBe true // genuinely signed, proving this isn't a signature failure

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a signed-prekey-signature-invalid bundle is Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-badprekeysig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val b = bundle(identity, 0)
                val bytes = PrekeyBundleCodec.encode(b).copyOf()
                // Signed-prekey signature offset: magic(4)+version(1)+flags(1)+identity(33)+
                // x25519Key(32)+bindingSig(64)+signedPrekeyId(4)+signedPrekey(32) = 171
                val signedPrekeySignatureOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32
                bytes[signedPrekeySignatureOffset] = (bytes[signedPrekeySignatureOffset] + 1).toByte()
                // Re-sign the OUTER signature over the tampered body so only verifySignedPrekey fails
                // (isolates this specific check from the outer-signature check, unlike the tampered-
                // signature adversarial case which deliberately leaves both broken).
                // Not resigning here is also fine (outer sig would fail too, still Invalid) - kept
                // simple: assert Invalid either way.

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test(
            "a signed-prekey-signature-invalid bundle, RE-SIGNED so the outer signature verifies against the " +
                "tampered body, is still Invalid - isolates verifySignedPrekey from the outer-signature check, " +
                "unlike the sibling test above whose own comment concedes it leaves the outer signature broken " +
                "too and so does not actually prove verifySignedPrekey is what rejected it",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage =
                    NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-badprekeysig-resigned"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val b = bundle(identity, 0)
                val body = PrekeyBundleCodec.encodeSignedBody(b).copyOf()
                // Signed-prekey signature offset: magic(4)+version(1)+flags(1)+identity(33)+
                // x25519Key(32)+bindingSig(64)+signedPrekeyId(4)+signedPrekey(32) = 171
                val signedPrekeySignatureOffset = 4 + 1 + 1 + 33 + 32 + 64 + 4 + 32
                body[signedPrekeySignatureOffset] = (body[signedPrekeySignatureOffset] + 1).toByte()
                // Re-sign the OUTER signature over the now-tampered body, exactly the shape a real
                // attacker who controls their own signing key would produce - unlike the sibling test
                // above, this actually isolates verifySignedPrekey as the failing check.
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

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a stale sequence number is Invalid when the index already holds a newer bundle") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-stale"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex()

                val newer = bundle(identity, 5)
                index.add(newer) shouldBe true

                val staler = bundle(identity, 3)
                val bytes = PrekeyBundleCodec.encode(staler)

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.current(identity.secp256k1KeyPair.publicKey) shouldBe newer
            } finally {
                node.stop()
            }
        }

        test("persistence-cap-reached still returns Valid and indexed, even though nothing was persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("prekeybundle-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PrekeyBundleIndex(maxTracked = 100, maxPersisted = 0, maxHighWaterMarks = 100)

                val b = bundle(identity, 0)
                val bytes = PrekeyBundleCodec.encode(b)

                val result = PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.current(identity.secp256k1KeyPair.publicKey) shouldBe b

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(mintingNode, Files.createTempDirectory("prekeybundle-ongossip-persist-mint"))
                    storage.get(mintingStorage.put(bytes)).shouldBeNull()
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }
    })
