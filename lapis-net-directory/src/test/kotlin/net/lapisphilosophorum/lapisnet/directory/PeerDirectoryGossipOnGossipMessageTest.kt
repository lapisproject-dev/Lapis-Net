package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

private fun record(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
    addresses: List<Multiaddr> = listOf(testAddress(4000 + sequenceNumber.toInt())),
): PeerRecord = PeerRecord.create(identity, addresses, setOf(PeerCapability.DM), sequenceNumber, 9_999_999_999L)

/** As [record], but genuinely self-signed by [signingIdentity] while embedding a DIFFERENT
 * identity's [IdentityBinding] - see [PeerRecordIndexTest]'s identical helper. */
private fun spoofedRecord(
    signingIdentity: DualKeyIdentity,
    victimBinding: IdentityBinding,
): PeerRecord {
    val body =
        PeerRecordCodec.encodeSignedBody(
            identity = signingIdentity.secp256k1KeyPair.publicKey,
            binding = victimBinding,
            possessionProof = ByteArray(64),
            addresses = emptyList(),
            capabilities = emptySet(),
            sequenceNumber = 0,
            notValidAfterEpochSecond = 9_999_999_999L,
        )
    val signature = signingIdentity.secp256k1KeyPair.sign(domainSeparatedDigest("LapisNet:peer-record:v1", body))
    return PeerRecord.fromDecoded(
        identity = signingIdentity.secp256k1KeyPair.publicKey,
        binding = victimBinding,
        addresses = emptyList(),
        capabilities = emptySet(),
        sequenceNumber = 0,
        notValidAfterEpochSecond = 9_999_999_999L,
        signature = signature,
    )
}

/**
 * Unit-level tests of [PeerDirectoryGossip.onGossipMessage] itself - mirrors
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGossipOnGossipMessageTest`'s test seam exactly:
 * only a single, never-connected [LapisNode] + [NabuStorage] is needed.
 */
class PeerDirectoryGossipOnGossipMessageTest :
    FunSpec({
        test("a valid record is Valid, persisted, and indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-valid"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val r = record(identity, 0)
                val bytes = PeerRecordCodec.encode(r)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.current(identity.secp256k1KeyPair.publicKey) shouldBe r
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
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-malformed"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val result = PeerDirectoryGossip.onGossipMessage(byteArrayOf(1, 2, 3), from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a signature-invalid record is Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-badsig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val r = record(identity, 0)
                val bytes = PeerRecordCodec.encode(r)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the outer signature

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a binding-invalid (spoofed peerId) record is Invalid - central attack, wiring-level companion") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val node = LapisNode.create(identityA)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-spoofed"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val spoofed = spoofedRecord(signingIdentity = identityA, victimBinding = identityB.binding)
                PeerRecord.verify(spoofed) shouldBe true // genuinely signed, proving this isn't a signature failure
                val bytes = PeerRecordCodec.encode(spoofed)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("an exact content-id duplicate is Invalid on the second delivery, not double-persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-dup"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val r = record(identity, 0)
                val bytes = PeerRecordCodec.encode(r)

                PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index) shouldBe ValidationResult.Valid
                val secondResult = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                secondResult shouldBe ValidationResult.Invalid
                index.size() shouldBe 1
            } finally {
                node.stop()
            }
        }

        test("a stale sequence number is Invalid when the index already holds a newer record") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-stale"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val newer = record(identity, 5)
                index.add(newer) shouldBe true

                val staler = record(identity, 3)
                val bytes = PeerRecordCodec.encode(staler)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

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
                val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex(maxTracked = 100, maxPersisted = 0)

                val r = record(identity, 0)
                val bytes = PeerRecordCodec.encode(r)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.current(identity.secp256k1KeyPair.publicKey) shouldBe r

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(mintingNode, Files.createTempDirectory("directory-ongossip-persist-mint"))
                    storage.get(mintingStorage.put(bytes)).shouldBeNull()
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }
    })
