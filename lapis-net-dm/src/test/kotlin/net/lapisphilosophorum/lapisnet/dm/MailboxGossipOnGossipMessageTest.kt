package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

/** Mirrors `PeerDirectoryGossipOnGossipMessageTest`/`InboxGossipOnGossipMessageTest`'s established
 * seam: [MailboxGossip.onGossipMessage] is exercised directly against a real (never-connected)
 * [NabuStorage] and a fresh [MailboxPointerIndex]. */
class MailboxGossipOnGossipMessageTest :
    FunSpec({
        test("accepts a pointer addressed to the local identity, persists and indexes it") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-gossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair
                val pointer =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val bytes = MailboxPointerCodec.encode(pointer)

                val result = MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity)

                result shouldBe ValidationResult.Valid
                index.pending().size shouldBe 1
            } finally {
                node.stop()
            }
        }

        test("a pointer not addressed to the local identity is dropped WITHOUT persisting/indexing/re-propagating") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-gossip-b"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair
                val actualRecipient = DualKeyIdentity.generate().secp256k1KeyPair.publicKey // NOT localIdentity
                val addressed =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = actualRecipient,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                // The pointer's own signature is genuinely valid - this test must prove the
                // ADDRESSING check, not signature failure, is what rejects it.
                MailboxPointer.verify(addressed) shouldBe true
                val addressedBytes = MailboxPointerCodec.encode(addressed)

                val result = MailboxGossip.onGossipMessage(addressedBytes, from, storage, index, localIdentity)

                result shouldBe ValidationResult.Invalid
                index.pending().size shouldBe 0

                // Prove nothing was persisted: mint the pointer bytes' CID independently on a
                // separate, never-connected node and confirm the node-under-test's storage lacks it
                // - mirrors MailEnvelopeAbuseTest's established technique.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(
                            mintingNode,
                            Files.createTempDirectory("mailbox-gossip-b-mint"),
                        )
                    storage.get(mintingStorage.put(addressedBytes)) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("a signature-invalid pointer is rejected, never persisted or indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-gossip-c"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val genuineSender = DualKeyIdentity.generate().secp256k1KeyPair
                val impostor = DualKeyIdentity.generate().secp256k1KeyPair
                val genuine =
                    MailboxPointer.create(
                        sender = genuineSender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val impostorSigned =
                    MailboxPointer.create(
                        sender = impostor,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val forged =
                    MailboxPointer.fromDecoded(
                        recipientIdentity = genuine.recipientIdentity,
                        senderIdentity = genuine.senderIdentity,
                        blobCid = genuine.blobCid,
                        notValidAfterEpochSecond = genuine.notValidAfterEpochSecond,
                        signature = impostorSigned.signature,
                    )

                val result =
                    MailboxGossip.onGossipMessage(
                        MailboxPointerCodec.encode(forged),
                        from,
                        storage,
                        index,
                        localIdentity,
                    )

                result shouldBe ValidationResult.Invalid
                index.pending().size shouldBe 0
            } finally {
                node.stop()
            }
        }

        test("a duplicate (already-tracked) pointer is declined without re-persisting or re-indexing") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-gossip-d"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair
                val pointer =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val bytes = MailboxPointerCodec.encode(pointer)

                MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity) shouldBe
                    ValidationResult.Valid
                index.pending().size shouldBe 1
                MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity) shouldBe
                    ValidationResult.Invalid
                index.pending().size shouldBe 1
            } finally {
                node.stop()
            }
        }

        test("a structurally malformed frame is rejected cleanly, never crashes") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-gossip-e"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey

                val result = MailboxGossip.onGossipMessage(byteArrayOf(1, 2, 3), from, storage, index, localIdentity)

                result shouldBe ValidationResult.Invalid
                index.pending().size shouldBe 0
            } finally {
                node.stop()
            }
        }

        test("persistence-cap-reached still tracks and propagates the pointer (durability-only degradation)") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-gossip-f"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex(maxTracked = 100, maxPersisted = 0)
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair
                val pointer =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )

                val pointerBytes = MailboxPointerCodec.encode(pointer)
                val result = MailboxGossip.onGossipMessage(pointerBytes, from, storage, index, localIdentity)

                result shouldBe ValidationResult.Valid
                index.pending().size shouldBe 1 // still tracked and would still be re-propagated

                // Prove it was NOT durably persisted (maxPersisted = 0): mint the same bytes' CID on
                // a separate, never-connected node and confirm this node's storage lacks it.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(
                            mintingNode,
                            Files.createTempDirectory("mailbox-gossip-f-mint"),
                        )
                    storage.get(mintingStorage.put(pointerBytes)) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }
    })
