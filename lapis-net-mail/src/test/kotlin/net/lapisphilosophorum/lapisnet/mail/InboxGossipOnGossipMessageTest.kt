package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun freshFrame(
    sender: Secp256k1KeyPair,
    recipients: List<Secp256k1PublicKey>,
    subject: String = "hello",
    body: String = "world",
): ByteArray {
    val messageBody = MessageBody(subject = subject, body = body)
    val bodyBytes = MessageBodyCodec.encode(messageBody)
    val contentCid = MessageBodyCodec.cidFor(bodyBytes)
    val envelope = MessageEnvelope.create(sender, recipients, contentCid)
    val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
    return MailFrameCodec.encode(envelopeBytes, bodyBytes)
}

/**
 * Unit-level tests of [InboxGossip.onGossipMessage] itself - the actual GossipSub validator
 * function, called directly rather than through a full two-node gossip mesh. Only a single,
 * never-connected [LapisNode] + [NabuStorage] is needed, mirroring
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGossipOnGossipMessageTest`'s exact test seam
 * reasoning: [InboxGossip.onGossipMessage] already takes [NabuStorage]/[InboxIndex] as plain
 * parameters, made `internal` for precisely this purpose.
 *
 * The mail-specific adversarial cases (unaddressed envelope, oversized recipient list, body
 * substitution, degenerate signatures, reserved encryption modes) live in
 * [MailEnvelopeAbuseTest] instead - this file covers the validator's ordinary accept/dedup/
 * persistence-cap behavior, mirroring how `VeritasGossipOnGossipMessageTest` and
 * `VeritasGrantTest`'s adversarial cases are split across two files.
 */
class InboxGossipOnGossipMessageTest :
    FunSpec({
        test("a fresh, valid, addressed frame is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val recipient = identity.secp256k1KeyPair.publicKey
                val bytes = freshFrame(sender, listOf(recipient))

                val result = InboxGossip.onGossipMessage(bytes, from, storage, index, recipient)

                result shouldBe ValidationResult.Valid
                val tracked = index.latest()
                tracked.size shouldBe 1
                tracked.single().envelope.sender shouldBe sender.publicKey
                tracked.single().body!!.subject shouldBe "hello"

                // Durable persistence, verified the same way TwoNodeVeritasGossipIntegrationTest
                // does: re-putting the identical bytes is idempotent/deterministic and yields the
                // same Cid without double-storing anything new.
                val frame = MailFrameCodec.decode(bytes)
                storage.get(storage.put(frame.bodyBytes)) shouldBe frame.bodyBytes
                storage.get(storage.put(frame.envelopeBytes)) shouldBe frame.envelopeBytes
            } finally {
                node.stop()
            }
        }

        test("a second delivery of the identical frame is declined as a duplicate") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-b"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val recipient = identity.secp256k1KeyPair.publicKey
                val bytes = freshFrame(sender, listOf(recipient))

                InboxGossip.onGossipMessage(bytes, from, storage, index, recipient) shouldBe ValidationResult.Valid
                val second = InboxGossip.onGossipMessage(bytes, from, storage, index, recipient)

                second shouldBe ValidationResult.Invalid
                index.latest().size shouldBe 1
            } finally {
                node.stop()
            }
        }

        test("structurally malformed frame bytes are rejected without crashing and without persisting anything") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-c"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()
                val recipient = identity.secp256k1KeyPair.publicKey

                val garbage = ByteArray(64) { it.toByte() }

                val result = InboxGossip.onGossipMessage(garbage, from, storage, index, recipient)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test("the from peer id is never an input to acceptance - an unrelated peer id still yields Valid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-d"))
                val unrelatedFrom = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val recipient = identity.secp256k1KeyPair.publicKey
                val bytes = freshFrame(sender, listOf(recipient))

                val result = InboxGossip.onGossipMessage(bytes, unrelatedFrom, storage, index, recipient)

                result shouldBe ValidationResult.Valid
            } finally {
                node.stop()
            }
        }

        test(
            "distinct addressed frames beyond the persistence cap are all still Valid and indexed, but only up " +
                "to the cap are actually persisted to disk",
        ) {
            // Direct analogue of VeritasGossipOnGossipMessageTest's round-3 regression test:
            // tryReservePersistence(), not canAccept(), is what bounds storage.put() calls once
            // distinct content ids exceed the durable-persistence budget.
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val recipient = identity.secp256k1KeyPair.publicKey

                val persistCap = 2
                val totalMessages = 5
                val index = InboxIndex(maxTracked = 100, maxPersisted = persistCap)

                val frames =
                    (1..totalMessages).map {
                        freshFrame(Secp256k1KeyPair.generate(), listOf(recipient), subject = "s$it", body = "b$it")
                    }

                val results = frames.map { InboxGossip.onGossipMessage(it, from, storage, index, recipient) }

                // (a) All 5 are still tracked - a full disk budget does not invalidate an
                // otherwise-valid, non-duplicate, correctly-addressed message.
                results shouldBe List(totalMessages) { ValidationResult.Valid }
                index.latest().size shouldBe totalMessages

                // (b) Only up to persistCap actually made it to durable storage. Verified
                // concretely against the real NabuStorage: mint each body's CID independently
                // (content-addressing means the CID is a pure function of the bytes) via a
                // separate, never-connected node's own blockstore, then check how many of those
                // CIDs the node-under-test's storage can actually serve - mirroring
                // VeritasGossipOnGossipMessageTest's persistence-cap test exactly.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                val persistedCount =
                    try {
                        val mintingStorage =
                            NabuStorage.attach(mintingNode, Files.createTempDirectory("mail-ongossip-persist-mint"))
                        frames.count { frameBytes ->
                            val bodyCid = mintingStorage.put(MailFrameCodec.decode(frameBytes).bodyBytes)
                            storage.get(bodyCid) != null
                        }
                    } finally {
                        mintingNode.stop()
                    }
                persistedCount shouldBe persistCap
            } finally {
                node.stop()
            }
        }

        // "storage failure path" (plan §7.7 item 6) is deliberately NOT covered here: this
        // repository mocks nothing, and there is no way to make a real NabuStorage.put() fail on
        // demand without either mocking or corrupting the temp directory mid-test (itself flaky).
        // Skipped, exactly as the plan's own test list anticipates.

        test("V0.9.2: a valid HYBRID_ECIES frame is Valid and lands in the index as InboxPayload.Sealed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-hybrid"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val recipient = identity.secp256k1KeyPair
                val body = MessageBody(subject = "encrypted", body = "hidden")
                val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), 1_000)
                val sealed = HybridEcies.seal(body, sender, context)
                val envelope =
                    MessageEnvelope.create(
                        sender = sender,
                        recipients = listOf(recipient.publicKey),
                        contentCid = sealed.contentCid,
                        sentAtEpochSecond = 1_000,
                        encryption = EncryptionMode.HYBRID_ECIES,
                        wraps = sealed.wraps,
                    )
                val frame = MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelope), sealed.sealedBodyBytes)

                val result = InboxGossip.onGossipMessage(frame, from, storage, index, recipient.publicKey)

                result shouldBe ValidationResult.Valid
                val tracked = index.latest()
                tracked.size shouldBe 1
                (tracked.single().payload is InboxPayload.Sealed) shouldBe true
                tracked.single().body shouldBe null
                HybridEcies.open(envelope, sealed.sealedBody, recipient) shouldBe body
            } finally {
                node.stop()
            }
        }

        test("V0.9.2: an MLS_ARCHIVE frame is Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-mls"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()
                val recipient = identity.secp256k1KeyPair.publicKey

                val sender = Secp256k1KeyPair.generate()
                val envelope = MessageEnvelope.create(sender, listOf(recipient), testCidForMls())
                val bytes = MessageEnvelopeCodec.encode(envelope)
                val encryptionByteOffset = 4 + 1 + 1 + 33 + 2 + 33 * 1 + 8
                bytes[encryptionByteOffset] = EncryptionMode.MLS_ARCHIVE.wireValue
                val bodyBytes = MessageBodyCodec.encode(MessageBody(subject = "s", body = "b"))
                val frame = MailFrameCodec.encode(bytes, bodyBytes)

                val result = InboxGossip.onGossipMessage(frame, from, storage, index, recipient)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test("V0.9.2: a HYBRID_ECIES frame whose body section is a plaintext MessageBody blob is Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-ongossip-wrong-blob-type"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val recipient = identity.secp256k1KeyPair
                // A structurally-valid plaintext MessageBody blob, wrong type for HYBRID_ECIES -
                // SealedBodyCodec.decode must reject it (bad magic: "LNMB" != "LNSB").
                val plaintextBodyBytes = MessageBodyCodec.encode(MessageBody(subject = "s", body = "b"))
                val plaintextContentCid = MessageBodyCodec.cidFor(plaintextBodyBytes)
                val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), 1_000)
                // Reuse a real wrap list shape (count-correct) so decode() gets past the wrap
                // section - it is the SealedBodyCodec.decode(frame.bodyBytes) call that must fail.
                val sealed =
                    HybridEcies.seal(MessageBody(subject = "irrelevant", body = "irrelevant"), sender, context)
                val envelope =
                    MessageEnvelope.create(
                        sender = sender,
                        recipients = listOf(recipient.publicKey),
                        contentCid = plaintextContentCid,
                        sentAtEpochSecond = 1_000,
                        encryption = EncryptionMode.HYBRID_ECIES,
                        wraps = sealed.wraps,
                    )
                val frame = MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelope), plaintextBodyBytes)

                val result = InboxGossip.onGossipMessage(frame, from, storage, index, recipient.publicKey)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }
    })

private fun testCidForMls(): io.ipfs.cid.Cid =
    io.ipfs.cid.Cid.buildCidV1(
        io.ipfs.cid.Cid.Codec.Raw,
        io.ipfs.multihash.Multihash.Type.sha2_256,
        ByteArray(32) { 3 },
    )
