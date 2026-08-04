package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.file.Files

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun encodedBody(
    subject: String = "s",
    body: String = "b",
): ByteArray = MessageBodyCodec.encode(MessageBody(subject = subject, body = body))

/** Hand-builds a structurally-minimal (magic/version/flags/sender/recipientCount only) envelope
 * buffer declaring [recipientCount] recipients that are never actually present - the shape
 * [MailEnvelopeAbuseTest]'s case (b) needs to prove the length check runs BEFORE allocation. */
private fun envelopeBytesDeclaringRecipientCount(
    sender: Secp256k1KeyPair,
    recipientCount: Int,
): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNME".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0)
        write(sender.publicKey.bytes)
        writeShort(recipientCount)
    }
    return out.toByteArray()
}

/**
 * The mandatory adversarial spec for [InboxGossip.onGossipMessage] and its supporting codecs -
 * see the V0.9.1 plan's test list, case (a) through (f). Each case is verified both at the
 * codec/constructor layer that can reject it AND, where applicable, end-to-end through
 * [InboxGossip.onGossipMessage] against a real (never-connected) [NabuStorage] and [InboxIndex],
 * mirroring [InboxGossipOnGossipMessageTest]'s test seam.
 */
class MailEnvelopeAbuseTest :
    FunSpec({
        test("(a) an envelope whose recipients omit the local identity is dropped WITHOUT being persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-abuse-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val actualRecipient = Secp256k1KeyPair.generate().publicKey // NOT localIdentity
                val localIdentity = identity.secp256k1KeyPair.publicKey

                val bodyBytes = encodedBody()
                val contentCid = MessageBodyCodec.cidFor(bodyBytes)
                val envelope = MessageEnvelope.create(sender, listOf(actualRecipient), contentCid)
                // The envelope's own signature is genuinely valid - this test must prove the
                // ADDRESSING check, not signature failure, is what rejects it.
                MessageEnvelope.verify(envelope) shouldBe true
                val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
                val frameBytes = MailFrameCodec.encode(envelopeBytes, bodyBytes)

                val result = InboxGossip.onGossipMessage(frameBytes, from, storage, index, localIdentity)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()

                // Prove nothing was persisted: mint both CIDs independently on a separate,
                // never-connected node and confirm the node-under-test's storage has neither.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage = NabuStorage.attach(mintingNode, Files.createTempDirectory("mail-abuse-a-mint"))
                    storage.get(mintingStorage.put(bodyBytes)) shouldBe null
                    storage.get(mintingStorage.put(envelopeBytes)) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("(b) a 10,000-recipient envelope is rejected BEFORE allocation, not as a truncation error") {
            val sender = Secp256k1KeyPair.generate()
            val bytes = envelopeBytesDeclaringRecipientCount(sender, 10_000)

            // Hand-built: magic(4) + version(1) + flags(1) + sender(33) + recipientCount(2) = 41
            // bytes total, declaring 10,000 recipients that are never actually present. If
            // decode() allocated/consumed on the attacker's declared count first, this would
            // surface as "truncated" instead - the whole point of this test is that it must not.
            val exception = shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
            exception.message?.contains("too many recipients") shouldBe true
            exception.message?.contains("truncated") shouldBe false

            // Same proof through the actual GossipSub validator: wrapped in a frame, it must be
            // Invalid, not a crash, and nothing persisted.
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-abuse-b"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()
                val frameBytes = MailFrameCodec.encode(bytes, ByteArray(0))

                val result =
                    InboxGossip.onGossipMessage(frameBytes, from, storage, index, identity.secp256k1KeyPair.publicKey)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test("(c) a contentCid the validator cannot honour never crashes it and is always rejected cleanly") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-abuse-c"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = Secp256k1KeyPair.generate()

                // c1/c2: a frame whose declared body section is unusable - either the length field
                // claims more than the buffer actually holds (truncated) or the buffer is simply
                // cut short. Re-expressed from the plan's original "unfetchable blob" wording: this
                // validator never fetches by CID at all (see MailFrameCodec's class doc comment for
                // why), so "unfetchable" here becomes "the frame's body section is unusable" -
                // MalformedMailFrameException, caught and turned into Invalid, never propagated as
                // a crash.
                run {
                    val envelope = MessageEnvelope.create(sender, listOf(localIdentity), testCid(1))
                    val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
                    val out = ByteArrayOutputStream()
                    DataOutputStream(out).apply {
                        write("LNMF".toByteArray(Charsets.US_ASCII))
                        writeByte(1)
                        writeByte(0)
                        writeShort(envelopeBytes.size)
                        write(envelopeBytes)
                        writeShort(500) // declares 500 body bytes, but none actually follow
                    }
                    val index = InboxIndex()

                    val result = InboxGossip.onGossipMessage(out.toByteArray(), from, storage, index, localIdentity)

                    result shouldBe ValidationResult.Invalid
                    index.latest() shouldBe emptyList()
                }

                // c3: a well-formed envelope whose contentCid is a well-formed CID for content
                // nothing has, paired with an unrelated (but structurally valid) body. The
                // validator makes zero storage.get()/findProviders() calls (see InboxGossip's
                // class doc comment for the "zero clock, zero network" invariant this pins), so
                // there is no DHT/Bitswap round trip to observe by construction - the real
                // guarantee under test is that onGossipMessage completes via the local CID-binding
                // comparison alone, not a network call.
                run {
                    val unrelatedContentCid = testCid(42) // not derived from any body this test built
                    val envelope = MessageEnvelope.create(sender, listOf(localIdentity), unrelatedContentCid)
                    val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
                    val unrelatedBody = encodedBody(subject = "unrelated", body = "unrelated content")
                    val frameBytes = MailFrameCodec.encode(envelopeBytes, unrelatedBody)
                    val index = InboxIndex()

                    val result = InboxGossip.onGossipMessage(frameBytes, from, storage, index, localIdentity)

                    result shouldBe ValidationResult.Invalid
                    index.latest() shouldBe emptyList()

                    val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                    mintingNode.start(bootstrapPeers = emptyList())
                    try {
                        val mintingStorage =
                            NabuStorage.attach(
                                mintingNode,
                                Files.createTempDirectory("mail-abuse-c3-mint"),
                            )
                        storage.get(mintingStorage.put(unrelatedBody)) shouldBe null
                    } finally {
                        mintingNode.stop()
                    }
                }
            } finally {
                node.stop()
            }
        }

        test("(d) a body substituted after the envelope was signed fails the CID-binding check, not the signature") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-abuse-d"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = Secp256k1KeyPair.generate()

                val bodyABytes = encodedBody(subject = "real", body = "the real message")
                val bodyBBytes = encodedBody(subject = "swapped", body = "a completely different message")
                val contentCidA = MessageBodyCodec.cidFor(bodyABytes)

                // Signed over bodyA's CID.
                val envelope = MessageEnvelope.create(sender, listOf(localIdentity), contentCidA)
                // The signature alone is genuinely valid - this is what makes the CID binding the
                // load-bearing check, not a defense-in-depth redundant with signature verification.
                MessageEnvelope.verify(envelope) shouldBe true
                val envelopeBytes = MessageEnvelopeCodec.encode(envelope)

                // But the frame carries bodyB.
                val frameBytes = MailFrameCodec.encode(envelopeBytes, bodyBBytes)
                val index = InboxIndex()

                val result = InboxGossip.onGossipMessage(frameBytes, from, storage, index, localIdentity)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage = NabuStorage.attach(mintingNode, Files.createTempDirectory("mail-abuse-d-mint"))
                    storage.get(mintingStorage.put(bodyABytes)) shouldBe null
                    storage.get(mintingStorage.put(bodyBBytes)) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("(e) degenerate all-0xFF and all-zero 64-byte signatures never throw - they verify false cleanly") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val degenerateSignatures = listOf(ByteArray(64) { 0xFF.toByte() }, ByteArray(64))

            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-abuse-e"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                degenerateSignatures.forEach { degenerateSignature ->
                    val bodyBytes = encodedBody()
                    val contentCid = MessageBodyCodec.cidFor(bodyBytes)
                    val degenerate =
                        MessageEnvelope.fromDecoded(
                            sender = sender.publicKey,
                            recipients = listOf(recipient),
                            sentAtEpochSecond = 1_000,
                            encryption = EncryptionMode.NONE,
                            contentCid = contentCid,
                            replyTo = null,
                            threadRoot = null,
                            signature = degenerateSignature,
                        )

                    // This is the exact regression class found in V0.1.7's review round
                    // (Secp256k1.verify throwing on right-length-but-malformed input) and fixed at
                    // the root in Secp256k1PublicKey.verify. This assertion pins that the mail
                    // path inherits that fix rather than re-introducing an unguarded call site.
                    MessageEnvelope.verify(degenerate) shouldBe false

                    val envelopeBytes = MessageEnvelopeCodec.encode(degenerate)
                    val frameBytes = MailFrameCodec.encode(envelopeBytes, bodyBytes)
                    val index = InboxIndex()

                    val result = InboxGossip.onGossipMessage(frameBytes, from, storage, index, recipient)

                    result shouldBe ValidationResult.Invalid
                }
            } finally {
                node.stop()
            }
        }

        test("(f) reserved encryption modes are rejected outright at all three layers") {
            // Layer 1: the constructor.
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.create(sender, listOf(recipient), testCid(1), encryption = EncryptionMode.HYBRID_ECIES)
            }
            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.create(sender, listOf(recipient), testCid(1), encryption = EncryptionMode.MLS_ARCHIVE)
            }

            // Layer 2: the decoder. Flip an otherwise-valid envelope's encryption byte in place.
            val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(1))
            val bytes = MessageEnvelopeCodec.encode(envelope)
            val encryptionByteOffset = 4 + 1 + 1 + 33 + 2 + 33 * 1 + 8

            val hybridBytes = bytes.copyOf()
            hybridBytes[encryptionByteOffset] = EncryptionMode.HYBRID_ECIES.wireValue
            val hybridException =
                shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(hybridBytes) }
            hybridException.message?.contains("reserved") shouldBe true

            val mlsBytes = bytes.copyOf()
            mlsBytes[encryptionByteOffset] = EncryptionMode.MLS_ARCHIVE.wireValue
            val mlsException = shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(mlsBytes) }
            mlsException.message?.contains("reserved") shouldBe true

            // Layer 3: the validator. Wrapped in a frame, decode() throws before onGossipMessage
            // ever reaches its own belt-and-braces encryption check - both layers are exercised by
            // construction here, since decode() is the very first thing onGossipMessage does after
            // MailFrameCodec.decode().
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-abuse-f"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val bodyBytes = encodedBody()

                listOf(hybridBytes, mlsBytes).forEach { tamperedEnvelopeBytes ->
                    val frameBytes = MailFrameCodec.encode(tamperedEnvelopeBytes, bodyBytes)
                    val index = InboxIndex()

                    val result = InboxGossip.onGossipMessage(frameBytes, from, storage, index, recipient)

                    result shouldBe ValidationResult.Invalid
                    index.latest() shouldBe emptyList()
                }

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage = NabuStorage.attach(mintingNode, Files.createTempDirectory("mail-abuse-f-mint"))
                    storage.get(mintingStorage.put(bodyBytes)) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }
    })
