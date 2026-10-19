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
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files

private class Fixture(
    val sender: Secp256k1KeyPair,
    val recipients: List<Secp256k1PublicKey>,
) {
    val body = MessageBodyCodec.encode(MessageBody(subject = "s", body = "b"))
    val cid = MessageBodyCodec.cidFor(body)
    val envelope = MessageEnvelope.create(sender, recipients, cid)
    val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
    val frame = MailFrameCodec.encode(envelopeBytes, body)
}

/**
 * V0.9.14: [InboxGossip.onGossipMessage] was split into [InboxGossip.checkEnvelope] and
 * [InboxGossip.ingestChecked] so that the DHT fetcher shares the checks. This pins that the gossip validator
 * decides exactly as before over the whole matrix (the older suites stay unchanged and green as well), that the
 * order of cheap checks is preserved, and that the DHT entry points decide like the gossip path.
 */
class InboxGossipRefactorEquivalenceTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val local = identity.secp256k1KeyPair.publicKey
        val node = LapisNode.create(identity)
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("inbox-equivalence"))
        val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

        afterSpec { runCatching { node.stop() } }

        fun gossip(
            bytes: ByteArray,
            index: InboxIndex = InboxIndex(),
            acceptance: MailAcceptanceCheck? = null,
        ) = InboxGossip.onGossipMessage(bytes, from, storage, index, local, acceptance)

        test("the validator matrix gives the established results") {
            val sender = Secp256k1KeyPair.generate()
            val good = Fixture(sender, listOf(local))
            gossip(good.frame) shouldBe ValidationResult.Valid

            gossip(ByteArray(10) { 1 }) shouldBe ValidationResult.Invalid // malformed frame
            gossip(MailFrameCodec.encode(ByteArray(40) { 2 }, good.body)) shouldBe ValidationResult.Invalid // envelope

            val notForUs = Fixture(sender, listOf(Secp256k1KeyPair.generate().publicKey))
            gossip(notForUs.frame) shouldBe ValidationResult.Invalid

            val badSignature = good.envelopeBytes.copyOf()
            badSignature[badSignature.size - 1] = (badSignature[badSignature.size - 1].toInt() xor 1).toByte()
            gossip(MailFrameCodec.encode(badSignature, good.body)) shouldBe ValidationResult.Invalid

            val otherBody = MessageBodyCodec.encode(MessageBody(subject = "other", body = "other"))
            // CID mismatch
            gossip(MailFrameCodec.encode(good.envelopeBytes, otherBody)) shouldBe ValidationResult.Invalid

            val index = InboxIndex()
            gossip(good.frame, index) shouldBe ValidationResult.Valid
            gossip(good.frame, index) shouldBe ValidationResult.Invalid // duplicate
            index.latest().size shouldBe 1

            // a body that matches the CID but is not a body
            val garbage = ByteArray(30) { 9 }
            val garbageEnvelope =
                MessageEnvelopeCodec.encode(
                    MessageEnvelope.create(sender, listOf(local), MessageBodyCodec.cidFor(garbage)),
                )
            gossip(MailFrameCodec.encode(garbageEnvelope, garbage)) shouldBe ValidationResult.Invalid
        }

        test("a policy-rejected sender is declined; with no gate the deposit lookup is never invoked") {
            val sender = Secp256k1KeyPair.generate()
            val fixture = Fixture(sender, listOf(local))
            val gated =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            gossip(fixture.frame, acceptance = gated) shouldBe ValidationResult.Invalid

            var lookups = 0
            val acceptAll =
                MailAcceptanceCheck(
                    gates = MailAcceptancePolicy.ACCEPT_ALL,
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    depositLookup = {
                        lookups++
                        null
                    },
                )
            gossip(fixture.frame, acceptance = acceptAll) shouldBe ValidationResult.Valid
            lookups shouldBe 0
        }

        test("order of the cheap checks: a CID mismatch is decided before the policy is asked") {
            val sender = Secp256k1KeyPair.generate()
            val fixture = Fixture(sender, listOf(local))
            var lookups = 0
            val gated =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    depositLookup = {
                        lookups++
                        null
                    },
                )
            val otherBody = MessageBodyCodec.encode(MessageBody(subject = "x", body = "y"))
            gossip(MailFrameCodec.encode(fixture.envelopeBytes, otherBody), acceptance = gated) shouldBe
                ValidationResult.Invalid
            lookups shouldBe 0
            gossip(fixture.frame, acceptance = gated) shouldBe ValidationResult.Invalid
            lookups shouldBe 1 // now the policy was reached
        }

        test("checkEnvelope without a body decides like the gossip path up to the policy, and runs the policy") {
            val sender = Secp256k1KeyPair.generate()
            val fixture = Fixture(sender, listOf(local))
            (InboxGossip.checkEnvelope(fixture.envelopeBytes, local, null) is EnvelopeCheck.Passed) shouldBe true
            (InboxGossip.checkEnvelope(ByteArray(20), local, null) is EnvelopeCheck.Failed) shouldBe true
            val other = Fixture(sender, listOf(Secp256k1KeyPair.generate().publicKey))
            (InboxGossip.checkEnvelope(other.envelopeBytes, local, null) is EnvelopeCheck.Failed) shouldBe true
            val tampered = fixture.envelopeBytes.copyOf()
            tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
            (InboxGossip.checkEnvelope(tampered, local, null) is EnvelopeCheck.Failed) shouldBe true
            val gated =
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            (InboxGossip.checkEnvelope(fixture.envelopeBytes, local, gated) is EnvelopeCheck.Failed) shouldBe true
            // with the body given, a mismatching body fails at that step
            val otherBody = MessageBodyCodec.encode(MessageBody(subject = "x", body = "y"))
            (InboxGossip.checkEnvelope(fixture.envelopeBytes, local, null, otherBody) is EnvelopeCheck.Failed) shouldBe
                true
            (
                InboxGossip.checkEnvelope(
                    fixture.envelopeBytes,
                    local,
                    null,
                    fixture.body,
                ) is EnvelopeCheck.Passed
            ) shouldBe
                true
        }

        test("ingestChecked verifies the body CID itself unless told it was checked, decodes, dedups and indexes") {
            val sender = Secp256k1KeyPair.generate()
            val fixture = Fixture(sender, listOf(local))
            val index = InboxIndex()
            val otherBody = MessageBodyCodec.encode(MessageBody(subject = "x", body = "y"))
            InboxGossip.ingestChecked(
                fixture.envelope,
                fixture.envelopeBytes,
                otherBody,
                storage,
                index,
                "test",
            ) shouldBe
                InboxIngestOutcome.INVALID
            InboxGossip.ingestChecked(
                fixture.envelope,
                fixture.envelopeBytes,
                fixture.body,
                storage,
                index,
                "test",
            ) shouldBe
                InboxIngestOutcome.ACCEPTED
            InboxGossip.ingestChecked(
                fixture.envelope,
                fixture.envelopeBytes,
                fixture.body,
                storage,
                index,
                "test",
            ) shouldBe
                InboxIngestOutcome.DUPLICATE
            index.latest().size shouldBe 1
            val garbage = ByteArray(30) { 9 }
            val garbageEnvelope = MessageEnvelope.create(sender, listOf(local), MessageBodyCodec.cidFor(garbage))
            InboxGossip.ingestChecked(
                garbageEnvelope,
                MessageEnvelopeCodec.encode(garbageEnvelope),
                garbage,
                storage,
                index,
                "test",
            ) shouldBe InboxIngestOutcome.INVALID
        }

        test("an inbox instance applies its own policy and index to the DHT entry points") {
            val identity2 = DualKeyIdentity.generate()
            val pubsubNode = LapisNode.create(identity2)
            pubsubNode.start(bootstrapPeers = emptyList())
            try {
                val pubsub =
                    net.lapisphilosophorum.lapisnet.networking.GossipPubSub
                        .attach(pubsubNode)
                val localKey = identity2.secp256k1KeyPair.publicKey
                val gated =
                    MailAcceptanceCheck(
                        gates = listOf(MailAcceptanceGate.VeritasPath),
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                    )
                val inboxStorage = NabuStorage.attach(pubsubNode, Files.createTempDirectory("inbox-equivalence-2"))
                val sender = Secp256k1KeyPair.generate()
                val fixture = Fixture(sender, listOf(localKey))
                val open = InboxGossip.attach(pubsub, inboxStorage, localKey)
                (open.dhtCheckEnvelope(fixture.envelopeBytes) is EnvelopeCheck.Passed) shouldBe true
                open.alreadyHas(fixture.envelope) shouldBe false
                open.dhtIngest(fixture.envelope, fixture.envelopeBytes, fixture.body) shouldBe
                    InboxIngestOutcome.ACCEPTED
                open.alreadyHas(fixture.envelope) shouldBe true
                open.messages().size shouldBe 1
                open.stop()

                val closed = InboxGossip.attach(pubsub, inboxStorage, localKey, gated)
                (closed.dhtCheckEnvelope(fixture.envelopeBytes) is EnvelopeCheck.Failed) shouldBe true
                closed.stop()
                pubsub.stop()
            } finally {
                pubsubNode.stop()
            }
        }
    })
