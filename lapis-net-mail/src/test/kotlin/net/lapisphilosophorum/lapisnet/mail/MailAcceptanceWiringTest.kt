package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGateEvaluator
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger

/** V0.9.17: contact bypass, reject listener, live policy replacement and gossip/DHT parity of the mail acceptance. */
class MailAcceptanceWiringTest :
    FunSpec({
        val me = Secp256k1KeyPair.generate().publicKey
        val zeroKarma = KarmaScoreLookup { 0.0 }

        fun frameAndEnvelope(
            sender: Secp256k1KeyPair,
            to: Secp256k1PublicKey = me,
        ): Triple<ByteArray, ByteArray, MessageEnvelope> {
            val bodyBytes = MessageBodyCodec.encode(MessageBody(subject = "s", body = "b"))
            val envelope = MessageEnvelope.create(sender, listOf(to), MessageBodyCodec.cidFor(bodyBytes))
            val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
            return Triple(MailFrameCodec.encode(envelopeBytes, bodyBytes), envelopeBytes, envelope)
        }

        fun check(
            gates: List<MailAcceptanceGate>,
            contacts: Set<Secp256k1PublicKey> = emptySet(),
            listener: MailRejectListener = MailRejectListener.NONE,
        ) = MailAcceptanceCheck(
            gates = gates,
            trustGraph = TrustGraph.fromEdges(emptyList()),
            karmaScoreOf = zeroKarma,
            isAcceptedContact = { it in contacts },
            rejectListener = listener,
        )

        test("policy: an accepted contact passes failing gates; empty gates never consult the contact lookup") {
            val sender = Secp256k1KeyPair.generate()
            val envelope = frameAndEnvelope(sender).third
            val lookups = AtomicInteger()
            val contact: (Secp256k1PublicKey) -> Boolean = {
                lookups.incrementAndGet()
                true
            }
            MailAcceptancePolicy.shouldAccept(
                me,
                envelope,
                { false },
                zeroKarma,
                listOf(MailAcceptanceGate.VeritasPath),
                isAcceptedContact = contact,
            ) shouldBe MailAcceptanceDecision.Accept
            lookups.get() shouldBe 1

            MailAcceptancePolicy.shouldAccept(
                me,
                envelope,
                { false },
                zeroKarma,
                MailAcceptancePolicy.ACCEPT_ALL,
                isAcceptedContact = contact,
            ) shouldBe MailAcceptanceDecision.Accept
            lookups.get() shouldBe 1
        }

        test("policy: a non-contact is rejected with the failed gates and the unchanged reason text") {
            val envelope = frameAndEnvelope(Secp256k1KeyPair.generate()).third
            val gates = listOf(MailAcceptanceGate.VeritasPath, MailAcceptanceGate.KarmaThreshold(3.0))
            val decision =
                MailAcceptancePolicy
                    .shouldAccept(me, envelope, { false }, zeroKarma, gates)
                    .shouldBeInstanceOf<MailAcceptanceDecision.Reject>()
            decision.failedGates shouldBe gates
            decision.reason shouldBe
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    envelope.sender,
                    listOf(
                        net.lapisphilosophorum.lapisnet.policy.AcceptanceGate.VeritasPath,
                        net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
                            .KarmaThreshold(3.0),
                    ),
                    { false },
                    net.lapisphilosophorum.lapisnet.policy
                        .KarmaScoreLookup { 0.0 },
                )
            decision.reason shouldBe "no Veritas path from local identity to sender; karma below threshold 3.0"

            val single =
                MailAcceptancePolicy.shouldAccept(me, envelope, { false }, zeroKarma, listOf(gates[0]))
            single.shouldBeInstanceOf<MailAcceptanceDecision.Reject>().failedGates shouldBe listOf(gates[0])
        }

        test("listener: called once per reject, never on accept, and a throwing listener cannot change the verdict") {
            val rejects = AtomicInteger()
            val sender = Secp256k1KeyPair.generate()
            val (_, envelopeBytes, _) = frameAndEnvelope(sender)
            val counting = check(listOf(MailAcceptanceGate.VeritasPath), listener = { rejects.incrementAndGet() })

            val r = InboxGossip.checkEnvelope(envelopeBytes, me, counting)
            r.shouldBeInstanceOf<EnvelopeCheck.Failed>()
            rejects.get() shouldBe 1

            val accepting =
                check(listOf(MailAcceptanceGate.VeritasPath), contacts = setOf(sender.publicKey), listener = {
                    rejects.incrementAndGet()
                })
            InboxGossip.checkEnvelope(envelopeBytes, me, accepting).shouldBeInstanceOf<EnvelopeCheck.Passed>()
            rejects.get() shouldBe 1

            val throwing = check(listOf(MailAcceptanceGate.VeritasPath), listener = { error("listener broke") })
            InboxGossip.checkEnvelope(envelopeBytes, me, throwing).shouldBeInstanceOf<EnvelopeCheck.Failed>()
        }

        test("tamper: a forged sender is stopped by the signature check before the contact bypass can apply") {
            val contact = Secp256k1KeyPair.generate()
            val attacker = Secp256k1KeyPair.generate()
            val rejects = AtomicInteger()
            val (_, _, genuine) = frameAndEnvelope(attacker)
            // Same signed fields, but claiming the contact as the sender.
            val forged =
                MessageEnvelope.fromDecoded(
                    sender = contact.publicKey,
                    recipients = genuine.recipients,
                    sentAtEpochSecond = genuine.sentAtEpochSecond,
                    encryption = genuine.encryption,
                    contentCid = genuine.contentCid,
                    replyTo = null,
                    threadRoot = null,
                    signature = genuine.signature,
                )
            val forgedBytes = MessageEnvelopeCodec.encode(forged)
            val c =
                check(listOf(MailAcceptanceGate.VeritasPath), contacts = setOf(contact.publicKey), listener = {
                    rejects.incrementAndGet()
                })
            val result = InboxGossip.checkEnvelope(forgedBytes, me, c).shouldBeInstanceOf<EnvelopeCheck.Failed>()
            result.reason shouldBe "signature invalid"
            rejects.get() shouldBe 0
        }

        test(
            "tamper: a contact listed only as recipient does not bypass; an envelope for someone else never reaches the policy",
        ) {
            val contact = Secp256k1KeyPair.generate()
            val stranger = Secp256k1KeyPair.generate()
            val rejects = AtomicInteger()
            val c =
                check(listOf(MailAcceptanceGate.VeritasPath), contacts = setOf(contact.publicKey), listener = {
                    rejects.incrementAndGet()
                })
            val (_, toContact, _) = frameAndEnvelope(stranger, to = me)
            InboxGossip.checkEnvelope(toContact, me, c).shouldBeInstanceOf<EnvelopeCheck.Failed>()
            rejects.get() shouldBe 1

            val (_, notForMe, _) = frameAndEnvelope(stranger, to = contact.publicKey)
            InboxGossip.checkEnvelope(notForMe, me, c).shouldBeInstanceOf<EnvelopeCheck.Failed>()
            rejects.get() shouldBe 1
        }

        test("parity: gossip and DHT entry decide identically, count identically, and follow updateAcceptanceCheck") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-acc-parity"))
                val pubsub = GossipPubSub.attach(node)
                val local = identity.secp256k1KeyPair.publicKey
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val inbox = InboxGossip.attach(pubsub, storage, local)
                val contactSender = Secp256k1KeyPair.generate()
                val strangerSender = Secp256k1KeyPair.generate()
                val rejects = AtomicInteger()

                fun both(sender: Secp256k1KeyPair): Pair<Boolean, Boolean> {
                    val (frame, envBytes, _) = frameAndEnvelope(sender, to = local)
                    val gossipOk =
                        InboxGossip.onGossipMessage(
                            frame,
                            from,
                            storage,
                            InboxIndex(),
                            local,
                            inbox.currentAcceptanceCheck(),
                        ) == ValidationResult.Valid
                    val dhtOk = inbox.dhtCheckEnvelope(envBytes) is EnvelopeCheck.Passed
                    return gossipOk to dhtOk
                }

                // no policy: everything passes on both paths
                inbox.currentAcceptanceCheck() shouldBe null
                both(strangerSender) shouldBe (true to true)

                val policy =
                    MailAcceptanceCheck(
                        gates = listOf(MailAcceptanceGate.VeritasPath),
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = zeroKarma,
                        isAcceptedContact = { it == contactSender.publicKey },
                        rejectListener = { rejects.incrementAndGet() },
                    )
                inbox.updateAcceptanceCheck(policy)
                (inbox.currentAcceptanceCheck() === policy) shouldBe true
                both(strangerSender) shouldBe (false to false)
                rejects.get() shouldBe 2
                both(contactSender) shouldBe (true to true)
                rejects.get() shouldBe 2

                inbox.updateAcceptanceCheck(null)
                both(strangerSender) shouldBe (true to true)
                inbox.stop()
                pubsub.stop()
                storage.stop()
            } finally {
                node.stop()
            }
        }
    })
