package net.lapisphilosophorum.lapisnet.mail

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Chain
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.payment.Bolt11Invoice
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom

private fun encodedBody(seed: Int): ByteArray =
    MessageBodyCodec.encode(MessageBody(subject = "s$seed", body = "b$seed"))

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** Minimal BOLT-11 feature set every real invoice needs - see
 * [FirstContactDepositVerifierTest]'s identical fixture for the full reasoning (duplicated per this
 * codebase's established per-file test-fixture convention). */
private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

private fun signedInvoice(
    signerPrivateKeyBytes: ByteArray,
    paymentHash: ByteArray,
    amountMsat: Long,
    description: String,
): String =
    Bolt11Invoice
        .create(
            chain = Chain.Mainnet,
            amount = MilliSatoshi(amountMsat),
            paymentHash = ByteVector32(paymentHash),
            privateKey = PrivateKey(signerPrivateKeyBytes),
            description = Either.Left(description),
            minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
            features = INVOICE_FEATURES,
        ).write()

/**
 * Adversarial, real-node, real-gossip-validator spec for [MailAcceptancePolicy] wired into
 * [InboxGossip.onGossipMessage] - mirrors [MailEnvelopeAbuseTest]'s "real (never-connected)
 * [NabuStorage]/[InboxIndex], mint-CIDs-on-a-separate-node" technique, and V0.4's own self-link
 * Sybil-resistance regression test
 * (`net.lapisphilosophorum.lapisnet.browser.BrowserApiRoutingTest`'s "a self-link from an
 * untrusted identity grants no credibility to the local viewer"), applied here against the mail
 * acceptance path specifically.
 */
class MailSpamResistanceTest :
    FunSpec({
        test(
            "a flood of 1,000 distinct unknown senders is entirely rejected before persistence, " +
                "one Veritas-linked sender still gets through",
        ) {
            val identity = DualKeyIdentity.generate()
            val localIdentity = identity.secp256k1KeyPair.publicKey
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-spam-flood"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val legitSender = Secp256k1KeyPair.generate()
                val trustGraph =
                    TrustGraph.fromEdges(listOf(Triple(localIdentity, legitSender.publicKey, MAX_TRUST_MICROS)))
                val acceptance =
                    MailAcceptanceCheck(
                        gates = listOf(MailAcceptanceGate.VeritasPath),
                        trustGraph = trustGraph,
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                    )

                val floodSize = 1_000
                val mintedBodies = mutableListOf<ByteArray>()
                val mintedEnvelopeBytes = mutableListOf<ByteArray>()

                repeat(floodSize) { i ->
                    val sender = Secp256k1KeyPair.generate()
                    val bodyBytes = encodedBody(i)
                    val contentCid = MessageBodyCodec.cidFor(bodyBytes)
                    val envelope = MessageEnvelope.create(sender, listOf(localIdentity), contentCid)
                    val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
                    val frameBytes = MailFrameCodec.encode(envelopeBytes, bodyBytes)

                    val result =
                        InboxGossip.onGossipMessage(frameBytes, from, storage, index, localIdentity, acceptance)

                    result shouldBe ValidationResult.Invalid
                    if (i < 5) {
                        mintedBodies += bodyBytes
                        mintedEnvelopeBytes += envelopeBytes
                    }
                }

                // The one Veritas-linked sender among the flood still gets through.
                val legitBodyBytes = encodedBody(-1)
                val legitContentCid = MessageBodyCodec.cidFor(legitBodyBytes)
                val legitEnvelope = MessageEnvelope.create(legitSender, listOf(localIdentity), legitContentCid)
                val legitFrame = MailFrameCodec.encode(MessageEnvelopeCodec.encode(legitEnvelope), legitBodyBytes)

                val legitResult =
                    InboxGossip.onGossipMessage(legitFrame, from, storage, index, localIdentity, acceptance)

                legitResult shouldBe ValidationResult.Valid
                index.latest() shouldHaveSize 1
                index
                    .latest()
                    .single()
                    .envelope.sender shouldBe legitSender.publicKey

                // None of the 1,000 rejected flood envelopes were ever persisted - proven, for a
                // representative sample, via the same "mint CIDs on a separate, never-connected
                // node, confirm the node-under-test's storage has neither" technique
                // MailEnvelopeAbuseTest established (checking all 1,000 individually would be
                // redundant: onGossipMessage's acceptance-policy rejection returns before the
                // persistence code path is ever reached, uniformly, for every rejected case).
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(mintingNode, Files.createTempDirectory("mail-spam-flood-mint"))
                    mintedBodies.forEach { body -> storage.get(mintingStorage.put(body)) shouldBe null }
                    mintedEnvelopeBytes.forEach { bytes -> storage.get(mintingStorage.put(bytes)) shouldBe null }
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("a self-link cannot manufacture a fake Veritas path to bypass the mail acceptance filter") {
            val identity = DualKeyIdentity.generate()
            val localIdentity = identity.secp256k1KeyPair.publicKey
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-spam-selflink"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                // X and Y are both strangers to the local identity - nobody has ever granted
                // either of them any trust from the local viewer's point of view.
                val identityX = Secp256k1KeyPair.generate()
                val identityY = Secp256k1KeyPair.generate()

                // X self-links to Y at full trust - a REAL, validly-signed VeritasGrant, resolved
                // through the exact same TrustGraph.fromGrants path a real deployment would use.
                // Mirrors V0.4's BrowserApiRoutingTest "a self-link from an untrusted identity
                // grants no credibility to the local viewer" regression exactly, applied to the
                // mail acceptance path.
                val selfLinkXtoY =
                    VeritasGrant.create(
                        truster = identityX,
                        target = identityY.publicKey,
                        trustMicros = MAX_TRUST_MICROS,
                        comment = "self-link: attacker-controlled",
                    )
                val trustGraph = TrustGraph.fromGrants(listOf(selfLinkXtoY))

                // Sanity: the local identity genuinely has no path to Y through this graph.
                MailAcceptancePolicy.veritasPathCheck(trustGraph, localIdentity)(identityY.publicKey) shouldBe false

                val acceptance =
                    MailAcceptanceCheck(
                        gates = listOf(MailAcceptanceGate.VeritasPath),
                        trustGraph = trustGraph,
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                    )

                val bodyBytes = encodedBody(0)
                val contentCid = MessageBodyCodec.cidFor(bodyBytes)
                val envelopeFromY = MessageEnvelope.create(identityY, listOf(localIdentity), contentCid)
                val frame = MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelopeFromY), bodyBytes)

                val result = InboxGossip.onGossipMessage(frame, from, storage, index, localIdentity, acceptance)

                result shouldBe ValidationResult.Invalid
                index.latest() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test(
            "a single valid deposit does not admit a second, different message " +
                "(replay-prevention at gossip-integration level)",
        ) {
            val identity = DualKeyIdentity.generate()
            val localIdentity = identity.secp256k1KeyPair.publicKey
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-spam-deposit-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val bodyA = encodedBody(1)
                val contentCidA = MessageBodyCodec.cidFor(bodyA)
                val envelopeA = MessageEnvelope.create(sender, listOf(localIdentity), contentCidA)

                val amountMsat = 2_000_000L
                val preimage = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val paymentHash = sha256(preimage)
                val memoForA =
                    FirstContactDepositVerifier.canonicalMemo(envelopeA.contentId(), sender.publicKey, localIdentity)
                val invoice =
                    signedInvoice(identity.secp256k1KeyPair.privateKey.bytes, paymentHash, amountMsat, memoForA)
                val deposit = FirstContactDeposit(preimage, paymentHash, invoice, amountMsat)

                // A naive/attacker-controlled application layer that hands out the SAME deposit for
                // every envelope from this sender, regardless of content - exactly the replay this
                // memo binding must stop.
                val depositLookup: (MessageEnvelope) -> FirstContactDeposit? = { deposit }
                val acceptance =
                    MailAcceptanceCheck(
                        gates = listOf(MailAcceptanceGate.VeritasPath),
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                        depositLookup = depositLookup,
                    )

                val frameA = MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelopeA), bodyA)
                val resultA = InboxGossip.onGossipMessage(frameA, from, storage, index, localIdentity, acceptance)
                resultA shouldBe ValidationResult.Valid

                // Envelope B: same sender, same recipient, DIFFERENT content - the SAME deposit
                // object is presented again via depositLookup.
                val bodyB = encodedBody(2)
                val contentCidB = MessageBodyCodec.cidFor(bodyB)
                val envelopeB = MessageEnvelope.create(sender, listOf(localIdentity), contentCidB)
                val frameB = MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelopeB), bodyB)

                val resultB = InboxGossip.onGossipMessage(frameB, from, storage, index, localIdentity, acceptance)

                resultB shouldBe ValidationResult.Invalid
                index.latest() shouldHaveSize 1
                index
                    .latest()
                    .single()
                    .envelope.contentCid shouldBe contentCidA
            } finally {
                node.stop()
            }
        }

        // --- ROUND-1 SECURITY AUDIT REGRESSION -----------------------------------------------------
        // Empirically demonstrated in the round-1 audit: N envelopes sharing ONE contentCid but
        // differing only in sentAtEpochSecond used to share the SAME memo (canonicalMemo bound only
        // contentCid/sender/recipient) yet have N DISTINCT contentIds (the inbox dedup key hashes the
        // full encoded envelope). A single paid deposit therefore admitted all N - the auditor's probe
        // fed 50 such envelopes through this exact real InboxGossip/NabuStorage path and got
        // "accepted = 50 of 50". This test pins the fix at the gossip-integration level: only the
        // FIRST of many sentAtEpochSecond-only variants is ever accepted for one deposit.
        test(
            "a single valid deposit does not admit N replays of the same body differing only in " +
                "sentAtEpochSecond (gossip-integration level)",
        ) {
            val identity = DualKeyIdentity.generate()
            val localIdentity = identity.secp256k1KeyPair.publicKey
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-spam-sentat-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = InboxIndex()

                val sender = Secp256k1KeyPair.generate()
                val body = encodedBody(1)
                val contentCid = MessageBodyCodec.cidFor(body)
                val baseEnvelope = MessageEnvelope.create(sender, listOf(localIdentity), contentCid)

                val amountMsat = 2_000_000L
                val preimage = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val paymentHash = sha256(preimage)
                val memo =
                    FirstContactDepositVerifier.canonicalMemo(baseEnvelope.contentId(), sender.publicKey, localIdentity)
                val invoice =
                    signedInvoice(identity.secp256k1KeyPair.privateKey.bytes, paymentHash, amountMsat, memo)
                val deposit = FirstContactDeposit(preimage, paymentHash, invoice, amountMsat)
                val depositLookup: (MessageEnvelope) -> FirstContactDeposit? = { deposit }
                val acceptance =
                    MailAcceptanceCheck(
                        gates = listOf(MailAcceptanceGate.VeritasPath),
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                        depositLookup = depositLookup,
                    )

                // Gossip the exact envelope the deposit's memo was bound to first - it must be
                // accepted (sanity: the deposit is genuinely valid for it).
                val baseFrame = MailFrameCodec.encode(MessageEnvelopeCodec.encode(baseEnvelope), body)
                val baseResult = InboxGossip.onGossipMessage(baseFrame, from, storage, index, localIdentity, acceptance)
                baseResult shouldBe ValidationResult.Valid

                // Now replay the SAME deposit (via the same depositLookup) against 49 further
                // envelopes - same sender/recipient/body (same contentCid, same memo-eligible triple
                // under the OLD, broken binding), each differing from the base ONLY in
                // sentAtEpochSecond. Every one of these has its own distinct contentId (the inbox
                // dedup key), so pre-fix every one of them independently passed `index.canAccept` and
                // was admitted - the auditor's probe measured exactly this and got "accepted = 50 of
                // 50". Post-fix, none of them match the deposit's envelope-contentId-bound memo.
                var replayAcceptedCount = 0
                repeat(49) { i ->
                    val variantEnvelope =
                        MessageEnvelope.create(
                            sender,
                            listOf(localIdentity),
                            contentCid,
                            sentAtEpochSecond = baseEnvelope.sentAtEpochSecond + i + 1,
                        )
                    val frame = MailFrameCodec.encode(MessageEnvelopeCodec.encode(variantEnvelope), body)
                    val result = InboxGossip.onGossipMessage(frame, from, storage, index, localIdentity, acceptance)
                    if (result == ValidationResult.Valid) replayAcceptedCount++
                }

                // Pre-fix this was `49` (all of them). Post-fix: none.
                replayAcceptedCount shouldBe 0
                index.latest() shouldHaveSize 1
            } finally {
                node.stop()
            }
        }
    })
