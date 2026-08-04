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
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.security.MessageDigest
import java.security.SecureRandom

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** Minimal BOLT-11 feature set every real invoice needs - see
 * [FirstContactDepositVerifierTest]'s identical fixture for the full reasoning (duplicated here
 * rather than shared, matching this codebase's established per-file test-fixture convention). */
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
 * Pure, no-network unit tests for [MailAcceptancePolicy] - mirrors
 * `net.lapisphilosophorum.lapisnet.madli.MadliRoutingPolicyTest`/`MadliReplicationPolicyTest`'s
 * shape: every case constructs its own [TrustGraph]/[KarmaScoreLookup] inputs directly, no gossip
 * or network machinery involved.
 */
class MailAcceptancePolicyTest :
    FunSpec({
        val localIdentity = Secp256k1KeyPair.generate().publicKey
        val recipient = localIdentity
        val zeroKarma = KarmaScoreLookup { 0.0 }

        fun envelopeFrom(sender: Secp256k1KeyPair): MessageEnvelope =
            MessageEnvelope.create(sender, listOf(recipient), testCid(1))

        test("no gates configured (ACCEPT_ALL) accepts a totally unknown sender") {
            val stranger = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = stranger.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(stranger),
                    hasVeritasPath = { false },
                    karmaScoreOf = zeroKarma,
                    gates = MailAcceptancePolicy.ACCEPT_ALL,
                )

            decision shouldBe MailAcceptanceDecision.Accept
        }

        test("Veritas gate on: a sender with no positive Veritas path is rejected") {
            val stranger = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = stranger.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(stranger),
                    hasVeritasPath = { false },
                    karmaScoreOf = zeroKarma,
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                )

            decision.shouldBeInstanceOf<MailAcceptanceDecision.Reject>()
        }

        test("Veritas gate on: a sender with a positive Veritas path is accepted") {
            val trusted = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = trusted.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(trusted),
                    hasVeritasPath = { true },
                    karmaScoreOf = zeroKarma,
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                )

            decision shouldBe MailAcceptanceDecision.Accept
        }

        test("veritasPathCheck: self always passes, even with an empty graph") {
            val emptyGraph = TrustGraph.fromEdges(emptyList())
            val check = MailAcceptancePolicy.veritasPathCheck(emptyGraph, localIdentity)

            check(localIdentity) shouldBe true
        }

        test("veritasPathCheck: a real multi-hop TrustGraph resolves a positive path") {
            val hop1 = Secp256k1KeyPair.generate().publicKey
            val target = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(localIdentity, hop1, MAX_TRUST_MICROS),
                        Triple(hop1, target, MAX_TRUST_MICROS),
                    ),
                )
            val check = MailAcceptancePolicy.veritasPathCheck(graph, localIdentity)

            check(target) shouldBe true
        }

        test("veritasPathCheck: an identity absent from the graph has no path") {
            val graph = TrustGraph.fromEdges(emptyList())
            val strangerKey = Secp256k1KeyPair.generate().publicKey
            val check = MailAcceptancePolicy.veritasPathCheck(graph, localIdentity)

            check(strangerKey) shouldBe false
        }

        // --- ROUND-1 SECURITY AUDIT REGRESSION -----------------------------------------------------
        // veritasPathCheck used to be `findPath(...) != null` - PATH EXISTENCE, not POSITIVE trust.
        // MIN_TRUST_MICROS (0) is both "default/no opinion" AND "the value used to revoke a prior
        // grant" (see VeritasGrant's doc comment), and TrustGraph.build admits zero-weight edges (only
        // self-edges are dropped). findPath happily returns a non-null, zero-score path for a
        // revoked/zero-weight edge, so the OLD check let a revoked direct edge - and any Sybil
        // identity reachable only through one zero-weight hop - straight through the gate. These two
        // tests pin the fix: trustMicros(...) > MIN_TRUST_MICROS correctly rejects both.
        test("veritasPathCheck: a revoked (zero-weight) direct edge does NOT pass the gate") {
            val revoked = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(localIdentity, revoked, MIN_TRUST_MICROS)))
            val check = MailAcceptancePolicy.veritasPathCheck(graph, localIdentity)

            check(revoked) shouldBe false
        }

        test("veritasPathCheck: a Sybil identity reachable only behind a zero-weight hop does NOT pass the gate") {
            val revokedHop = Secp256k1KeyPair.generate().publicKey
            val sybil = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(localIdentity, revokedHop, MIN_TRUST_MICROS),
                        Triple(revokedHop, sybil, MAX_TRUST_MICROS),
                    ),
                )
            val check = MailAcceptancePolicy.veritasPathCheck(graph, localIdentity)

            check(sybil) shouldBe false
        }

        test("Karma-threshold gate: a score exactly at the boundary is accepted") {
            val sender = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = sender.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(sender),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 5.0 },
                    gates = listOf(MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                )

            decision shouldBe MailAcceptanceDecision.Accept
        }

        test("Karma-threshold gate: a score just below the boundary is rejected") {
            val sender = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = sender.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(sender),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 4.999_999 },
                    gates = listOf(MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                )

            decision.shouldBeInstanceOf<MailAcceptanceDecision.Reject>()
        }

        test("Karma-threshold gate: a score comfortably above the boundary is accepted") {
            val sender = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = sender.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(sender),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 100.0 },
                    gates = listOf(MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                )

            decision shouldBe MailAcceptanceDecision.Accept
        }

        test("both gates configured: a sender failing Veritas but clearing Karma is still accepted (OR semantics)") {
            val sender = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = sender.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(sender),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 10.0 },
                    gates = listOf(MailAcceptanceGate.VeritasPath, MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                )

            decision shouldBe MailAcceptanceDecision.Accept
        }

        test("both gates configured: a sender failing BOTH is rejected") {
            val sender = Secp256k1KeyPair.generate()
            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = sender.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(sender),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    gates = listOf(MailAcceptanceGate.VeritasPath, MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                )

            decision.shouldBeInstanceOf<MailAcceptanceDecision.Reject>()
        }

        test("a totally unknown sender who fails every gate is admitted anyway by a valid, real deposit") {
            val stranger = Secp256k1KeyPair.generate()
            val bodyBytes = MessageBodyCodec.encode(MessageBody(subject = "s", body = "b"))
            val contentCid = MessageBodyCodec.cidFor(bodyBytes)
            val envelope = MessageEnvelope.create(stranger, listOf(recipient), contentCid)

            val recipientKeyPair = Secp256k1KeyPair.generate()
            val amountMsat = 3_000_000L
            val preimage = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val paymentHash = sha256(preimage)
            val memo =
                FirstContactDepositVerifier.canonicalMemo(
                    envelope.contentId(),
                    stranger.publicKey,
                    recipientKeyPair.publicKey,
                )
            val invoice = signedInvoice(recipientKeyPair.privateKey.bytes, paymentHash, amountMsat, memo)
            val deposit = FirstContactDeposit(preimage, paymentHash, invoice, amountMsat)

            // Sanity: without the deposit, every configured gate genuinely rejects this stranger.
            val withoutDeposit =
                MailAcceptancePolicy.shouldAccept(
                    sender = stranger.publicKey,
                    recipient = recipientKeyPair.publicKey,
                    envelope = envelope,
                    hasVeritasPath = { false },
                    karmaScoreOf = zeroKarma,
                    gates = listOf(MailAcceptanceGate.VeritasPath, MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                )
            withoutDeposit.shouldBeInstanceOf<MailAcceptanceDecision.Reject>()

            // With the same genuinely-verifying deposit attached, the same failing gates are
            // bypassed entirely.
            val withDeposit =
                MailAcceptancePolicy.shouldAccept(
                    sender = stranger.publicKey,
                    recipient = recipientKeyPair.publicKey,
                    envelope = envelope,
                    hasVeritasPath = { false },
                    karmaScoreOf = zeroKarma,
                    gates = listOf(MailAcceptanceGate.VeritasPath, MailAcceptanceGate.KarmaThreshold(minScore = 5.0)),
                    deposit = deposit,
                )
            withDeposit shouldBe MailAcceptanceDecision.Accept
        }

        test("a deposit that fails FirstContactDepositVerifier.verify does not bypass a failing gate") {
            val stranger = Secp256k1KeyPair.generate()
            val garbageDeposit =
                FirstContactDeposit(
                    preimage = ByteArray(32) { 1 },
                    paymentHash = ByteArray(32) { 2 },
                    signedInvoice = "not-a-real-invoice",
                    requiredAmountMsat = 1_000L,
                )

            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = stranger.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(stranger),
                    hasVeritasPath = { false },
                    karmaScoreOf = zeroKarma,
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    deposit = garbageDeposit,
                )

            decision.shouldBeInstanceOf<MailAcceptanceDecision.Reject>()
        }

        test("empty gates short-circuits even when a deposit is present and gates would have rejected") {
            val stranger = Secp256k1KeyPair.generate()
            val fakeDeposit =
                FirstContactDeposit(
                    preimage = ByteArray(32) { 1 },
                    paymentHash = ByteArray(32) { 2 },
                    signedInvoice = "irrelevant",
                    requiredAmountMsat = 1_000L,
                )

            val decision =
                MailAcceptancePolicy.shouldAccept(
                    sender = stranger.publicKey,
                    recipient = recipient,
                    envelope = envelopeFrom(stranger),
                    hasVeritasPath = { false },
                    karmaScoreOf = zeroKarma,
                    gates = MailAcceptancePolicy.ACCEPT_ALL,
                    deposit = fakeDeposit,
                )

            decision shouldBe MailAcceptanceDecision.Accept
        }
    })
