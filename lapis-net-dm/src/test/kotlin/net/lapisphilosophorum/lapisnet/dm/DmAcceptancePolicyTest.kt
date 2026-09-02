package net.lapisphilosophorum.lapisnet.dm

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
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import java.security.MessageDigest
import java.security.SecureRandom

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

private fun validDepositFor(
    recipient: Secp256k1KeyPair,
    initiator: Secp256k1KeyPair,
    amountMsat: Long = 1_000_000L,
): Pair<DmFirstContactDeposit, DmDepositBinding> {
    val binding =
        DmDepositBinding(X25519KeyPair.generate().publicKey, initiator.publicKey, recipient.publicKey)
    val preimage = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val paymentHash = sha256(preimage)
    val memo = DmFirstContactDepositVerifier.canonicalMemo(binding)
    val invoice =
        Bolt11Invoice
            .create(
                chain = Chain.Mainnet,
                amount = MilliSatoshi(amountMsat),
                paymentHash = ByteVector32(paymentHash),
                privateKey = PrivateKey(recipient.privateKey.bytes),
                description = Either.Left(memo),
                minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
                features = INVOICE_FEATURES,
            ).write()
    return DmFirstContactDeposit(preimage, paymentHash, invoice, amountMsat) to binding
}

class DmAcceptancePolicyTest :
    FunSpec({
        val sender = Secp256k1KeyPair.generate()
        val recipient = Secp256k1KeyPair.generate()

        test("ACCEPT_ALL (empty gates) accepts unconditionally, both directions") {
            DmAcceptancePolicy.shouldFetch(
                sender.publicKey,
                recipient.publicKey,
                DmAcceptancePolicy.ACCEPT_ALL,
                hasVeritasPath = { false },
                karmaScoreOf = KarmaScoreLookup { 0.0 },
            ) shouldBe DmAcceptanceDecision.Accept
            DmAcceptancePolicy.classifyDelivered(
                sender.publicKey,
                recipient.publicKey,
                DmAcceptancePolicy.ACCEPT_ALL,
                hasVeritasPath = { false },
                karmaScoreOf = KarmaScoreLookup { 0.0 },
            ) shouldBe DmAcceptanceDecision.Accept
        }

        test("VeritasPath gate: passes when hasVeritasPath returns true") {
            DmAcceptancePolicy.classifyDelivered(
                sender.publicKey,
                recipient.publicKey,
                listOf(AcceptanceGate.VeritasPath),
                hasVeritasPath = { true },
                karmaScoreOf = KarmaScoreLookup { 0.0 },
            ) shouldBe DmAcceptanceDecision.Accept
        }

        test("KarmaThreshold gate: passes at or above the threshold") {
            DmAcceptancePolicy.classifyDelivered(
                sender.publicKey,
                recipient.publicKey,
                listOf(AcceptanceGate.KarmaThreshold(5.0)),
                hasVeritasPath = { false },
                karmaScoreOf = KarmaScoreLookup { 5.0 },
            ) shouldBe DmAcceptanceDecision.Accept
        }

        test("an accepted contact bypasses every configured gate") {
            DmAcceptancePolicy.classifyDelivered(
                sender.publicKey,
                recipient.publicKey,
                listOf(AcceptanceGate.VeritasPath),
                hasVeritasPath = { false },
                karmaScoreOf = KarmaScoreLookup { 0.0 },
                isAcceptedContact = { true },
            ) shouldBe DmAcceptanceDecision.Accept
        }

        test("a deposit at or above the floor that verifies bypasses every configured gate") {
            val (deposit, binding) = validDepositFor(recipient, sender)
            val decision =
                DmAcceptancePolicy.classifyDelivered(
                    sender.publicKey,
                    recipient.publicKey,
                    listOf(AcceptanceGate.VeritasPath),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    minDepositMsat = 1_000_000L,
                    deposit = deposit,
                    depositBinding = binding,
                )
            decision shouldBe DmAcceptanceDecision.Accept
        }

        test("a deposit below the floor does NOT bypass gates, even though it structurally verifies") {
            val (deposit, binding) = validDepositFor(recipient, sender, amountMsat = 500_000L)
            val decision =
                DmAcceptancePolicy.classifyDelivered(
                    sender.publicKey,
                    recipient.publicKey,
                    listOf(AcceptanceGate.VeritasPath),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    minDepositMsat = 1_000_000L,
                    deposit = deposit,
                    depositBinding = binding,
                )
            decision.shouldBeQuarantine()
        }

        test("a deposit whose binding.recipientIdentity does not match the LOCAL identity does NOT bypass gates") {
            // V0.8.6 hardening-pass finding regression test: an attacker mints their own binding +
            // invoice, self-issued to their OWN key as "recipient", and passes it to a node whose
            // real local identity is `recipient` (not the attacker). Before the fix this slipped
            // through because the function trusted `depositBinding.recipientIdentity` as-if it were
            // the caller's local identity; now the explicit `localRecipient` parameter must match.
            val attacker = Secp256k1KeyPair.generate()
            val (deposit, selfIssuedBinding) = validDepositFor(recipient = attacker, initiator = attacker)
            val decision =
                DmAcceptancePolicy.classifyDelivered(
                    sender = attacker.publicKey,
                    localRecipient = recipient.publicKey,
                    gates = listOf(AcceptanceGate.VeritasPath),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    minDepositMsat = 1_000_000L,
                    deposit = deposit,
                    depositBinding = selfIssuedBinding,
                )
            decision.shouldBeQuarantine()
        }

        test("classifyDelivered NEVER returns Reject, for every failing combination") {
            DmAcceptancePolicy
                .classifyDelivered(
                    sender.publicKey,
                    recipient.publicKey,
                    listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(10.0)),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                ).shouldBeQuarantine()
        }

        test("shouldFetch NEVER returns Quarantine, for every failing combination") {
            val decision =
                DmAcceptancePolicy.shouldFetch(
                    sender.publicKey,
                    recipient.publicKey,
                    listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(10.0)),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            decision shouldBe DmAcceptanceDecision.Reject((decision as DmAcceptanceDecision.Reject).reason)
        }

        test("shouldFetch: an accepted contact still bypasses gates") {
            DmAcceptancePolicy.shouldFetch(
                sender.publicKey,
                recipient.publicKey,
                listOf(AcceptanceGate.VeritasPath),
                hasVeritasPath = { false },
                karmaScoreOf = KarmaScoreLookup { 0.0 },
                isAcceptedContact = { true },
            ) shouldBe DmAcceptanceDecision.Accept
        }
    })

private fun DmAcceptanceDecision.shouldBeQuarantine() {
    (this is DmAcceptanceDecision.Quarantine) shouldBe true
}
