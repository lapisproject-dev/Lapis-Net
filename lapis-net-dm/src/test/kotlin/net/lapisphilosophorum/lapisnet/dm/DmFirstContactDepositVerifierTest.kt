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

private fun signedInvoice(
    signerPrivateKeyBytes: ByteArray,
    paymentHash: ByteArray,
    amountMsat: Long?,
    description: Either<String, ByteVector32>,
): String =
    Bolt11Invoice
        .create(
            chain = Chain.Mainnet,
            amount = amountMsat?.let { MilliSatoshi(it) },
            paymentHash = ByteVector32(paymentHash),
            privateKey = PrivateKey(signerPrivateKeyBytes),
            description = description,
            minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
            features = INVOICE_FEATURES,
        ).write()

/** Mirrors `lapis-net-mail`'s `FirstContactDepositVerifierTest.ValidTuple` - the SAME 32-byte
 * secp256k1 scalar is used as both the Lapis [recipient] keypair and the ACINQ signing key, so
 * `invoice.nodeId == recipient` holds. */
private class ValidTuple {
    val initiator: Secp256k1KeyPair = Secp256k1KeyPair.generate()
    val recipient: Secp256k1KeyPair = Secp256k1KeyPair.generate()
    val ephemeral: X25519KeyPair = X25519KeyPair.generate()
    val binding =
        DmDepositBinding(
            x3dhEphemeralPublicKey = ephemeral.publicKey,
            initiatorIdentity = initiator.publicKey,
            recipientIdentity = recipient.publicKey,
        )
    val amountMsat: Long = 1_000_000L
    val preimage: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val paymentHash: ByteArray = sha256(preimage)
    val memo: String = DmFirstContactDepositVerifier.canonicalMemo(binding)
    val invoice: String =
        signedInvoice(recipient.privateKey.bytes, paymentHash, amountMsat, Either.Left(memo))
    val deposit: DmFirstContactDeposit = DmFirstContactDeposit(preimage, paymentHash, invoice, amountMsat)
}

class DmFirstContactDepositVerifierTest :
    FunSpec({
        test("a fully valid tuple verifies true") {
            val tuple = ValidTuple()
            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, tuple.deposit) shouldBe true
        }

        test("transplanting a genuine deposit into a DIFFERENT session (different ephemeral key) is rejected") {
            val tuple = ValidTuple()
            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, tuple.deposit) shouldBe true

            val otherBinding =
                DmDepositBinding(
                    x3dhEphemeralPublicKey = X25519KeyPair.generate().publicKey,
                    initiatorIdentity = tuple.initiator.publicKey,
                    recipientIdentity = tuple.recipient.publicKey,
                )
            DmFirstContactDepositVerifier.verify(otherBinding, tuple.recipient.publicKey, tuple.deposit) shouldBe false
        }

        test("a wrong nodeId (invoice signed by someone other than recipient) is rejected") {
            val tuple = ValidTuple()
            val otherKey = Secp256k1KeyPair.generate()
            val wrongSignerInvoice =
                signedInvoice(otherKey.privateKey.bytes, tuple.paymentHash, tuple.amountMsat, Either.Left(tuple.memo))
            val deposit = DmFirstContactDeposit(tuple.preimage, tuple.paymentHash, wrongSignerInvoice, tuple.amountMsat)

            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("an amount mismatch between deposit and invoice is rejected") {
            val tuple = ValidTuple()
            val deposit = DmFirstContactDeposit(tuple.preimage, tuple.paymentHash, tuple.invoice, tuple.amountMsat + 1)
            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("a preimage/paymentHash mismatch is rejected") {
            val tuple = ValidTuple()
            val corrupt = tuple.preimage.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val deposit = DmFirstContactDeposit(corrupt, tuple.paymentHash, tuple.invoice, tuple.amountMsat)
            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("a descriptionHash-only invoice is rejected") {
            val tuple = ValidTuple()
            val hashInvoice =
                signedInvoice(
                    tuple.recipient.privateKey.bytes,
                    tuple.paymentHash,
                    tuple.amountMsat,
                    Either.Right(ByteVector32(sha256(tuple.memo.toByteArray(Charsets.UTF_8)))),
                )
            val deposit = DmFirstContactDeposit(tuple.preimage, tuple.paymentHash, hashInvoice, tuple.amountMsat)
            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("garbage invoice bytes are rejected, never thrown") {
            val tuple = ValidTuple()
            val deposit = DmFirstContactDeposit(tuple.preimage, tuple.paymentHash, "not-an-invoice", tuple.amountMsat)
            DmFirstContactDepositVerifier.verify(tuple.binding, tuple.recipient.publicKey, deposit) shouldBe false
        }
    })
