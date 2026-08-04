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
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.security.MessageDigest
import java.security.SecureRandom

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun encodedBody(
    subject: String = "s",
    body: String = "b",
): ByteArray = MessageBodyCodec.encode(MessageBody(subject = subject, body = body))

/** Minimal BOLT-11 feature set every real invoice needs - mirrors
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifierTest`'s identical fixture (see
 * [Bolt11Invoice]'s own `init` block - both are required or the invoice fails to even construct). */
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
    expirySeconds: Long? = null,
    timestampSeconds: Long = System.currentTimeMillis() / 1000,
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
            expirySeconds = expirySeconds,
            timestampSeconds = timestampSeconds,
        ).write()

/**
 * A complete, real, in-process-generated valid [FirstContactDeposit] tuple, mirroring
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifierTest`'s `ValidTuple` - every
 * field's actual cryptography is real, nothing mocked or faked. The SAME 32-byte secp256k1 scalar
 * is deliberately used as both the Lapis [recipient] keypair and the ACINQ Lightning node private
 * key that signs [invoice] - this is what makes [FirstContactDepositVerifier]'s mandatory
 * recipient-binding check (`invoice.nodeId == recipient`) hold for this fixture.
 */
private class ValidTuple(
    envelopeSender: Secp256k1KeyPair = Secp256k1KeyPair.generate(),
    val bodyBytes: ByteArray = encodedBody(),
) {
    val sender: Secp256k1KeyPair = envelopeSender
    val recipient: Secp256k1KeyPair = Secp256k1KeyPair.generate()
    val contentCid: Cid = MessageBodyCodec.cidFor(bodyBytes)
    val envelope: MessageEnvelope = MessageEnvelope.create(sender, listOf(recipient.publicKey), contentCid)
    val amountMsat: Long = 5_000_000L
    val preimage: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val paymentHash: ByteArray = sha256(preimage)
    val memo: String =
        FirstContactDepositVerifier.canonicalMemo(envelope.contentId(), sender.publicKey, recipient.publicKey)

    val invoice: String =
        signedInvoice(
            signerPrivateKeyBytes = recipient.privateKey.bytes,
            paymentHash = paymentHash,
            amountMsat = amountMsat,
            description = Either.Left(memo),
        )

    val deposit: FirstContactDeposit =
        FirstContactDeposit(preimage, paymentHash, invoice, requiredAmountMsat = amountMsat)
}

class FirstContactDepositVerifierTest :
    FunSpec({
        test("a fully valid tuple verifies true") {
            val tuple = ValidTuple()

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, tuple.deposit) shouldBe true
        }

        test("a corrupted preimage (sha256 mismatch) is rejected") {
            val tuple = ValidTuple()
            val corruptPreimage = tuple.preimage.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val corruptDeposit =
                FirstContactDeposit(corruptPreimage, tuple.paymentHash, tuple.invoice, tuple.amountMsat)

            FirstContactDepositVerifier.verify(
                tuple.envelope,
                tuple.recipient.publicKey,
                corruptDeposit,
            ) shouldBe false
        }

        test("a wrong requiredAmountMsat (not matching the invoice's real amount) is rejected") {
            val tuple = ValidTuple()
            val wrongAmountDeposit =
                FirstContactDeposit(tuple.preimage, tuple.paymentHash, tuple.invoice, tuple.amountMsat + 1)

            FirstContactDepositVerifier.verify(
                tuple.envelope,
                tuple.recipient.publicKey,
                wrongAmountDeposit,
            ) shouldBe false
        }

        test("an invoice actually signed for a different amount than claimed is rejected") {
            val tuple = ValidTuple()
            val differentAmountInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat + 1,
                    description = Either.Left(tuple.memo),
                )
            val deposit =
                FirstContactDeposit(tuple.preimage, tuple.paymentHash, differentAmountInvoice, tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("an amountless invoice is rejected") {
            val tuple = ValidTuple()
            val amountlessInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = null,
                    description = Either.Left(tuple.memo),
                )
            val deposit = FirstContactDeposit(tuple.preimage, tuple.paymentHash, amountlessInvoice, tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("an invoice signed by a key other than the recipient's is rejected (recipient binding)") {
            val tuple = ValidTuple()
            val otherKey = Secp256k1KeyPair.generate()
            val wrongSignerInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = otherKey.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(tuple.memo),
                )
            val deposit = FirstContactDeposit(tuple.preimage, tuple.paymentHash, wrongSignerInvoice, tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("an invoice whose own embedded payment hash differs from the deposit's is rejected") {
            val tuple = ValidTuple()
            val otherPaymentHash = sha256(ByteArray(32) { (it + 9).toByte() })
            val invoiceWithDifferentHash =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = otherPaymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(tuple.memo),
                )
            // deposit still claims tuple.preimage/tuple.paymentHash - the invoice's OWN embedded
            // payment hash (otherPaymentHash) is what must mismatch here.
            val deposit =
                FirstContactDeposit(tuple.preimage, tuple.paymentHash, invoiceWithDifferentHash, tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("a garbage signedInvoice string is rejected, not thrown") {
            val tuple = ValidTuple()
            val deposit = FirstContactDeposit(tuple.preimage, tuple.paymentHash, "not-an-invoice", tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe false
        }

        test("an invoice using descriptionHash instead of description is rejected") {
            val tuple = ValidTuple()
            val descriptionHashInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Right(ByteVector32(sha256(tuple.memo.toByteArray(Charsets.UTF_8)))),
                )
            val deposit =
                FirstContactDeposit(tuple.preimage, tuple.paymentHash, descriptionHashInvoice, tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe false
        }

        // --- THE CENTRAL TEST: anti-replay memo binding is load-bearing ---------------------------
        // Proves a deposit valid for envelope A is rejected for a SECOND, DIFFERENT envelope B -
        // same sender, same recipient, DIFFERENT content - and that every other check the deposit
        // would otherwise pass (hash, signature, amount, recipient binding) genuinely still passes;
        // only the memo binding is what stops the replay. Mirrors V0.9.2's wrap-transplant test
        // rigor: first prove the deposit is genuinely valid for A, then prove the SAME deposit,
        // unmodified, fails for B, and confirm the reason is specifically the memo (by constructing
        // a THIRD invoice, re-signed for B's own canonical memo but otherwise identical, and showing
        // THAT one verifies true against B - isolating the memo as the sole differentiator).
        test("a valid deposit's memo, replayed against a second envelope with different content, is rejected") {
            val tuple = ValidTuple()
            // Sanity: the tuple's own deposit is genuinely valid for its own envelope.
            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, tuple.deposit) shouldBe true

            // Envelope B: same sender, same recipient, but DIFFERENT body content -> different
            // contentCid. Everything else about the deposit (preimage, paymentHash, invoice,
            // requiredAmountMsat) is left completely unchanged - the replay attempt is exactly
            // "present the same paid deposit against a different message".
            val differentBodyBytes = encodedBody(subject = "different", body = "a completely different message")
            val differentContentCid = MessageBodyCodec.cidFor(differentBodyBytes)
            val envelopeB =
                MessageEnvelope.create(tuple.sender, listOf(tuple.recipient.publicKey), differentContentCid)

            FirstContactDepositVerifier.verify(envelopeB, tuple.recipient.publicKey, tuple.deposit) shouldBe false

            // Isolate the memo as the SOLE differentiator: an invoice re-signed for B's own
            // canonical memo (same preimage/paymentHash/amount/signer otherwise) verifies true
            // against B - proving the hash/signature/amount/recipient checks were never the
            // obstacle, only the memo binding was.
            val memoForB =
                FirstContactDepositVerifier.canonicalMemo(
                    envelopeB.contentId(),
                    tuple.sender.publicKey,
                    tuple.recipient.publicKey,
                )
            val invoiceForB =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(memoForB),
                )
            val depositForB = FirstContactDeposit(tuple.preimage, tuple.paymentHash, invoiceForB, tuple.amountMsat)

            FirstContactDepositVerifier.verify(envelopeB, tuple.recipient.publicKey, depositForB) shouldBe true
        }

        // --- ROUND-1 SECURITY AUDIT REGRESSION -----------------------------------------------------
        // The memo used to bind only (contentCid, sender, recipient) - the BODY's content id, not
        // the ENVELOPE's. sentAtEpochSecond/replyTo/threadRoot/recipients are all signed but were
        // outside contentCid, while the inbox dedup key (MessageEnvelopeCodec.contentId(), via
        // InboxIndex.canAccept) hashes the FULL encoded envelope including those fields. So two
        // envelopes sharing one contentCid but differing only in sentAtEpochSecond used to share the
        // SAME memo yet have DISTINCT contentIds - one verified deposit admitted both. This proves
        // the fix: canonicalMemo is now keyed off envelope.contentId(), so varying ONLY
        // sentAtEpochSecond (same body, same sender, same recipient) already changes the required
        // memo and the replay is rejected.
        test(
            "a valid deposit's memo, replayed against a second envelope differing only in " +
                "sentAtEpochSecond (same contentCid), is rejected",
        ) {
            val tuple = ValidTuple()
            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, tuple.deposit) shouldBe true

            // Envelope B: identical sender/recipient/body (same contentCid) - ONLY
            // sentAtEpochSecond differs. Pre-fix this shared tuple.memo verbatim; that is exactly
            // the vulnerability.
            val envelopeB =
                MessageEnvelope.create(
                    tuple.sender,
                    listOf(tuple.recipient.publicKey),
                    tuple.contentCid,
                    sentAtEpochSecond = tuple.envelope.sentAtEpochSecond + 1,
                )
            envelopeB.contentCid shouldBe tuple.envelope.contentCid
            envelopeB.contentId().contentEquals(tuple.envelope.contentId()) shouldBe false

            FirstContactDepositVerifier.verify(envelopeB, tuple.recipient.publicKey, tuple.deposit) shouldBe false

            // Isolate the memo as the SOLE differentiator, exactly as the different-content test
            // does above: an invoice re-signed for B's own canonical memo verifies true against B.
            val memoForB =
                FirstContactDepositVerifier.canonicalMemo(
                    envelopeB.contentId(),
                    tuple.sender.publicKey,
                    tuple.recipient.publicKey,
                )
            val invoiceForB =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(memoForB),
                )
            val depositForB = FirstContactDeposit(tuple.preimage, tuple.paymentHash, invoiceForB, tuple.amountMsat)

            FirstContactDepositVerifier.verify(envelopeB, tuple.recipient.publicKey, depositForB) shouldBe true
        }

        test("a valid deposit's memo, replayed against a second envelope with a different recipient, is rejected") {
            val tuple = ValidTuple()
            val otherRecipient = Secp256k1KeyPair.generate()
            val envelopeToOtherRecipient =
                MessageEnvelope.create(tuple.sender, listOf(otherRecipient.publicKey), tuple.contentCid)

            // Same deposit, same content, same sender - only the recipient differs. The nodeId
            // check ALSO independently fails here (invoice.nodeId == tuple.recipient !=
            // otherRecipient), so this additionally exercises the mandatory recipient-binding
            // check, not just the memo.
            FirstContactDepositVerifier.verify(
                envelopeToOtherRecipient,
                otherRecipient.publicKey,
                tuple.deposit,
            ) shouldBe false
        }

        // Deliberate: expiry is NEVER checked - same choice V0.6's LightningProofVerifier.verify
        // documented and made, restated explicitly here rather than silently inherited.
        test("an already-expired invoice still verifies true") {
            val tuple = ValidTuple()
            val expiredInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.recipient.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(tuple.memo),
                    expirySeconds = 1L,
                    timestampSeconds = 1L,
                )
            val deposit = FirstContactDeposit(tuple.preimage, tuple.paymentHash, expiredInvoice, tuple.amountMsat)

            FirstContactDepositVerifier.verify(tuple.envelope, tuple.recipient.publicKey, deposit) shouldBe true
        }
    })
