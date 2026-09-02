package net.lapisphilosophorum.lapisnet.dm

private const val DM_DEPOSIT_PREIMAGE_SIZE = 32
private const val DM_DEPOSIT_PAYMENT_HASH_SIZE = 32

/**
 * A structural claim that a sender paid a real Lightning Network payment to earn a first-contact
 * exception into a gated recipient's DM offline-mailbox pre-check (see [DmAcceptancePolicy] and
 * `docs/architecture.adoc`'s "two acceptance gates" section). Structurally near-identical to
 * `lapis-net-mail`'s `FirstContactDeposit` (V0.9.4) - a deliberately separate type, not a reuse of
 * it: this deposit is bound to a DM SESSION (via [DmDepositBinding]'s X3DH ephemeral key), not to a
 * single mail envelope's content id - see [DmFirstContactDepositVerifier]'s own class doc comment
 * for why a per-session binding, not a per-message one, is the correct shape for a ratchet-based
 * conversation.
 *
 * This class validates SHAPE ONLY - it never verifies the cryptography. That is entirely
 * [DmFirstContactDepositVerifier.verify]'s job.
 */
class DmFirstContactDeposit(
    preimage: ByteArray,
    paymentHash: ByteArray,
    val signedInvoice: String,
    val requiredAmountMsat: Long,
) {
    private val storedPreimage: ByteArray = preimage.copyOf()

    /** Returns a fresh copy on every access. */
    val preimage: ByteArray get() = storedPreimage.copyOf()

    private val storedPaymentHash: ByteArray = paymentHash.copyOf()

    /** Returns a fresh copy on every access. */
    val paymentHash: ByteArray get() = storedPaymentHash.copyOf()

    init {
        require(storedPreimage.size == DM_DEPOSIT_PREIMAGE_SIZE) {
            "preimage must be exactly $DM_DEPOSIT_PREIMAGE_SIZE bytes"
        }
        require(storedPaymentHash.size == DM_DEPOSIT_PAYMENT_HASH_SIZE) {
            "paymentHash must be exactly $DM_DEPOSIT_PAYMENT_HASH_SIZE bytes"
        }
        val invoiceBytes = signedInvoice.toByteArray(Charsets.US_ASCII).size
        require(invoiceBytes in 1..DmContentCodec.MAX_SIGNED_INVOICE_BYTES) {
            "signedInvoice must be 1..${DmContentCodec.MAX_SIGNED_INVOICE_BYTES} US-ASCII bytes, was $invoiceBytes"
        }
        require(requiredAmountMsat > 0) { "requiredAmountMsat must be positive, was $requiredAmountMsat" }
    }

    override fun equals(other: Any?): Boolean =
        other is DmFirstContactDeposit &&
            storedPreimage.contentEquals(other.storedPreimage) &&
            storedPaymentHash.contentEquals(other.storedPaymentHash) &&
            signedInvoice == other.signedInvoice &&
            requiredAmountMsat == other.requiredAmountMsat

    override fun hashCode(): Int {
        var result = storedPreimage.contentHashCode()
        result = 31 * result + storedPaymentHash.contentHashCode()
        result = 31 * result + signedInvoice.hashCode()
        result = 31 * result + requiredAmountMsat.hashCode()
        return result
    }

    override fun toString(): String =
        "DmFirstContactDeposit(signedInvoice.length=${signedInvoice.length}, requiredAmountMsat=$requiredAmountMsat)"

    companion object {
        const val PREIMAGE_SIZE = DM_DEPOSIT_PREIMAGE_SIZE
        const val PAYMENT_HASH_SIZE = DM_DEPOSIT_PAYMENT_HASH_SIZE
    }
}
