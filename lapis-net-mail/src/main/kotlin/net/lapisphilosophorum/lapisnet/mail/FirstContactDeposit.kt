package net.lapisphilosophorum.lapisnet.mail

/** Number of bytes in a BOLT-11 payment preimage / payment hash - identical to
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProof`'s own constants (duplicated locally
 * rather than reused: this module has no dependency on `lapis-net-virtus`, see
 * [FirstContactDepositVerifier]'s class doc comment for why). */
private const val DEPOSIT_PREIMAGE_SIZE = 32
private const val DEPOSIT_PAYMENT_HASH_SIZE = 32

/**
 * A structural claim that a sender paid a real Lightning Network payment - proven by
 * [FirstContactDeposit.preimage], whose `sha256(preimage)` equals
 * [FirstContactDeposit.paymentHash] - against [FirstContactDeposit.signedInvoice], a real, signed
 * BOLT-11 invoice string, to earn a first-contact exception past an untrusted-sender
 * [MailAcceptancePolicy] gate. Structurally near-identical to
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProof` (V0.6) - see that class's doc comment
 * for the precedent this mirrors - but a distinct type, not a reuse of it: a
 * [FirstContactDeposit] is presented alongside a [MessageEnvelope], not an `LtrRecord`, and its
 * anti-replay binding (see [FirstContactDepositVerifier.canonicalMemo]) is keyed off an
 * envelope's `(contentId, sender, recipient)` - the full envelope content id, not just the
 * message body's `contentCid` - not Virtus's `(cid, viewId)`.
 *
 * [requiredAmountMsat] is this claim's own analogue of `LtrRecord.initialValueMsat` - a
 * structurally-asserted amount, cross-checked against [signedInvoice]'s real embedded amount by
 * [FirstContactDepositVerifier.verify], never trusted on its own. A sender cannot claim to have
 * paid more (or less) than the invoice they actually settled.
 *
 * **This class validates SHAPE ONLY - it never verifies the cryptography.** Constructing a
 * [FirstContactDeposit] with well-formed fields proves nothing about whether `sha256(preimage)`
 * actually equals [paymentHash], whether [signedInvoice] is even parseable, or whether its
 * embedded signature is valid. That is entirely [FirstContactDepositVerifier.verify]'s job - see
 * [net.lapisphilosophorum.lapisnet.virtus.LightningProof]'s doc comment for why this "structural,
 * not verified" split is a deliberate, established discipline in this codebase, not an oversight.
 */
class FirstContactDeposit(
    preimage: ByteArray,
    paymentHash: ByteArray,
    signedInvoice: String,
    requiredAmountMsat: Long,
) {
    private val storedPreimage: ByteArray = preimage.copyOf()

    /** 32-byte payment preimage - public data once presented, not a secret. Returns a fresh copy
     * on every access. NOT checked against [paymentHash] here - see
     * [FirstContactDepositVerifier.verify]. */
    val preimage: ByteArray get() = storedPreimage.copyOf()

    private val storedPaymentHash: ByteArray = paymentHash.copyOf()

    /** 32-byte payment hash, also present (redundantly) inside [signedInvoice] itself - see
     * [FirstContactDepositVerifier.verify]'s consistency check between the two. Returns a fresh
     * copy on every access. */
    val paymentHash: ByteArray get() = storedPaymentHash.copyOf()

    /** A BOLT-11 bech32 invoice string (`"lnbc…"`/`"lntb…"`/`"lnbcrt…"`) - obtained out-of-band
     * from the recipient (see this module's scope-cut notes: nothing in this codebase issues or
     * pays a Lightning invoice), never re-derived or normalized here. */
    val signedInvoice: String = signedInvoice

    /** The amount, in millisatoshi, this deposit claims to have paid - cross-checked byte-for-byte
     * against [signedInvoice]'s own embedded amount by [FirstContactDepositVerifier.verify]. */
    val requiredAmountMsat: Long = requiredAmountMsat

    init {
        require(storedPreimage.size == DEPOSIT_PREIMAGE_SIZE) {
            "preimage must be exactly $DEPOSIT_PREIMAGE_SIZE bytes"
        }
        require(storedPaymentHash.size == DEPOSIT_PAYMENT_HASH_SIZE) {
            "paymentHash must be exactly $DEPOSIT_PAYMENT_HASH_SIZE bytes"
        }
        val invoiceBytes = signedInvoice.toByteArray(Charsets.US_ASCII).size
        require(invoiceBytes in 1..MAX_SIGNED_INVOICE_BYTES) {
            "signedInvoice must be 1..$MAX_SIGNED_INVOICE_BYTES US-ASCII bytes, was $invoiceBytes"
        }
        require(this.requiredAmountMsat > 0) {
            "requiredAmountMsat must be positive, was ${this.requiredAmountMsat}"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is FirstContactDeposit &&
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
        "FirstContactDeposit(preimage=${storedPreimage.toDepositHexPreview()}, " +
            "paymentHash=${storedPaymentHash.toDepositHexPreview()}, signedInvoice.length=${signedInvoice.length}, " +
            "requiredAmountMsat=$requiredAmountMsat)"

    companion object {
        /** See [DEPOSIT_PREIMAGE_SIZE]. Exposed publicly so callers don't need to hardcode `32`
         * independently. */
        const val PREIMAGE_SIZE = DEPOSIT_PREIMAGE_SIZE

        /** See [DEPOSIT_PAYMENT_HASH_SIZE]. */
        const val PAYMENT_HASH_SIZE = DEPOSIT_PAYMENT_HASH_SIZE

        /** Identical cap and reasoning to
         * `net.lapisphilosophorum.lapisnet.virtus.LightningProof.MAX_SIGNED_INVOICE_BYTES`: generous
         * enough for a real, heavily route-hinted BOLT-11 invoice while still bounding the field
         * before allocation. */
        const val MAX_SIGNED_INVOICE_BYTES = 2048
    }
}

/** Short, non-sensitive hex preview for [FirstContactDeposit.toString] - mirrors
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProof`'s file-local `toLightningHexPreview()`
 * (a private extension is not visible across files/modules, hence a separate, distinctly-named
 * copy here). A preimage/payment hash is public data once presented, not a secret, so this is
 * truncated purely to keep toString() output compact, not for secrecy. */
private fun ByteArray.toDepositHexPreview(): String = take(8).joinToString("") { "%02x".format(it) } + "…"
