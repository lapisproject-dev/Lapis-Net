package net.lapisphilosophorum.lapisnet.dm

import fr.acinq.lightning.payment.Bolt11Invoice
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

private const val DM_FIRST_CONTACT_MEMO_PREFIX = "lapisnet-dm-first-contact:v1:"

/**
 * The complete cryptographic verification chain for a [DmFirstContactDeposit] presented alongside a
 * [DmDepositBinding] - structurally near-identical to `lapis-net-mail`'s
 * `FirstContactDepositVerifier.verify` (see that object's class doc comment for the full six-step
 * shape this mirrors), deliberately reimplemented here rather than called through, mirroring that
 * object's own "sole consumer" `fr.acinq.*` confinement discipline.
 *
 * **Why bound to a SESSION, not a MESSAGE - unlike mail's identical-looking mechanism.** Mail binds
 * a deposit to one `MessageEnvelope`'s content id, because each mail message is its own independent,
 * separately-gated unit. A DM first-contact deposit instead buys entry into an entire RATCHET
 * SESSION - binding per-message would mean the sender pays again for every subsequent message in the
 * same conversation, which defeats the point of a ratchet stream. [canonicalMemo] therefore binds to
 * [DmDepositBinding.x3dhEphemeralPublicKey] - X3DH mints a fresh one per handshake attempt, so this
 * still closes exactly one session per deposit, never letting a single payment resurrect indefinitely
 * many sessions.
 */
object DmFirstContactDepositVerifier {
    /**
     * The canonical BOLT-11 `description` a [DmFirstContactDeposit]'s [DmFirstContactDeposit.signedInvoice]
     * must carry for [binding] - full (not fingerprint) hex encoding of every field, mirroring
     * `lapis-net-mail`'s `FirstContactDepositVerifier.canonicalMemo`'s exact convention.
     */
    fun canonicalMemo(binding: DmDepositBinding): String =
        DM_FIRST_CONTACT_MEMO_PREFIX +
            binding.x3dhEphemeralPublicKey.bytes.toDmDepositHex() + ":" +
            binding.initiatorIdentity.bytes.toDmDepositHex() + ":" +
            binding.recipientIdentity.bytes.toDmDepositHex()

    /**
     * The full verification chain for [deposit], presented alongside [binding] to earn a
     * first-contact exception into [recipient]'s DM acceptance policy. Returns `false` - never
     * throws - for any failure. Steps, all AND-ed (identical shape to `FirstContactDepositVerifier.
     * verify`):
     *  1. `sha256(deposit.preimage) == deposit.paymentHash`.
     *  2. [deposit]'s [DmFirstContactDeposit.signedInvoice] parses as a real, signature-valid BOLT-11
     *     invoice ([Bolt11Invoice.read] verifies the signature internally).
     *  3. The invoice's own parsed payment hash equals [deposit]'s [DmFirstContactDeposit.paymentHash].
     *  4. The invoice declares a non-null amount equal to [deposit]'s [DmFirstContactDeposit.requiredAmountMsat]
     *     exactly.
     *  5. The invoice's signer (`nodeId`) equals [recipient]'s bytes - mandatory, the
     *     anti-recipient-spoofing check.
     *  6. The invoice's `description` equals [canonicalMemo] for [binding] exactly - the anti-replay/
     *     anti-transplant check. A `descriptionHash`-only invoice is rejected outright.
     *
     * **Deliberately NOT checked: invoice expiry** - same deliberate choice as mail's identical
     * verifier and V0.6's `LightningProofVerifier`.
     */
    fun verify(
        binding: DmDepositBinding,
        recipient: Secp256k1PublicKey,
        deposit: DmFirstContactDeposit,
    ): Boolean =
        runCatching {
            val computedHash = sha256(deposit.preimage)
            if (!computedHash.contentEquals(deposit.paymentHash)) return@runCatching false

            val parsed = Bolt11Invoice.read(deposit.signedInvoice)
            if (parsed.isFailure) return@runCatching false
            val invoice = parsed.get()

            if (!invoice.paymentHash.toByteArray().contentEquals(deposit.paymentHash)) return@runCatching false

            val invoiceAmountMsat = invoice.amount ?: return@runCatching false
            if (invoiceAmountMsat.toLong() != deposit.requiredAmountMsat) return@runCatching false

            if (!invoice.nodeId.value
                    .toByteArray()
                    .contentEquals(recipient.bytes)
            ) {
                return@runCatching false
            }
            if (binding.recipientIdentity != recipient) return@runCatching false

            val description = invoice.description ?: return@runCatching false
            if (description != canonicalMemo(binding)) return@runCatching false

            true
        }.getOrDefault(false)

    /** A fresh [MessageDigest] instance per call - [MessageDigest] is not thread-safe. */
    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}

private fun ByteArray.toDmDepositHex(): String = joinToString("") { "%02x".format(it) }
