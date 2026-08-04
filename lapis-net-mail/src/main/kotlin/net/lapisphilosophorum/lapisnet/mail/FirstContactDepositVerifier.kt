package net.lapisphilosophorum.lapisnet.mail

import fr.acinq.lightning.payment.Bolt11Invoice
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

/** Domain-separation prefix for [FirstContactDepositVerifier.canonicalMemo] - deliberately
 * distinct from every other signing-domain tag in this codebase (see
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifier`'s
 * `LIGHTNING_MEMO_PREFIX`/`"LapisNet:<purpose>:v<n>"` precedent this loosely mirrors), even though
 * this is a BOLT-11 invoice *description* string, not a secp256k1 signing digest. */
private const val FIRST_CONTACT_MEMO_PREFIX = "lapisnet-mail-first-contact:v1:"

/**
 * The complete cryptographic verification chain for a [FirstContactDeposit]: preimage-to-hash,
 * real BOLT-11 parsing + signature verification (via [Bolt11Invoice.read]), and the
 * anti-spoofing/anti-replay cross-checks against the [MessageEnvelope] the deposit is presented
 * alongside.
 *
 * **Structurally near-identical to
 * `net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifier.verify` - deliberately
 * reimplemented here, not called through, and not a dependency on `lapis-net-virtus`.** That
 * verifier's signature is intrinsically Virtus-specific (`LtrRecord.viewId`/`initialValueMsat`/
 * `cid`) and cannot be invoked against a [MessageEnvelope]; per this wave's plan, this object
 * reuses the *chain* (the same six-step shape: hash check, real BOLT-11 parse+signature, embedded-
 * hash consistency, amount binding, recipient binding, anti-replay memo binding) with mail's own
 * domain-separated memo tag and mail-specific binding fields, rather than reinventing the
 * cryptography from scratch. Every `fr.acinq.*` type stays confined to this one file, mirroring
 * that module's own "sole consumer" discipline (see this module's `build.gradle.kts` header
 * comment).
 *
 * **Called from [InboxGossip]'s gossip hot path, exactly like `LightningProofVerifier.verify`
 * (V0.6) - a pure, bounded, local computation (hash a preimage, parse+verify a BOLT-11 signature,
 * compare a few fields) with no network I/O and no liveness dependency on any third party, safe to
 * run on every gossip-received envelope a [MailAcceptancePolicy] gate would otherwise reject.**
 */
object FirstContactDepositVerifier {
    /**
     * The canonical BOLT-11 `description` a [FirstContactDeposit]'s
     * [signedInvoice][FirstContactDeposit.signedInvoice] must carry for a specific
     * `(envelopeContentId, sender, recipient)` triple - the anti-replay binding that stops a
     * genuine, validly-signed `(preimage, invoice)` pair paid to earn ONE envelope past a
     * recipient's acceptance gate from being replayed against a SECOND, different envelope.
     *
     * **Every field is load-bearing:**
     *  - [envelopeContentId] - [MessageEnvelope.contentId], a SHA-256 over the envelope's FULL
     *    encoded bytes (every signed field: `sender`, `recipients`, `sentAtEpochSecond`,
     *    `encryption`, `contentCid`, `replyTo`, `threadRoot`, `wraps` - plus the signature itself)
     *    - binds the deposit to this EXACT envelope, not merely its body content. This is
     *      deliberately NOT just the body's `contentCid`: `contentCid` alone omits
     *      `sentAtEpochSecond`/`replyTo`/`threadRoot`/`recipients`, all of which are
     *      attacker-chosen and signed but outside `contentCid`, so a memo keyed only on
     *      `contentCid` would let one paid deposit validate an unbounded number of envelopes that
     *      share a body but differ in those fields - each with a distinct
     *      [MessageEnvelopeCodec.contentId] (the inbox dedup key), so every one of them would be
     *      accepted as if independently paid for. Binding the full envelope `contentId` closes
     *      that gap in one step, matching the dedup key exactly.
     *  - [sender] binds the deposit to the exact identity that paid it - without it, an attacker
     *    who observes a legitimate deposit's invoice (its `description` is public, visible in the
     *    gossiped invoice string) could copy the SAME body bytes (an `EncryptionMode.NONE`
     *    message's plaintext body is visible on the wire) into their OWN, differently-signed
     *    envelope addressed to the same recipient. This is now redundant with [envelopeContentId]
     *    (a re-signed envelope already has a different `contentId`), but kept for defense-in-depth
     *    and because it costs nothing.
     *  - [recipient] binds the deposit to the exact recipient it was paid to gain entry to - without
     *    it, a deposit paid to earn entry into recipient A's inbox could be replayed against
     *    recipient B's inbox for the identical `(sender, envelopeContentId)` pair when the same
     *    envelope addresses multiple recipients. Also (redundantly, defense-in-depth) enforced by
     *    the mandatory `invoice.nodeId == recipient` check in [verify] below - mirroring
     *    `LightningProofVerifier`'s own double-binding of `viewId` via both its memo and its
     *    `nodeId` check.
     *
     * Bound into the invoice itself (not just some other signed structure) because the invoice's
     * own BOLT-11 signature is what actually proves a real Lightning node committed to it.
     */
    fun canonicalMemo(
        envelopeContentId: ByteArray,
        sender: Secp256k1PublicKey,
        recipient: Secp256k1PublicKey,
    ): String =
        FIRST_CONTACT_MEMO_PREFIX + envelopeContentId.toDepositHex() + ":" +
            sender.bytes.toDepositHex() + ":" + recipient.bytes.toDepositHex()

    /**
     * The full verification chain for [deposit], presented alongside [envelope] to earn a
     * first-contact exception into [recipient]'s inbox. Returns `false` - never throws - for any
     * failure: a hash mismatch, an unparseable/incorrectly-signed invoice, a recipient/amount/
     * content mismatch, or any unexpected exception from the underlying `lightning-kmp`/
     * `bitcoin-kmp` call chain (defense-in-depth against a remote DoS via adversarial invoice
     * bytes - see this object's class doc comment).
     *
     * Steps, all AND-ed (mirroring `LightningProofVerifier.verify`'s exact shape):
     *  1. `sha256(deposit.preimage) == deposit.paymentHash`.
     *  2. [deposit]'s [FirstContactDeposit.signedInvoice] parses as a real BOLT-11 invoice with a
     *     valid signature ([Bolt11Invoice.read] verifies the signature internally as part of
     *     parsing).
     *  3. The invoice's own parsed payment hash equals [deposit]'s [FirstContactDeposit.paymentHash].
     *  4. The invoice declares a non-null amount, and that amount (in msat) equals [deposit]'s
     *     [FirstContactDeposit.requiredAmountMsat] exactly - the invoice is the source of truth for
     *     the amount, an amountless invoice cannot prove any specific payment size, and this is the
     *     anti-amount-spoofing check.
     *  5. The invoice's signer (`nodeId`) equals [recipient]'s bytes - **mandatory, not optional**:
     *     a Lightning node key IS its Lapis identity, by the same protocol commitment V0.6's
     *     `LightningProofVerifier` established. This is the anti-recipient-spoofing check; without
     *     it, a sender could pay ANY Lightning node (including their own) and claim the resulting
     *     proof earns entry into a completely different recipient's inbox.
     *  6. The invoice's `description` equals [canonicalMemo] for `(envelope.contentId(),
     *     envelope.sender, recipient)` exactly - the anti-replay check (see [canonicalMemo]'s doc
     *     comment on why every field is load-bearing, in particular why the FULL envelope
     *     `contentId` is bound rather than just `envelope.contentCid`). An invoice using
     *     `descriptionHash` instead of a plain `description` is rejected outright: there is no way
     *     to confirm a hash-only description actually matches the canonical memo without the
     *     preimage of that hash, which this verifier never has.
     *
     * **Deliberately NOT checked: invoice expiry - the same deliberate choice V0.6's
     * `LightningProofVerifier.verify` documented and made, restated explicitly here rather than
     * silently inherited.** A settled payment's invoice may legitimately be past its own BOLT-11
     * expiry by the time the resulting envelope propagates through gossip - the payment already
     * happened, and expiry only ever governs whether a *new* payment attempt against that invoice
     * should still be accepted, which is irrelevant once a preimage already proves settlement.
     */
    fun verify(
        envelope: MessageEnvelope,
        recipient: Secp256k1PublicKey,
        deposit: FirstContactDeposit,
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

            val description = invoice.description ?: return@runCatching false
            if (description != canonicalMemo(envelope.contentId(), envelope.sender, recipient)) {
                return@runCatching false
            }

            true
        }.getOrDefault(false)

    /** A fresh [MessageDigest] instance per call - [MessageDigest] is not thread-safe (mirrors
     * `LightningProofVerifier`'s own `sha256` helper and every other hashing call site in this
     * codebase). */
    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}

/** Full (not truncated/fingerprint) lower-case hex encoding - deliberately distinct from
 * `net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex` (which hashes-then-truncates for
 * display) since [FirstContactDepositVerifier.canonicalMemo] needs every byte of a key
 * unambiguously identified, not a lossy fingerprint. Mirrors the same file-local, non-shared
 * `toHex()` convention already used by `LightningProofVerifier` and elsewhere in this codebase -
 * there is no shared hex-encoding helper to reuse instead. */
private fun ByteArray.toDepositHex(): String = joinToString("") { "%02x".format(it) }
