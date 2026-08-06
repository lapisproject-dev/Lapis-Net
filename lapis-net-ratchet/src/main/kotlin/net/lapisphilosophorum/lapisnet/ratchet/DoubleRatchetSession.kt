package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.X25519AgreementException
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Thrown for every CRYPTOGRAPHIC failure to recover a plaintext, and for a session used in a way
 * its current key state cannot support: a failed GCM tag (whether the tampering was in the
 * ciphertext, the header, or the associated data - all three are indistinguishable here BY DESIGN),
 * a degenerate X25519 agreement during a ratchet step, or any third-party exception from
 * BouncyCastle/JCE. Deliberately a single, undifferentiated type, mirroring
 * [net.lapisphilosophorum.lapisnet.mail.MailDecryptionException]'s and [X3dhException]'s identical
 * reasoning: AES-GCM cannot distinguish "wrong key" from "tampered input", and neither should this
 * API, so nothing here can be used as a decryption oracle. No `AEADBadTagException`,
 * `GeneralSecurityException`, or `X25519AgreementException` ever escapes [DoubleRatchetSession]. */
class DoubleRatchetException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Thrown when a message is refused on grounds decided ENTIRELY from PUBLIC data - the plaintext
 * wire header the attacker themselves wrote, plus this session's own message counters - **before
 * any key derivation runs and without touching any secret**: a skip distance beyond [DoubleRatchetSession.MAX_SKIP],
 * a message number below the current receive position with no stored skipped key (a replay, or a
 * key already evicted from the bounded skip window), or a `previousChainLength` inconsistent with
 * the position this session already reached.
 *
 * **Why this is a SEPARATE type from [DoubleRatchetException], and why that is not an oracle.**
 * Every decision funnelled here is computable by the attacker from bytes they can already read: the
 * header is unencrypted in this wave (no header encryption - see [RatchetMessageHeader]), and
 * message counters are visible in it. Distinguishing "I refuse to derive that many keys" from "the
 * tag failed" therefore discloses nothing an observer did not already have. What it DOES buy is
 * real: a legitimate client can tell "this message is permanently undecryptable, stop retrying and
 * surface a gap to the user" apart from "something tampered with this frame". This is the same
 * split [CorruptedPrekeyStoreException] (structural, pre-decryption, safe to differentiate) versus
 * [net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException] (cryptographic,
 * deliberately undifferentiated) already draws in this codebase. Nothing that consults SECRET
 * material is ever reported through this type. */
class RatchetMessageRejectedException(
    message: String,
) : RuntimeException(message)

private fun aesGcmEncrypt(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    plaintext: ByteArray,
): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(plaintext)
}

private fun aesGcmDecryptRaw(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    ciphertext: ByteArray,
): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext)
}

/** Funnels every AEAD failure into [DoubleRatchetException] - mirrors `HybridEcies.open`'s and
 * `KeystoreEncryption.decrypt`'s identical funnels. No third-party exception ever escapes. */
private fun aesGcmDecryptFunnelled(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    ciphertext: ByteArray,
): ByteArray =
    try {
        aesGcmDecryptRaw(key, nonce, aad, ciphertext)
    } catch (e: AEADBadTagException) {
        throw DoubleRatchetException(
            "decryption failed: tampered or mismatched ciphertext/header/associated data",
            e,
        )
    } catch (e: GeneralSecurityException) {
        throw DoubleRatchetException("decryption failed: ${e.message}", e)
    } catch (e: OutOfMemoryError) {
        throw DoubleRatchetException("decryption failed: oversized allocation", e)
    } catch (e: RuntimeException) {
        throw DoubleRatchetException("decryption failed: ${e.message}", e)
    }

/**
 * A live, stateful Double Ratchet session (V0.8.3) - the ongoing encrypted channel an
 * [X3dhSharedSecret]/[X3dhSharedSecret.associatedData] pair from a completed X3DH handshake
 * bootstraps into. Reimplemented from the public Signal Double Ratchet specification, for the same
 * licensing reason [X3dh] states in its own class doc comment (no libsignal, AGPL-3.0-incompatible).
 *
 * **This wave carries real STATE, unlike V0.8.2's stateless handshake primitive.** A live session
 * persists across many messages over potentially a long time, so correctness failures here (a
 * forward-secrecy leak, a post-compromise-security gap, a state-persistence bug that resurrects old
 * keys) are ongoing, silent compromises of an entire conversation - not one-shot handshake bugs.
 * Every design decision below is made with that in mind.
 *
 * **Bootstrap asymmetry - who becomes sender, who becomes receiver, and why.** The X3DH
 * INITIATOR becomes the ratchet SENDER ([initializeSender]). It DOES have the responder's initial
 * ratchet public key already - the responder's SIGNED PREKEY public key IS that initial ratchet
 * key. The sender generates its OWN fresh ratchet keypair and immediately performs one DH ratchet
 * step, so it has a sending chain from message zero. The X3DH RESPONDER becomes the ratchet
 * RECEIVER ([initializeReceiver]). Its initial ratchet keypair IS the signed prekey keypair it
 * already holds - it does NOT generate a fresh one at init. It has `RK = SK`, NO sending chain and
 * NO receiving chain until the first inbound message arrives (see [canSend]).
 *
 * **The KDF ladder** lives entirely in [RatchetKdf] - see that object's class doc comment for the
 * full HKDF-SHA256 (root chain) / HMAC-SHA256 (symmetric chains) construction, written out exactly.
 *
 * **The AEAD nonce: AES-256-GCM with an explicit, uniformly random, transmitted 12-byte nonce - NOT
 * a derived nonce, unlike `HybridEcies`'s wrap key.** `HybridEcies`'s derived-nonce safety
 * (`HybridEcies.kt`'s class doc comment) rests on "the key is single-use by construction, and that
 * construction is a FRESH `SecureRandom` ephemeral per call - stateless, nothing can rewind it. If
 * the ephemeral key ever repeats, a transmitted random nonce would not have saved the scheme
 * either, since the same `SecureRandom` produced both." **That escape hatch does not hold here.** A
 * Double Ratchet message key is single-use by construction too, but the construction is a
 * PERSISTED COUNTER (`Ns`/`Nr` plus the sending/receiving chain key) - not a fresh random draw. A
 * stale persisted session blob (restored backup, a crashed write that left the previous file in
 * place, a copied state directory, a caller that violates this class's persist-before-send
 * ordering, see below) resurrects a `(chain key, N)` pair that has already been used, and the next
 * [encrypt] call re-derives the IDENTICAL message key. Under a DERIVED nonce, that would be a
 * genuine `(key, nonce)` repeat under AES-GCM - the catastrophic case, where the GHASH
 * authentication subkey becomes recoverable and the two plaintexts' XOR leaks. Under an EXPLICIT
 * RANDOM nonce, it degrades to "two ciphertexts under one key with distinct nonces", which GCM
 * tolerates with no confidentiality loss at all - what remains is a protocol-level DUPLICATE the
 * peer rejects as a replay (see this class's replay-rejection discussion below). Crucially, the
 * mail wave's own escape hatch - "a random nonce would not save it either, same RNG" - is FALSE
 * here: the rollback is a STORAGE fault, not an RNG fault, and the `SecureRandom` producing the
 * nonce is completely unaffected by it.
 *
 * The symmetric worry - does an explicit nonce weaken anything a derived nonce would have
 * provided? - resolves cleanly in the random nonce's favour: if `SecureRandom` were ever broken and
 * returned all-zero bytes for every call, every message would get nonce = 0, and that is HARMLESS,
 * because the KEY still differs per message (it comes from the HMAC chain ladder, not from this
 * `SecureRandom`). So the random nonce is safe under RNG failure AND under state rollback; a
 * derived nonce would only ever have been safe under the first. This is the same choice
 * `HybridEcies`'s OWN body layer already makes, for a structurally analogous reason
 * (`HybridEcies.kt`: "The body's content key ... is chosen by the sender and not tied to any
 * freshly-generated asymmetric key, so its AEAD nonce IS explicit and random"). The Double
 * Ratchet's message key is derivation-wise like the mail wave's WRAP, but freshness-wise like its
 * BODY - it follows the body.
 *
 * **The message header and its AAD binding.** See [RatchetMessageCodec]'s class doc comment for the
 * exact 60-byte wire layout. `AAD = headerBytes[0..59] || associatedData[0..70]` (131 bytes) - the
 * header bytes are read VERBATIM off the wire (or freshly assembled, in [encrypt]) and NEVER
 * re-serialised from [RatchetMessageHeader]'s parsed fields, the rule this codebase's own history
 * credits with making V0.4's keystore encryption pass security review in a single round.
 *
 * **NO HEADER ENCRYPTION IN THIS WAVE** - see [RatchetMessageHeader]'s own doc comment for this
 * deliberate, documented Signal-protocol-standard scope cut.
 *
 * **Two independent, cheap-first gates against the skipped-key DoS**, checked BEFORE any
 * derivation: [RatchetMessageCodec.MAX_CHAIN_LENGTH] at [RatchetMessageCodec.decode] (rejects
 * `Int.MAX_VALUE` and similar absurd wire claims before this class is ever entered), and
 * [MAX_SKIP] at [decrypt] (a tighter bound computed against THIS session's own position). This
 * codebase's CID-length OOM history (`Fix CID multihash-length OOM DoS`, commit `0c56dbb`) is why
 * both gates exist rather than one.
 *
 * **State is committed only AFTER the AEAD tag verifies - the single most important design
 * decision in this class.** Every derivation [decrypt] performs - skipped message keys, a DH
 * ratchet step's new root/chain keys, a new ratchet keypair - is built into SCRATCH locals first.
 * Only after [aesGcmDecryptFunnelled] returns successfully are those installed, the superseded live
 * arrays zeroed, and the skipped-key store updated. If the tag fails, every scratch array is zeroed
 * and the session is byte-for-byte what it was before the call. Without this, the session is
 * trivially destroyable by an unauthenticated attacker: a single garbage frame carrying a random
 * (but validly-encoded) `ratchetPublicKey` would drive a DH ratchet step, discard the real
 * receiving chain key, and permanently desynchronise the session - a one-packet remote DoS. It also
 * makes the stale-old-chain case degrade cleanly: a genuinely old message from a chain two ratchets
 * back, whose key was never stored as skipped, falls through to the "unknown ratchet key" branch and
 * provokes a spurious ratchet step whose results are simply discarded when the tag fails, instead of
 * corrupting the session.
 *
 * **Persist and destroy ordering - where forward secrecy actually dies in real implementations, and
 * the exact rules this class follows:**
 * 1. **Destruction happens INSIDE the state transition, so the persist/destroy question never
 *    arises at persist time.** Every superseded key - the old chain key on a symmetric step, the
 *    old root key/chain keys/ratchet private key on a DH ratchet step, the message key and derived
 *    AEAD key after use, an evicted skipped key - is zeroed and unreachable from this object BEFORE
 *    [encrypt]/[decrypt] returns. At every instant a caller could possibly call
 *    [DoubleRatchetSessionCodec.encode], this session holds ONLY current, still-needed key
 *    material - there is no window in which a snapshot could capture a superseded key.
 * 2. [DoubleRatchetSessionCodec.encode] is a pure read - it mutates and destroys nothing.
 * 3. **The ordering that DOES matter is the CALLER's** (a future online-DM wave, which owns actual
 *    file I/O - this class performs none): persist the post-[encrypt] state BEFORE putting the
 *    ciphertext on the wire, and persist the post-[decrypt] state BEFORE acting on the plaintext.
 *    Getting this backwards and crashing mid-window rewinds `Ns`/`Nr` on restart - which, because
 *    this wave transmits a random rather than derived nonce (see above), degrades to a rejectable
 *    protocol-level replay rather than a catastrophic key-recovery-grade AES-GCM nonce reuse.
 *    **Stated as a rule, not yet as a viable implementation plan**: as written, "persist once per
 *    message in each direction" means one full [DoubleRatchetSessionCodec.encode] - a fresh
 *    Argon2id derivation at [KeystoreEncryption.DEFAULT_MEMORY_KIB]/[KeystoreEncryption.DEFAULT_ITERATIONS]
 *    (64 MiB / 3 passes, order 10^2 ms) plus a full re-serialisation of up to
 *    [MAX_SKIPPED_KEYS_STORED] skipped entries - PER MESSAGE, in both directions. Nothing about that
 *    is incorrect, but it is not viable as a live network message-send path's per-message cost. This
 *    wave deliberately defers the resolution (most likely: cache the Argon2id-derived key for the
 *    session's lifetime instead of re-deriving it per [DoubleRatchetSessionCodec.encode] call, or wrap
 *    a cheap session-scoped key once under the Argon2id-derived one) to the online-DM wave that
 *    actually owns the persistence call sites - see the "not wired into a live network message-send
 *    path" scope cut below.
 * 4. Loading a stale blob is the residual, accepted, documented gap nothing in this class alone can
 *    prevent - the mitigations are entirely rule 3's (atomic durable writes, one canonical blob) plus
 *    the random-nonce choice above, which converts a rollback from a key-recovery-grade break into a
 *    benign, rejectable duplicate.
 * 5. The ONE place "persist then destroy" is correct: closing a session -
 *    `DoubleRatchetSessionCodec.encode(session, passphrase)` then `session.destroy()`. Correct
 *    precisely because what [destroy] erases is CURRENT state the persisted blob legitimately
 *    carries - not superseded material. Do not blur this with rule 1.
 *
 * **Explicit, deliberate scope cuts for this wave** (stated here rather than silently omitted,
 * mirroring this codebase's established practice):
 * - No sealed sender.
 * - No post-quantum ratchet (no PQXDH, no PQ KEM in the root chain) - consistent with V0.8.2's own cut.
 * - **No secure-erase guarantee beyond best-effort `ByteArray.fill(0)`** - the same limitation
 *   V0.4/V0.8.2 already state; this wave adds nothing to it and claims nothing more. See
 *   [destroy]'s own doc comment.
 * - **Not wired into a live network message-send path.** This class is a standalone, independently
 *   testable state machine; gossip/libp2p plumbing belongs to a later, online-DM-focused wave.
 * - **No file I/O.** [DoubleRatchetSessionCodec] is a pure bytes<->object codec; the durable-write
 *   discipline (atomic temp-file + `force(true)` + `ATOMIC_MOVE` + sidecar lock) is the caller's,
 *   and `PrekeyStore` is the reference implementation to copy.
 * - **No session registry, and therefore the X3DH initial-message replay gap is only PARTIALLY
 *   closed** - see [X3dh]'s own (corrected) doc comment: this class closes per-message replay
 *   WITHIN an established session; a duplicate X3DH initial message producing a SECOND,
 *   independent session is not visible from here.
 * - No multi-device / no session migration between devices.
 * - No automatic signed-prekey-driven session re-establishment, no session expiry, no periodic
 *   re-keying scheduler.
 */
class DoubleRatchetSession private constructor(
    private val associatedData: ByteArray,
    private var rootKey: ByteArray,
    private var sendingChainKey: ByteArray?,
    private var receivingChainKey: ByteArray?,
    private var ourRatchetKeyPair: X25519KeyPair,
    private var theirRatchetPublicKey: X25519PublicKey?,
    private var ns: Int,
    private var nr: Int,
    private var pn: Int,
    private val skippedKeys: SkippedMessageKeyStore,
    private val random: SecureRandom,
) {
    @Volatile
    private var destroyed = false
    private var dhStepCount = 0
    private var derivedKeyCount = 0L

    /** Test seam, mirroring `HybridEcies.sealWithEphemeralKeyHook`'s documented visibility
     * reasoning EXACTLY: invoked with the ACTUAL soon-to-be-zeroed backing array, immediately
     * before `fill(0)`, so a test can hold that reference and afterwards observe it come back
     * all-zero - proving the zeroization mutated the real array, not a throwaway copy. `internal`,
     * deliberately NOT a public property: a public hook would hand any caller live chain-key
     * material, i.e. a compiler-unenforced way to defeat this session's forward secrecy from
     * outside this module. `null` for every production caller. */
    internal var onKeyMaterialSupersededForTest: ((ByteArray) -> Unit)? = null

    /** AUDIT-GRADE test seam (V0.8.3 security review, round 2 major finding). Fires from
     * [stateForCodec] with the ratchet private scalar copy and every skipped-entry key material copy
     * it allocated, at the point they are captured for zeroing in its own `finally` - mirroring
     * [onKeyMaterialSupersededForTest]'s identical "hand the test the real reference before
     * `fill(0)`" reasoning for locals a reflection-based test cannot otherwise reach (they are stack
     * locals inside a function, not fields). `internal`, `null` for every production caller. */
    internal var onStateForCodecLocalsCapturedForTest: ((ByteArray, List<ByteArray>) -> Unit)? = null

    /** `true` iff [encrypt] can currently be called - `false` for a freshly [initializeReceiver]d
     * session that has not yet decrypted its first inbound message (it has no sending chain until
     * then - see this class's own "bootstrap asymmetry" doc-comment section), or for a [destroy]ed
     * session. */
    val canSend: Boolean
        @Synchronized get() = !destroyed && sendingChainKey != null

    private fun checkNotDestroyed() {
        check(!destroyed) { "this DoubleRatchetSession has been destroyed and is no longer usable" }
    }

    /** Encrypts [plaintext] using this session's current sending chain, advancing it by one step.
     *
     * @throws DoubleRatchetException if this session cannot currently send (see [canSend]), or if
     *   this sending chain has already reached [RatchetMessageCodec.MAX_CHAIN_LENGTH] messages
     *   without a reply and needs a fresh DH ratchet step (triggered by decrypting an inbound
     *   message carrying a new ratchet key) before it can send further.
     */
    @Synchronized
    fun encrypt(plaintext: ByteArray): RatchetMessage {
        checkNotDestroyed()
        require(plaintext.isNotEmpty()) {
            "cannot encrypt an empty plaintext - an empty AES-GCM plaintext would encrypt to a " +
                "tag-only ciphertext, which RatchetMessage's constructor disallows (minimum " +
                "GCM_TAG_SIZE + 1 bytes); a protocol-level empty/keepalive message must carry at " +
                "least one padding byte"
        }
        require(plaintext.size <= RatchetMessageCodec.MAX_PLAINTEXT_BYTES) {
            "plaintext exceeds ${RatchetMessageCodec.MAX_PLAINTEXT_BYTES} bytes: ${plaintext.size}"
        }
        val currentChainKey =
            sendingChainKey
                ?: throw DoubleRatchetException(
                    "this session cannot send yet - it was initialised as a receiver (X3DH " +
                        "responder) and has no sending chain until it has decrypted its first " +
                        "inbound message; see canSend",
                )
        // Checked BEFORE any key derivation, exactly like decrypt()'s STEP 1 DoS gates: ns is about
        // to be handed to RatchetMessageHeader's constructor, which enforces this same range with a
        // raw IllegalArgumentException - typed inconsistently with this method's documented
        // DoubleRatchetException-only contract. Guarding here keeps that boundary inside this API's
        // own exception taxonomy, and fails BEFORE currentChainKey/messageKeyMaterial ever exist, so
        // there is nothing to clean up.
        if (ns > RatchetMessageCodec.MAX_CHAIN_LENGTH) {
            throw DoubleRatchetException(
                "this sending chain is exhausted at ns=$ns (MAX_CHAIN_LENGTH=" +
                    "${RatchetMessageCodec.MAX_CHAIN_LENGTH}) without a reply from the peer - re-key " +
                    "the session (a fresh DH ratchet step, triggered by decrypting an inbound message " +
                    "carrying a new ratchet key) before sending further",
            )
        }
        val (nextChainKey, messageKeyMaterial) = RatchetKdf.chainKdf(currentChainKey)
        derivedKeyCount++

        var aesKey: ByteArray? = null
        var aad: ByteArray? = null
        var committed = false
        try {
            // Deliberately no all-zero-nonce guard here, unlike HybridEcies.seal's/
            // MailAttachmentCipher.encrypt's all-zero KEY guards: a repeated nonce is harmless
            // because the KEY differs for every message by construction (it comes from the HMAC
            // chain ladder, not from this SecureRandom) - see this class's own nonce-strategy
            // section for the full argument.
            val nonce = ByteArray(GCM_NONCE_SIZE).also(random::nextBytes)
            val ciphertextLength = plaintext.size + GCM_TAG_SIZE
            val header = RatchetMessageHeader(ourRatchetKeyPair.publicKey, pn, ns, nonce)
            val headerBytes = RatchetMessageCodec.encodeHeader(header, ciphertextLength)
            aad = headerBytes + associatedData
            aesKey = RatchetKdf.messageKeyKdf(messageKeyMaterial, associatedData)
            val ciphertext = aesGcmEncrypt(aesKey, nonce, aad, plaintext)
            check(ciphertext.size == ciphertextLength) {
                "AES-GCM produced ${ciphertext.size} bytes, expected $ciphertextLength"
            }

            onKeyMaterialSupersededForTest?.invoke(currentChainKey)
            currentChainKey.fill(0)
            sendingChainKey = nextChainKey
            ns++
            committed = true
            return RatchetMessage(header, headerBytes, ciphertext)
        } finally {
            messageKeyMaterial.fill(0)
            aesKey?.fill(0)
            aad?.fill(0)
            if (!committed) nextChainKey.fill(0)
        }
    }

    /** Turns message-key material into the AEAD key, decrypts, and zeroes the intermediate AEAD
     * key - shared by [decrypt]'s skipped-key path and its main derivation path. Does NOT zero
     * [messageKeyMaterial] - the caller owns that. Throws [DoubleRatchetException] on any AEAD
     * failure. */
    private fun decryptWithMessageKeyMaterial(
        messageKeyMaterial: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val aesKey = RatchetKdf.messageKeyKdf(messageKeyMaterial, associatedData)
        try {
            return aesGcmDecryptFunnelled(aesKey, nonce, aad, ciphertext)
        } finally {
            aesKey.fill(0)
        }
    }

    /**
     * Decrypts [message] against this session's current state, advancing it as needed - including,
     * if [message] carries a new ratchet public key, performing a DH ratchet step first. See this
     * class's own doc comment for the full "state is committed only after the AEAD tag verifies"
     * discipline this method implements, and for the exact adversarial properties it defends.
     *
     * @throws RatchetMessageRejectedException for a rejection decided from PUBLIC data alone
     *   (excessive skip distance, a message number already consumed or evicted, an inconsistent
     *   `previousChainLength`) - see that type's own doc comment for why this is not an oracle.
     * @throws DoubleRatchetException for every cryptographic failure (a failed AEAD tag, wherever
     *   the tampering was; a degenerate X25519 agreement during a forced ratchet step).
     */
    @Suppress("CyclomaticComplexMethod", "LongMethod")
    @Synchronized
    fun decrypt(message: RatchetMessage): ByteArray {
        checkNotDestroyed()
        val header = message.header
        val aad = message.headerBytes + associatedData

        // --- STEP 0: skipped-key path, tried FIRST - Signal's own ordering. Lets a legitimately
        // out-of-order message from an OLD chain (whose ratchetPublicKey is no longer DHr)
        // decrypt without provoking a spurious ratchet step. ---
        val skippedId = SkippedMessageKeyId(header.ratchetPublicKey.bytes, header.messageNumber)
        val skippedMessageKeyMaterial = skippedKeys.peek(skippedId)
        if (skippedMessageKeyMaterial != null) {
            try {
                val plaintext =
                    decryptWithMessageKeyMaterial(skippedMessageKeyMaterial, header.nonce, aad, message.ciphertext)
                // Delete-on-use: this is what makes a decrypted message unreplayable, matching the
                // uniform property every other decrypt path gets from Nr/Ns advancing past it.
                skippedKeys.remove(skippedId)
                return plaintext
            } finally {
                skippedMessageKeyMaterial.fill(0)
            }
        }

        // --- STEP 1: DoS gates, decided from PUBLIC data ONLY - before ANY derivation. ---
        val ratchetStepNeeded =
            theirRatchetPublicKey == null || header.ratchetPublicKey != theirRatchetPublicKey
        if (ratchetStepNeeded) {
            val currentReceivingChainKey = receivingChainKey
            if (currentReceivingChainKey != null) {
                if (header.previousChainLength < nr) {
                    throw RatchetMessageRejectedException(
                        "previousChainLength ${header.previousChainLength} is below this session's " +
                            "current receive position $nr - the peer claims a shorter previous chain " +
                            "than this session already consumed from it",
                    )
                }
                if (header.previousChainLength.toLong() - nr > MAX_SKIP) {
                    throw RatchetMessageRejectedException(
                        "skipping ${header.previousChainLength.toLong() - nr} messages in the old " +
                            "chain exceeds MAX_SKIP ($MAX_SKIP)",
                    )
                }
            }
            if (header.messageNumber.toLong() > MAX_SKIP) {
                throw RatchetMessageRejectedException(
                    "messageNumber ${header.messageNumber} in the new chain exceeds MAX_SKIP ($MAX_SKIP)",
                )
            }
        } else {
            // A freshly initializeSender()'d session sets theirRatchetPublicKey to the responder's
            // SIGNED PREKEY (a PUBLIC value, gossiped in every PrekeyBundle) while leaving
            // receivingChainKey null until the first inbound message is decrypted (see this
            // class's own "bootstrap asymmetry" doc-comment section). A frame that echoes that same
            // public key back before this session has ever received a reply therefore lands in this
            // branch with no receiving chain to derive from. This is decided from PUBLIC data alone
            // (the header's ratchetPublicKey plus this session's own receivingChainKey nullness, not
            // any secret material), so it belongs in RatchetMessageRejectedException, not a raw
            // NullPointerException out of the `receivingChainKey!!` below.
            if (receivingChainKey == null) {
                throw RatchetMessageRejectedException(
                    "message claims this session's current ratchet public key, but this session has " +
                        "no receiving chain established for it yet - it must decrypt an inbound " +
                        "message carrying a NEW ratchet key first (a DH ratchet step) before it can " +
                        "accept one claiming the same key back",
                )
            }
            if (header.messageNumber < nr) {
                throw RatchetMessageRejectedException(
                    "message number ${header.messageNumber} in this chain has already been " +
                        "consumed, or its skipped key has been evicted from this session's bounded " +
                        "skip window - it is permanently undecryptable",
                )
            }
            if (header.messageNumber.toLong() - nr > MAX_SKIP) {
                throw RatchetMessageRejectedException(
                    "skipping ${header.messageNumber.toLong() - nr} messages exceeds MAX_SKIP ($MAX_SKIP)",
                )
            }
        }

        // --- STEP 2+3: derive into SCRATCH, then decrypt. Live fields untouched until commit. ---
        val pendingSkipped = mutableListOf<Pair<SkippedMessageKeyId, ByteArray>>()
        var scratchRootKey: ByteArray? = null
        var scratchRootKeyIntermediate: ByteArray? = null
        var scratchSendingChainKey: ByteArray? = null
        var scratchOurKeyPair: X25519KeyPair? = null
        var scratchTheirKey: X25519PublicKey? = null
        var scratchReceivingChainKey: ByteArray? = null
        var scratchReceiveNumber = 0
        var scratchPreviousSendChainLength = 0
        var scratchSendNumber = 0
        var messageKeyMaterial: ByteArray? = null
        var committed = false
        try {
            if (ratchetStepNeeded) {
                // (a) Skip the REMAINDER of the current receiving chain, into pendingSkipped.
                val oldReceivingChainKey = receivingChainKey
                if (oldReceivingChainKey != null) {
                    var ck = oldReceivingChainKey.copyOf()
                    for (n in nr until header.previousChainLength) {
                        val (nextCk, mkm) = RatchetKdf.chainKdf(ck)
                        derivedKeyCount++
                        pendingSkipped += SkippedMessageKeyId(theirRatchetPublicKey!!.bytes, n) to mkm
                        ck.fill(0)
                        ck = nextCk
                    }
                    ck.fill(0)
                }

                // (b) The DH ratchet step itself - TWO root-KDF applications, Signal's own
                // DHRatchet(): first mix in a DH using our CURRENT (about-to-be-superseded)
                // keypair, then generate a fresh keypair and mix in a second DH using THAT.
                //
                // Each value is assigned into its `scratch*` variable on the SAME line it is
                // produced, rather than batched at the end of this branch - so that an exception
                // thrown ANYWHERE after a value exists (x25519SharedSecret's X25519AgreementException,
                // X25519KeyPair.generate's broken-RNG guard, RatchetKdf.chainKdf's `require` inside
                // the forward-skip loop below) still leaves that value reachable from a `scratch*`
                // field, and therefore zeroed/destroyed by this method's `finally` block (see below).
                // Before this, a freshly generated ratchet private scalar and its derived root/chain
                // keys could linger un-zeroed on the heap if an exception landed between their
                // production and their (formerly batched) assignment. `rootAfterFirstDh` and
                // `receivingChainAfterStep` in particular are assigned into `scratchRootKeyIntermediate`/
                // `scratchReceivingChainKey` the INSTANT the first rootKdf call returns - not only once
                // they are consumed below - so that a throw from `X25519KeyPair.generate` or the
                // second `x25519SharedSecret` (both BEFORE either value is otherwise referenced again)
                // still leaves them reachable from a scratch field.
                val newTheirRatchetKey = header.ratchetPublicKey
                scratchTheirKey = newTheirRatchetKey
                val dh1 = x25519SharedSecret(ourRatchetKeyPair.privateKey, newTheirRatchetKey)
                val (rootAfterFirstDh, receivingChainAfterStep) =
                    try {
                        RatchetKdf.rootKdf(rootKey, dh1, associatedData)
                    } finally {
                        dh1.fill(0)
                    }
                scratchRootKeyIntermediate = rootAfterFirstDh
                scratchReceivingChainKey = receivingChainAfterStep
                val newOurKeyPair = X25519KeyPair.generate(random)
                scratchOurKeyPair = newOurKeyPair
                val dh2 = x25519SharedSecret(newOurKeyPair.privateKey, newTheirRatchetKey)
                val (rootAfterSecondDh, sendingChainAfterStep) =
                    try {
                        RatchetKdf.rootKdf(rootAfterFirstDh, dh2, associatedData)
                    } finally {
                        dh2.fill(0)
                        rootAfterFirstDh.fill(0)
                    }
                scratchRootKey = rootAfterSecondDh
                scratchSendingChainKey = sendingChainAfterStep

                // (c) Skip FORWARD inside the new receiving chain, then derive the message's own key.
                var ck2 = receivingChainAfterStep
                for (n in 0 until header.messageNumber) {
                    val (nextCk2, mkm) = RatchetKdf.chainKdf(ck2)
                    derivedKeyCount++
                    pendingSkipped += SkippedMessageKeyId(newTheirRatchetKey.bytes, n) to mkm
                    ck2.fill(0)
                    ck2 = nextCk2
                }
                val (finalReceivingChainKey, mkFinal) = RatchetKdf.chainKdf(ck2)
                derivedKeyCount++
                ck2.fill(0)

                scratchReceivingChainKey = finalReceivingChainKey
                scratchPreviousSendChainLength = ns
                scratchSendNumber = 0
                scratchReceiveNumber = header.messageNumber + 1
                messageKeyMaterial = mkFinal
            } else {
                var ck = receivingChainKey!!.copyOf()
                for (n in nr until header.messageNumber) {
                    val (nextCk, mkm) = RatchetKdf.chainKdf(ck)
                    derivedKeyCount++
                    pendingSkipped += SkippedMessageKeyId(theirRatchetPublicKey!!.bytes, n) to mkm
                    ck.fill(0)
                    ck = nextCk
                }
                val (finalChainKey, mkm) = RatchetKdf.chainKdf(ck)
                derivedKeyCount++
                ck.fill(0)
                scratchReceivingChainKey = finalChainKey
                scratchReceiveNumber = header.messageNumber + 1
                messageKeyMaterial = mkm
            }

            // --- STEP 3: decrypt. A throw here leaves the session UNCHANGED (committed is still
            // false, so the finally block below zeroes every scratch array). ---
            val plaintext =
                decryptWithMessageKeyMaterial(messageKeyMaterial, header.nonce, aad, message.ciphertext)
            committed = true

            // --- STEP 4: COMMIT, in this exact order. ---
            if (ratchetStepNeeded) {
                onKeyMaterialSupersededForTest?.invoke(rootKey)
                rootKey.fill(0)
                sendingChainKey?.let {
                    onKeyMaterialSupersededForTest?.invoke(it)
                    it.fill(0)
                }
                ourRatchetKeyPair.privateKey.destroy()
                rootKey = scratchRootKey!!
                sendingChainKey = scratchSendingChainKey
                ourRatchetKeyPair = scratchOurKeyPair!!
                theirRatchetPublicKey = scratchTheirKey
                pn = scratchPreviousSendChainLength
                ns = scratchSendNumber
                dhStepCount++
            }
            receivingChainKey?.let {
                onKeyMaterialSupersededForTest?.invoke(it)
                it.fill(0)
            }
            receivingChainKey = scratchReceivingChainKey
            nr = scratchReceiveNumber
            pendingSkipped.forEach { (id, mkm) ->
                skippedKeys.put(id, mkm)
                mkm.fill(0)
            }
            return plaintext
        } catch (e: DoubleRatchetException) {
            throw e
        } catch (e: RatchetMessageRejectedException) {
            throw e
        } catch (e: X25519AgreementException) {
            throw DoubleRatchetException("ratchet step failed: ${e.message}", e)
        } finally {
            messageKeyMaterial?.fill(0)
            if (!committed) {
                scratchRootKeyIntermediate?.fill(0)
                scratchRootKey?.fill(0)
                scratchSendingChainKey?.fill(0)
                scratchReceivingChainKey?.fill(0)
                scratchOurKeyPair?.privateKey?.destroy()
                pendingSkipped.forEach { (_, mkm) -> mkm.fill(0) }
            }
        }
    }

    /** Zeroes every piece of key material this session holds - the root key, both chain keys, the
     * ratchet private key (in place, via `X25519PrivateKey.destroy`), and every stored skipped
     * message key - and marks the session unusable. Idempotent. Every other public method throws
     * [IllegalStateException] afterwards.
     *
     * **Correct shutdown order is PERSIST, THEN DESTROY** - see this class's own "persist and
     * destroy ordering" doc-comment section, rule 5, for why this is the ONE place that ordering is
     * right: what this method erases is CURRENT state a persisted blob legitimately carries, not
     * superseded material (every superseded key is already destroyed inside the state transition
     * that superseded it, before [encrypt]/[decrypt] ever returns).
     *
     * **Best-effort, not a guarantee** - `ByteArray.fill(0)` cannot reach copies a JVM garbage
     * collector may have made while relocating the array, and this project makes no secure-erase
     * claim beyond that (the same limitation `X25519PrivateKey.destroy`/`X3dhSharedSecret.destroy`
     * already state; this wave adds nothing and claims nothing more). */
    @Synchronized
    fun destroy() {
        if (destroyed) return
        rootKey.fill(0)
        sendingChainKey?.fill(0)
        receivingChainKey?.fill(0)
        ourRatchetKeyPair.privateKey.destroy()
        skippedKeys.destroyAll()
        destroyed = true
    }

    // --- Test-visibility accessors, all internal, all mirroring PeerRecordIndex.size()'s
    // established precedent for exposing otherwise-private state to tests. ---

    internal fun dhRatchetStepCount(): Int = dhStepCount

    internal fun derivedMessageKeyCount(): Long = derivedKeyCount

    internal fun sendingRatchetPublicKey(): X25519PublicKey = ourRatchetKeyPair.publicKey

    internal fun receivingRatchetPublicKey(): X25519PublicKey? = theirRatchetPublicKey

    internal fun sendMessageNumber(): Int = ns

    internal fun receiveMessageNumber(): Int = nr

    internal fun previousSendChainLength(): Int = pn

    internal fun skippedKeyCount(): Int = skippedKeys.size()

    /** Defensive COPIES of every secret byte array reachable from this session: root key, sending
     * chain key (if any), receiving chain key (if any), ratchet private key, and every stored
     * skipped message key. Used by `DoubleRatchetAdversarialTest`'s forward-secrecy case to assert
     * an old key's bytes appear nowhere in the live session's material. */
    @Synchronized
    internal fun keyMaterialSnapshotForTest(): List<ByteArray> =
        buildList {
            add(rootKey.copyOf())
            sendingChainKey?.let { add(it.copyOf()) }
            receivingChainKey?.let { add(it.copyOf()) }
            add(ourRatchetKeyPair.privateKey.bytes)
            skippedKeys.entriesOldestFirst().forEach { (_, _, keyMaterial) -> add(keyMaterial) }
        }

    /** Internal-only accessor for [DoubleRatchetSessionCodec], to persist every field this session
     * holds without exposing them as a public API surface. Every array returned is a fresh copy
     * except where noted. */
    @Synchronized
    internal fun stateForCodec(): DoubleRatchetSessionState {
        checkNotDestroyed()
        // ourRatchetKeyPair.privateKey.bytes and skippedKeys.entriesOldestFirst() each allocate
        // fresh copies, and DoubleRatchetSessionState's constructor immediately copies every array it
        // is handed AGAIN into its own storage (see that class's `<field> = <field>.copyOf()` for
        // every one of them) - so ALL of these intermediates are redundant the instant the
        // constructor returns. rootKey/sendingChainKey/receivingChainKey are therefore passed
        // WITHOUT an extra `.copyOf()` here (the constructor already copies; an intermediate copy at
        // this call site would itself be an abandoned, un-zeroed duplicate of live session secrets),
        // and the two intermediates that genuinely cannot be avoided - the ratchet private scalar and
        // the skipped-entry key material - are zeroed in a `finally`, mirroring
        // X25519KeyPair.publicKeyFor's identical "zero the one intermediate scalar copy this function
        // introduces" discipline.
        val ourRatchetPrivateKeyBytes = ourRatchetKeyPair.privateKey.bytes
        val skippedEntries = skippedKeys.entriesOldestFirst()
        try {
            return DoubleRatchetSessionState(
                associatedData = associatedData.copyOf(),
                rootKey = rootKey,
                sendingChainKey = sendingChainKey,
                receivingChainKey = receivingChainKey,
                ourRatchetPrivateKeyBytes = ourRatchetPrivateKeyBytes,
                theirRatchetPublicKey = theirRatchetPublicKey,
                sendMessageNumber = ns,
                receiveMessageNumber = nr,
                previousSendChainLength = pn,
                skippedEntries = skippedEntries,
            )
        } finally {
            onStateForCodecLocalsCapturedForTest?.invoke(ourRatchetPrivateKeyBytes, skippedEntries.map { it.third })
            ourRatchetPrivateKeyBytes.fill(0)
            skippedEntries.forEach { it.third.fill(0) }
        }
    }

    companion object {
        /** Maximum message keys that may be derived-and-skipped WITHIN ONE CHAIN, in response to a
         * single incoming message, before the message is rejected outright.
         *
         * 1,000 is chosen the way this codebase chooses every other numeric cap - generous headroom
         * above a realistic worst case, not derived from a protocol requirement (mirroring
         * `PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS`'s and `PeerRecordIndex.MAX_TRACKED_RECORDS`-style
         * caps' identical framing, and carrying the same provisional-magnitude caveat: chosen for
         * parity with existing precedent, not from pilot data). The bound that matters is WORK PER
         * INBOUND MESSAGE - and it differs by path:
         *
         * - **Same-chain path** (the header echoes this session's CURRENT ratchet public key): at
         *   most [MAX_SKIP] chain-KDF steps (2,000 HMAC-SHA256 evaluations over 32-byte inputs),
         *   single-digit milliseconds, at most [MAX_SKIP] skipped-key entries allocated.
         * - **Ratchet-step path** (the header carries ANY novel, structurally valid
         *   `ratchetPublicKey` - a fact decided from public data alone, before the AEAD tag is ever
         *   checked): [decrypt] runs TWO independent [MAX_SKIP]-bounded loops in the SAME call - one
         *   to skip the remainder of the OLD receiving chain, one to skip forward into the NEW one -
         *   for up to `2 * [MAX_SKIP]` chain-KDF steps (~4,000 HMAC-SHA256 evaluations) in that one
         *   [decrypt] call. This path ALSO performs one fresh X25519 keypair generation plus two
         *   X25519 scalar multiplications (the two DH agreements Signal's own `DHRatchet()`
         *   requires) - three scalar operations an attacker can force per frame merely by supplying a
         *   novel ratchet public key, entirely BEFORE the AEAD tag is checked and on top of the HMAC
         *   cost above. Still single-digit milliseconds in absolute terms, and the entire result -
         *   HMACs, DH agreements, everything - is discarded with no state committed the moment the
         *   tag fails to verify. This asymmetric, header-driven pre-authentication cost is inherent
         *   to the Double Ratchet with unencrypted headers (Signal's own construction has the
         *   identical property); a cheaper posture, if ever wanted, would move the fresh-keypair
         *   generation after the AEAD check (deriving the receiving chain first, generating the
         *   sending keypair only on commit).
         *
         * Doubling [MAX_SKIP] doubles the cost an unauthenticated peer can impose per frame; halving
         * it starts to reject plausible real gossip reordering. Every gate that protects this
         * ([RatchetMessageCodec.MAX_CHAIN_LENGTH] and this one) is checked BEFORE any derivation loop
         * or DH agreement runs, never inside or after them.
         *
         * **A message skipped further ahead than this is permanently undecryptable.** That is the
         * correct, accepted consequence of a bounded skip window, not a bug.
         */
        const val MAX_SKIP = 1_000

        /** Total skipped message keys this session retains across ALL chains. Beyond it, the OLDEST
         * stored key is evicted (and zeroed) to make room - and that message becomes permanently
         * undecryptable, again a correct, accepted consequence.
         *
         * **Deliberately exactly `2 * MAX_SKIP`, and both halves of that ratio are load-bearing.**
         * (i) A single [decrypt] that crosses a DH ratchet boundary can legitimately need to store
         * up to [MAX_SKIP] keys for the OLD chain plus up to [MAX_SKIP] for the NEW one; sizing the
         * store at exactly that sum means one legitimate worst-case burst fills the store without
         * evicting anything it just stored in the SAME call - **provided the store was EMPTY when
         * that call began.** [SkippedMessageKeyStore] evicts strictly by insertion order, so if the
         * store already holds `k` entries from EARLIER calls, the first `k` of a 2,000-entry burst in
         * a later call ARE evicted by the later entries within that same call - this bound is a
         * per-call worst case against an empty store, not a standing guarantee that any one call
         * never evicts anything it just inserted. (ii) It bounds memory honestly, though not down to
         * the byte: the in-memory representation is a [SkippedMessageKeyId] (a 32-byte array) mapping
         * to a 32-byte value plus `LinkedHashMap.Entry` overhead, not the 68-byte figure that is
         * really this session's ON-WIRE `SKIPPED_ENTRY_SIZE` (see [DoubleRatchetSessionCodec]) - still
         * comfortably under 250 KB per session, so even a thousand concurrent sessions stay in the low
         * hundreds of MB, just not via that exact arithmetic.
         */
        const val MAX_SKIPPED_KEYS_STORED = MAX_SKIP * 2

        /**
         * Bootstraps the X3DH INITIATOR's side of the ratchet - the session that can send from
         * message zero. See this class's own "bootstrap asymmetry" doc-comment section for the full
         * argument.
         *
         * [theirInitialRatchetKey] **is the responder's SIGNED PREKEY public key** - the initial
         * ratchet public key in the standard X3DH/Double-Ratchet composition (`PrekeyBundle.signedPrekey`,
         * the very key `DH1`/`DH3` were computed against). This function deliberately does NOT reach
         * into `PrekeyBundle`/`PrekeyStore` to fetch it: this module's whole value is being a
         * standalone, network-free, independently testable primitive, and a later online-DM wave
         * owns that wiring.
         *
         * Generates a FRESH ratchet keypair and performs one DH ratchet step immediately.
         *
         * **Does NOT destroy [sharedSecret]** - the caller owns its lifetime and should call
         * [X3dhSharedSecret.destroy] on it once every session derived from it exists, mirroring
         * `ecdhSharedSecret`'s and `PrekeyStore.x25519IdentityPrivateKey`'s identical
         * caller-owns-the-lifetime rule. The 32-byte copy this function takes via
         * [X3dhSharedSecret.sharedSecret] IS zeroed here, in a `finally`.
         *
         * @throws DoubleRatchetException if the initial DH agreement is degenerate (unreachable via
         *   any public API today, since [theirInitialRatchetKey] is validated by
         *   [net.lapisphilosophorum.lapisnet.identity.X25519PublicKey]'s own constructor - kept as
         *   defence in depth).
         */
        fun initializeSender(
            sharedSecret: X3dhSharedSecret,
            theirInitialRatchetKey: X25519PublicKey,
            random: SecureRandom = SecureRandom(),
        ): DoubleRatchetSession {
            val ad = sharedSecret.associatedData
            require(ad.size == X3DH_ASSOCIATED_DATA_SIZE) {
                "associatedData must be $X3DH_ASSOCIATED_DATA_SIZE bytes, was ${ad.size}"
            }
            val sk = sharedSecret.sharedSecret
            val ourKeyPair = X25519KeyPair.generate(random)
            var committed = false
            try {
                require(sk.size == ROOT_KEY_SIZE) { "sharedSecret must be $ROOT_KEY_SIZE bytes, was ${sk.size}" }
                val dh = x25519SharedSecret(ourKeyPair.privateKey, theirInitialRatchetKey)
                val (rootKey, sendingChainKey) =
                    try {
                        RatchetKdf.rootKdf(sk, dh, ad)
                    } finally {
                        dh.fill(0)
                    }
                val session =
                    DoubleRatchetSession(
                        associatedData = ad,
                        rootKey = rootKey,
                        sendingChainKey = sendingChainKey,
                        receivingChainKey = null,
                        ourRatchetKeyPair = ourKeyPair,
                        theirRatchetPublicKey = theirInitialRatchetKey,
                        ns = 0,
                        nr = 0,
                        pn = 0,
                        skippedKeys = SkippedMessageKeyStore(),
                        random = random,
                    )
                committed = true
                return session
            } catch (e: X25519AgreementException) {
                throw DoubleRatchetException("failed to initialize sender session: ${e.message}", e)
            } finally {
                sk.fill(0)
                if (!committed) ourKeyPair.privateKey.destroy()
            }
        }

        /**
         * Bootstraps the X3DH RESPONDER's side of the ratchet - the session that must decrypt
         * before it can send (see [canSend]). See this class's own "bootstrap asymmetry" doc-comment
         * section for the full argument.
         *
         * [ourRatchetKeyPair] **is this identity's own SIGNED PREKEY keypair** (`PrekeyStore`'s
         * current signed-prekey public key plus `signedPrekeyPrivateKey()`), the same keypair the
         * X3DH handshake's `DH1`/`DH3` used. It is NOT freshly generated here: it must be the key
         * the initiator already saw in the published `PrekeyBundle`, or the two sides' first
         * root-KDF applications would disagree.
         *
         * **This session takes its OWN COPY of [ourRatchetKeyPair]'s private half and never touches
         * the caller's object.** Load-bearing, not hygiene: on its first DH ratchet step this
         * session calls `X25519PrivateKey.destroy()` on whatever it holds as its own keypair, and
         * that method zeroes the actual backing scalar IN PLACE. Destroying the CALLER's object
         * would zero the very key a caller may still be holding elsewhere (e.g. a second session
         * bootstrapped from the same signed prekey, or `PrekeyStore` bookkeeping). Copying removes
         * the question entirely.
         *
         * A receiver-initialised session cannot send until it has decrypted its first inbound
         * message - see [canSend] and [encrypt].
         */
        fun initializeReceiver(
            sharedSecret: X3dhSharedSecret,
            ourRatchetKeyPair: X25519KeyPair,
            random: SecureRandom = SecureRandom(),
        ): DoubleRatchetSession {
            val ad = sharedSecret.associatedData
            require(ad.size == X3DH_ASSOCIATED_DATA_SIZE) {
                "associatedData must be $X3DH_ASSOCIATED_DATA_SIZE bytes, was ${ad.size}"
            }
            val sk = sharedSecret.sharedSecret
            try {
                require(sk.size == ROOT_KEY_SIZE) { "sharedSecret must be $ROOT_KEY_SIZE bytes, was ${sk.size}" }
                // ourRatchetKeyPair.privateKey.bytes allocates a fresh scalar copy, and
                // X25519KeyPair.fromPrivateKeyBytes immediately copies it AGAIN into the
                // X25519PrivateKey it constructs - zero this intermediate in a `finally`, mirroring
                // stateForCodec's identical pattern below.
                val callerPrivateKeyBytes = ourRatchetKeyPair.privateKey.bytes
                val ownedKeyPair =
                    try {
                        X25519KeyPair.fromPrivateKeyBytes(callerPrivateKeyBytes)
                    } finally {
                        callerPrivateKeyBytes.fill(0)
                    }
                return DoubleRatchetSession(
                    associatedData = ad,
                    rootKey = sk.copyOf(),
                    sendingChainKey = null,
                    receivingChainKey = null,
                    ourRatchetKeyPair = ownedKeyPair,
                    theirRatchetPublicKey = null,
                    ns = 0,
                    nr = 0,
                    pn = 0,
                    skippedKeys = SkippedMessageKeyStore(),
                    random = random,
                )
            } finally {
                sk.fill(0)
            }
        }

        /** Builds a session from already-validated persisted state; never call this with anything
         * that did not come out of [DoubleRatchetSessionCodec.decode] - mirrors
         * `PrekeyBundle.fromDecoded`'s identical "produces an unverified-by-construction object,
         * callers must have already validated the input" framing, adapted to this class's own
         * invariants (all enforced by the private constructor's own field types, e.g.
         * [X25519PublicKey]'s canonical-encoding checks). */
        internal fun fromDecodedState(
            associatedData: ByteArray,
            rootKey: ByteArray,
            sendingChainKey: ByteArray?,
            receivingChainKey: ByteArray?,
            ourRatchetKeyPair: X25519KeyPair,
            theirRatchetPublicKey: X25519PublicKey?,
            sendMessageNumber: Int,
            receiveMessageNumber: Int,
            previousSendChainLength: Int,
            skippedKeys: SkippedMessageKeyStore,
            random: SecureRandom,
        ): DoubleRatchetSession =
            DoubleRatchetSession(
                associatedData = associatedData,
                rootKey = rootKey,
                sendingChainKey = sendingChainKey,
                receivingChainKey = receivingChainKey,
                ourRatchetKeyPair = ourRatchetKeyPair,
                theirRatchetPublicKey = theirRatchetPublicKey,
                ns = sendMessageNumber,
                nr = receiveMessageNumber,
                pn = previousSendChainLength,
                skippedKeys = skippedKeys,
                random = random,
            )
    }
}
