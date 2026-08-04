package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.ecdhSharedSecret
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_SIZE = 32
private const val HKDF_OKM_SIZE = AES_KEY_SIZE + GCM_NONCE_SIZE // 44
private const val GCM_TAG_BITS = 128

/** Exactly 38 ASCII bytes - fixed length, so concatenating it with the (also fixed-length,
 * 32-byte) wrap AAD digest as HKDF info material is injective without needing a length prefix. */
private val HKDF_INFO_LABEL = "LapisNet:mail-hybrid-ecies:v1:wrap-key".toByteArray(Charsets.US_ASCII)

/**
 * Thrown by [HybridEcies.open] for EVERY failure to recover a plaintext: a wrap that is not
 * addressed to this identity, a tampered ephemeral key, a flipped ciphertext bit, a failed GCM tag
 * on either layer, or - the case this whole design exists for - a wrap/body pair transplanted onto
 * a different envelope (see [MailAadContext]'s class doc comment). Deliberately a single,
 * undifferentiated type, mirroring `KeystoreDecryptionException`: AES-GCM cannot distinguish
 * "wrong key" from "tampered input", and neither should this API, so nothing here can be used as a
 * decryption oracle. No `AEADBadTagException`, `GeneralSecurityException`,
 * `fr.acinq.secp256k1.Secp256k1Exception`, or any other third-party exception ever escapes
 * [HybridEcies.open].
 *
 * The one exception: a [MalformedMessageBodyException] surfacing from step 8 of [HybridEcies.open]
 * (the decrypted plaintext authenticated correctly but does not parse as a [MessageBody])
 * propagates UNCHANGED. A plaintext that authenticates but fails to parse means the sender
 * produced garbage, not that this call failed to decrypt - a different fault, deliberately not
 * conflated with this type.
 */
class MailDecryptionException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Everything [HybridEcies.seal] produces, ready for [MailSender] to store, sign and publish. */
class SealedMessage internal constructor(
    val sealedBody: SealedBody,
    sealedBodyBytes: ByteArray,
    val contentCid: Cid,
    wraps: List<EciesWrap>,
) {
    private val storedSealedBodyBytes: ByteArray = sealedBodyBytes.copyOf()

    /** Returns a fresh copy on every access. */
    val sealedBodyBytes: ByteArray get() = storedSealedBodyBytes.copyOf()

    /** Immutable snapshot. */
    val wraps: List<EciesWrap> = wraps.toList()
}

/**
 * Hybrid ECIES encryption for [MessageBody] payloads (V0.9.2): a fresh AES-256-GCM content key per
 * message encrypts the [MessageBodyCodec]-encoded body into a [SealedBody] blob, and that content
 * key is ECIES-wrapped once per recipient plus once for the sender (so sent mail stays readable to
 * its own sender - "Sender wrappt zusätzlich für sich selbst").
 *
 * **The AAD binding, and the attack it closes.** See [MailAadContext]'s class doc comment for the
 * full design. In short: without it, an attacker could take a legitimately-sealed body and its
 * wraps from one envelope, attach them to a NEW envelope with a substituted sender (or recipient
 * set) that they sign correctly with their OWN key, and produce something that passes every
 * V0.9.1 check (signature, addressing, CID binding) - the recipient's inbox would show a message
 * apparently from the attacker whose content was never sent to them by that identity. Both AEADs
 * here bind the sender, the full recipient set, and the rest of the envelope's content-independent
 * fields via [MailAadContext.contextBytes], so a transplanted wrap/body pair is derived against,
 * and authenticated with, the wrong context and fails to decrypt.
 *
 * **The AAD binding is NOT sender authentication by itself.** It is a cryptographic *binding*
 * between a wrap/body pair and one specific (sender, recipients, timestamp, ...) tuple - it says
 * nothing about who is allowed to construct that tuple in the first place. Nothing in [seal]'s
 * ~40 lines requires a secret: `ECDH(ephemeral_priv, recipient_pub)`, HKDF-SHA256, and AES-256-GCM
 * are all public operations over public keys, so an attacker can reimplement them outside this API
 * against a self-authored [MailAadContext] that claims any sender they like, and produce a
 * wrap/body pair that opens cleanly for a real recipient. What makes `envelope.sender`
 * trustworthy is the envelope's ECDSA signature, not the AAD - which is why [open] verifies
 * [MessageEnvelope.verify] itself before touching any wrap. The `internal` test seam
 * [openWithContext] deliberately skips that check (see its own doc comment) so tests can isolate
 * the AAD binding from the signature check; it must never be exposed outside this module.
 *
 * **The key derivation.** `ikm = ecdhSharedSecret(...)` - confirmed (see
 * `net.lapisphilosophorum.lapisnet.identity.ecdhSharedSecret`'s doc comment) to already be
 * `SHA-256(compressed shared point)`, a full-entropy 32-byte string, not a raw curve coordinate -
 * so no additional pre-hash step is needed before using it as HKDF input keying material.
 * `salt = ephemeralPublicKey.bytes` (33 bytes, non-secret, unique per [seal] call).
 * `info = HKDF_INFO_LABEL || aadForWrap(...)` (38 + 32 = 70 fixed bytes, so the concatenation is
 * injective with no length prefix needed). `HKDF-SHA256(ikm, salt, info, L=44)` (BouncyCastle's
 * low-level `crypto.generators` API, matching `KeystoreEncryption`'s `Argon2BytesGenerator` usage
 * style) yields `wrapKey (32 bytes) || wrapNonce (12 bytes)`. HKDF-Extract is not load-bearing for
 * entropy here (ikm is already uniform) - HKDF-Expand IS load-bearing: it is what makes each
 * recipient slot's derived key a distinct function of `aadForWrap`, so a transplanted wrap fails
 * for two independent reasons (wrong derived key AND wrong GCM AAD), not merely one.
 *
 * **Why the wrap nonce is derived, not transmitted, while the body nonce is random and
 * transmitted.** The wrap key is single-use by construction (a fresh ephemeral keypair per [seal]
 * call and a distinct HKDF context per recipient slot), so nonce reuse is impossible unless the
 * ephemeral key repeats - in which case a transmitted random nonce would not save the scheme
 * either, since the same `SecureRandom` produced both. Deriving it puts zero attacker-controlled
 * nonce bytes on the wire. This is exactly RFC 9180 (HPKE)'s key-schedule shape: derive `key` and
 * `base_nonce` from the KEM shared secret, transmit only `enc`. The body's content key, by
 * contrast, is chosen by the sender and not tied to any freshly-generated asymmetric key, so its
 * AEAD nonce ([SealedBody.nonce]) IS explicit and random - the belt-and-braces choice for that
 * layer, and a second, independent freshness source.
 *
 * **Bounded-work invariant.** [open] performs exactly one ECDH and two AES-GCM operations,
 * independent of how many wraps the envelope carries - the recipient's slot is located BY INDEX
 * (via [MailAadContext.recipients]/sender comparison), never by trial-decrypting every wrap. A
 * trial-decryption loop would let a 65-wrap envelope cost 65 ECDH operations per delivery attempt,
 * an amplification vector this design removes entirely.
 *
 * **Forward secrecy is DELIBERATELY ABSENT.** Archived mail must stay decryptable for as long as
 * the recipient holds their long-term secp256k1 identity key - there is intentionally no ratchet,
 * no ephemeral-key deletion on the recipient side, and no post-compromise security. Compromise of
 * a recipient's long-term private key retroactively exposes every message ever sealed to them.
 * This is the explicit product requirement for a store-and-forward email replacement, not an
 * oversight - V0.8's Double Ratchet is the forward-secret 1:1 channel and is a different
 * subsystem.
 *
 * **Deliberate scope cuts, stated here so they are not mistaken for oversights:**
 * - **No post-quantum hybrid.** secp256k1 ECDH only. A store-and-forward archive is precisely the
 *   harvest-now-decrypt-later target, and this is accepted for now - a PQ-hybrid KEM would be a
 *   new [EncryptionMode] wire value.
 * - **No key rotation for archived mail.** A sealed body is bound to the identity keys that
 *   existed at send time. Rotating an identity key makes previously received mail permanently
 *   unreadable. No re-wrapping path exists.
 * - **No multi-device wrapping.** Exactly one wrap per recipient's single published identity key.
 *   A recipient with two devices must share the private key between them - V0.8's multi-device
 *   sub-wave was cut from this arc.
 * - **[EncryptionMode.MLS_ARCHIVE] stays reserved and rejected** at the same three layers as
 *   V0.9.1 left it - no implementation plan exists in this arc.
 * - **The gossip validator ([InboxGossip]) never decrypts and never holds a private key** - a
 *   positive property, not a limitation: private key material never enters the GossipSub
 *   validator, by construction (it is only ever given a [net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey]).
 */
object HybridEcies {
    /**
     * Seals [body] for [context]'s sender and recipients. [sender] must be the keypair for
     * `context.sender` - this, together with requiring `context.encryption == HYBRID_ECIES`, makes
     * sealing against a mismatched envelope structurally impossible.
     */
    fun seal(
        body: MessageBody,
        sender: Secp256k1KeyPair,
        context: MailAadContext,
        random: SecureRandom = SecureRandom(),
    ): SealedMessage {
        require(context.encryption == EncryptionMode.HYBRID_ECIES) {
            "MailAadContext.encryption must be HYBRID_ECIES to seal, was ${context.encryption}"
        }
        require(context.sender == sender.publicKey) {
            "sender keypair does not match context.sender - sealing against a mismatched context " +
                "would produce mail nobody (including the sender) could ever open"
        }

        val plaintext = MessageBodyCodec.encode(body)
        require(plaintext.size <= SealedBodyCodec.MAX_PLAINTEXT_BYTES) {
            "encoded body (${plaintext.size} bytes) exceeds the ${SealedBodyCodec.MAX_PLAINTEXT_BYTES}-byte " +
                "limit a sealed body can carry"
        }

        val contentKey = ByteArray(AES_KEY_SIZE).also(random::nextBytes)
        // Mirrors Ed25519Keys.kt's SecureRandom sanity guard: an all-zero key is the classic
        // symptom of a broken or mocked SecureRandom, rejected here rather than silently sealing
        // with a degenerate key.
        require(!contentKey.all { it == 0.toByte() }) {
            "generated content key must not be all-zero (likely broken RNG)"
        }
        val bodyNonce = ByteArray(GCM_NONCE_SIZE).also(random::nextBytes)

        try {
            val ciphertext = aesGcmEncrypt(contentKey, bodyNonce, context.aadForBody(), plaintext)
            val sealed = SealedBody(bodyNonce, ciphertext)
            val sealedBytes = SealedBodyCodec.encode(sealed)
            val contentCid = MessageBodyCodec.cidFor(sealedBytes)

            val ephemeral = Secp256k1KeyPair.generate(random)
            val wraps =
                (0 until context.wrapCount).map { slotIndex ->
                    val slotKey = context.slotKey(slotIndex)
                    val shared = ecdhSharedSecret(ephemeral.privateKey, slotKey)
                    try {
                        val aad = context.aadForWrap(slotIndex, slotKey, ephemeral.publicKey, contentCid)
                        val (wrapKey, wrapNonce) = deriveWrapKeyAndNonce(shared, ephemeral.publicKey.bytes, aad)
                        try {
                            val wrappedKey = aesGcmEncrypt(wrapKey, wrapNonce, aad, contentKey)
                            EciesWrap(ephemeral.publicKey, wrappedKey)
                        } finally {
                            wrapKey.fill(0)
                            wrapNonce.fill(0)
                        }
                    } finally {
                        shared.fill(0)
                    }
                }

            return SealedMessage(sealed, sealedBytes, contentCid, wraps)
        } finally {
            contentKey.fill(0)
            plaintext.fill(0)
        }
    }

    /** Opens an envelope's sealed body for [localIdentity]. Verifies [envelope]'s signature itself
     * - callers do NOT need to call [MessageEnvelope.verify] first. This matters because the AAD
     * binding (see [MailAadContext]'s class doc comment) is a binding, not an authentication: an
     * attacker who reimplements [seal]'s handful of ECDH/HKDF/AES-GCM steps outside this API - no
     * secret material is required - can produce a wrap/body pair that decrypts cleanly under a
     * self-authored context claiming any sender they like. Without a signature check, such a forged
     * envelope would open exactly as successfully as a genuine one; the signature is what makes
     * `envelope.sender` trustworthy. @throws MailDecryptionException on any failure to recover the
     * plaintext - see that type's doc comment for the full list of causes it funnels together
     * (including a failed signature check). */
    fun open(
        envelope: MessageEnvelope,
        sealedBody: SealedBody,
        localIdentity: Secp256k1KeyPair,
    ): MessageBody {
        if (envelope.encryption != EncryptionMode.HYBRID_ECIES) {
            throw MailDecryptionException("envelope encryption mode is ${envelope.encryption}, not HYBRID_ECIES")
        }
        if (!MessageEnvelope.verify(envelope)) {
            throw MailDecryptionException("envelope signature does not verify")
        }
        val context = MailAadContext.of(envelope)
        val sealedBytes = SealedBodyCodec.encode(sealedBody)
        if (MessageBodyCodec.cidFor(sealedBytes) != envelope.contentCid) {
            throw MailDecryptionException("sealed body does not match the envelope's contentCid")
        }
        return openWithContext(context, envelope.contentCid, envelope.wraps, sealedBody, localIdentity)
    }

    /** Test seam - lets a test open the SAME wrap bytes under two different [MailAadContext]s and
     * prove that the context, and nothing else, decides success (see `HybridEciesAdversarialTest`'s
     * wrap-transplant case). `internal`, mirroring `InboxGossip.onGossipMessage`'s own documented
     * test-seam visibility reasoning.
     *
     * **Deliberately does NOT call [MessageEnvelope.verify]** - unlike [open], which does. This
     * function takes a bare [MailAadContext] rather than a [MessageEnvelope], so there is no
     * signature to check; that is precisely what lets tests prove the AAD binding is sufficient on
     * its own, independent of the signature check [open] additionally performs. Never call this
     * from production code - [open] is the only sound public entry point. */
    internal fun openWithContext(
        context: MailAadContext,
        contentCid: Cid,
        wraps: List<EciesWrap>,
        sealedBody: SealedBody,
        localIdentity: Secp256k1KeyPair,
    ): MessageBody {
        val recipientSlot = context.recipients.indexOf(localIdentity.publicKey)
        val slotIndex =
            when {
                recipientSlot >= 0 -> recipientSlot
                localIdentity.publicKey == context.sender -> context.recipients.size
                else -> -1
            }
        if (slotIndex < 0) {
            throw MailDecryptionException("no wrap in this envelope is addressed to this identity")
        }
        val wrap =
            wraps.getOrNull(slotIndex)
                ?: throw MailDecryptionException("this envelope carries no wrap at slot $slotIndex")

        try {
            val shared = ecdhSharedSecret(localIdentity.privateKey, wrap.ephemeralPublicKey)
            val contentKey: ByteArray
            try {
                val aad = context.aadForWrap(slotIndex, context.slotKey(slotIndex), wrap.ephemeralPublicKey, contentCid)
                val (wrapKey, wrapNonce) = deriveWrapKeyAndNonce(shared, wrap.ephemeralPublicKey.bytes, aad)
                try {
                    contentKey = aesGcmDecrypt(wrapKey, wrapNonce, aad, wrap.wrappedKey)
                } finally {
                    wrapKey.fill(0)
                    wrapNonce.fill(0)
                }
            } finally {
                shared.fill(0)
            }

            try {
                val plaintext = aesGcmDecrypt(contentKey, sealedBody.nonce, context.aadForBody(), sealedBody.ciphertext)
                try {
                    return MessageBodyCodec.decode(plaintext)
                } finally {
                    plaintext.fill(0)
                }
            } finally {
                contentKey.fill(0)
            }
        } catch (e: MalformedMessageBodyException) {
            // Authenticated correctly but did not parse - the SENDER's fault, not a decryption
            // failure. Propagates unchanged, deliberately not wrapped in MailDecryptionException -
            // see that type's doc comment.
            throw e
        } catch (e: MailDecryptionException) {
            throw e
        } catch (e: AEADBadTagException) {
            throw MailDecryptionException("decryption failed: tampered or mismatched ciphertext/AAD", e)
        } catch (e: GeneralSecurityException) {
            throw MailDecryptionException("decryption failed: ${e.message}", e)
        } catch (e: RuntimeException) {
            // Covers fr.acinq.secp256k1.Secp256k1Exception and any other third-party exception -
            // open() must never leak an arbitrary exception type to callers, mirroring
            // KeystoreEncryption.decrypt's identical funnel.
            throw MailDecryptionException("decryption failed: ${e.message}", e)
        }
    }

    /** `HKDF-SHA256(ikm, salt, info, L=44)` -> `(wrapKey[0..31], wrapNonce[32..43])`. See this
     * object's class doc comment for the exact construction and why it is correct given
     * `ecdhSharedSecret`'s confirmed output shape. */
    private fun deriveWrapKeyAndNonce(
        ikm: ByteArray,
        salt: ByteArray,
        aad: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val info = HKDF_INFO_LABEL + aad
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info))
        val okm = ByteArray(HKDF_OKM_SIZE)
        generator.generateBytes(okm, 0, okm.size)
        val wrapKey = okm.copyOfRange(0, AES_KEY_SIZE)
        val wrapNonce = okm.copyOfRange(AES_KEY_SIZE, HKDF_OKM_SIZE)
        okm.fill(0)
        return wrapKey to wrapNonce
    }

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

    private fun aesGcmDecrypt(
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
}
