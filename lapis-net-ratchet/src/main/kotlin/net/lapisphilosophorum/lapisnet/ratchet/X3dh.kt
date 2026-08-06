package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.security.SecureRandom
import java.time.Instant

/** X3DH spec section 2.2's `F`: a byte sequence of `0xFF` bytes with length equal to the curve's
 * field-element size - 32 for X25519 (57 for X448, which this project does not implement). Domain-
 * separates this construction from any other protocol that might otherwise produce colliding DH
 * outputs, per the Signal spec's own stated rationale. `internal` (rather than `private`) so
 * [X3dhKnownAnswerTest] can pin this exact constant directly, rather than only indirectly via the
 * assembled IKM's length - see that test's doc comment. */
internal const val F_PREFIX_LENGTH = 32
internal val F_PREFIX = ByteArray(F_PREFIX_LENGTH) { 0xFF.toByte() }

/** X3DH spec section 2.2: the HKDF salt is a zero-filled byte sequence of the hash output length -
 * 32 zero bytes for SHA-256. Passing the explicit 32-zero-byte value here (rather than `null`) is
 * spec-literal and self-documenting - it also happens to be equivalent to `null` under HMAC's own
 * key-padding rule (HMAC zero-pads any key shorter than the hash's block size, so a 0-byte and a
 * 32-zero-byte HMAC key produce byte-identical results per RFC 5869's own "if not provided, it is
 * set to a string of HashLen zeros"), which is also what makes BouncyCastle's `HKDFParameters`
 * collapse a `null` salt to a zero-length one - measured against the resolved `bcprov-jdk18on`
 * jar. Do not read that BC-internal collapse as evidence that `null` would produce a WRONG key
 * schedule here; it would not - HKDF-Extract's use of the salt as an HMAC key makes the two forms
 * genuinely equivalent, not merely coincidentally so. `internal` so [X3dhKnownAnswerTest] can
 * assert against this constant directly - see that test's doc comment. */
internal val HKDF_SALT = ByteArray(32)

/** Exactly 31 ASCII bytes - fixed length, so concatenating it with the (also fixed-length, 71-byte)
 * associated data as HKDF `info` material is injective without needing a length prefix. Versioned
 * (`v1`) so a future change to this wave's key schedule can never silently collide with this one.
 * `internal` so [X3dhKnownAnswerTest] can assert against this constant directly, rather than
 * re-declaring its own local copy of the label text - see that test's doc comment. */
internal val HKDF_INFO_LABEL = "LapisNet:x3dh:v1:X25519:SHA-256".toByteArray(Charsets.US_ASCII)

private const val SHARED_SECRET_SIZE = 32

/** Associated-data header magic, mirroring `net.lapisphilosophorum.lapisnet.mail.MailAadContext`'s
 * own `"LNAC"` magic + version precedent. */
private val AD_MAGIC = "LNX3".toByteArray(Charsets.US_ASCII)
private const val AD_VERSION: Byte = 1

/** `4 (magic) + 1 (version) + 33 (initiator identity) + 33 (responder identity)`. */
private const val AD_SIZE = 4 + 1 + 33 + 33

/** The exact, fixed size of [X3dh.associatedData]'s output - 71 bytes. `internal` (and not merely
 * a private constant) so [DoubleRatchetSession] and [DoubleRatchetSessionCodec] can VALIDATE the
 * associated data they are handed and persist/reload, rather than trusting a length. Fixedness is
 * load-bearing downstream, not cosmetic: the Double Ratchet concatenates its own fixed-length HKDF
 * info labels with this value without a length prefix, which is injective only because BOTH parts
 * have a fixed length - see [RatchetKdf]'s class doc comment. */
internal const val X3DH_ASSOCIATED_DATA_SIZE = AD_SIZE

/** Thrown for every X3DH handshake failure - a bundle/header that fails one of the mandatory
 * pre-DH checks, a mismatched key, or an internal invariant violation. Deliberately a single,
 * undifferentiated type for the pre-DH validation failures (mirroring
 * `net.lapisphilosophorum.lapisnet.mail.MailDecryptionException`'s "nothing here can be used as an
 * oracle" reasoning) - a caller does not get to distinguish "wrong signature" from "expired bundle"
 * from "self-handshake attempted" via exception subtype, only via the message. */
class X3dhException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * The initiator-supplied header a responder needs to reproduce the handshake - the X3DH "initial
 * message" header fields (everything except the ciphertext of the first application message,
 * which is out of scope for this wave, see this file's class doc comment below).
 *
 * **Deliberately has NO wire codec in this sub-wave.** This wave's deliverable is the handshake
 * primitive and the prekey publication/consumption machinery, callable and independently testable
 * - not yet wired into a live message-send path. The initial-message wire format (how this header
 * travels alongside the first Double-Ratchet-encrypted application message) is V0.8.3's/V0.8.4's
 * to define; inventing one here would only have to be changed then.
 */
class X3dhPreKeyMessageHeader(
    val initiatorIdentity: Secp256k1PublicKey,
    val initiatorEncryptionBinding: EncryptionKeyBinding,
    val ephemeralPublicKey: X25519PublicKey,
    val signedPrekeyId: Int,
    val oneTimePrekeyId: Int?,
) {
    /** The initiator's X25519 identity key - a read-through alias into
     * [initiatorEncryptionBinding], mirroring [PrekeyBundle.x25519IdentityKey]'s identical
     * never-a-second-copy discipline. */
    val initiatorX25519IdentityKey: X25519PublicKey get() = initiatorEncryptionBinding.x25519PublicKey

    init {
        require(signedPrekeyId >= 0) { "signedPrekeyId must be >= 0, was $signedPrekeyId" }
        require(oneTimePrekeyId == null || oneTimePrekeyId >= 0) {
            "oneTimePrekeyId must be null or >= 0, was $oneTimePrekeyId"
        }
    }

    override fun toString(): String =
        "X3dhPreKeyMessageHeader(initiatorIdentity=${initiatorIdentity.fingerprint()}, " +
            "ephemeralPublicKey=$ephemeralPublicKey, signedPrekeyId=$signedPrekeyId, oneTimePrekeyId=$oneTimePrekeyId)"
}

/**
 * The handshake output. Carries the derived shared secret AND the associated data as a single,
 * inseparable unit - **the two must never be separated or used independently**, because the
 * associated data is what makes the derived secret specific to one (initiator, responder) identity
 * pair (see [X3dh]'s own class doc comment for the full "unknown key share" analysis this closes).
 * `equals`/`hashCode` are deliberately NOT overridden - `ByteArray`'s reference-identity default
 * gives no accidental constant-time-unsafe comparison surface; tests compare contents explicitly
 * via `org.bouncycastle.util.Arrays.constantTimeAreEqual` or `contentEquals`, never `shouldBe` on
 * this class directly.
 */
class X3dhSharedSecret internal constructor(
    sharedSecret: ByteArray,
    associatedData: ByteArray,
) {
    private val storedSharedSecret: ByteArray = sharedSecret.copyOf()
    private val storedAssociatedData: ByteArray = associatedData.copyOf()

    /** Returns a fresh copy on every access. */
    val sharedSecret: ByteArray get() = storedSharedSecret.copyOf()

    /** Returns a fresh copy on every access. */
    val associatedData: ByteArray get() = storedAssociatedData.copyOf()

    /** Zeroes the backing shared-secret bytes in place. Does not zero [associatedData] - it is not
     * secret. */
    fun destroy() {
        storedSharedSecret.fill(0)
    }

    override fun toString(): String = "X3dhSharedSecret(REDACTED)"
}

class X3dhInitiation internal constructor(
    val header: X3dhPreKeyMessageHeader,
    val session: X3dhSharedSecret,
)

/**
 * X3DH (Signal's Extended Triple Diffie-Hellman), reimplemented from the public specification -
 * not adapted from libsignal, which is AGPL-3.0-licensed and therefore incompatible with this
 * Apache-2.0 project (verified 2026-08-04 during this arc's planning pass; a closed licensing
 * question, not a re-litigable design choice).
 *
 * **This is the highest-risk primitive in the codebase to date.** Every prior wave in this project
 * reused already-established cryptographic primitives (AES-256-GCM, HKDF-SHA256, secp256k1
 * ECDH/ECDSA, Ed25519) in new combinations; X3DH itself - the multi-DH handshake protocol, its
 * associated-data construction, its HKDF info-string derivation - has no precedent anywhere in this
 * codebase and is built here directly from the published Signal specification.
 *
 * **The byte-level construction, pinned exactly (see [X3dhKnownAnswerTest] for the regression that
 * locks every constant below):**
 * ```
 * DH1 = X25519(IK_A, SPK_B)      // initiator identity   x responder signed prekey
 * DH2 = X25519(EK_A, IK_B)       // initiator ephemeral   x responder identity
 * DH3 = X25519(EK_A, SPK_B)      // initiator ephemeral   x responder signed prekey
 * DH4 = X25519(EK_A, OPK_B)      // initiator ephemeral   x responder one-time prekey [omitted if none]
 *
 * IKM  = F (32 x 0xFF) || DH1 || DH2 || DH3 [|| DH4]     // 128 or 160 bytes
 * salt = 32 zero bytes
 * info = "LapisNet:x3dh:v1:X25519:SHA-256" (31 bytes) || AD (71 bytes)     // 102 bytes
 * SK   = HKDF-SHA256-Expand(HKDF-SHA256-Extract(salt, IKM), info, L = 32)
 * ```
 * `DH4` is appended at the end when a one-time prekey is used and entirely OMITTED otherwise -
 * never zero-filled, never reordered. Because its presence/absence changes the IKM length (128 vs
 * 160 bytes), the two cases are trivially domain-separated by HKDF-Extract itself - confirmed by
 * [X3dhKnownAnswerTest]'s pinned hex vector, which would fail if `DH4` were silently dropped from
 * (or zero-filled into) the derivation. (`X3dhAdversarialTest`'s and `X3dhTest`'s own "with vs.
 * without a one-time prekey" comparisons also observe the two secrets differing, but each varies
 * enough OTHER inputs alongside `DH4` - a different responder identity, or a fresh ephemeral per
 * call - that the inequality they observe is over-determined and does not by itself isolate this
 * property; the known-answer test's single pinned IKM/output pair is what actually does.)
 *
 * **X25519's output is the raw shared u-coordinate, NOT hashed - the opposite of this codebase's
 * secp256k1 `ecdhSharedSecret`, which already returns `SHA-256(compressed point)`.** See
 * [net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret]'s own doc comment for the measured
 * evidence. Consequence: HKDF-Extract over the assembled IKM above is genuinely LOAD-BEARING for
 * entropy-smoothing in this key schedule, not belt-and-braces.
 *
 * **The associated data (AD), and why it is built from the secp256k1 IDENTITY keys, never the
 * X25519 sub-keys.** `AD = "LNX3" || 0x01 || IK_A.bytes (33, secp256k1 compressed) || IK_B.bytes
 * (33, secp256k1 compressed)` - 71 fixed bytes, initiator-first ALWAYS (never sorted, never
 * symmetric). This is the mechanism that closes the "unknown key share" gap
 * [EncryptionKeyBinding] and [PrekeyBundle] leave open by construction (see [PrekeyBundle]'s class
 * doc comment for the full attack): because an X25519 key cannot sign, anyone can mint a FRESH,
 * self-consistent [EncryptionKeyBinding] over a victim's PUBLIC X25519 identity key/signed
 * prekey/one-time prekeys and publish it under their OWN secp256k1 identity - all three of
 * [PrekeyBundle.verify]/`verifyEncryptionBinding`/`verifySignedPrekey` then genuinely pass. If Alice
 * initiates against "Mallory"'s bundle built this way, she derives DH values that only the REAL
 * holder of the X25519 private keys (Bob, not Mallory) can reproduce - Mallory cannot complete the
 * handshake, so this is NOT by itself a confidentiality break. What WOULD make it one: if Alice's
 * and Bob's respective ADs happened to match despite the two parties disagreeing about who the
 * responder is. Building AD from the secp256k1 identities (`IK_Mallory` on Alice's side vs.
 * `IK_Bob` on Bob's side - the X25519 keys are IDENTICAL in this specific attack, since Bob's real
 * keys are what got copied) makes the two ADs - and therefore, because AD is folded into HKDF
 * `info` below, the two SHARED SECRETS - genuinely DIFFERENT. Alice's first message, encrypted
 * under her own derived secret and intended for "Mallory", then simply fails to decrypt for Bob (or
 * for anyone) rather than opening cleanly for whichever party happens to hold the matching private
 * keys. See [X3dhAdversarialTest]'s case (e2) for the full, executable proof, and
 * `docs/architecture.adoc`'s V0.8.2 section for the complete write-up including the residual,
 * accepted "DoS/confusion, not confidentiality break" risk this construction leaves open.
 *
 * **Deliberate deviation from X3DH section 2.2's fixed `info` string: AD is folded into
 * `info`, not left to a downstream AEAD's associated-data slot alone.** If AD lived only in a
 * future Double-Ratchet AEAD's AD parameter (the literal X3DH spec's own approach), the protection
 * above would depend on that FUTURE layer remembering to use it - a layer that forgets still
 * derives IDENTICAL session keys on both sides, silently reintroducing the confidentiality break.
 * Folding AD into HKDF `info` here means the two parties derive DIFFERENT shared secrets the moment
 * their views of "who is the responder" diverge, unconditionally, with no future wiring required to
 * benefit from it. Direct precedent for this reasoning already exists in this codebase:
 * `net.lapisphilosophorum.lapisnet.mail.HybridEcies`'s class doc comment states almost exactly this
 * argument for its own wrap-key derivation ("HKDF-Expand IS load-bearing: it is what makes each
 * recipient slot's derived key a distinct function of `aadForWrap`, so a transplanted wrap fails for
 * two independent reasons... not merely one"). HKDF `info` is public, non-secret domain-separation
 * input to a PRF; adding fixed-length public context to it cannot weaken the derivation.
 *
 * **Explicit, deliberate scope cuts for this wave (stated here rather than silently omitted):**
 * - No PQXDH / post-quantum hybrid key exchange.
 * - No formal deniability analysis beyond X3DH's own published security properties.
 * - No wire codec for [X3dhPreKeyMessageHeader] - see that class's own doc comment.
 * - **No replay protection for a repeated identical initial message - and V0.8.3's Double Ratchet
 *   session layer only PARTIALLY closes this, corrected from an earlier overstatement.** Replay
 *   detection needs per-session state, and [X3dh] is a stateless pure function by design. What THIS
 *   wave DOES provide toward it: a one-time prekey, once consumed via
 *   [PrekeyStore.consumeOneTimePrekey], is durably consumed, so a replayed initiation naming a
 *   one-time prekey is refused at the store layer, before [respond] is ever reached. A replay
 *   naming NO one-time prekey (an exhausted bundle, or an initiator that chose none) is NOT detected
 *   by anything in this wave - see [X3dhAdversarialTest]'s case (f) for the explicit, tested
 *   boundary this leaves. **V0.8.3's `DoubleRatchetSession` closes only the per-message half of this
 *   gap** (delete-on-use of skipped message keys, and rejection of a message number already
 *   consumed, within ONE already-established session) - it does NOT close the other half: a
 *   replayed X3DH initial message naming no one-time prekey still lets a responder derive the same
 *   `SK` twice and construct TWO INDEPENDENT `DoubleRatchetSession` objects, and nothing in either
 *   session's own state machine can see across to the other. Closing that needs a durable session
 *   registry keyed by the initiator's ephemeral public key, which remains V0.8.4's to build.
 * - **One-time prekey collisions are inherent to gossip publication**, unlike Signal's server (which
 *   hands each one-time prekey to exactly one requester): a gossip-published [PrekeyBundle] is seen
 *   in full by every subscriber, so two initiators can independently pick the same one-time prekey;
 *   the second responder-side [PrekeyStore.consumeOneTimePrekey] then fails and that initiator must
 *   retry with `preferredOneTimePrekeyId = null`, falling back to signed-prekey-only X3DH - the same
 *   class of degradation X3DH itself documents for prekey exhaustion.
 * - **The one-time-prekey rule a caller (a future wiring layer, V0.8.4) MUST obey, stated in bold
 *   because getting it wrong reopens exactly the reuse [PrekeyStore] closes:** consume the one-time
 *   prekey BEFORE calling [respond], and if consumption fails (unknown or already-consumed id), the
 *   responder MUST abort the handshake entirely, NEVER retry [respond] with
 *   `consumedOneTimePrekey = null`. Falling back would let a replayed initiation whose
 *   one-time prekey was already used still obtain a valid session, defeating one-time prekeys
 *   entirely. This is a DIFFERENT situation from prekey EXHAUSTION (an initiator-side condition - a
 *   bundle carrying zero one-time prekeys to begin with), where DH1-DH3-only X3DH is the correct,
 *   spec-sanctioned degradation - the two must never be conflated. [respond] additionally asserts
 *   that the consumed id itself matches `header.oneTimePrekeyId` (see [respond]'s own doc comment,
 *   check 3) - [PrekeyStore.consumeOneTimePrekey] returns a [ConsumedOneTimePrekey] precisely so
 *   this can be enforced in code, not merely documented as a caller obligation.
 */
object X3dh {
    /** The exact bytes bound into both the AEAD-style associated data and (via [HKDF_INFO_LABEL])
     * the HKDF `info` string - see this object's class doc comment for the full analysis of why
     * this is built from the secp256k1 IDENTITY keys, initiator-first, never sorted. */
    internal fun associatedData(
        initiatorIdentity: Secp256k1PublicKey,
        responderIdentity: Secp256k1PublicKey,
    ): ByteArray {
        val ad = ByteArray(AD_SIZE)
        var offset = 0
        AD_MAGIC.copyInto(ad, offset)
        offset += AD_MAGIC.size
        ad[offset] = AD_VERSION
        offset += 1
        initiatorIdentity.bytes.copyInto(ad, offset)
        offset += 33
        responderIdentity.bytes.copyInto(ad, offset)
        offset += 33
        check(offset == AD_SIZE) { "associatedData assembly produced an unexpected size" }
        return ad
    }

    /** `HKDF-SHA256(ikm, salt, info, L = length)`, exposed internally so
     * [X3dhKnownAnswerTest] can pin RFC 5869's published vectors against THIS module's own call
     * path, not a reimplementation of it. */
    internal fun hkdfSha256(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info))
        val okm = ByteArray(length)
        generator.generateBytes(okm, 0, length)
        return okm
    }

    private fun deriveSharedSecret(
        dh1: ByteArray,
        dh2: ByteArray,
        dh3: ByteArray,
        dh4: ByteArray?,
        associatedData: ByteArray,
    ): ByteArray {
        val ikmSize = F_PREFIX_LENGTH + dh1.size + dh2.size + dh3.size + (dh4?.size ?: 0)
        val ikm = ByteArray(ikmSize)
        try {
            var offset = 0
            F_PREFIX.copyInto(ikm, offset)
            offset += F_PREFIX.size
            dh1.copyInto(ikm, offset)
            offset += dh1.size
            dh2.copyInto(ikm, offset)
            offset += dh2.size
            dh3.copyInto(ikm, offset)
            offset += dh3.size
            if (dh4 != null) {
                dh4.copyInto(ikm, offset)
                offset += dh4.size
            }
            check(offset == ikmSize) { "IKM assembly produced an unexpected size" }

            val info = HKDF_INFO_LABEL + associatedData
            return hkdfSha256(ikm, HKDF_SALT, info, SHARED_SECRET_SIZE)
        } finally {
            ikm.fill(0)
        }
    }

    /**
     * Initiates an X3DH handshake against [bundle]. Performs the following checks, in exactly this
     * order, ALL before any DH computation runs:
     * 1. [PrekeyBundle.verify] - the bundle's outer signature.
     * 2. [verifyEncryptionBinding] - rejects a bundle whose encryption binding was signed by a
     *    DIFFERENT identity than its own claimed [PrekeyBundle.identity] (the verbatim-transplant
     *    unknown-key-share shape).
     * 3. [verifySignedPrekey] - rejects a forged/tampered signed-prekey signature.
     * 4. The bundle must not be expired.
     * 5. The bundle must not claim to be its own initiator's identity (a self-handshake is
     *    meaningless: AD would be `IK_A || IK_A`).
     * 6. [initiatorEncryptionBinding] must itself verify against [initiatorIdentity] - publishing a
     *    header no responder could validate would be pointless.
     * 7. [initiatorX25519IdentityPrivateKey] must actually match [initiatorEncryptionBinding]'s
     *    public key.
     *
     * Then selects a one-time prekey ([preferredOneTimePrekeyId] if given - it must exist in
     * [bundle], else [X3dhException] - otherwise uniformly at random from [bundle]'s list via
     * [random], or none if the bundle carries none), generates a fresh ephemeral X25519 keypair,
     * computes DH1-DH3 (+DH4 if a one-time prekey was selected), derives the shared secret, and
     * destroys the ephemeral private key before returning.
     */
    fun initiate(
        initiatorIdentity: Secp256k1PublicKey,
        initiatorEncryptionBinding: EncryptionKeyBinding,
        initiatorX25519IdentityPrivateKey: X25519PrivateKey,
        bundle: PrekeyBundle,
        nowEpochSecond: Long = Instant.now().epochSecond,
        preferredOneTimePrekeyId: Int? = null,
        random: SecureRandom = SecureRandom(),
    ): X3dhInitiation {
        if (!PrekeyBundle.verify(bundle)) throw X3dhException("prekey bundle signature does not verify")
        if (!bundle.verifyEncryptionBinding()) {
            throw X3dhException(
                "prekey bundle's encryption key binding does not verify against the bundle's own claimed identity",
            )
        }
        if (!bundle.verifySignedPrekey()) throw X3dhException("prekey bundle's signed prekey signature does not verify")
        if (bundle.notValidAfterEpochSecond < nowEpochSecond) {
            throw X3dhException("prekey bundle expired at ${bundle.notValidAfterEpochSecond}, now is $nowEpochSecond")
        }
        if (bundle.identity == initiatorIdentity) {
            throw X3dhException("refusing to initiate an X3DH handshake against one's own identity")
        }
        if (!EncryptionKeyBinding.verify(initiatorIdentity, initiatorEncryptionBinding)) {
            throw X3dhException("initiator's own encryption key binding does not verify against initiatorIdentity")
        }
        // publicKeyFor, not fromPrivateKeyBytes: only the public key is needed here, so this must
        // not retain a second, separately-owned X25519PrivateKey wrapping a copy of the caller's
        // long-term identity scalar for the rest of this call - see that helper's doc comment.
        val derivedInitiatorX25519Public = X25519KeyPair.publicKeyFor(initiatorX25519IdentityPrivateKey)
        if (derivedInitiatorX25519Public != initiatorEncryptionBinding.x25519PublicKey) {
            throw X3dhException(
                "initiatorX25519IdentityPrivateKey does not match initiatorEncryptionBinding's public key",
            )
        }

        val oneTimePrekey =
            when {
                preferredOneTimePrekeyId != null ->
                    bundle.oneTimePrekeys.find { it.id == preferredOneTimePrekeyId }
                        ?: throw X3dhException(
                            "preferredOneTimePrekeyId $preferredOneTimePrekeyId is not present in this bundle",
                        )
                bundle.oneTimePrekeys.isEmpty() -> null
                else -> bundle.oneTimePrekeys[random.nextInt(bundle.oneTimePrekeys.size)]
            }

        val ephemeral = X25519KeyPair.generate(random)
        try {
            val ad = associatedData(initiatorIdentity, bundle.identity)
            var dh1: ByteArray? = null
            var dh2: ByteArray? = null
            var dh3: ByteArray? = null
            var dh4: ByteArray? = null
            try {
                // The DH computations themselves live INSIDE this try (not just deriveSharedSecret's
                // use of their results) so a throw from x25519SharedSecret partway through - e.g. on
                // dh2/dh3/dh4 - still reaches the finally below and zeroes whichever earlier DH
                // outputs were already computed, rather than leaking them on the heap. See
                // x25519SharedSecret's own doc comment for why X25519AgreementException, though
                // unreachable via this class's public API today, remains a declared possibility this
                // code defends against rather than assumes away.
                dh1 = x25519SharedSecret(initiatorX25519IdentityPrivateKey, bundle.signedPrekey)
                dh2 = x25519SharedSecret(ephemeral.privateKey, bundle.x25519IdentityKey)
                dh3 = x25519SharedSecret(ephemeral.privateKey, bundle.signedPrekey)
                dh4 = oneTimePrekey?.let { x25519SharedSecret(ephemeral.privateKey, it.publicKey) }
                val sharedSecretBytes = deriveSharedSecret(dh1, dh2, dh3, dh4, ad)
                val session = X3dhSharedSecret(sharedSecretBytes, ad)
                sharedSecretBytes.fill(0)
                val header =
                    X3dhPreKeyMessageHeader(
                        initiatorIdentity = initiatorIdentity,
                        initiatorEncryptionBinding = initiatorEncryptionBinding,
                        ephemeralPublicKey = ephemeral.publicKey,
                        signedPrekeyId = bundle.signedPrekeyId,
                        oneTimePrekeyId = oneTimePrekey?.id,
                    )
                return X3dhInitiation(header, session)
            } finally {
                dh1?.fill(0)
                dh2?.fill(0)
                dh3?.fill(0)
                dh4?.fill(0)
            }
        } finally {
            ephemeral.privateKey.destroy()
        }
    }

    /**
     * Responds to an X3DH initiation described by [header]. Performs the following checks, in
     * exactly this order, ALL before any DH computation runs:
     * 1. [header]'s `signedPrekeyId` must match [responderSignedPrekeyId] (the responder rotated;
     *    the initiator used a stale bundle).
     * 2. [header]'s `initiatorEncryptionBinding` must verify against `header.initiatorIdentity` -
     *    the responder-side mirror of [initiate]'s check 6; without it the initiator's ephemeral/
     *    identity DH inputs would be entirely unbound to any accountable identity.
     * 3. `header.oneTimePrekeyId` and [consumedOneTimePrekey] must both be present or both absent,
     *    AND, when both present, `consumedOneTimePrekey.id` must equal `header.oneTimePrekeyId` -
     *    **see this object's class doc comment for the mandatory caller contract this enforces**: a
     *    caller must consume the one-time prekey NAMED IN THE HEADER via
     *    [PrekeyStore.consumeOneTimePrekey] BEFORE calling this function, and never retry with
     *    `null` if that consumption failed. The id-equality half of this check exists precisely
     *    because [ConsumedOneTimePrekey] carries its own id: a caller wiring bug that consumes the
     *    WRONG id (plausible once a real call site exists, in V0.8.4 - a bare private key carries no
     *    id to cross-check) would otherwise derive a silently-mismatched secret that only surfaces
     *    much later, at first AEAD use, with no diagnostic pointing at the real cause. Failing loudly
     *    here instead turns that class of bug into an immediate, obvious [X3dhException].
     * 4. `header.initiatorIdentity` must not equal [responderIdentity] (mirrors [initiate]'s
     *    self-handshake refusal).
     * 5. [responderEncryptionBinding] must verify against [responderIdentity] - the responder-side
     *    mirror of [initiate]'s check 6, now applied to the RESPONDER's own material.
     * 6. [responderX25519IdentityPrivateKey] must actually derive to [responderEncryptionBinding]'s
     *    public key - the responder-side mirror of [initiate]'s check 7.
     * 7. [responderSignedPrekeyPrivateKey] must actually derive to [responderSignedPrekeyPublicKey] -
     *    a responder-specific self-check with no [initiate]-side analogue, closing the gap where
     *    check 1 above only compares the signed-prekey ID integer, not the key material itself.
     *
     * The responder-side DH mirror produces byte-IDENTICAL outputs to the initiator's:
     * `DH1 = X25519(SPK_B, IK_A)`, `DH2 = X25519(IK_B, EK_A)`, `DH3 = X25519(SPK_B, EK_A)`,
     * `DH4 = X25519(OPK_B, EK_A)` if consumed.
     *
     * **Mirrors [initiate]'s checks 6 and 7 for the RESPONDER's own key material (checks 5-7
     * above).** [initiate] verifies both that the INITIATOR's own [EncryptionKeyBinding] verifies
     * against `initiatorIdentity` (check 6) and that `initiatorX25519IdentityPrivateKey` actually
     * derives to that binding's public key (check 7). [respond] verifies the initiator's binding
     * (check 2, this function's mirror of [initiate]'s check 6) and - as of this hardening pass -
     * ALSO verifies [responderEncryptionBinding] against [responderIdentity] (check 5, the mirror of
     * [initiate]'s check 6 for the responder's own material) and that
     * [responderX25519IdentityPrivateKey] actually derives to [responderEncryptionBinding]'s public
     * key (check 6, the mirror of [initiate]'s check 7). A THIRD, responder-specific self-check
     * (check 7, with no [initiate]-side analogue, since an initiator has no equivalent "signed
     * prekey it published under an id") additionally confirms [responderSignedPrekeyPrivateKey]
     * actually derives to [responderSignedPrekeyPublicKey] - the public key this responder actually
     * published under [responderSignedPrekeyId] - not merely that the id INTEGER matches [header]
     * (check 1). Before this hardening pass, a caller that passed a `signedPrekeyId`/
     * `signedPrekeyPrivateKey` pair pulled from two different snapshots (e.g. a stale [PrekeyStore]
     * handle after another handle's `rotateSignedPrekey` - see [PrekeyStore.signedPrekeyId]'s own doc
     * comment for exactly this hazard) was NOT caught: the id comparison at check 1 passed, DH1/DH3
     * were silently computed against the WRONG scalar, and the resulting [X3dhSharedSecret] diverged
     * from the initiator's with no diagnostic pointing at the cause - only surfacing much later, at
     * first AEAD use. This was the same failure shape check 3's `ConsumedOneTimePrekey` id-pairing
     * assertion already closes for one-time prekeys; checks 5-7 below close the equivalent gap for
     * the responder's own long-term keys, at the cost of two new required parameters
     * ([responderEncryptionBinding], [responderSignedPrekeyPublicKey]) that a caller must now supply
     * - both are values a real caller already has on hand from its own [PrekeyStore]/
     * [EncryptionKeyBinding], so this is pure additional validation, not new state to track.
     */
    fun respond(
        responderIdentity: Secp256k1PublicKey,
        responderEncryptionBinding: EncryptionKeyBinding,
        responderX25519IdentityPrivateKey: X25519PrivateKey,
        responderSignedPrekeyId: Int,
        responderSignedPrekeyPublicKey: X25519PublicKey,
        responderSignedPrekeyPrivateKey: X25519PrivateKey,
        header: X3dhPreKeyMessageHeader,
        consumedOneTimePrekey: ConsumedOneTimePrekey?,
    ): X3dhSharedSecret {
        if (header.signedPrekeyId != responderSignedPrekeyId) {
            throw X3dhException(
                "initial message names signed prekey id ${header.signedPrekeyId} but this responder holds " +
                    "id $responderSignedPrekeyId",
            )
        }
        if (!EncryptionKeyBinding.verify(header.initiatorIdentity, header.initiatorEncryptionBinding)) {
            throw X3dhException("initial message's initiator encryption key binding does not verify")
        }
        if ((header.oneTimePrekeyId == null) != (consumedOneTimePrekey == null)) {
            throw X3dhException(
                "oneTimePrekeyId and consumedOneTimePrekey must both be present or both absent",
            )
        }
        if (consumedOneTimePrekey != null && consumedOneTimePrekey.id != header.oneTimePrekeyId) {
            throw X3dhException(
                "consumedOneTimePrekey.id (${consumedOneTimePrekey.id}) does not match header.oneTimePrekeyId " +
                    "(${header.oneTimePrekeyId}) - the caller consumed the wrong one-time prekey",
            )
        }
        if (header.initiatorIdentity == responderIdentity) {
            throw X3dhException("refusing to respond to an X3DH handshake initiated by one's own identity")
        }
        if (!EncryptionKeyBinding.verify(responderIdentity, responderEncryptionBinding)) {
            throw X3dhException("responder's own encryption key binding does not verify against responderIdentity")
        }
        // publicKeyFor, not fromPrivateKeyBytes - same "no second, separately-owned X25519PrivateKey
        // copy" reasoning as initiate()'s own check 7.
        val derivedResponderX25519Public = X25519KeyPair.publicKeyFor(responderX25519IdentityPrivateKey)
        if (derivedResponderX25519Public != responderEncryptionBinding.x25519PublicKey) {
            throw X3dhException(
                "responderX25519IdentityPrivateKey does not match responderEncryptionBinding's public key",
            )
        }
        val derivedResponderSignedPrekeyPublic = X25519KeyPair.publicKeyFor(responderSignedPrekeyPrivateKey)
        if (derivedResponderSignedPrekeyPublic != responderSignedPrekeyPublicKey) {
            throw X3dhException(
                "responderSignedPrekeyPrivateKey does not match responderSignedPrekeyPublicKey - the caller's " +
                    "signedPrekeyId/signedPrekeyPrivateKey/signedPrekeyPublicKey are from inconsistent snapshots",
            )
        }

        val ad = associatedData(header.initiatorIdentity, responderIdentity)
        var dh1: ByteArray? = null
        var dh2: ByteArray? = null
        var dh3: ByteArray? = null
        var dh4: ByteArray? = null
        try {
            // Same reasoning as initiate(): the DH computations themselves live inside this try so a
            // throw partway through still reaches the finally below and zeroes whichever earlier DH
            // outputs were already computed.
            dh1 = x25519SharedSecret(responderSignedPrekeyPrivateKey, header.initiatorX25519IdentityKey)
            dh2 = x25519SharedSecret(responderX25519IdentityPrivateKey, header.ephemeralPublicKey)
            dh3 = x25519SharedSecret(responderSignedPrekeyPrivateKey, header.ephemeralPublicKey)
            dh4 = consumedOneTimePrekey?.let { x25519SharedSecret(it.privateKey, header.ephemeralPublicKey) }
            val sharedSecretBytes = deriveSharedSecret(dh1, dh2, dh3, dh4, ad)
            val session = X3dhSharedSecret(sharedSecretBytes, ad)
            sharedSecretBytes.fill(0)
            return session
        } finally {
            dh1?.fill(0)
            dh2?.fill(0)
            dh3?.fill(0)
            dh4?.fill(0)
        }
    }
}
