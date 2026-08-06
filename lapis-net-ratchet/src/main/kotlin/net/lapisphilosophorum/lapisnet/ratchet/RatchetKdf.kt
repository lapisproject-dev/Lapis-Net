package net.lapisphilosophorum.lapisnet.ratchet

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter

/** Exactly 31 ASCII bytes. Fixed length, so concatenating it with the (also fixed-length, 71-byte)
 * X3DH associated data as HKDF `info` material is injective WITHOUT a length prefix - the identical
 * argument [X3dh]'s own `HKDF_INFO_LABEL` doc comment makes, and the reason
 * [X3DH_ASSOCIATED_DATA_SIZE]'s fixedness is validated rather than assumed. Versioned (`v1`) so a
 * future change to this ladder can never silently collide with this one. `internal` so
 * [DoubleRatchetKnownAnswerTest] can pin it directly instead of re-declaring a local copy - the
 * exact gap [X3dhKnownAnswerTest]'s own doc comment records having had to close. */
internal val ROOT_KDF_INFO_LABEL = "LapisNet:double-ratchet:v1:root".toByteArray(Charsets.US_ASCII)

/** Exactly 34 ASCII bytes. Same fixed-length/injectivity argument as [ROOT_KDF_INFO_LABEL]. */
internal val MESSAGE_KDF_INFO_LABEL = "LapisNet:double-ratchet:v1:message".toByteArray(Charsets.US_ASCII)

/** Signal's published chain-KDF domain-separation constants: the message key is `HMAC(ck, 0x01)`,
 * the next chain key is `HMAC(ck, 0x02)`. Two DIFFERENT one-byte inputs under the SAME HMAC key are
 * what make the message key and the next chain key computationally independent of each other -
 * which is in turn what makes forward secrecy real: possession of `CK_(n+1)` yields nothing about
 * `MK_n`. */
internal const val MESSAGE_KEY_HMAC_CONSTANT: Byte = 0x01
internal const val CHAIN_KEY_HMAC_CONSTANT: Byte = 0x02

/** 32 zero bytes - RFC 5869's own "if not provided, it is set to a string of HashLen zeros" default,
 * passed explicitly rather than as `null`, for the same spec-literal/self-documenting reason
 * [X3dh]'s own `HKDF_SALT` states at length. Used ONLY by [messageKeyKdf], never by [rootKdf]
 * (whose salt is the root key itself). */
internal val MESSAGE_KDF_SALT = ByteArray(32)

internal const val ROOT_KEY_SIZE = 32
internal const val CHAIN_KEY_SIZE = 32
internal const val MESSAGE_KEY_MATERIAL_SIZE = 32
internal const val AES_KEY_SIZE = 32
internal const val GCM_NONCE_SIZE = 12
internal const val GCM_TAG_SIZE = 16
internal const val GCM_TAG_BITS = 128

/**
 * The entire Double Ratchet KDF ladder for V0.8.3, isolated in its own file so it is auditable on
 * its own, mirroring how [X3dh] keeps its own key derivation self-contained. Three layers, each
 * with a distinct role:
 *
 * - [rootKdf] - the DH ratchet's root-chain advancement. HKDF-SHA256, `salt = current root key`,
 *   `ikm = fresh DH output`. Runs once per DH ratchet step (i.e. roughly once per direction change
 *   in the conversation, not once per message).
 * - [chainKdf] - the symmetric sending/receiving chain step. HMAC-SHA256 only (no HKDF) - Signal's
 *   own published chain-KDF shape. Runs once per message.
 * - [messageKeyKdf] - turns one chain step's message-key MATERIAL into the actual AES-256 key used
 *   to encrypt/decrypt that one message. HKDF-SHA256 again, this time salted with 32 zero bytes
 *   (the material itself, an HMAC-SHA256 output, is already uniform).
 *
 * **`hmacSha256`/`hkdfSha256` are LOCAL, deliberate duplicates of [X3dh]'s own private helper and of
 * `HybridEcies`'s inline HKDF usage - not calls into either.** [X3dh] is a stateless handshake
 * primitive whose `hkdfSha256` is `internal` purely so `X3dhKnownAnswerTest` can pin RFC 5869's
 * vectors against it; making the Double Ratchet's whole key schedule depend on that test seam would
 * couple two independent constructions through an accessor that exists for a third reason entirely,
 * and would mean a future change to X3DH's helper silently changes this ladder too. A handful of
 * identical lines, pinned INDEPENDENTLY by [DoubleRatchetKnownAnswerTest] against the same RFC 5869
 * vectors, is the cheaper coupling.
 */
internal object RatchetKdf {
    /** `HMAC-SHA256(key, data)` via BouncyCastle's low-level `crypto.macs.HMac`, matching this
     * codebase's established `crypto.generators`-level BouncyCastle usage style
     * (`KeystoreEncryption`'s `Argon2BytesGenerator`, `HybridEcies`'s/`X3dh`'s `HKDFBytesGenerator`)
     * rather than the JCE `javax.crypto.Mac` facade.
     *
     * **Deliberately BouncyCastle, not `javax.crypto.Mac` - and the reason is key hygiene, not
     * style.** `Mac.init` requires a `javax.crypto.spec.SecretKeySpec`, whose constructor copies the
     * key bytes into a private field this code can never zero; BouncyCastle's `KeyParameter` is
     * likewise a copy, but the whole `HMac` instance is local to this function and unreachable after
     * it returns, and no JCE provider caches it. Neither is a hard guarantee (see
     * [DoubleRatchetSession]'s own honest statement about best-effort zeroization on the JVM), but
     * the BouncyCastle path leaves strictly fewer copies in strictly shorter-lived objects.
     *
     * A FRESH [HMac] instance per call - `HMac` is stateful and not thread-safe, mirroring
     * `domainSeparatedDigest`'s identical "a fresh `MessageDigest` instance is created per call"
     * rule. */
    internal fun hmacSha256(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    /** `HKDF-SHA256(ikm, salt, info, L = length)` - see this object's class doc comment for why this
     * is a local duplicate of [X3dh.hkdfSha256], not a call into it. */
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

    /**
     * The DH ratchet's root-chain advancement, run once per DH ratchet step:
     * ```
     * info = ROOT_KDF_INFO_LABEL (31) || associatedData (71)          = 102 bytes
     * okm  = HKDF-SHA256(ikm = dhOutput, salt = rootKey, info = info, L = 64)
     * newRootKey  = okm[ 0..31]
     * newChainKey = okm[32..63]
     * ```
     *
     * **`ikm = dhOutput`, `salt = rootKey` - this is the RFC 5869 assignment Signal's spec mandates,
     * and it is the right way round: the salt is the KNOWN-TO-BOTH, already-uniform value and the
     * IKM is the FRESH entropy.** HKDF-Extract is genuinely LOAD-BEARING here for
     * entropy-smoothing, because [net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret]
     * returns the RAW shared u-coordinate - not a hash of it - which is not uniformly distributed.
     * This is the exact contrast that function's own doc comment and [X3dh]'s class doc comment
     * already draw against `ecdhSharedSecret`; the same contrast holds here and is restated, not
     * assumed carried over.
     *
     * **`associatedData` is folded into `info` here, not left to the AEAD alone** - the identical
     * argument [X3dh]'s class doc comment makes for its own `info`, and `HybridEcies`'s for its wrap
     * key. Consequence: two sessions between different identity pairs whose DH values somehow
     * coincided would still derive different root chains, so cross-session confusion
     * (`DoubleRatchetAdversarialTest` case (g)) fails at the KDF, one full layer before the AEAD's
     * AAD check - two independent reasons, not one. Public, fixed-length context added to a PRF's
     * `info` cannot weaken the derivation.
     *
     * Zeroes its own intermediate `okm` buffer before returning the split halves as fresh arrays.
     * Does NOT zero [rootKey] or [dhOutput] - both are caller-owned.
     */
    internal fun rootKdf(
        rootKey: ByteArray,
        dhOutput: ByteArray,
        associatedData: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        require(rootKey.size == ROOT_KEY_SIZE) { "rootKey must be $ROOT_KEY_SIZE bytes, was ${rootKey.size}" }
        require(dhOutput.size == 32) { "dhOutput must be 32 bytes, was ${dhOutput.size}" }
        require(associatedData.size == X3DH_ASSOCIATED_DATA_SIZE) {
            "associatedData must be $X3DH_ASSOCIATED_DATA_SIZE bytes, was ${associatedData.size}"
        }
        val info = ROOT_KDF_INFO_LABEL + associatedData
        val okm = hkdfSha256(dhOutput, rootKey, info, ROOT_KEY_SIZE + CHAIN_KEY_SIZE)
        try {
            val newRootKey = okm.copyOfRange(0, ROOT_KEY_SIZE)
            val newChainKey = okm.copyOfRange(ROOT_KEY_SIZE, ROOT_KEY_SIZE + CHAIN_KEY_SIZE)
            return newRootKey to newChainKey
        } finally {
            okm.fill(0)
        }
    }

    /**
     * The symmetric sending/receiving chain step, run once per message:
     * ```
     * messageKeyMaterial = HMAC-SHA256(key = chainKey, data = [0x01])   -> 32 bytes (MK_n material)
     * nextChainKey       = HMAC-SHA256(key = chainKey, data = [0x02])   -> 32 bytes (CK_(n+1))
     * ```
     *
     * Does NOT zero [chainKey] - the caller owns it and must zero it after installing
     * `nextChainKey`, mirroring `x25519SharedSecret`'s "never destroy a caller-supplied key it does
     * not own" rule. One-wayness of HMAC-SHA256 is precisely what makes forward secrecy real: an
     * attacker holding `CK_(n+1)` cannot recover `CK_n`, and therefore cannot recover `MK_n`,
     * `MK_(n-1)`, ... - this is the property `DoubleRatchetAdversarialTest` case (a) tests the
     * OBSERVABLE half of; the computational half (HMAC-SHA256's one-wayness) is an assumption no JVM
     * test can verify, stated honestly rather than overclaimed.
     */
    internal fun chainKdf(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        require(chainKey.size == CHAIN_KEY_SIZE) { "chainKey must be $CHAIN_KEY_SIZE bytes, was ${chainKey.size}" }
        val nextChainKey = hmacSha256(chainKey, byteArrayOf(CHAIN_KEY_HMAC_CONSTANT))
        val messageKeyMaterial = hmacSha256(chainKey, byteArrayOf(MESSAGE_KEY_HMAC_CONSTANT))
        return nextChainKey to messageKeyMaterial
    }

    /**
     * Turns one chain step's message-key MATERIAL into the AES-256 key actually used to
     * encrypt/decrypt that one message:
     * ```
     * info   = MESSAGE_KDF_INFO_LABEL (34) || associatedData (71)        = 105 bytes
     * aesKey = HKDF-SHA256(ikm = messageKeyMaterial, salt = MESSAGE_KDF_SALT (32 zeros), info, L = 32)
     * ```
     *
     * **HKDF-Extract is NOT load-bearing for entropy here** (the IKM is already an HMAC-SHA256
     * output, i.e. uniform); **HKDF-Expand IS load-bearing**, exactly as `HybridEcies`'s class doc
     * comment states for its own wrap key: it is what makes the AEAD key a distinct function of
     * [associatedData] and of this layer's own domain label, so a message transplanted between
     * sessions fails for two independent reasons (wrong derived key AND wrong GCM AAD), not merely
     * one.
     *
     * **Why this extra HKDF step exists at all instead of using the chain material directly as the
     * AES key**: it gives a clean cryptographic boundary between "chain-ladder material" and "AEAD
     * key" (so a hypothetical AEAD-key recovery yields nothing about the chain), it is this
     * codebase's established `HKDF -> key` idiom (`HybridEcies.deriveWrapKeyAndNonce`), and it is
     * the single place [associatedData] enters the per-message key.
     *
     * **`L = 32`, key only - no nonce is derived here**, unlike `HybridEcies.deriveWrapKeyAndNonce`'s
     * `L = 44` (key + nonce). See [DoubleRatchetSession]'s class doc comment for the full nonce-
     * strategy argument: this wave transmits an explicit, random, 12-byte nonce per message instead
     * of deriving one, because a Double Ratchet message key's single-use property rests on a
     * PERSISTED counter (which can rewind on a stale restored session snapshot), not on a fresh
     * `SecureRandom` draw per call the way `HybridEcies`'s wrap key's does.
     *
     * Does NOT zero [messageKeyMaterial] - caller-owned.
     */
    internal fun messageKeyKdf(
        messageKeyMaterial: ByteArray,
        associatedData: ByteArray,
    ): ByteArray {
        require(messageKeyMaterial.size == MESSAGE_KEY_MATERIAL_SIZE) {
            "messageKeyMaterial must be $MESSAGE_KEY_MATERIAL_SIZE bytes, was ${messageKeyMaterial.size}"
        }
        require(associatedData.size == X3DH_ASSOCIATED_DATA_SIZE) {
            "associatedData must be $X3DH_ASSOCIATED_DATA_SIZE bytes, was ${associatedData.size}"
        }
        val info = MESSAGE_KDF_INFO_LABEL + associatedData
        return hkdfSha256(messageKeyMaterial, MESSAGE_KDF_SALT, info, AES_KEY_SIZE)
    }
}
