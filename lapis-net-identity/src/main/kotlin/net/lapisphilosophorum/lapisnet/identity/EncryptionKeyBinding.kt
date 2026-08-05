package net.lapisphilosophorum.lapisnet.identity

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest

private const val SIGNATURE_SIZE = 64

/** Domain-separation tag for the secp256k1-identity -> X25519-encryption-sub-key vouch (V0.8.2). A
 * DISTINCT, versioned tag, never shared with [IdentityBinding]'s own
 * `"LapisNet:identity-binding:v1"` tag - two different signing purposes over similarly-shaped
 * 32-byte public key bytes must never share a domain tag, exactly the reasoning
 * [domainSeparatedDigest]'s own doc comment states. */
private const val ENCRYPTION_BINDING_DOMAIN_TAG = "LapisNet:x25519-encryption-key:v1"

/**
 * Cryptographic proof that a secp256k1 identity (the canonical Lapis Net identity) vouches for a
 * given X25519 key (used only as that identity's encryption sub-key for the X3DH handshake, V0.8.2).
 * Structurally IDENTICAL to [IdentityBinding] - same `create`/`verify` companion shape, same
 * defensive-copy discipline, same 64-byte compact-ECDSA-signature-size guard - with its own,
 * separately domain-tagged digest so this signature can never be confused with [IdentityBinding]'s,
 * even though both are produced by the SAME secp256k1 key over a same-shaped 32-byte public key.
 *
 * **This binding is a ONE-WAY vouch, and - unlike [net.lapisphilosophorum.lapisnet.directory.PeerRecord]'s
 * `possessionProof` - there is deliberately no mutual counter-signature here.** An X25519 key
 * cannot sign (there is no secret-key signing operation for a Montgomery-curve Diffie-Hellman
 * key), and XEdDSA (Signal's own answer - converting an X25519 key to Ed25519 to sign with it) is
 * an explicit scope cut for this wave (see [X3dh]'s doc comment for why: adding a second,
 * from-scratch cryptographic construction inside a wave that already builds X3DH from scratch
 * would compound, not contain, this wave's risk). The equivalent protection this codebase's
 * `IdentityBinding`/`PeerRecord.possessionProof` precedent would otherwise suggest instead lives in
 * [X3dh]'s associated-data construction - see that object's class doc comment, and
 * `docs/architecture.adoc`'s V0.8.2 section, for the full "unknown key share" attack analysis this
 * binding's one-way-ness makes possible, and exactly what closes it (folding the secp256k1
 * identities into both the AEAD-style associated data AND the HKDF `info` string, so the two
 * parties to an attempted attack derive genuinely DIFFERENT shared secrets rather than relying on
 * a downstream layer to notice a mismatched AAD).
 */
class EncryptionKeyBinding(
    val x25519PublicKey: X25519PublicKey,
    signature: ByteArray,
) {
    private val storedSignature: ByteArray = signature.copyOf()

    /** Returns a fresh copy on every access. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == SIGNATURE_SIZE) {
            "encryption key binding signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is EncryptionKeyBinding &&
            x25519PublicKey == other.x25519PublicKey &&
            storedSignature.contentEquals(other.storedSignature)

    override fun hashCode(): Int = 31 * x25519PublicKey.hashCode() + storedSignature.contentHashCode()

    override fun toString(): String = "EncryptionKeyBinding(x25519PublicKey=$x25519PublicKey)"

    companion object {
        private fun bindingDigest(x25519PublicKey: X25519PublicKey): ByteArray =
            domainSeparatedDigest(ENCRYPTION_BINDING_DOMAIN_TAG, x25519PublicKey.bytes)

        fun create(
            secp256k1KeyPair: Secp256k1KeyPair,
            x25519PublicKey: X25519PublicKey,
        ): EncryptionKeyBinding {
            val digest = bindingDigest(x25519PublicKey)
            val signature = secp256k1KeyPair.sign(digest)
            return EncryptionKeyBinding(x25519PublicKey, signature)
        }

        fun verify(
            secp256k1PublicKey: Secp256k1PublicKey,
            binding: EncryptionKeyBinding,
        ): Boolean {
            val digest = bindingDigest(binding.x25519PublicKey)
            return secp256k1PublicKey.verify(digest, binding.signature)
        }
    }
}
