package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.time.Instant

/** Domain-separation tag for [PrekeyBundle]'s OWN outer signature - covers the whole encoded body,
 * including both [PrekeyBundle.encryptionBinding]'s and [PrekeyBundle.signedPrekeySignature]'s own
 * bytes. A DISTINCT tag from both of those (see [EncryptionKeyBinding]'s own
 * `"LapisNet:x25519-encryption-key:v1"` tag and [SIGNED_PREKEY_DOMAIN_TAG] below) - three
 * independent signing purposes, never sharing a domain tag, mirroring
 * `net.lapisphilosophorum.lapisnet.directory.PeerRecord`'s identical three-signature precedent. */
private const val PREKEY_BUNDLE_DOMAIN_TAG = "LapisNet:x3dh-prekey-bundle:v1"

/** Domain-separation tag for [PrekeyBundle.signedPrekeySignature] - see
 * [PrekeyBundle.signedPrekeyDigest]'s doc comment for exactly what bytes this covers and why it is
 * deliberately WIDER than the Signal X3DH spec's own `Sig(IK_B, Encode(SPK_B))`. */
private const val SIGNED_PREKEY_DOMAIN_TAG = "LapisNet:x3dh-signed-prekey:v1"

private const val SIGNATURE_SIZE = 64

private fun intToBigEndian4(value: Int): ByteArray =
    byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

/**
 * A signed, publishable statement: "[identity] can be reached via X3DH at X25519 identity key
 * [x25519IdentityKey], its current signed prekey is [signedPrekey] (id [signedPrekeyId], signed by
 * [identity]'s OWN secp256k1 signing key - never by the X25519 key itself, since X25519 keys
 * cannot sign), and it additionally offers these one-time prekeys [oneTimePrekeys] for the next
 * initiator to consume." The V0.8.2 counterpart to
 * `net.lapisphilosophorum.lapisnet.directory.PeerRecord`: gossiped over its own topic
 * (`PrekeyBundleGossip`, in `lapis-net-directory` - this module is deliberately network-free, see
 * this module's `build.gradle.kts`), latest-wins per identity by [sequenceNumber].
 *
 * **THREE independently-verified signatures, and no pair is sufficient** - mirroring
 * `PeerRecord`'s identical three-signature design: [verify] (outer, [PREKEY_BUNDLE_DOMAIN_TAG],
 * covers the whole body including both other signatures' bytes), [verifyEncryptionBinding]
 * (`"LapisNet:x25519-encryption-key:v1"`, proves [identity] vouches for [x25519IdentityKey]), and
 * [verifySignedPrekey] ([SIGNED_PREKEY_DOMAIN_TAG], proves [identity] vouches for [signedPrekey]
 * being current). Every consumer - [net.lapisphilosophorum.lapisnet.ratchet.X3dh.initiate], and (in
 * `lapis-net-directory`) `PrekeyBundleIndex.add`/`PrekeyBundleGossip.onGossipMessage` - MUST call
 * all three before any DH computation runs, exactly mirroring `PeerRecord`'s own "no pair alone is
 * sufficient" contract, including `add`'s independent re-verification regardless of whatever
 * already ran in the gossip validator (that function is reachable via other paths too).
 *
 * **[x25519IdentityKey] is a read-through alias into [encryptionBinding], never a second, separately
 * stored copy** - structurally impossible for the bundle's claimed X25519 identity key and the key
 * its binding actually vouches for to disagree, removing an entire class of "which one did the
 * verifier check?" bug by construction. This is a deliberate strengthening over a literal reading of
 * the wave's own planning notes, which implied a separately-carried field.
 *
 * **Why [signedPrekeyDigest] is deliberately WIDER than the Signal spec's own
 * `Sig(IK_B, Encode(SPK_B))`.** Signal's signature covers the signed prekey ALONE because in
 * Signal, `IK_B` *is* the X25519 identity key, and signing with it is itself already a
 * proof-of-possession. Here, the signature is produced by the **secp256k1** identity key instead
 * (X25519 keys cannot sign), so a bare `Sig(SPK)` would be freely transplantable between different
 * bundles of the SAME identity that differ only in their X25519 identity key or prekey id. Binding
 * `identity ‖ x25519IdentityKey ‖ signedPrekey ‖ signedPrekeyId` into one domain-separated digest
 * (each part independently length-prefixed by [domainSeparatedDigest], so the concatenation is
 * injective) makes every component of the bundle's key material a single, non-separable unit.
 *
 * **The possession-proof question - answered deliberately in the NEGATIVE, no field added.** Unlike
 * `PeerRecord.possessionProof` (an Ed25519 counter-signature closing an equivalent gap for that
 * record type), NO possession-proof field exists here, and none should be added. An X25519 key
 * cannot sign; the only avenues considered - XEdDSA (Signal's own answer, a from-scratch
 * cryptographic construction and an explicit scope cut for this wave - see [net.lapisphilosophorum.lapisnet.ratchet.X3dh]'s
 * class doc comment), an Ed25519 counter-signature by the identity's OWN Ed25519 transport key (an
 * equally one-way vouch that proves nothing about the X25519 PRIVATE key), and a DH-based
 * possession tag (not publicly verifiable by a third party) - were each evaluated and rejected. A
 * "FRESHLY RE-SIGNED encryption binding over a victim's PUBLIC X25519 key" (an unknown-key-share
 * attack: Mallory harvests Bob's public `x25519IdentityKey`/`signedPrekey`/`oneTimePrekeys` off
 * gossip and re-signs a fully self-consistent bundle under her OWN secp256k1 identity) therefore
 * passes all three signature checks above. This is NOT a confidentiality break: Mallory cannot
 * compute the responder-side DH terms that need Bob's private keys, so only Bob - not Mallory - can
 * ever complete the matching handshake. What closes the attack from becoming a confidentiality
 * break is [net.lapisphilosophorum.lapisnet.ratchet.X3dh]'s associated-data construction, folded
 * into BOTH the AEAD-style AD and the HKDF `info` string, using the secp256k1 identities (not the
 * X25519 sub-keys, which are IDENTICAL on both sides of this specific attack) - see that object's
 * class doc comment for the full analysis, and `docs/architecture.adoc`'s V0.8.2 section for the
 * complete writeup, including the residual, accepted "DoS/confusion, not confidentiality break" risk.
 *
 * **Explicit, deliberate scope cuts for V0.8.2** (stated here rather than silently omitted,
 * mirroring `PeerRecord`'s own established practice):
 * - No PQXDH / post-quantum hybrid key exchange. X25519 only.
 * - No formal deniability analysis beyond X3DH's own published security properties.
 * - No DHT publication - gossip only (`PrekeyBundleGossip`, in `lapis-net-directory`), the same
 *   `Kademlia.dialPeer`-broken limitation as every prior wave.
 * - Not yet wired into a live message-send path - this wave's deliverable is the handshake
 *   primitive and prekey publication/consumption machinery, callable and independently testable.
 *   V0.8.3 (Double Ratchet) and V0.8.4 (online DM) own that wiring.
 * - No XEdDSA, no signed-prekey rotation scheduler (`PrekeyStore.rotateSignedPrekey` is exposed as
 *   a directly callable primitive; nothing in this wave calls it periodically).
 * - **The gossip-specific one-time-prekey collision limitation**: a gossip-published bundle is seen
 *   in full by every subscriber (unlike Signal's server, which hands out each one-time prekey to
 *   exactly one requester), so two initiators can independently pick the same one-time prekey; the
 *   second responder-side consumption then fails and that initiator must retry with no one-time
 *   prekey (DH1-DH3-only X3DH). See `net.lapisphilosophorum.lapisnet.ratchet.X3dh`'s doc comment.
 */
class PrekeyBundle private constructor(
    val identity: Secp256k1PublicKey,
    val encryptionBinding: EncryptionKeyBinding,
    val signedPrekeyId: Int,
    val signedPrekey: X25519PublicKey,
    signedPrekeySignature: ByteArray,
    oneTimePrekeys: List<OneTimePrekey>,
    val sequenceNumber: Long,
    val notValidAfterEpochSecond: Long,
    signature: ByteArray,
) {
    /** The X25519 identity key IS `encryptionBinding.x25519PublicKey` - a read-through alias, never
     * a second, separately stored copy that could disagree with it (see this class's doc comment). */
    val x25519IdentityKey: X25519PublicKey get() = encryptionBinding.x25519PublicKey

    /** Immutable snapshot, capped at [PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS]. */
    val oneTimePrekeys: List<OneTimePrekey> = oneTimePrekeys.toList()

    private val storedSignedPrekeySignature: ByteArray = signedPrekeySignature.copyOf()
    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [identity]'s secp256k1 key over [signedPrekeyDigest]'s
     * bytes. Returns a fresh copy on every access. Never log at any level. */
    val signedPrekeySignature: ByteArray get() = storedSignedPrekeySignature.copyOf()

    /** Compact 64-byte ECDSA signature by [identity] over this bundle's full encoded body
     * ([PREKEY_BUNDLE_DOMAIN_TAG]-tagged) - the bundle's OWN outer signature, distinct from both
     * [encryptionBinding]'s signature and [signedPrekeySignature]. Returns a fresh copy on every
     * access. Never log at any level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == SIGNATURE_SIZE) {
            "prekey bundle signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
        require(storedSignedPrekeySignature.size == SIGNATURE_SIZE) {
            "signed prekey signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
        require(signedPrekeyId >= 0) { "signedPrekeyId must be >= 0, was $signedPrekeyId" }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0, was $sequenceNumber" }
        require(this.oneTimePrekeys.size <= PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS) {
            "at most ${PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS} one-time prekeys allowed, was ${this.oneTimePrekeys.size}"
        }
        require(
            this.oneTimePrekeys
                .map { it.id }
                .toSet()
                .size == this.oneTimePrekeys.size,
        ) {
            "one-time prekey ids must be unique within a bundle"
        }
        require(
            this.oneTimePrekeys
                .map { it.publicKey }
                .toSet()
                .size == this.oneTimePrekeys.size,
        ) {
            "one-time prekey public keys must be unique within a bundle"
        }
        // Deliberately NO range check on notValidAfterEpochSecond HERE - this field is
        // attacker-controlled and this constructor runs for gossip-decoded bundles too, mirroring
        // PeerRecord's identical decision. create()'s own require(), one layer up, caps how far a
        // LOCALLY-signed bundle's claimed TTL may reach into the future.
    }

    /** SHA-256 over this bundle's full canonical bytes - the dedup/index key `PrekeyBundleIndex`
     * (in `lapis-net-directory`) uses. */
    fun contentId(): ByteArray = PrekeyBundleCodec.contentId(this)

    override fun equals(other: Any?): Boolean {
        if (other !is PrekeyBundle) return false
        return identity == other.identity &&
            encryptionBinding == other.encryptionBinding &&
            signedPrekeyId == other.signedPrekeyId &&
            signedPrekey == other.signedPrekey &&
            storedSignedPrekeySignature.contentEquals(other.storedSignedPrekeySignature) &&
            oneTimePrekeys == other.oneTimePrekeys &&
            sequenceNumber == other.sequenceNumber &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = identity.hashCode()
        result = 31 * result + encryptionBinding.hashCode()
        result = 31 * result + signedPrekeyId
        result = 31 * result + signedPrekey.hashCode()
        result = 31 * result + storedSignedPrekeySignature.contentHashCode()
        result = 31 * result + oneTimePrekeys.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + notValidAfterEpochSecond.hashCode()
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Never includes any signature - mirrors `PeerRecord.toString`'s precedent. */
    override fun toString(): String =
        "PrekeyBundle(identity=${identity.fingerprint()}, x25519IdentityKey=${x25519IdentityKey.fingerprint()}, " +
            "signedPrekeyId=$signedPrekeyId, oneTimePrekeys=${oneTimePrekeys.size}, " +
            "sequenceNumber=$sequenceNumber, notValidAfterEpochSecond=$notValidAfterEpochSecond)"

    companion object {
        /** 7 days - deliberately LONGER than `PeerRecord.MAX_TTL_WINDOW_SECONDS`'s 24 hours: a
         * prekey bundle is expected to change far less often than a presence/address heartbeat
         * (prekeys are consumed, not renewed on every online session), so a shorter TTL would force
         * needless re-signing. Same provisional-magnitude caveat as every sibling cap in this
         * codebase. */
        const val MAX_TTL_WINDOW_SECONDS = 604_800L

        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(PREKEY_BUNDLE_DOMAIN_TAG, body)

        /** The EXACT bytes [PrekeyBundle.signedPrekeySignature] covers - deliberately WIDER than
         * the Signal spec's own `Sig(IK_B, Encode(SPK_B))`, see [PrekeyBundle]'s class doc comment
         * for why. */
        internal fun signedPrekeyDigest(
            identity: Secp256k1PublicKey,
            x25519IdentityKey: X25519PublicKey,
            signedPrekey: X25519PublicKey,
            signedPrekeyId: Int,
        ): ByteArray =
            domainSeparatedDigest(
                SIGNED_PREKEY_DOMAIN_TAG,
                identity.bytes,
                x25519IdentityKey.bytes,
                signedPrekey.bytes,
                intToBigEndian4(signedPrekeyId),
            )

        /**
         * Creates and signs a new bundle for [identity]. Refuses to sign if [encryptionBinding]
         * does not actually verify against [identity] (mirrors `PeerRecord.create`'s identical
         * refusal for a broken `IdentityBinding`), and refuses a [notValidAfterEpochSecond] further
         * than [MAX_TTL_WINDOW_SECONDS] beyond [nowEpochSecond] (mirrors `PeerRecord.create`'s
         * identical, honest-signing-path-only TTL cap - see that function's doc comment for why
         * this binds only the signing path, not gossip ingestion).
         */
        fun create(
            identity: DualKeyIdentity,
            encryptionBinding: EncryptionKeyBinding,
            signedPrekeyId: Int,
            signedPrekey: X25519PublicKey,
            oneTimePrekeys: List<OneTimePrekey>,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            nowEpochSecond: Long = Instant.now().epochSecond,
        ): PrekeyBundle {
            require(EncryptionKeyBinding.verify(identity.secp256k1KeyPair.publicKey, encryptionBinding)) {
                "encryptionBinding does not verify against identity - refusing to embed it in a signed PrekeyBundle"
            }
            require(notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS) {
                "notValidAfterEpochSecond ($notValidAfterEpochSecond) claims validity more than " +
                    "$MAX_TTL_WINDOW_SECONDS seconds beyond now ($nowEpochSecond) - refusing to sign " +
                    "an unreasonably long-lived prekey bundle"
            }
            val signedPrekeySignature =
                identity.secp256k1KeyPair.sign(
                    signedPrekeyDigest(
                        identity.secp256k1KeyPair.publicKey,
                        encryptionBinding.x25519PublicKey,
                        signedPrekey,
                        signedPrekeyId,
                    ),
                )
            val body =
                PrekeyBundleCodec.encodeSignedBody(
                    identity = identity.secp256k1KeyPair.publicKey,
                    encryptionBinding = encryptionBinding,
                    signedPrekeyId = signedPrekeyId,
                    signedPrekey = signedPrekey,
                    signedPrekeySignature = signedPrekeySignature,
                    oneTimePrekeys = oneTimePrekeys,
                    sequenceNumber = sequenceNumber,
                    notValidAfterEpochSecond = notValidAfterEpochSecond,
                )
            val signature = identity.secp256k1KeyPair.sign(signingDigest(body))
            return PrekeyBundle(
                identity.secp256k1KeyPair.publicKey,
                encryptionBinding,
                signedPrekeyId,
                signedPrekey,
                signedPrekeySignature,
                oneTimePrekeys,
                sequenceNumber,
                notValidAfterEpochSecond,
                signature,
            )
        }

        /** Checks ONLY this bundle's own outer [PrekeyBundle.signature] - does NOT check
         * [verifyEncryptionBinding] or [verifySignedPrekey]. A caller MUST call all three, see this
         * class's doc comment. */
        fun verify(bundle: PrekeyBundle): Boolean {
            val body = PrekeyBundleCodec.encodeSignedBody(bundle)
            return bundle.identity.verify(signingDigest(body), bundle.signature)
        }

        /** As [verify], but additionally asserts [bundle] was signed by [expectedIdentity]. */
        fun verify(
            expectedIdentity: Secp256k1PublicKey,
            bundle: PrekeyBundle,
        ): Boolean = bundle.identity == expectedIdentity && verify(bundle)

        /** Reconstructs a bundle from already-decoded, unverified fields - used by
         * [PrekeyBundleCodec.decode] and by adversarial tests. Callers must call [verify],
         * [verifyEncryptionBinding], AND [verifySignedPrekey] before trusting the result. */
        internal fun fromDecoded(
            identity: Secp256k1PublicKey,
            encryptionBinding: EncryptionKeyBinding,
            signedPrekeyId: Int,
            signedPrekey: X25519PublicKey,
            signedPrekeySignature: ByteArray,
            oneTimePrekeys: List<OneTimePrekey>,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            signature: ByteArray,
        ): PrekeyBundle =
            PrekeyBundle(
                identity,
                encryptionBinding,
                signedPrekeyId,
                signedPrekey,
                signedPrekeySignature,
                oneTimePrekeys,
                sequenceNumber,
                notValidAfterEpochSecond,
                signature,
            )
    }
}

/** `true` iff [PrekeyBundle.encryptionBinding] is a valid vouch BY [PrekeyBundle.identity] for
 * [PrekeyBundle.x25519IdentityKey]. This is the check that rejects a bundle whose embedded
 * encryption binding was signed by a DIFFERENT secp256k1 identity than the bundle's own claimed
 * [PrekeyBundle.identity] field (the verbatim-transplant shape of an unknown-key-share attack - see
 * [PrekeyBundle]'s class doc comment for the full analysis, including the more dangerous
 * freshly-re-signed variant this check alone does NOT close). */
fun PrekeyBundle.verifyEncryptionBinding(): Boolean = EncryptionKeyBinding.verify(identity, encryptionBinding)

/** `true` iff [PrekeyBundle.signedPrekeySignature] is a valid secp256k1 signature by
 * [PrekeyBundle.identity] over [PrekeyBundle.signedPrekeyDigest]'s bytes (identity, X25519 identity
 * key, signed prekey, and its id, all bound into one digest - see [PrekeyBundle]'s class doc
 * comment for why this is wider than the Signal spec's own signed-prekey signature). */
fun PrekeyBundle.verifySignedPrekey(): Boolean =
    identity.verify(
        PrekeyBundle.signedPrekeyDigest(identity, x25519IdentityKey, signedPrekey, signedPrekeyId),
        signedPrekeySignature,
    )
