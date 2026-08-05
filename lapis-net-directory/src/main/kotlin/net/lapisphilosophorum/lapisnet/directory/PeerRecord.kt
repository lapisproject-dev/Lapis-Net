package net.lapisphilosophorum.lapisnet.directory

import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify

/** Domain-separation tag for a [PeerRecord]'s OWN outer signature - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. Deliberately a SEPARATE tag from
 * `IdentityBinding`'s `"LapisNet:identity-binding:v1"`, even though both signatures in a single
 * [PeerRecord] are produced by the SAME secp256k1 private key - see this class's doc comment for
 * why a [PeerRecord] carries THREE independently-verified signatures, not one. */
private const val PEER_RECORD_DOMAIN_TAG = "LapisNet:peer-record:v1"

/** Domain-separation tag for [PeerRecord.possessionProof] - the Ed25519 COUNTER-signature that
 * makes the identity<->transport-key binding genuinely MUTUAL (V0.8.1 sub-wave audit round 2,
 * major finding 1 fix). SEPARATE from both [PEER_RECORD_DOMAIN_TAG] and
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own `"LapisNet:identity-binding:v1"`
 * tag - three distinct signing purposes must never share a domain tag, even though two of the
 * three (the outer signature and [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]) are
 * produced by the SAME secp256k1 key. See this class's doc comment for the full reasoning. */
private const val PEER_RECORD_POSSESSION_DOMAIN_TAG = "LapisNet:peer-record-possession:v1"

private const val SIGNATURE_SIZE = 64

/** The exact bytes [PeerRecord.possessionProof] signs (Ed25519-signed by [PeerRecord.binding]'s
 * own `ed25519PublicKey`) and [verifyPossession] re-derives to check it - deliberately just
 * [identity]'s raw compressed bytes, nothing else. Unlike the outer [PEER_RECORD_DOMAIN_TAG]
 * signature (which must cover the WHOLE record body so a relay cannot tamper with addresses/
 * capabilities/sequence number/TTL undetected), this counter-signature only needs to prove ONE
 * narrow fact - "the holder of this Ed25519 private key vouches for THIS secp256k1 identity" - so
 * it is computed independently of addresses/capabilities/sequenceNumber/notValidAfterEpochSecond,
 * sidestepping any chicken-and-egg ordering problem with the rest of the record body (there would
 * be no way for a signature to cover a body that already contains that very signature). */
private fun possessionDigest(identity: Secp256k1PublicKey): ByteArray =
    domainSeparatedDigest(PEER_RECORD_POSSESSION_DOMAIN_TAG, identity.bytes)

/**
 * A signed, self-published statement: "[identity] can currently be reached at [addresses], its
 * libp2p transport identity ([peerId]) is [binding]-proven, it claims [capabilities], and this
 * statement is valid until [notValidAfterEpochSecond]." The foundational record type for the V0.8
 * (direct messages and calls) arc's V0.8.1 sub-wave: V0.8.2 (X3DH) resolves recipients' prekey
 * bundles through a directory built on this record; V0.8.4 (online DM) resolves recipients'
 * current network addresses through it.
 *
 * **Gossip-only, no DHT publication - the same accepted limitation as every V0.9 mail sub-wave.**
 * `org.peergos.protocol.dht.Kademlia.dialPeer` is documented broken since V0.1.4 (see
 * `docs/architecture.adoc`'s Storage section) - propagation is entirely via
 * [PeerDirectoryGossip]'s GossipSub topic, mirroring
 * `net.lapisphilosophorum.lapisnet.mail.InboxGossip`'s identical precedent. A node offline during
 * the gossip window has no catch-up path.
 *
 * **THREE independently-verified signatures, deliberately not two - see [verify], [verifyBinding],
 * and [verifyPossession].** [binding] is [identity]'s OWN pre-existing
 * `net.lapisphilosophorum.lapisnet.identity.IdentityBinding` (from its
 * `net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity`, computed once at identity-generation
 * time) - reused verbatim, not a second, PeerRecord-specific binding scheme. It proves "[identity]
 * vouches for [binding].ed25519PublicKey being its own transport key" ([binding]'s own
 * `"LapisNet:identity-binding:v1"` tag). This record's OWN [signature] (a SEPARATE ECDSA signature
 * over a SEPARATE, `"LapisNet:peer-record:v1"`-tagged digest of the full record body, including
 * the embedded [binding]'s bytes) proves "[identity] signed THIS EXACT record" - addresses,
 * capabilities, sequence number, and TTL included, so a relay cannot tamper with any of them
 * without invalidating [signature].
 *
 * **[verify] + [verifyBinding] alone are NOT sufficient - V0.8.1 sub-wave audit round 2, major
 * finding 1, the CROSS-BINDING/PEER-ID-SPOOFING gap this wave's original docs claimed to close but
 * did not.** [binding] (`IdentityBinding`) is a ONE-WAY vouch: it proves [identity] signed
 * `binding.ed25519PublicKey`, but an Ed25519 PUBLIC key is public by definition, so ANYONE can
 * mint a fresh, self-consistent `IdentityBinding.create(attackerSecp256k1KeyPair,
 * victimEd25519PublicKey)` - this passes [verifyBinding] (the attacker's own key correctly signed
 * it) while [peerId] resolves to the VICTIM's real, derivable `PeerId`. Both [verify] (genuinely
 * signed by the attacker) and [verifyBinding] (genuinely self-consistent) then pass, exactly the
 * "signature-valid record rejected on a second check" property this wave's original design claimed
 * to prove - except the auditor's PROBE A ran this through the REAL gossip validator and it was
 * accepted, indexed, persisted, and re-propagated. The root cause: NEITHER check requires
 * PROOF-OF-POSSESSION of the Ed25519 PRIVATE key - `IdentityBinding` only requires possessing the
 * PUBLIC half. [possessionProof] fixes this by making the binding genuinely MUTUAL: a SEPARATE
 * Ed25519 signature, by `binding.ed25519PublicKey`'s own PRIVATE key, over [identity]'s bytes
 * (`"LapisNet:peer-record-possession:v1"`-tagged, see [verifyPossession]) - something only the
 * genuine holder of that Ed25519 private key can produce, and the auditor's exploit above cannot,
 * since it never had access to the victim's Ed25519 private key, only the public key it copied off
 * an earlier, legitimately-published record. **All three checks are load-bearing and no pair alone
 * is sufficient** - [PeerDirectoryGossip]'s validator MUST call [verify], [verifyBinding], AND
 * [verifyPossession] before trusting [peerId]/[addresses]; see `PeerRecordSpoofingTest`'s case (a)
 * for the ORIGINAL (already-closed) exploit shape - reusing a victim's OWN binding object
 * verbatim - and its case (h) for THIS one - re-signing a FRESH binding over the victim's public
 * Ed25519 key, the actual gap this fix closes.
 *
 * **[binding] travels self-contained inside this record, not looked up separately** - there is no
 * existing directory to resolve it against yet (this record type IS the directory).
 *
 * **Explicit, deliberate scope cuts for V0.8.1 (stated here, consistent with this project's
 * practice of disclosing limitations rather than hiding them - see `NabuStorage`'s V0.1.4 gap
 * note):**
 *  - No DHT publication (see above).
 *  - No `SFU_CAPABLE` capability flag - see [PeerCapability]'s doc comment.
 *  - No bandwidth-class measurement.
 *  - **No reachability verification of advertised [addresses]** - mirrors V0.4's own, still-open
 *    gap: an attacker or a stale node can advertise unreachable addresses and nothing currently
 *    detects this.
 *  - **A minimum-address-count of zero is intentional, not an oversight** - unlike
 *    `MessageEnvelope.recipients` (which requires at least one), a [PeerRecord] with zero
 *    [addresses] is structurally valid: it is a legitimate way for an identity to say "no known
 *    reachable address right now" while still renewing its [notValidAfterEpochSecond] heartbeat.
 *
 * **A known, accepted tension with the original spec's "Metadaten-Minimierung" design principle,
 * documented rather than papered over:** broadcasting presence/address records over a network-wide
 * GossipSub topic ([PeerDirectoryGossip.PEER_RECORD_GOSSIP_TOPIC]) means every subscribed node
 * learns every published identity's current addresses and online-status heartbeat. Accepted
 * resolution (decided 2026-08-04): this is no worse than the multiaddr already published in V0.4's
 * `lapisnet://connect` QR/deep-link flow, and [PeerPresenceAnnouncer]'s enforced minimum-republish-
 * interval bounds how often a caller that goes through it republishes its OWN presence - see that
 * class's doc comment for the audit-round-1 correction on why this is only a PARTIAL mitigation,
 * not a network-wide guarantee against [PeerRecord] being a fine-grained real-time presence oracle:
 * [PeerDirectoryGossip.announce] itself is unrate-limited, and [PeerDirectoryGossip.onGossipMessage]
 * applies no inbound per-identity rate limit at all.
 */
class PeerRecord private constructor(
    val identity: Secp256k1PublicKey,
    val binding: IdentityBinding,
    possessionProof: ByteArray,
    addresses: List<Multiaddr>,
    capabilities: Set<PeerCapability>,
    val sequenceNumber: Long,
    val notValidAfterEpochSecond: Long,
    signature: ByteArray,
) {
    /** Immutable snapshot, capped at [PeerRecordCodec.MAX_ADDRESSES] - safe from later mutation of
     * any list the caller passed in. */
    val addresses: List<Multiaddr> = addresses.toList()

    /** Immutable snapshot. */
    val capabilities: Set<PeerCapability> = capabilities.toSet()

    private val storedSignature: ByteArray = signature.copyOf()
    private val storedPossessionProof: ByteArray = possessionProof.copyOf()

    /** Compact 64-byte ECDSA signature by [identity] over this record's canonical bytes -
     * [PEER_RECORD_DOMAIN_TAG], NOT [binding]'s own domain tag. Returns a fresh copy on every
     * access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    /** Compact 64-byte Ed25519 signature by [binding].ed25519PublicKey's OWN private key over
     * [identity]'s bytes - the proof-of-possession counter-signature that makes this record's
     * identity<->transport-key binding genuinely mutual (V0.8.1 sub-wave audit round 2, major
     * finding 1 fix; see [PeerRecord]'s class doc comment and [verifyPossession]). Returns a fresh
     * copy on every access. Never log this at any log level. */
    val possessionProof: ByteArray get() = storedPossessionProof.copyOf()

    /**
     * The libp2p [PeerId] [binding] claims for [identity] - derived from [binding].ed25519PublicKey
     * exactly as `net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId` derives a real
     * node's own `PeerId` from its `DualKeyIdentity.ed25519KeyPair.publicKey`. **NEVER trust this
     * without first confirming [verify], [verifyBinding], AND [verifyPossession] all return
     * `true`** - see this class's doc comment on why all three checks are independently required.
     */
    val peerId: PeerId get() = PeerId.fromPubKey(unmarshalEd25519PublicKey(binding.ed25519PublicKey.bytes))

    init {
        require(storedSignature.size == SIGNATURE_SIZE) {
            "peer record signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
        require(storedPossessionProof.size == SIGNATURE_SIZE) {
            "peer record possession proof must be a compact $SIGNATURE_SIZE-byte Ed25519 signature"
        }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0, was $sequenceNumber" }
        require(this.addresses.size <= PeerRecordCodec.MAX_ADDRESSES) {
            "at most ${PeerRecordCodec.MAX_ADDRESSES} addresses allowed, was ${this.addresses.size}"
        }
        // Deliberately NO range check on notValidAfterEpochSecond - this field is
        // attacker-controlled (PeerDirectoryGossip.onGossipMessage must never trust it for an
        // accept/reject decision - see that function's doc comment) and this constructor runs for
        // both locally-created AND gossip-decoded records. Mirrors MessageEnvelope's identical
        // decision about sentAtEpochSecond.
    }

    /** SHA-256 over this record's full canonical bytes (signed body + signature, see
     * [PeerRecordCodec.encode]) - the dedup/index key [PeerRecordIndex] uses. */
    fun contentId(): ByteArray = PeerRecordCodec.contentId(this)

    override fun equals(other: Any?): Boolean {
        if (other !is PeerRecord) return false
        return identity == other.identity &&
            binding == other.binding &&
            addresses == other.addresses &&
            capabilities == other.capabilities &&
            sequenceNumber == other.sequenceNumber &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            storedSignature.contentEquals(other.storedSignature) &&
            storedPossessionProof.contentEquals(other.storedPossessionProof)
    }

    override fun hashCode(): Int {
        var result = identity.hashCode()
        result = 31 * result + binding.hashCode()
        result = 31 * result + addresses.hashCode()
        result = 31 * result + capabilities.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + notValidAfterEpochSecond.hashCode()
        result = 31 * result + storedSignature.contentHashCode()
        result = 31 * result + storedPossessionProof.contentHashCode()
        return result
    }

    /** Never includes any signature (outer, binding, or possession proof) - mirrors
     * `net.lapisphilosophorum.lapisnet.trust.VeritasGrant.toString`'s precedent. */
    override fun toString(): String =
        "PeerRecord(identity=${identity.fingerprint()}, peerId=$peerId, addresses=${addresses.size}, " +
            "capabilities=$capabilities, sequenceNumber=$sequenceNumber, " +
            "notValidAfterEpochSecond=$notValidAfterEpochSecond)"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(PEER_RECORD_DOMAIN_TAG, body)

        /**
         * Creates and signs a new record for [identity]. Reuses [identity].binding verbatim as
         * this record's [binding] - see this class's doc comment on why a second binding scheme is
         * not invented. Additionally computes [PeerRecord.possessionProof] fresh - a NEW Ed25519
         * counter-signature by [identity].ed25519KeyPair's own private key, independent of
         * [identity].binding (V0.8.1 sub-wave audit round 2, major finding 1 fix; see [PeerRecord]'s
         * class doc comment). [sequenceNumber] must be strictly greater than any previously-announced
         * sequence number for this SAME [identity] for [PeerRecordIndex] to accept it as the new
         * current record - the caller (typically [PeerPresenceAnnouncer]'s caller) owns tracking
         * "what sequence number did I last use".
         *
         * @throws IllegalArgumentException if [identity].verifyBinding() is false - i.e. if the
         * caller handed in a [DualKeyIdentity] whose own binding is broken, this function refuses
         * to sign and publish a record built on top of it.
         */
        fun create(
            identity: DualKeyIdentity,
            addresses: List<Multiaddr>,
            capabilities: Set<PeerCapability>,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
        ): PeerRecord {
            require(identity.verifyBinding()) {
                "identity's own IdentityBinding does not verify - refusing to embed it in a signed PeerRecord"
            }
            val possessionProof =
                identity.ed25519KeyPair.sign(possessionDigest(identity.secp256k1KeyPair.publicKey))
            val body =
                PeerRecordCodec.encodeSignedBody(
                    identity = identity.secp256k1KeyPair.publicKey,
                    binding = identity.binding,
                    possessionProof = possessionProof,
                    addresses = addresses,
                    capabilities = capabilities,
                    sequenceNumber = sequenceNumber,
                    notValidAfterEpochSecond = notValidAfterEpochSecond,
                )
            val signature = identity.secp256k1KeyPair.sign(signingDigest(body))
            return PeerRecord(
                identity.secp256k1KeyPair.publicKey,
                identity.binding,
                possessionProof,
                addresses,
                capabilities,
                sequenceNumber,
                notValidAfterEpochSecond,
                signature,
            )
        }

        /** Checks ONLY this record's own outer [PeerRecord.signature] against [PeerRecord.identity]
         * - mirrors `net.lapisphilosophorum.lapisnet.trust.VeritasGrant.verify`'s single-signature
         * contract exactly. **Does NOT check [verifyBinding] or [verifyPossession]** - a caller (in
         * particular [PeerDirectoryGossip.onGossipMessage]) MUST call all three, see this class's
         * doc comment. */
        fun verify(record: PeerRecord): Boolean {
            val body = PeerRecordCodec.encodeSignedBody(record)
            return record.identity.verify(signingDigest(body), record.signature)
        }

        /** As [verify], but additionally asserts [record] was signed by [expectedIdentity] rather
         * than trusting whichever identity key happens to be embedded in the record. */
        fun verify(
            expectedIdentity: Secp256k1PublicKey,
            record: PeerRecord,
        ): Boolean = record.identity == expectedIdentity && verify(record)

        /** Reconstructs a record from already-decoded, unverified fields. Used by
         * [PeerRecordCodec.decode] and by adversarial tests that need to hand-construct a
         * structurally-valid-but-cryptographically-broken record (e.g. a mismatched
         * identity/binding pair) - callers must call [verify], [verifyBinding], AND
         * [verifyPossession] before trusting the result. Deliberately does NOT re-check
         * `identity.verifyBinding()` the way [create] does - a decoded/hand-built record is exactly
         * the case where that check is expected to legitimately fail (that is what [verifyBinding]
         * tests). [possessionProof] defaults to a same-size all-zero placeholder (structurally
         * valid, cryptographically not) so existing callers that only care about the OTHER fields
         * do not need to fabricate a real Ed25519 signature just to compile - mirrors how [signature]
         * itself is routinely passed as `ByteArray(64)` in this codebase's own adversarial tests. */
        internal fun fromDecoded(
            identity: Secp256k1PublicKey,
            binding: IdentityBinding,
            addresses: List<Multiaddr>,
            capabilities: Set<PeerCapability>,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            signature: ByteArray,
            possessionProof: ByteArray = ByteArray(SIGNATURE_SIZE),
        ): PeerRecord =
            PeerRecord(
                identity,
                binding,
                possessionProof,
                addresses,
                capabilities,
                sequenceNumber,
                notValidAfterEpochSecond,
                signature,
            )
    }
}

/** `true` iff [PeerRecord.binding] is actually a valid secp256k1-identity proof for
 * `binding.ed25519PublicKey` - i.e. [PeerRecord.identity] really vouches for the transport key
 * [PeerRecord.peerId] is derived from. See [PeerRecord]'s class doc comment: callers must check
 * this, [PeerRecord.verify], AND [verifyPossession] before trusting [PeerRecord.peerId]/
 * [PeerRecord.addresses]. An extension function (not a companion member) purely so call sites read
 * as `record.verifyBinding()`, symmetric with `record.contentId()`. */
fun PeerRecord.verifyBinding(): Boolean = IdentityBinding.verify(identity, binding)

/** `true` iff [PeerRecord.possessionProof] is a genuine Ed25519 signature, by
 * [PeerRecord.binding]'s own `ed25519PublicKey`'s PRIVATE key, over [PeerRecord.identity]'s bytes -
 * i.e. proof that whoever built this record actually HOLDS the Ed25519 private key
 * [PeerRecord.peerId] is derived from, not merely a public key copied off an earlier record it
 * observed on the wire. This is the check that closes the cross-binding/peerId-spoofing gap
 * [verify] + [verifyBinding] alone leave open - see [PeerRecord]'s class doc comment for the full
 * exploit and `PeerRecordSpoofingTest`'s case (h) for the adversarial proof. An extension function
 * for the same reason [verifyBinding] is one: call sites read as `record.verifyPossession()`. */
fun PeerRecord.verifyPossession(): Boolean =
    binding.ed25519PublicKey.verify(possessionDigest(identity), possessionProof)
