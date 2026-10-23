package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import java.nio.ByteBuffer
import java.time.Instant

private const val ANONYMOUS_PEER_RECORD_DOMAIN_TAG = "LapisNet:anonymous-peer-record:v1"
private const val ANONYMOUS_SERVICE_POSSESSION_DOMAIN_TAG = "LapisNet:anonymous-peer-record-service-possession:v1"

/** What a hidden-mode identity may advertise. Deliberately no RELAY: a relay is public by design. */
enum class AnonymousCapability(
    val bit: Int,
) {
    DM(0),
    MAIL(1),
    CALL_SIGNAL(2),
    ;

    companion object {
        const val ALL_BITS: Int = 0b111
    }
}

internal fun possessionBody(
    identity: Secp256k1PublicKey,
    sequenceNumber: Long,
): ByteArray =
    ByteBuffer
        .allocate(33 + 8)
        .put(identity.bytes)
        .putLong(sequenceNumber)
        .array()

/**
 * The directory entry of an identity that runs in anonymity mode (wave V0.10.0-D): "[identity] can be reached
 * through the onion service [onionAddress]". It carries NO network address, NO libp2p peer ID and NO
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]: the binding would tie the identity to the
 * transport key (= peer ID), which every direct connection shows next to the IP.
 *
 * Fixed wire size of 248 bytes with no length fields and no free-form fields, so it offers no tagging or covert
 * channel. Two signatures: the outer secp256k1 signature of the identity over the whole body, and an Ed25519
 * possession proof of the SERVICE key over `identity || sequenceNumber` (nobody can claim a foreign onion service
 * for their identity, and an old proof does not transplant into a newer entry).
 *
 * A *revocation* (flag bit 0) has no service key, proof, capabilities or prekey digest and ends the entry (the way
 * back to normal mode). Sequence numbers are epoch milliseconds, the same scale as [PeerRecord] (cross-type
 * downgrade protection, see [IdentitySupersession]).
 *
 * `toString` shows the identity fingerprint, the revoked flag and the sequence number only.
 */
class AnonymousPeerRecord private constructor(
    val identity: Secp256k1PublicKey,
    val serviceKey: Ed25519PublicKey?,
    servicePossessionProof: ByteArray,
    val capabilities: Set<AnonymousCapability>,
    prekeyBundleDigest: ByteArray?,
    val sequenceNumber: Long,
    val notValidAfterEpochSecond: Long,
    signature: ByteArray,
) {
    private val storedProof = servicePossessionProof.copyOf()
    private val storedDigest = prekeyBundleDigest?.copyOf()
    private val storedSignature = signature.copyOf()

    /** Ed25519 proof by the service key; all zero for a revocation. Fresh copy. */
    val servicePossessionProof: ByteArray get() = storedProof.copyOf()

    /** SHA-256 digest of the current prekey bundle, or `null` for none. Fresh copy. */
    val prekeyBundleDigest: ByteArray? get() = storedDigest?.copyOf()
    val signature: ByteArray get() = storedSignature.copyOf()
    val revoked: Boolean get() = serviceKey == null

    /** The onion service address, or `null` for a revocation. */
    val onionAddress: OnionServiceAddress? get() = serviceKey?.let { OnionServiceAddress(it) }

    init {
        require(storedProof.size == 64) { "service possession proof must be 64 bytes" }
        require(storedSignature.size == 64) { "signature must be 64 bytes" }
        require(storedDigest == null || storedDigest.size == 32) { "prekey bundle digest must be 32 bytes" }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
    }

    fun contentId(): ByteArray = AnonymousPeerRecordCodec.contentId(this)

    override fun equals(other: Any?): Boolean =
        other is AnonymousPeerRecord &&
            identity == other.identity &&
            serviceKey == other.serviceKey &&
            storedProof.contentEquals(other.storedProof) &&
            capabilities == other.capabilities &&
            (storedDigest ?: ByteArray(0)).contentEquals(other.storedDigest ?: ByteArray(0)) &&
            sequenceNumber == other.sequenceNumber &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            storedSignature.contentEquals(other.storedSignature)

    override fun hashCode(): Int = 31 * identity.hashCode() + sequenceNumber.hashCode()

    override fun toString(): String =
        "AnonymousPeerRecord(identity=${identity.fingerprint()}, revoked=$revoked, seq=$sequenceNumber)"

    companion object {
        const val MAX_TTL_WINDOW_SECONDS = 6 * 3600L
        const val MAX_CLOCK_SKEW_SECONDS = 300L

        private fun signingDigest(body: ByteArray): ByteArray =
            domainSeparatedDigest(ANONYMOUS_PEER_RECORD_DOMAIN_TAG, body)

        private fun possessionDigest(
            identity: Secp256k1PublicKey,
            sequenceNumber: Long,
        ): ByteArray =
            domainSeparatedDigest(ANONYMOUS_SERVICE_POSSESSION_DOMAIN_TAG, possessionBody(identity, sequenceNumber))

        /** Signs an entry for the onion service [serviceKey]. Refuses TTLs beyond [MAX_TTL_WINDOW_SECONDS]. */
        fun create(
            identity: DualKeyIdentity,
            serviceKey: Ed25519KeyPair,
            capabilities: Set<AnonymousCapability>,
            prekeyBundleDigest: ByteArray?,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            nowEpochSecond: Long = Instant.now().epochSecond,
        ): AnonymousPeerRecord {
            require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
            require(notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS) {
                "anonymous peer record validity exceeds the window"
            }
            require(
                prekeyBundleDigest == null || prekeyBundleDigest.size == 32,
            ) { "prekey bundle digest must be 32 bytes" }
            val id = identity.secp256k1KeyPair.publicKey
            val proof = serviceKey.sign(possessionDigest(id, sequenceNumber))
            return signed(
                id,
                identity,
                serviceKey.publicKey,
                proof,
                capabilities,
                prekeyBundleDigest,
                sequenceNumber,
                notValidAfterEpochSecond,
            )
        }

        /** Signs a revocation: the identity no longer has an onion presence (back to normal mode). */
        fun createRevocation(
            identity: DualKeyIdentity,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            nowEpochSecond: Long = Instant.now().epochSecond,
        ): AnonymousPeerRecord {
            require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
            require(notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS + MAX_CLOCK_SKEW_SECONDS) {
                "anonymous peer record validity exceeds the window"
            }
            return signed(
                identity.secp256k1KeyPair.publicKey,
                identity,
                null,
                ByteArray(64),
                emptySet(),
                null,
                sequenceNumber,
                notValidAfterEpochSecond,
            )
        }

        private fun signed(
            id: Secp256k1PublicKey,
            identity: DualKeyIdentity,
            serviceKey: Ed25519PublicKey?,
            proof: ByteArray,
            capabilities: Set<AnonymousCapability>,
            digest: ByteArray?,
            seq: Long,
            nva: Long,
        ): AnonymousPeerRecord {
            val body = AnonymousPeerRecordCodec.encodeSignedBody(id, serviceKey, proof, capabilities, digest, seq, nva)
            val signature = identity.secp256k1KeyPair.sign(signingDigest(body))
            return AnonymousPeerRecord(id, serviceKey, proof, capabilities, digest, seq, nva, signature)
        }

        /** Complete verification (never throws): structure, time window, possession proof, outer signature. */
        fun verify(
            record: AnonymousPeerRecord,
            nowEpochSecond: Long,
        ): Boolean =
            try {
                val key = record.serviceKey
                val consistent =
                    if (key == null) {
                        record.capabilities.isEmpty() &&
                            record.prekeyBundleDigest == null &&
                            record.servicePossessionProof.all { it == 0.toByte() }
                    } else {
                        !isDegenerate(key.bytes) && !isDegenerate(record.servicePossessionProof)
                    }
                // the revocation window gets the skew on top so it always covers a still-valid anonymous entry
                val upper =
                    nowEpochSecond + MAX_TTL_WINDOW_SECONDS + MAX_CLOCK_SKEW_SECONDS
                consistent &&
                    !isDegenerate(record.signature) &&
                    record.notValidAfterEpochSecond >= nowEpochSecond &&
                    record.notValidAfterEpochSecond <= upper &&
                    (
                        key == null ||
                            key.verify(
                                possessionDigest(record.identity, record.sequenceNumber),
                                record.servicePossessionProof,
                            )
                    ) &&
                    record.identity.verify(
                        signingDigest(AnonymousPeerRecordCodec.encodeSignedBody(record)),
                        record.signature,
                    )
            } catch (e: RuntimeException) {
                false
            }

        private fun isDegenerate(bytes: ByteArray): Boolean =
            bytes.all { it == 0.toByte() } || bytes.all { it == 0xFF.toByte() }

        internal fun fromDecoded(
            identity: Secp256k1PublicKey,
            serviceKey: Ed25519PublicKey?,
            proof: ByteArray,
            capabilities: Set<AnonymousCapability>,
            digest: ByteArray?,
            seq: Long,
            nva: Long,
            signature: ByteArray,
        ) = AnonymousPeerRecord(identity, serviceKey, proof, capabilities, digest, seq, nva, signature)
    }
}
