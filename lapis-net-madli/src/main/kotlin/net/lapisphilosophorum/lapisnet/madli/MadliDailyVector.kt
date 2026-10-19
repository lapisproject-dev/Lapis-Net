package net.lapisphilosophorum.lapisnet.madli

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify

/** Domain-separation tag for Madli daily-vector signatures - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. Deliberately distinct from every other
 * signing purpose in this project. */
private const val MADLI_DAILY_VECTOR_DOMAIN_TAG = "LapisNet:madli-daily-vector:v1"

private const val SIGNATURE_SIZE = 64

/**
 * A signed, bilateral, per-day observation of one libp2p peer's infrastructure quality
 * (Bitswap/DHT serving), cast by [observer] about [observedPeer] on [epochDay]. Structurally
 * mirrors `KarmaVote`: private constructor + companion `create`/`verify`/`fromDecoded`, defensive
 * `ByteArray` copy of the signature, hand-written `equals`/`hashCode`/`toString` (excluding the
 * signature), own domain-separation tag.
 *
 * **[observedPeer] is a libp2p [PeerId], not a [Secp256k1PublicKey].** Madli rates infrastructure
 * peers (Bitswap/DHT serving quality of a specific libp2p node), not Lapis identities - the same
 * distinction the vault note draws between "wer ist vertrauenswürdig" (Veritas, identity-keyed)
 * and "welcher Knoten liefert gut" (Madli, PeerId-keyed). [observer] remains a
 * [Secp256k1PublicKey] - the canonical Lapis identity, whose Veritas standing drives the
 * consumer-side weighting in [MadliAggregator].
 *
 * **No `nonce` field - deliberate, and the OPPOSITE of `KarmaVote`/`LtrRecord`.** Those are
 * accumulating models (every vote/record is kept, never resolved to one winner for a given key),
 * so a `nonce` is needed to keep two otherwise-identical entries content-id-distinct. Madli is
 * latest-wins-per-`(observer, observedPeer, epochDay)` (like `VeritasGrant`'s latest-wins-per-
 * (truster, target) chain), not accumulating: a day has exactly one summary per observer for one
 * observed peer. A byte-identical re-publish of the same summary IS a replay and SHOULD dedup by
 * content-id (handled by [MadliVectorIndex]'s content-id map). Two genuinely different vectors for
 * the same `(observer, observedPeer, epochDay)` tuple (e.g. the observer republishing a corrected
 * summary) naturally have different content-ids (different [metrics]), and are handled by the
 * index's per-tuple replace-on-conflict rule (see [MadliVectorIndex]'s doc comment) rather than by
 * a nonce keeping them both alive side by side.
 *
 * **[signature] - never log this at any log level.**
 */
class MadliDailyVector private constructor(
    val observer: Secp256k1PublicKey,
    val observedPeer: PeerId,
    val epochDay: Long,
    /** The five core infrastructure metrics, or `null` for a relay-only (v2) vector. */
    val metrics: MadliMetrics?,
    /** The relay-reliability observation, or `null` for a core-only (v1-encoded) vector. */
    val relayMetrics: MadliRelayMetrics?,
    signature: ByteArray,
) {
    private val storedSignature: ByteArray = signature.copyOf()

    /** 64-byte ECDSA signature by [observer] over the canonical bytes. Fresh copy per access.
     * Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(metrics != null || relayMetrics != null) {
            "a vector must carry core metrics, relay metrics, or both"
        }
        require(storedSignature.size == SIGNATURE_SIZE) {
            "vector signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
    }

    /**
     * SHA-256 over this vector's full canonical bytes (signed body + signature, see
     * [MadliDailyVectorCodec.encode]) - the content id [MadliVectorIndex] dedups gossip delivery
     * by, mirroring `KarmaVote.contentId`'s role exactly.
     */
    fun contentId(): ByteArray = MadliDailyVectorCodec.contentId(this)

    override fun equals(other: Any?): Boolean {
        if (other !is MadliDailyVector) return false
        return observer == other.observer &&
            observedPeer == other.observedPeer &&
            epochDay == other.epochDay &&
            metrics == other.metrics &&
            relayMetrics == other.relayMetrics &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = observer.hashCode()
        result = 31 * result + observedPeer.hashCode()
        result = 31 * result + epochDay.hashCode()
        result = 31 * result + (metrics?.hashCode() ?: 0)
        result = 31 * result + (relayMetrics?.hashCode() ?: 0)
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Deliberately excludes [signature] - see this class's doc comment on never logging it. */
    override fun toString(): String =
        "MadliDailyVector(observer=${observer.fingerprint()}, observedPeer=$observedPeer, " +
            "epochDay=$epochDay, metrics=$metrics, relayMetrics=$relayMetrics)"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray =
            domainSeparatedDigest(MADLI_DAILY_VECTOR_DOMAIN_TAG, body)

        /** Creates and signs a new Madli daily vector. [metrics] should be [observer]'s own real,
         * locally-collected observation of [observedPeer]'s serving quality on [epochDay] - see
         * this class's doc comment on the trust model (structural-only, never verified against
         * real Bitswap/DHT traffic by any other node). */
        fun create(
            observer: Secp256k1KeyPair,
            observedPeer: PeerId,
            epochDay: Long,
            metrics: MadliMetrics,
        ): MadliDailyVector = create(observer, observedPeer, epochDay, metrics, null)

        /** As the core-only overload, but may additionally (or exclusively) carry a
         * [relayMetrics] block. At least one of [metrics]/[relayMetrics] must be non-null. A
         * vector with [relayMetrics] != null is encoded as wire-format v2; a core-only vector is
         * always encoded as v1 (the canonical encoding - see [MadliDailyVectorCodec]). */
        fun create(
            observer: Secp256k1KeyPair,
            observedPeer: PeerId,
            epochDay: Long,
            metrics: MadliMetrics?,
            relayMetrics: MadliRelayMetrics?,
        ): MadliDailyVector {
            require(metrics != null || relayMetrics != null) {
                "a vector must carry core metrics, relay metrics, or both"
            }
            val body =
                MadliDailyVectorCodec.encodeSignedBody(
                    observer.publicKey,
                    observedPeer,
                    epochDay,
                    metrics,
                    relayMetrics,
                )
            val signature = observer.sign(signingDigest(body))
            return MadliDailyVector(observer.publicKey, observedPeer, epochDay, metrics, relayMetrics, signature)
        }

        /** Self-contained cryptographic verification: checks [vector]'s signature against the
         * observer public key embedded in the vector itself. */
        fun verify(vector: MadliDailyVector): Boolean {
            val body = MadliDailyVectorCodec.encodeSignedBody(vector)
            return vector.observer.verify(signingDigest(body), vector.signature)
        }

        /** As [verify], but additionally asserts [vector] was signed by [expectedObserver] rather
         * than trusting whichever observer key happens to be embedded in the vector. */
        fun verify(
            expectedObserver: Secp256k1PublicKey,
            vector: MadliDailyVector,
        ): Boolean = vector.observer == expectedObserver && verify(vector)

        /** Reconstructs a vector from already-decoded, unverified fields. Used only by
         * [MadliDailyVectorCodec.decode] - callers must call [verify] before trusting the
         * result. */
        internal fun fromDecoded(
            observer: Secp256k1PublicKey,
            observedPeer: PeerId,
            epochDay: Long,
            metrics: MadliMetrics?,
            relayMetrics: MadliRelayMetrics?,
            signature: ByteArray,
        ): MadliDailyVector = MadliDailyVector(observer, observedPeer, epochDay, metrics, relayMetrics, signature)
    }
}

/** Days since the Unix epoch in UTC. `floorDiv` (not `/`) so a pre-1970 or negative millis input
 * still maps monotonically, mirroring `LtrWeightCalculator`'s defensive-clamp discipline for
 * out-of-range time. */
fun currentEpochDayUtc(nowMillis: Long = System.currentTimeMillis()): Long = Math.floorDiv(nowMillis, 86_400_000L)
