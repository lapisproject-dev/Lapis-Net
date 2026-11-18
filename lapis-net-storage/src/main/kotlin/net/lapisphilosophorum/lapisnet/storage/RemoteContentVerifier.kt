package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import java.time.Instant

/** Bounds of lookups through circuits (wave V0.10.0-J2), shared by the storage and the onion layer. */
object LookupLimits {
    /** The largest block a circuit lookup can carry: the 128 KiB answer class minus its 6-byte header. */
    const val MAX_CONTENT: Int = 131_066
}

/**
 * The checks both ends of a circuit lookup (wave V0.10.0-J2) apply to untrusted content: a block must hash to its CID,
 * an IPNS record must be validly signed by the key its name names. Public so that the onion layer (which must not
 * duplicate them) uses exactly the checks [NabuStorage] uses. Pure, no network, a fresh digest per call.
 */
object RemoteContentVerifier {
    /** CIDv1, raw codec, SHA-256 multihash of 32 bytes: the only CID shape the codebase produces. */
    private val RAW_SHA256_CID_PREFIX = byteArrayOf(0x01, 0x55, 0x12, 0x20)
    private const val RAW_SHA256_CID_SIZE = 4 + 32

    /** `true` iff [bytes] is the raw block that [cid] (CIDv1, raw codec, SHA-256) names. */
    fun blockMatchesCid(
        cid: Cid,
        bytes: ByteArray,
    ): Boolean = matchesCid(cid, bytes)

    /**
     * The CID encoded by [key] if it is exactly a CIDv1 with raw codec and a SHA-256 multihash, else `null`. The shape
     * is checked by hand BEFORE Nabu's `Cid.cast` runs: that one allocates from a declared length before any bound
     * check, so an untrusted key never reaches it unchecked.
     */
    fun parseRawSha256Cid(key: ByteArray): Cid? {
        if (key.size != RAW_SHA256_CID_SIZE) return null
        for (i in RAW_SHA256_CID_PREFIX.indices) if (key[i] != RAW_SHA256_CID_PREFIX[i]) return null
        val cid = runCatching { Cid.cast(key) }.getOrNull() ?: return null
        if (cid.codec != Cid.Codec.Raw || cid.type != Multihash.Type.sha2_256) return null
        return cid
    }

    /** The wire form of a raw/SHA-256 [cid] as [parseRawSha256Cid] accepts it, or `null` for any other CID. */
    fun rawSha256CidBytes(cid: Cid): ByteArray? {
        if (cid.codec != Cid.Codec.Raw || cid.type != Multihash.Type.sha2_256 || cid.hash.size != 32) return null
        return RAW_SHA256_CID_PREFIX + cid.hash
    }

    /** `true` iff [key] is exactly `/ipns/` followed by a canonical Ed25519 identity multihash. */
    fun isIpnsRoutingKey(key: ByteArray): Boolean {
        val publisher = parseIpnsKey(key) ?: return false
        return runCatching { ipnsKeyFor(publisher).contentEquals(key) }.getOrDefault(false)
    }

    /** The routing key `/ipns/<multihash>` of an Ed25519 [publisher]. */
    fun ipnsRoutingKey(publisher: io.libp2p.core.PeerId): ByteArray = ipnsKeyFor(publisher)

    /**
     * `true` iff [raw] is an IPNS record that validates completely (signature, canonical encoding, expiry at [now]) and
     * is signed by the key [key] names.
     */
    fun ipnsRecordValid(
        key: ByteArray,
        raw: ByteArray,
        now: Instant,
        limits: DhtLimits = DhtLimits(),
    ): Boolean {
        val publisher = parseIpnsKey(key) ?: return false
        return IpnsRecordCodec.validate(key, raw, now, limits)?.publisher == publisher
    }
}
