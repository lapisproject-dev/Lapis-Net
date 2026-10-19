package net.lapisphilosophorum.lapisnet.storage

import io.libp2p.core.PeerId

/** The `/ipns/` key-space prefix every IPNS DHT key starts with. */
internal val IPNS_PREFIX: ByteArray = "/ipns/".toByteArray(Charsets.US_ASCII)

/**
 * `0x00 0x24` (identity multihash, 36 bytes) followed by the protobuf `PublicKey` header for an
 * Ed25519 key (`type = Ed25519`, `data` of 32 bytes): the fixed 6 bytes in front of the raw key.
 */
private val ED25519_IDENTITY_HEADER: ByteArray = byteArrayOf(0x00, 0x24, 0x08, 0x01, 0x12, 0x20)

private const val ED25519_KEY_BYTES = 32

/** Size of the only IPNS key shape accepted: prefix, identity-multihash header, raw Ed25519 key. */
internal const val IPNS_KEY_SIZE = 6 + 6 + ED25519_KEY_BYTES

/** Offset, within an IPNS key, of the marshalled protobuf public key (what a record's `pubKey` field holds). */
internal const val IPNS_KEY_PROTOBUF_OFFSET = 6 + 2

/** Offset, within an IPNS key, of the raw 32-byte Ed25519 public key. */
internal const val IPNS_KEY_RAW_OFFSET = 6 + 6

/**
 * The DHT key under which [peerId]'s IPNS record lives: `/ipns/` + the peer ID's bytes. Only
 * Ed25519 peer IDs (identity multihash of the protobuf public key) have an IPNS name here.
 */
internal fun ipnsKeyFor(peerId: PeerId): ByteArray {
    val key = IPNS_PREFIX + peerId.bytes
    require(parseIpnsKey(key) != null) { "only Ed25519 peer IDs have an IPNS name" }
    return key
}

/**
 * The publisher a DHT [key] names, or `null` unless [key] is exactly `/ipns/` followed by an
 * Ed25519 identity multihash. Hand-written, with a fixed expected length checked FIRST: Nabu's
 * `Cid.cast` / `Multihash.deserialize` allocate `new byte[declaredLength]` before any bound check, so a
 * declared length is never trusted here. A raw key of all zeros or all `0xFF` bytes is refused too.
 */
internal fun parseIpnsKey(key: ByteArray): PeerId? {
    if (key.size != IPNS_KEY_SIZE) return null
    for (i in IPNS_PREFIX.indices) if (key[i] != IPNS_PREFIX[i]) return null
    for (i in ED25519_IDENTITY_HEADER.indices) {
        if (key[IPNS_PREFIX.size + i] != ED25519_IDENTITY_HEADER[i]) return null
    }
    val raw = key.copyOfRange(IPNS_KEY_RAW_OFFSET, IPNS_KEY_SIZE)
    if (raw.all { it == 0.toByte() } || raw.all { it == 0xFF.toByte() }) return null
    return runCatching { PeerId(key.copyOfRange(IPNS_PREFIX.size, IPNS_KEY_SIZE)) }.getOrNull()
}
