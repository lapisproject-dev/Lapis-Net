package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import java.math.BigInteger
import java.security.MessageDigest

/**
 * The DHT key a block is announced and looked up under: the BARE multihash of its [Cid]. This is
 * the key Nabu's responder hashes in `getKClosestPeers` and the key `GET_PROVIDERS` /
 * `ADD_PROVIDER` carry on the wire - NOT `cid.toBytes()`, whose version/codec prefix would put a
 * CIDv1 at a different point of the keyspace than the same content's CIDv0.
 */
internal fun dhtKeyFor(cid: Cid): ByteArray = cid.bareMultihash().toBytes()

/**
 * Kademlia XOR distance between a DHT [key] and a peer, both mapped into the keyspace the way
 * Nabu's router does it (`sha256` of the key bytes / of the peer-ID bytes). A fresh
 * [MessageDigest] per call - instances are not thread-safe.
 */
internal fun keyDistance(
    key: ByteArray,
    peerIdBytes: ByteArray,
): BigInteger {
    val a = MessageDigest.getInstance("SHA-256").digest(key)
    val b = MessageDigest.getInstance("SHA-256").digest(peerIdBytes)
    val xor = ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }
    return BigInteger(1, xor)
}
