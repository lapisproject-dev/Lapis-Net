package net.lapisphilosophorum.lapisnet.directory

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest

/**
 * The single, fixed DHT key under which onion relays announce themselves as providers (V0.10.0-B).
 * Like [MessagingRendezvous] no block exists under it; it is only a key. Because the key is public, the
 * provider set reveals which nodes are relays (which their gossiped descriptors do anyway) and is
 * eclipse-prone; a lookup result is a hint only and every descriptor found through it is fully verified.
 */
object OnionRelayRendezvous {
    const val DOMAIN_TAG: String = "LapisNet:onion-relays:v1"

    fun cid(): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, domainSeparatedDigest(DOMAIN_TAG))
}
