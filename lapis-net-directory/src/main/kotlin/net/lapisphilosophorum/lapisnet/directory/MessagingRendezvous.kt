package net.lapisphilosophorum.lapisnet.directory

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * The DHT key under which a node announces "I have something for this recipient" (V0.9.14, provider
 * records). No block with this CID exists - it is only a key. Provider records are accepted by a DHT peer
 * only from the provider itself (checked against Nabu's `ADD_PROVIDER` handling by a test), so an announcement
 * is source-authenticated; what it reveals is documented in docs/architecture.adoc ("Metadata: recipient
 * lookups reveal who talks to whom").
 */
object MessagingRendezvous {
    const val DOMAIN_TAG: String = "LapisNet:dht-inbox-rendezvous:v1"

    /** Raw-codec CIDv1 over `SHA-256(DOMAIN_TAG || recipient)` (domain-separated, length-prefixed). */
    fun cidFor(recipient: Secp256k1PublicKey): Cid =
        Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, domainSeparatedDigest(DOMAIN_TAG, recipient.bytes))
}
