package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

object InboxTopics {
    /**
     * The GossipSub topic a given identity's inbox lives on:
     * `"LapisNet:inbox:<64 lowercase hex chars of sha256(compressed pubkey)>:v1"`.
     *
     * Topic-per-identity, gossip-based, deliberately NOT a DHT inbox record:
     * `org.peergos.protocol.dht.Kademlia.dialPeer` is documented broken (see
     * `net.lapisphilosophorum.lapisnet.storage.NabuStorage.provide`'s doc comment and the
     * architecture doc's V0.1.4 section), so this wave routes entirely through GossipSub, exactly
     * as `net.lapisphilosophorum.lapisnet.trust.VeritasGossip` already does for a different topic
     * shape (one network-wide topic there, one topic per recipient identity here).
     *
     * Hashing the key rather than embedding it directly is cosmetic, not a privacy control - the
     * public key is public by construction and the mapping is trivially recomputable by anyone who
     * knows the key. It exists purely to give every topic string a fixed 64-hex-char shape.
     * Deliberately NOT [net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex], which
     * truncates to the first 8 bytes of the digest: a truncated topic name would let two distinct
     * identities' inboxes collide onto the same topic string.
     */
    fun forRecipient(recipient: Secp256k1PublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(recipient.bytes)
        val hex = digest.joinToString("") { "%02x".format(it) }
        return "LapisNet:inbox:$hex:v1"
    }
}
