package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

object MailboxTopics {
    /**
     * The GossipSub topic a given identity's offline mailbox lives on:
     * `"LapisNet:mailbox:<64 lowercase hex chars of sha256(compressed pubkey)>:v1"`.
     *
     * Topic-per-recipient-identity, mirroring
     * `net.lapisphilosophorum.lapisnet.mail.InboxTopics.forRecipient`'s exact structure and its
     * identical "hashing the key is cosmetic, not a privacy control" caveat: the public key is
     * public by construction and the mapping is trivially recomputable by anyone who knows the key.
     * Deliberately NOT [net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex], which
     * truncates to the first 8 bytes of the digest - a truncated topic name would let two distinct
     * identities' mailboxes collide onto the same topic string.
     */
    fun forRecipient(recipient: Secp256k1PublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(recipient.bytes)
        val hex = digest.joinToString("") { "%02x".format(it) }
        return "LapisNet:mailbox:$hex:v1"
    }
}
