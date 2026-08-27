package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.time.Instant

private const val MAILBOX_POINTER_DOMAIN_TAG = "LapisNet:mailbox-pointer:v1"
private const val SIGNATURE_SIZE = 64

/**
 * V0.8.5's offline-delivery pointer: a signed, gossiped record saying "an encrypted [DmEnvelope]
 * blob for [recipientIdentity], deposited by [senderIdentity], is stored in Nabu under [blobCid],
 * valid until [notValidAfterEpochSecond]". Gossiped on [MailboxTopics.forRecipient]`(recipientIdentity)`
 * - see [MailboxGossip] for the validator and [MailboxPoller] for the recipient-side fetch-and-decrypt
 * driver.
 *
 * **Central mechanism, stated here because this is the type that carries it.** A bare CID alone is
 * not fetchable: `NabuStorage.findProviders` (DHT-based provider discovery) has been broken since
 * V0.1.4 (see `docs/architecture.adoc`), so this pointer carries [senderIdentity] - not an address,
 * which would go stale - as a routing HINT. The recipient resolves the sender's CURRENT address at
 * fetch time via `PeerDirectoryGossip.lookup(senderIdentity)` (V0.8.1) and does a direct Bitswap
 * fetch by explicit peer ([MailboxPoller.attemptOne]), never touching `findProviders`. This means
 * **the sender must remain reachable (or at least come back online periodically) for offline
 * delivery to complete** - both to serve the eventual Bitswap fetch, and, more fundamentally
 * (GossipSub has no message replay - see `MailboxRedeliveryScheduler`'s own doc comment), to have
 * this pointer periodically re-announced so that a recipient whose node was not yet running at the
 * time of the original publish can ever learn the pointer exists at all. This is a real, inherent
 * limitation of routing around the broken DHT with gossip alone - documented plainly, not silently
 * papered over, in `docs/roadmap.adoc`'s and `docs/architecture.adoc`'s V0.8.5 sections.
 *
 * **Metadata-minimization honesty note - a deliberate, necessary deviation from the original DM
 * concept note's "Mailbox-Records enthalten keine Klartext-Absenderkennung" (mailbox records carry
 * no plaintext sender identification) principle, stated here rather than silently claiming more
 * privacy than this mechanism delivers.** This pointer carries [senderIdentity] in the clear,
 * signed, and gossiped on a topic derived from [recipientIdentity]. The recipient cannot resolve a
 * routing hint to fetch the blob without knowing WHOSE current address to look up, and
 * [MailboxGossip]'s validator cannot cheaply reject a forged pointer without a signer identity to
 * check it against. A fully metadata-blind mailbox record is not achievable under this wave's
 * broken-DHT-workaround fetch mechanism - anyone who can subscribe to
 * [MailboxTopics.forRecipient]`(X)` (i.e. anyone, since GossipSub topics are not access-controlled)
 * learns "someone claiming identity S deposited a message for X at time T", exactly the same
 * exposure `PeerRecord`'s own class doc comment already accepts for presence/address gossip. No
 * onion routing is attempted (an explicit, deliberate scope cut - the original DM concept note's own
 * open question, left open here, not resolved) - see `DmSessionManager.sendOffline`'s doc comment
 * for the full list of this wave's scope cuts.
 *
 * **Extended 2026-08-2x, security audit round 1 minor finding: this note stopped at identity
 * metadata, but the exposure does not.** This pointer also publishes [blobCid] in the clear, and
 * Bitswap serves blocks to any requesting peer with no read-access control (see `NabuStorage`'s own
 * doc comment, `allowAllReads`). Consequently, ANY mailbox-topic observer - not merely the intended
 * recipient - can Bitswap-fetch the full encrypted [DmEnvelope] blob directly from [senderIdentity],
 * learning the exact ciphertext length (hence an approximate plaintext length) and retaining that
 * ciphertext indefinitely for later cryptanalysis or a post-compromise decryption attempt, even
 * without ever being the message's actual recipient. This is a strictly LARGER exposure than
 * V0.8.4's online path, where the frame only ever traverses the recipient's own libp2p stream -
 * stated here for the same reason as the paragraph above: this note's purpose is to state the real
 * exposure, not to silently claim more privacy than this mechanism delivers.
 *
 * **`internal` constructor - only [MailboxPointerCodec.decode] and [create] build one**, mirroring
 * `PeerRecord`'s own internal-ctor discipline.
 */
class MailboxPointer private constructor(
    val recipientIdentity: Secp256k1PublicKey,
    val senderIdentity: Secp256k1PublicKey,
    val blobCid: Cid,
    val notValidAfterEpochSecond: Long,
    signature: ByteArray,
) {
    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [senderIdentity] over this pointer's canonical bytes.
     * Returns a fresh copy on every access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == SIGNATURE_SIZE) {
            "mailbox pointer signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
        // Deliberately NO range check on notValidAfterEpochSecond here - same reasoning as
        // PeerRecord's init block: this field is attacker-controlled and this constructor runs for
        // both locally-created AND gossip-decoded pointers. MailboxGossip.onGossipMessage must never
        // consult it for accept/reject (TTL is read/poll-time only, see MailboxPoller.pollOnce).
    }

    /** SHA-256 over this pointer's full canonical bytes (signed body + signature) - the dedup/
     * index key [MailboxPointerIndex] uses. */
    fun contentId(): ByteArray = MailboxPointerCodec.contentId(this)

    /** Never includes the signature or [blobCid]'s raw bytes beyond the CID's own printable
     * form. */
    override fun toString(): String =
        "MailboxPointer(recipient=${recipientIdentity.fingerprint()}, sender=${senderIdentity.fingerprint()}, " +
            "blobCid=$blobCid, notValidAfterEpochSecond=$notValidAfterEpochSecond)"

    companion object {
        /** Generous - an offline deposit should survive a realistic "recipient on vacation"
         * absence, unlike `PeerRecord`'s 24h heartbeat window. Provisional magnitude, not derived
         * from pilot data, same framing as every sibling cap in this codebase. */
        const val MAX_TTL_WINDOW_SECONDS = 30 * 86_400L

        /** [DmSessionManager.sendOffline]'s default TTL when the caller does not specify one. */
        const val DEFAULT_TTL_SECONDS = 7 * 86_400L

        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(MAILBOX_POINTER_DOMAIN_TAG, body)

        /**
         * Creates and signs a new pointer for [recipientIdentity], deposited by [sender].
         *
         * @throws IllegalArgumentException if [notValidAfterEpochSecond] claims validity more than
         *   [MAX_TTL_WINDOW_SECONDS] beyond [nowEpochSecond].
         */
        fun create(
            sender: Secp256k1KeyPair,
            recipientIdentity: Secp256k1PublicKey,
            blobCid: Cid,
            notValidAfterEpochSecond: Long,
            nowEpochSecond: Long = Instant.now().epochSecond,
        ): MailboxPointer {
            require(notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS) {
                "notValidAfterEpochSecond ($notValidAfterEpochSecond) claims validity more than " +
                    "$MAX_TTL_WINDOW_SECONDS seconds beyond now ($nowEpochSecond) - refusing to sign " +
                    "an unreasonably long-lived mailbox pointer"
            }
            val body =
                MailboxPointerCodec.encodeSignedBody(
                    recipientIdentity,
                    sender.publicKey,
                    blobCid,
                    notValidAfterEpochSecond,
                )
            val signature = sender.sign(signingDigest(body))
            return MailboxPointer(recipientIdentity, sender.publicKey, blobCid, notValidAfterEpochSecond, signature)
        }

        /** Checks [pointer]'s own [MailboxPointer.signature] against [MailboxPointer.senderIdentity]. */
        fun verify(pointer: MailboxPointer): Boolean {
            val body = MailboxPointerCodec.encodeSignedBody(pointer)
            return pointer.senderIdentity.verify(signingDigest(body), pointer.signature)
        }

        /** Reconstructs a pointer from already-decoded, unverified fields. Used by
         * [MailboxPointerCodec.decode] and by adversarial tests that need to hand-construct a
         * structurally-valid-but-cryptographically-broken pointer. Callers must call [verify]
         * before trusting the result. */
        internal fun fromDecoded(
            recipientIdentity: Secp256k1PublicKey,
            senderIdentity: Secp256k1PublicKey,
            blobCid: Cid,
            notValidAfterEpochSecond: Long,
            signature: ByteArray,
        ): MailboxPointer =
            MailboxPointer(recipientIdentity, senderIdentity, blobCid, notValidAfterEpochSecond, signature)
    }
}
