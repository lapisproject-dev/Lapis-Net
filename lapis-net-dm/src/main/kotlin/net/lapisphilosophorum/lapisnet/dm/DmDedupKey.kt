package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessage

private const val DOMAIN_TAG = "LapisNet:dm-dedup:v1"

/** Dedup key for a delivered [net.lapisphilosophorum.lapisnet.dm.DmInboundMessage], shared across
 * both delivery paths.
 *
 * **Originated in V0.8.4, which only computed and exposed this key - nothing in that wave
 * deduplicated against anything with it.** V0.8.5 (a later sub-wave, since landed in this branch)
 * adds an offline mailbox path that can redeliver a message also delivered online through V0.8.4's
 * [DmProtocol] stream; that path needs a dedup key derived from fields BOTH delivery paths can see,
 * so it did not have to retrofit one. **V0.8.5, since landed, is exactly what consumes it** -
 * [DmSessionManager.processInboundDmEnvelope] computes `DmDedupKey.of(...)` and checks it against
 * `isRecentlyDelivered(dedupKey)` for every inbound envelope, online or offline, before it is ever
 * handed to a session for decryption - see that method's own doc comment and `docs/architecture.adoc`
 * for the cross-path `recentlyDeliveredDedupKeys`/durable-registry mechanics this key feeds.
 *
 * **The exact preimage is [net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]'s
 * domain-separated construction, NOT plain concatenation** (doc correction, security audit round 1
 * finding, 2026-08-11: an earlier revision of this comment stated the formula as plain
 * concatenation, `SHA-256(domainTag || senderIdentity.bytes(33) || ratchetPublicKey.bytes(32) ||
 * messageNumber(4, big-endian))`, which does not match [of]'s actual implementation and would have
 * produced a different, non-matching key for anyone implementing V0.8.5's redelivery path against
 * the prose instead of the code). The REAL preimage `domainSeparatedDigest` builds is `len(tag) ||
 * tag || len(senderIdentity) || senderIdentity.bytes(33) || len(ratchetPublicKey) ||
 * ratchetPublicKey.bytes(32) || len(messageNumber) || messageNumber(4, big-endian)`, where every
 * `len(...)` is a 2-byte big-endian length prefix (1 byte for `tag`'s own length) - see that
 * function's own doc comment for the exact byte layout. This is STRICTLY STRONGER than plain
 * concatenation (unambiguous parsing, no cross-field boundary ambiguity), so the implementation is
 * not changing - only this comment, to match it. A [known-answer test][DmDedupKeyTest] pins the
 * exact preimage so this contract is enforced in code, not merely in prose.
 *
 * A message's `(ratchetPublicKey, messageNumber)` pair is unique per session
 * position by the Double Ratchet's own construction (`Ns`/`Nr` never rewind for a correctly-
 * persisted session - the exact property
 * [net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageRejectedException]'s "message number
 * already consumed" check enforces), and [senderIdentity] scopes it across DIFFERENT sessions this
 * identity may hold. Deliberately computed from fields ALREADY on the decoded [RatchetMessage] - the
 * same fields V0.8.5's offline mailbox path will see too, so a message delivered both online (this
 * wave) and later redelivered via the mailbox produces the IDENTICAL dedup key without either path
 * needing to know about the other.
 */
object DmDedupKey {
    fun of(
        senderIdentity: Secp256k1PublicKey,
        message: RatchetMessage,
    ): ByteArray =
        domainSeparatedDigest(
            DOMAIN_TAG,
            senderIdentity.bytes,
            message.header.ratchetPublicKey.bytes,
            intToBigEndian4(message.header.messageNumber),
        )

    private fun intToBigEndian4(value: Int): ByteArray =
        byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte(),
        )
}
