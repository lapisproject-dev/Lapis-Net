package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.directory.SealedMailboxBox
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxKind
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.security.SecureRandom

/** Thrown by [SealedMailboxItemCodec.seal] when the envelope does not fit the fixed item size. */
class SealedMailboxItemTooLargeException : IllegalArgumentException("envelope exceeds the sealed item capacity")

/**
 * V0.10.0-F1: the fixed-size sealed envelope the anonymity-mode offline mailbox announces on the shared
 * topic. Since V0.10.0-F2 the box itself is the generic [SealedMailboxBox] (lapis-net-directory), shared with
 * mail; this object seals and opens it for direct messages ([SealedMailboxKind.DM]) and adds the
 * [DmEnvelopeCodec] step. Layout, key derivation and the honest limits are documented on [SealedMailboxBox].
 *
 * [open] never throws and never reveals why an item was refused.
 */
object SealedMailboxItemCodec {
    const val SEALED_ITEM_BYTES = SealedMailboxBox.ITEM_BYTES
    const val FRAGMENT_BYTES = 716
    const val FRAGMENT_COUNT = 8

    /** The largest [DmEnvelope] encoding a sealed item can carry (5,668 bytes). */
    const val MAX_ENVELOPE_BYTES = SealedMailboxBox.MAX_PAYLOAD_BYTES

    /**
     * Fixed envelope overhead around the content plaintext: the envelope frame prefix and length
     * field, the ratchet header and the AEAD tag. The content plaintext must satisfy
     * `plaintext.size + ENVELOPE_OVERHEAD_BYTES <= MAX_ENVELOPE_BYTES` for an anonymity-mode send.
     */
    const val ENVELOPE_OVERHEAD_BYTES =
        DmEnvelopeCodec.DM_ENVELOPE_FIXED_PREFIX_SIZE + 2 +
            net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec.HEADER_SIZE + 16

    /** Items refused by [open] since start (diagnostics only, never any content). */
    val refusedCount get() = SealedMailboxBox.refusedCount

    fun seal(
        envelopeBytes: ByteArray,
        recipientKey: X25519PublicKey,
        notValidAfterEpochSecond: Long,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        if (envelopeBytes.isEmpty() || envelopeBytes.size > MAX_ENVELOPE_BYTES) {
            throw SealedMailboxItemTooLargeException()
        }
        return SealedMailboxBox.seal(
            SealedMailboxKind.DM,
            envelopeBytes,
            recipientKey,
            notValidAfterEpochSecond,
            random,
        )
    }

    /** Opens [item] with [ownPrivate]; `null` for anything that is not a valid, unexpired DM item for us. */
    fun open(
        item: ByteArray,
        ownPrivate: X25519PrivateKey,
        nowEpochSecond: Long,
    ): DmEnvelope? {
        val bytes = SealedMailboxBox.open(item, ownPrivate, nowEpochSecond, SealedMailboxKind.DM) ?: return null
        return try {
            DmEnvelopeCodec.decode(bytes)
        } catch (e: MalformedDmEnvelopeException) {
            SealedMailboxBox.refusedCount.incrementAndGet()
            null
        } catch (e: RuntimeException) {
            SealedMailboxBox.refusedCount.incrementAndGet()
            null
        } finally {
            bytes.fill(0)
        }
    }
}
