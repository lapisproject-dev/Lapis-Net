package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * The recipient-wrap-list section appended to a [MessageEnvelopeCodec.encodeSignedBody] body when
 * (and only when) the envelope's mode is [EncryptionMode.HYBRID_ECIES].
 *
 * Layout: `wrapCount(2) | ( ephemeralPublicKey(33) | wrappedKey(48) ) * wrapCount`. All integers
 * big-endian. Every record is fixed width (see [EciesWrap]'s doc comment) - the only
 * declared-length field in the whole section is `wrapCount`, and it is validated against the
 * already-decoded recipient count BEFORE a single byte is allocated for the records.
 *
 * **Wraps are always inline - there is deliberately no CID-referenced "recipients blob" variant.**
 * A CID-referenced blob is unfetchable in this codebase for exactly the reason [MailFrameCodec]
 * carries the body inline instead of a pointer: `Kademlia.dialPeer` is documented broken since
 * V0.1.4, and [InboxGossip]'s gossip validator may make no network calls at all - a recipient could
 * never reliably obtain their own wrap from a blob referenced only by CID. At
 * `MAX_RECIPIENTS = 64` the worst-case section is `2 + 65*81 = 5,267` bytes, which is about 8% of
 * [MessageEnvelopeCodec.MAX_BODY_SIZE] - there is no size pressure a blob would relieve. A future
 * high-fan-out variant gets its own [EncryptionMode] wire value (the mechanism this codebase
 * already uses for forward-compatible mode additions, mirroring `LtrRecordCodec`'s `proofType`
 * precedent), not a retrofit of this one.
 */
internal object EciesWrapCodec {
    /** recipients.size + 1: one wrap per recipient plus the sender's own self-wrap. */
    const val MAX_WRAPS = MessageEnvelopeCodec.MAX_RECIPIENTS + 1 // 65

    fun encodeInto(
        out: DataOutputStream,
        wraps: List<EciesWrap>,
    ) {
        out.writeShort(wraps.size)
        wraps.forEach { wrap ->
            out.write(wrap.ephemeralPublicKey.bytes)
            out.write(wrap.wrappedKey)
        }
    }

    /**
     * @param expectedWrapCount `recipients.size + 1`, already known from the recipient section
     *   decoded earlier in the same buffer. Passing it lets this function reject a bogus
     *   `wrapCount` with a single comparison, before any per-record allocation.
     *
     * Order of operations, non-negotiable (mirrors [MessageEnvelopeCodec.decode]'s
     * check-before-allocate discipline exactly):
     * 1. Read `wrapCount`.
     * 2. Reject `wrapCount !in 1..MAX_WRAPS` - the cheap absolute bound that holds regardless of
     *    what a future caller passes as [expectedWrapCount].
     * 3. Reject `wrapCount != expectedWrapCount` - the precise bound for this actual envelope.
     * 4. Only then allocate and read the per-wrap records.
     *
     * Total allocation is bounded at `65 * 81 = 5,265` bytes before any input is trusted.
     * [Secp256k1PublicKey]'s own curve check runs at construction; its `IllegalArgumentException`
     * is caught by [MessageEnvelopeCodec.decode]'s existing `catch (e: RuntimeException)` -
     * meaning an off-curve ephemeral public key can never reach an ECDH call, see
     * `HybridEciesAdversarialTest`'s dedicated case for the end-to-end proof.
     */
    fun decodeFrom(
        input: DataInputStream,
        expectedWrapCount: Int,
    ): List<EciesWrap> {
        val wrapCount = input.readUnsignedShort()
        if (wrapCount !in 1..MAX_WRAPS) {
            throw MalformedMessageEnvelopeException("invalid wrap count: $wrapCount")
        }
        if (wrapCount != expectedWrapCount) {
            throw MalformedMessageEnvelopeException(
                "wrap count $wrapCount does not match recipient count + 1 ($expectedWrapCount)",
            )
        }
        return (0 until wrapCount).map {
            val ephemeralBytes = ByteArray(EPHEMERAL_PUBLIC_KEY_SIZE).also { buf -> input.readFully(buf) }
            val wrappedKeyBytes = ByteArray(WRAPPED_KEY_SIZE).also { buf -> input.readFully(buf) }
            EciesWrap(Secp256k1PublicKey(ephemeralBytes), wrappedKeyBytes)
        }
    }
}
