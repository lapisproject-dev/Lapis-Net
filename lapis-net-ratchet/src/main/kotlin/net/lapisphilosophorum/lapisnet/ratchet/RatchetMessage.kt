package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey

/**
 * The plaintext, per-message ratchet header. `internal constructor`: the ONLY ways to obtain one
 * are [DoubleRatchetSession.encrypt] and [RatchetMessageCodec.decode], both of which validate every
 * field. A public constructor would let a caller hand [DoubleRatchetSession.decrypt] a header that
 * never passed the codec's range checks - the same reasoning [ConsumedOneTimePrekey]'s own
 * `internal constructor` already applies to a different caller-discipline contract in this module.
 *
 * **NO HEADER ENCRYPTION IN THIS WAVE - a deliberate, documented scope cut, not an oversight.**
 * [ratchetPublicKey], [previousChainLength] and [messageNumber] travel in the clear; only the
 * payload is confidential. This is the Signal Double Ratchet's own standard, published limitation
 * (its optional header-encryption variant is a separate construction), carried forward here
 * knowingly: a passive observer of a future DM stream can count messages per chain and observe when
 * a DH ratchet step occurs.
 */
class RatchetMessageHeader internal constructor(
    val ratchetPublicKey: X25519PublicKey,
    val previousChainLength: Int,
    val messageNumber: Int,
    nonce: ByteArray,
) {
    private val storedNonce: ByteArray = nonce.copyOf()

    /** Returns a fresh copy on every access. Not secret - it is on the wire in the clear - but the
     * defensive copy keeps a caller from mutating a header the AAD is already bound to. */
    val nonce: ByteArray get() = storedNonce.copyOf()

    init {
        require(previousChainLength in 0..RatchetMessageCodec.MAX_CHAIN_LENGTH) {
            "previousChainLength must be in 0..${RatchetMessageCodec.MAX_CHAIN_LENGTH}, was $previousChainLength"
        }
        require(messageNumber in 0..RatchetMessageCodec.MAX_CHAIN_LENGTH) {
            "messageNumber must be in 0..${RatchetMessageCodec.MAX_CHAIN_LENGTH}, was $messageNumber"
        }
        require(storedNonce.size == GCM_NONCE_SIZE) { "nonce must be $GCM_NONCE_SIZE bytes, was ${storedNonce.size}" }
    }

    /** Never prints the nonce - not because it is secret, but so a log line can never be mistaken
     * for a complete record of an AEAD input. */
    override fun toString(): String =
        "RatchetMessageHeader(ratchetPublicKey=${ratchetPublicKey.fingerprint()}, " +
            "previousChainLength=$previousChainLength, messageNumber=$messageNumber)"
}

/**
 * One encrypted Double Ratchet message: its parsed [header], the VERBATIM header bytes that header
 * was decoded from (or encoded to), and the AEAD ciphertext.
 *
 * **[headerBytes] exists so the AAD is never reconstructed from parsed fields.** This is the rule
 * `docs/architecture.adoc` credits for V0.4's keystore encryption passing security review in a
 * single round - the opposite mistake (reconstructing AAD from parsed fields rather than the
 * literal header bytes) has caused real bugs elsewhere. [RatchetMessageCodec.decode] populates this
 * with the exact bytes it read off the wire; [DoubleRatchetSession.encrypt] populates it with the
 * exact bytes it assembled before encrypting - in neither direction is [header] ever re-serialised
 * to reconstruct these bytes.
 */
class RatchetMessage internal constructor(
    val header: RatchetMessageHeader,
    headerBytes: ByteArray,
    ciphertext: ByteArray,
) {
    private val storedHeaderBytes: ByteArray = headerBytes.copyOf()
    private val storedCiphertext: ByteArray = ciphertext.copyOf()

    /** The literal, verbatim header bytes - `internal` because it exists for the AAD-binding
     * discipline, not as a public API surface a caller should ever need to inspect directly. */
    internal val headerBytes: ByteArray get() = storedHeaderBytes.copyOf()

    /** Returns a fresh copy on every access. */
    val ciphertext: ByteArray get() = storedCiphertext.copyOf()

    init {
        require(storedHeaderBytes.size == RatchetMessageCodec.HEADER_SIZE) {
            "headerBytes must be ${RatchetMessageCodec.HEADER_SIZE} bytes, was ${storedHeaderBytes.size}"
        }
        require(storedCiphertext.size in (GCM_TAG_SIZE + 1)..RatchetMessageCodec.MAX_CIPHERTEXT_BYTES) {
            "ciphertext must be in ${GCM_TAG_SIZE + 1}..${RatchetMessageCodec.MAX_CIPHERTEXT_BYTES} bytes, " +
                "was ${storedCiphertext.size}"
        }
    }

    override fun toString(): String = "RatchetMessage(header=$header, ciphertextLength=${storedCiphertext.size})"
}
