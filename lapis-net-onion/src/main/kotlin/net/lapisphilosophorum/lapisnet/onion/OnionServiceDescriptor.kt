package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.nio.ByteBuffer

/** One introduction point of an onion service: the relay (with its signed onion key binding) and the auth key registered there. */
class IntroPointEntry(
    val relayOnionKeyBinding: OnionKeyBinding,
    val authKey: Ed25519PublicKey,
) {
    override fun equals(other: Any?): Boolean =
        other is IntroPointEntry && relayOnionKeyBinding == other.relayOnionKeyBinding && authKey == other.authKey

    override fun hashCode(): Int = 31 * relayOnionKeyBinding.hashCode() + authKey.hashCode()

    override fun toString(): String = "IntroPointEntry(REDACTED)"
}

/**
 * The signed advertisement of an onion service (wave V0.10.0-C): its end-to-end encryption key and its
 * introduction points. Signed by the service key (Ed25519), so the address IS the key that must have
 * signed it. It contains no Lapis identity, no peer ID and no network address. Without blinding (see
 * docs/anonymity.adoc) it is public and linkable over time.
 *
 * Validity: `now <= notValidAfter <= now + MAX_TTL_WINDOW + MAX_CLOCK_SKEW`, and the descriptor never
 * outlives any introduction relay's onion key binding.
 */
class OnionServiceDescriptor private constructor(
    val serviceKey: Ed25519PublicKey,
    val sequenceNumber: Long,
    val notValidAfterEpochSecond: Long,
    val encKey: X25519PublicKey,
    introPoints: List<IntroPointEntry>,
    signature: ByteArray,
) {
    val introPoints: List<IntroPointEntry> = introPoints.toList()
    private val storedSignature = signature.copyOf()
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == 64) { "signature must be 64 bytes" }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
    }

    fun address(): OnionServiceAddress = OnionServiceAddress(serviceKey)

    override fun equals(other: Any?): Boolean =
        other is OnionServiceDescriptor &&
            serviceKey == other.serviceKey &&
            sequenceNumber == other.sequenceNumber &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            encKey == other.encKey &&
            introPoints == other.introPoints &&
            storedSignature.contentEquals(other.storedSignature)

    override fun hashCode(): Int = 31 * serviceKey.hashCode() + sequenceNumber.hashCode()

    override fun toString(): String = "OnionServiceDescriptor(seq=$sequenceNumber, REDACTED)"

    companion object {
        const val MAX_INTRO_POINTS = 3
        const val MAX_TTL_WINDOW_SECONDS = 6 * 3600L
        const val MAX_CLOCK_SKEW_SECONDS = 300L
        private const val DOMAIN = "LapisNet:onion-service-descriptor:v1"

        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(DOMAIN, body)

        fun create(
            serviceKey: Ed25519KeyPair,
            encKey: X25519PublicKey,
            introPoints: List<IntroPointEntry>,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            nowEpochSecond: Long,
        ): OnionServiceDescriptor {
            require(introPoints.size in 1..MAX_INTRO_POINTS) { "1..$MAX_INTRO_POINTS introduction points required" }
            require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
            require(notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS) {
                "descriptor validity exceeds the window"
            }
            val body =
                OnionServiceDescriptorCodec.encodeSignedBody(
                    serviceKey.publicKey,
                    sequenceNumber,
                    notValidAfterEpochSecond,
                    encKey,
                    introPoints,
                )
            val d =
                OnionServiceDescriptor(
                    serviceKey.publicKey,
                    sequenceNumber,
                    notValidAfterEpochSecond,
                    encKey,
                    introPoints,
                    serviceKey.sign(signingDigest(body)),
                )
            require(verify(d, nowEpochSecond)) { "descriptor does not verify" }
            return d
        }

        /** Complete verification; never throws, any internal failure is a `false`. */
        fun verify(
            d: OnionServiceDescriptor,
            nowEpochSecond: Long,
        ): Boolean =
            try {
                val relays: List<Secp256k1PublicKey> = d.introPoints.map { it.relayOnionKeyBinding.relayIdentity }
                d.introPoints.size in 1..MAX_INTRO_POINTS &&
                    d.notValidAfterEpochSecond >= nowEpochSecond &&
                    d.notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS + MAX_CLOCK_SKEW_SECONDS &&
                    d.introPoints.all {
                        d.notValidAfterEpochSecond <= it.relayOnionKeyBinding.notValidAfterEpochSecond
                    } &&
                    d.introPoints.all { OnionKeyBinding.verify(it.relayOnionKeyBinding, nowEpochSecond) } &&
                    relays.toSet().size == relays.size &&
                    d.introPoints
                        .map { it.authKey }
                        .toSet()
                        .size == d.introPoints.size &&
                    d.serviceKey.verify(
                        signingDigest(
                            OnionServiceDescriptorCodec.encodeSignedBody(
                                d.serviceKey,
                                d.sequenceNumber,
                                d.notValidAfterEpochSecond,
                                d.encKey,
                                d.introPoints,
                            ),
                        ),
                        d.signature,
                    )
            } catch (e: RuntimeException) {
                false
            }

        internal fun fromDecoded(
            serviceKey: Ed25519PublicKey,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            encKey: X25519PublicKey,
            introPoints: List<IntroPointEntry>,
            signature: ByteArray,
        ) = OnionServiceDescriptor(serviceKey, sequenceNumber, notValidAfterEpochSecond, encKey, introPoints, signature)
    }
}

/**
 * Wire format: `ver(1) | serviceKey(32) | seq(8) | notValidAfter(8) | encKey(32) | count(1) |
 * count x [identity(33) | onionKey(32) | bindingNotValidAfter(8) | bindingSig(64) | authKey(32)] | sig(64)`.
 * Exact length `146 + 169*count` (at most 653); the length is checked before anything else.
 */
object OnionServiceDescriptorCodec {
    const val VERSION = 1
    const val FIXED_SIZE = 146
    const val ENTRY_SIZE = 169
    const val MAX_ENCODED_SIZE = FIXED_SIZE + ENTRY_SIZE * OnionServiceDescriptor.MAX_INTRO_POINTS
    private const val HEADER_SIZE = 1 + 32 + 8 + 8 + 32 + 1

    fun encodedSize(introPoints: Int): Int = FIXED_SIZE + ENTRY_SIZE * introPoints

    internal fun encodeSignedBody(
        serviceKey: Ed25519PublicKey,
        sequenceNumber: Long,
        notValidAfter: Long,
        encKey: X25519PublicKey,
        introPoints: List<IntroPointEntry>,
    ): ByteArray {
        val b = ByteBuffer.allocate(HEADER_SIZE + ENTRY_SIZE * introPoints.size)
        b.put(VERSION.toByte())
        b.put(serviceKey.bytes)
        b.putLong(sequenceNumber)
        b.putLong(notValidAfter)
        b.put(encKey.bytes)
        b.put(introPoints.size.toByte())
        for (e in introPoints) {
            val k = e.relayOnionKeyBinding
            b.put(k.relayIdentity.bytes)
            b.put(k.onionKey.bytes)
            b.putLong(k.notValidAfterEpochSecond)
            b.put(k.signature)
            b.put(e.authKey.bytes)
        }
        return b.array()
    }

    fun encode(d: OnionServiceDescriptor): ByteArray =
        encodeSignedBody(d.serviceKey, d.sequenceNumber, d.notValidAfterEpochSecond, d.encKey, d.introPoints) +
            d.signature

    /** Throws only [CellFormatException]. */
    fun decode(bytes: ByteArray): OnionServiceDescriptor {
        if (bytes.size < FIXED_SIZE + ENTRY_SIZE || bytes.size > MAX_ENCODED_SIZE) {
            throw CellFormatException("wrong descriptor length")
        }
        if ((bytes.size - FIXED_SIZE) % ENTRY_SIZE != 0) throw CellFormatException("wrong descriptor length")
        try {
            val b = ByteBuffer.wrap(bytes)

            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            if (b.get().toInt() != VERSION) throw CellFormatException("unsupported version")
            val serviceKey = Ed25519PublicKey(take(32))
            val seq = b.getLong()
            if (seq < 0) throw CellFormatException("negative sequence number")
            val nva = b.getLong()
            val enc = X25519PublicKey(take(32))
            val count = b.get().toInt() and 0xFF
            if (bytes.size != encodedSize(count)) throw CellFormatException("wrong descriptor length")
            val entries = ArrayList<IntroPointEntry>(count)
            repeat(count) {
                val identity = Secp256k1PublicKey(take(33))
                val onion = X25519PublicKey(take(32))
                val bnva = b.getLong()
                val sig = take(64)
                val auth = Ed25519PublicKey(take(32))
                entries += IntroPointEntry(OnionKeyBinding(identity, onion, bnva, sig), auth)
            }
            val signature = take(64)
            return OnionServiceDescriptor.fromDecoded(serviceKey, seq, nva, enc, entries, signature)
        } catch (e: CellFormatException) {
            throw e
        } catch (e: RuntimeException) {
            throw CellFormatException("invalid descriptor field")
        }
    }
}
