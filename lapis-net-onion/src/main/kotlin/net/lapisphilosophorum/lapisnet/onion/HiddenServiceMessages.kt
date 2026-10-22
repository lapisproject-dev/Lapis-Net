package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.DIGEST_SIZE
import java.nio.ByteBuffer
import java.security.SecureRandom

/*
 * Body formats of the hidden-service relay messages (wave V0.10.0-C, unreleased). Every body has a
 * FIXED length and no length field: the exact length is checked first, so no allocation depends on
 * attacker-chosen data, and a decode failure message never contains input bytes. toString() of every
 * body is redacted.
 */

/** Wire constants of the hidden-service protocol. */
object HsConstants {
    const val VERSION: Byte = 1
    const val COOKIE_SIZE = 20
    const val KEY_SIZE = 32
    const val SIGNATURE_SIZE = 64

    /** `version | authKey | notValidAfter | establishSeq | sig`. */
    const val ESTABLISH_INTRO_SIZE = 1 + KEY_SIZE + 8 + 8 + SIGNATURE_SIZE

    /** HPKE plaintext of INTRODUCE: `rpId(32) | rpFingerprint(32) | cookie(20) | X(32) | pad`. */
    const val INTRODUCE_PLAINTEXT_SIZE = 192
    const val AEAD_TAG_SIZE = 16

    /** `version | authKey | hpkeEnc | hpkeCiphertext`. */
    const val INTRODUCE_SIZE = 1 + KEY_SIZE + KEY_SIZE + INTRODUCE_PLAINTEXT_SIZE + AEAD_TAG_SIZE
    const val RENDEZVOUS1_SIZE = COOKIE_SIZE + KEY_SIZE + KEY_SIZE
    const val RENDEZVOUS2_SIZE = KEY_SIZE + KEY_SIZE

    /** Largest relay message addressed to the last hop of a maximum-length circuit. */
    val E2E_BLOB_SIZE: Int get() = RelayMessageCodec.maxData(OnionConstants.MAX_HOPS)

    /** Establish-intro signatures older than this are refused (bounds the replay window). */
    const val MAX_ESTABLISH_WINDOW_SECONDS = 3600L
}

/** Status byte values of INTRODUCE_ACK. */
object IntroduceStatus {
    const val FORWARDED: Byte = 0
    const val UNKNOWN: Byte = 1
    const val RATE_LIMITED: Byte = 2
    const val MALFORMED: Byte = 3
}

private fun requireSize(
    data: ByteArray,
    size: Int,
    what: String,
) {
    if (data.size != size) throw CellFormatException("$what has wrong size")
}

private fun ed25519OrThrow(bytes: ByteArray): Ed25519PublicKey =
    try {
        Ed25519PublicKey(bytes)
    } catch (e: IllegalArgumentException) {
        throw CellFormatException("invalid key")
    }

/** ESTABLISH_INTRO (receiver to introduction point). The introduction point's id is implicit and bound into the signature. */
class EstablishIntroBody(
    val authKey: Ed25519PublicKey,
    val notValidAfterEpochSecond: Long,
    val establishSeq: Long,
    signature: ByteArray,
) {
    private val storedSignature = signature.copyOf()
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedSignature.size == HsConstants.SIGNATURE_SIZE) { "signature size" }
    }

    fun encode(): ByteArray {
        val b = ByteBuffer.allocate(HsConstants.ESTABLISH_INTRO_SIZE)
        b.put(HsConstants.VERSION)
        b.put(authKey.bytes)
        b.putLong(notValidAfterEpochSecond)
        b.putLong(establishSeq)
        b.put(storedSignature)
        return b.array()
    }

    /** `true` iff the signature is valid for the introduction point [introRelayIdDigest]. Never throws. */
    fun verify(introRelayIdDigest: ByteArray): Boolean =
        try {
            authKey.verify(
                signedDigest(introRelayIdDigest, authKey, notValidAfterEpochSecond, establishSeq),
                storedSignature,
            )
        } catch (e: RuntimeException) {
            false
        }

    override fun toString(): String = "EstablishIntroBody(REDACTED)"

    companion object {
        private const val DOMAIN = "LapisNet:hs-establish-intro:v1"

        private fun signedDigest(
            introRelayIdDigest: ByteArray,
            authKey: Ed25519PublicKey,
            notValidAfter: Long,
            seq: Long,
        ): ByteArray =
            domainSeparatedDigest(
                DOMAIN,
                introRelayIdDigest,
                authKey.bytes,
                ByteBuffer.allocate(8).putLong(notValidAfter).array(),
                ByteBuffer.allocate(8).putLong(seq).array(),
            )

        fun create(
            authKey: Ed25519KeyPair,
            introRelayIdDigest: ByteArray,
            notValidAfterEpochSecond: Long,
            establishSeq: Long,
        ): EstablishIntroBody {
            require(introRelayIdDigest.size == DIGEST_SIZE) { "digest size" }
            val sig =
                authKey.sign(
                    signedDigest(introRelayIdDigest, authKey.publicKey, notValidAfterEpochSecond, establishSeq),
                )
            return EstablishIntroBody(authKey.publicKey, notValidAfterEpochSecond, establishSeq, sig)
        }

        fun decode(data: ByteArray): EstablishIntroBody {
            requireSize(data, HsConstants.ESTABLISH_INTRO_SIZE, "establish-intro body")
            val b = ByteBuffer.wrap(data)
            if (b.get() != HsConstants.VERSION) throw CellFormatException("unsupported version")
            val key = ed25519OrThrow(ByteArray(HsConstants.KEY_SIZE).also { b.get(it) })
            val nva = b.getLong()
            val seq = b.getLong()
            if (seq < 0) throw CellFormatException("invalid sequence")
            val sig = ByteArray(HsConstants.SIGNATURE_SIZE).also { b.get(it) }
            return EstablishIntroBody(key, nva, seq, sig)
        }
    }
}

/** INTRODUCE1 (sender to introduction point) and INTRODUCE2 (introduction point to receiver): same bytes. */
class IntroduceBody(
    authKeyBytes: ByteArray,
    hpkeEnc: ByteArray,
    hpkeCiphertext: ByteArray,
) {
    private val storedAuthKey = authKeyBytes.copyOf()
    private val storedEnc = hpkeEnc.copyOf()
    private val storedCt = hpkeCiphertext.copyOf()
    val authKeyBytes: ByteArray get() = storedAuthKey.copyOf()
    val hpkeEnc: ByteArray get() = storedEnc.copyOf()
    val hpkeCiphertext: ByteArray get() = storedCt.copyOf()

    init {
        require(storedAuthKey.size == HsConstants.KEY_SIZE && storedEnc.size == HsConstants.KEY_SIZE) { "key size" }
        require(storedCt.size == HsConstants.INTRODUCE_PLAINTEXT_SIZE + HsConstants.AEAD_TAG_SIZE) { "ciphertext size" }
    }

    fun encode(): ByteArray {
        val b = ByteBuffer.allocate(HsConstants.INTRODUCE_SIZE)
        b.put(HsConstants.VERSION)
        b.put(storedAuthKey)
        b.put(storedEnc)
        b.put(storedCt)
        return b.array()
    }

    override fun toString(): String = "IntroduceBody(REDACTED)"

    companion object {
        /** Reads the auth key out of a raw body without any other parsing: the introduction point's lookup. */
        fun peekAuthKey(data: ByteArray): ByteArray? =
            if (data.size == HsConstants.INTRODUCE_SIZE && data[0] == HsConstants.VERSION) {
                data.copyOfRange(1, 1 + HsConstants.KEY_SIZE)
            } else {
                null
            }

        fun decode(data: ByteArray): IntroduceBody {
            requireSize(data, HsConstants.INTRODUCE_SIZE, "introduce body")
            if (data[0] != HsConstants.VERSION) throw CellFormatException("unsupported version")
            return IntroduceBody(
                data.copyOfRange(1, 33),
                data.copyOfRange(33, 65),
                data.copyOfRange(65, data.size),
            )
        }
    }
}

/** The HPKE plaintext of an INTRODUCE: where to rendezvous and the sender's ephemeral for the end-to-end handshake. */
class IntroducePlaintext(
    rendezvousRelayIdDigest: ByteArray,
    rendezvousOnionKeyFingerprint: ByteArray,
    cookie: ByteArray,
    val clientEphemeral: net.lapisphilosophorum.lapisnet.identity.X25519PublicKey,
) {
    private val storedRp = rendezvousRelayIdDigest.copyOf()
    private val storedFp = rendezvousOnionKeyFingerprint.copyOf()
    private val storedCookie = cookie.copyOf()
    val rendezvousRelayIdDigest: ByteArray get() = storedRp.copyOf()
    val rendezvousOnionKeyFingerprint: ByteArray get() = storedFp.copyOf()
    val cookie: ByteArray get() = storedCookie.copyOf()

    init {
        require(storedRp.size == DIGEST_SIZE && storedFp.size == DIGEST_SIZE) { "digest size" }
        require(storedCookie.size == HsConstants.COOKIE_SIZE) { "cookie size" }
    }

    fun encode(random: SecureRandom): ByteArray {
        val out = ByteArray(HsConstants.INTRODUCE_PLAINTEXT_SIZE)
        storedRp.copyInto(out, 0)
        storedFp.copyInto(out, 32)
        storedCookie.copyInto(out, 64)
        clientEphemeral.bytes.copyInto(out, 64 + HsConstants.COOKIE_SIZE)
        fillRandom(out, 64 + HsConstants.COOKIE_SIZE + 32, random)
        return out
    }

    override fun toString(): String = "IntroducePlaintext(REDACTED)"

    companion object {
        fun decode(data: ByteArray): IntroducePlaintext {
            requireSize(data, HsConstants.INTRODUCE_PLAINTEXT_SIZE, "introduce plaintext")
            val x =
                try {
                    net.lapisphilosophorum.lapisnet.identity
                        .X25519PublicKey(data.copyOfRange(84, 116))
                } catch (e: IllegalArgumentException) {
                    throw CellFormatException("invalid ephemeral")
                }
            return IntroducePlaintext(
                data.copyOfRange(0, 32),
                data.copyOfRange(32, 64),
                data.copyOfRange(64, 84),
                x,
            )
        }
    }
}

/** RENDEZVOUS1 (receiver to rendezvous point): `cookie | Y | AUTH`. Y and AUTH are opaque to the rendezvous point. */
class Rendezvous1Body(
    cookie: ByteArray,
    serverEphemeral: ByteArray,
    auth: ByteArray,
) {
    private val storedCookie = cookie.copyOf()
    private val storedY = serverEphemeral.copyOf()
    private val storedAuth = auth.copyOf()
    val cookie: ByteArray get() = storedCookie.copyOf()
    val serverEphemeral: ByteArray get() = storedY.copyOf()
    val auth: ByteArray get() = storedAuth.copyOf()

    init {
        require(storedCookie.size == HsConstants.COOKIE_SIZE && storedY.size == 32 && storedAuth.size == 32) { "size" }
    }

    fun encode(): ByteArray = storedCookie + storedY + storedAuth

    /** The RENDEZVOUS2 payload the rendezvous point forwards (`Y | AUTH`). */
    fun rendezvous2Payload(): ByteArray = storedY + storedAuth

    override fun toString(): String = "Rendezvous1Body(REDACTED)"

    companion object {
        fun decode(data: ByteArray): Rendezvous1Body {
            requireSize(data, HsConstants.RENDEZVOUS1_SIZE, "rendezvous1 body")
            return Rendezvous1Body(data.copyOfRange(0, 20), data.copyOfRange(20, 52), data.copyOfRange(52, 84))
        }
    }
}

/** One-byte status bodies (INTRO_ESTABLISHED, INTRODUCE_ACK, RENDEZVOUS_ESTABLISHED). */
object StatusBody {
    fun encode(status: Byte): ByteArray = byteArrayOf(status)

    fun decode(data: ByteArray): Byte {
        requireSize(data, 1, "status body")
        return data[0]
    }
}

/** ESTABLISH_RENDEZVOUS body: the 20-byte cookie. */
object CookieBody {
    fun decode(data: ByteArray): ByteArray {
        requireSize(data, HsConstants.COOKIE_SIZE, "cookie body")
        return data.copyOf()
    }
}
