package net.lapisphilosophorum.lapisnet.call

import java.security.SecureRandom

/**
 * A 128-bit call identifier, minted by the caller ([random]) on [CallManager.placeCall] and carried
 * unchanged through every [CallSignal] exchanged for that call.
 *
 * **Deliberately NOT a Kotlin `value class` over a `ByteArray`** - a `value class` inlines to its
 * single property and inherits `ByteArray`'s own REFERENCE `equals`/`hashCode` (arrays never get
 * structural equality "for free" just by being wrapped), which would silently break every
 * [CallManager] lookup keyed by [CallId] (two [CallId]s built from equal-content-but-different-
 * instance byte arrays would never compare equal). Mirrors `DmSessionManager`'s own private
 * `DedupKeyId` wrapper's identical "class, not value class, with an explicit `contentEquals`-based
 * `equals`/`hashCode`" pattern - see that class's own doc comment for the precedent this follows.
 */
class CallId private constructor(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access - the caller cannot mutate the stored id through it. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    /** Short hex fingerprint safe to log - a full [CallId] carries no secret material (it is public
     * information exchanged in plaintext-adjacent [CallSignal] fields once decrypted), but a short
     * fingerprint is still the established logging convention throughout this codebase
     * (`Secp256k1PublicKey.fingerprint`, `DoubleRatchetSession` logging, etc.) - consistency over a
     * marginal information difference. */
    fun fingerprint(): String = storedBytes.joinToString("") { "%02x".format(it) }.take(8)

    override fun equals(other: Any?): Boolean = other is CallId && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = storedBytes.contentHashCode()

    override fun toString(): String = "CallId(${fingerprint()})"

    companion object {
        const val SIZE = 16

        /** Mints a fresh, random [CallId] - the caller's job on [CallManager.placeCall]. */
        fun random(random: SecureRandom): CallId {
            val bytes = ByteArray(SIZE)
            random.nextBytes(bytes)
            return CallId(bytes)
        }

        /** Wraps an already-known [SIZE]-byte id - used by [CallSignalCodec.decode] for an inbound
         * signal's `callId` field.
         *
         * @throws IllegalArgumentException if [bytes] is not exactly [SIZE] bytes or is all-zero
         *   (an all-zero id is never minted by [random] - vanishingly unlikely from a real
         *   [SecureRandom] draw - so treating it as invalid is tamper evidence, not a false positive
         *   against any legitimate caller). [CallSignalCodec.decode] translates this into a
         *   [MalformedCallSignalException], its own established contract for turning a caught
         *   [RuntimeException] from a field constructor into its own exception type.
         */
        fun of(bytes: ByteArray): CallId {
            require(bytes.size == SIZE) { "CallId must be $SIZE bytes, was ${bytes.size}" }
            require(bytes.any { it != 0.toByte() }) { "CallId must not be all-zero" }
            return CallId(bytes)
        }
    }
}
