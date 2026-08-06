package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer
import java.security.SecureRandom

/** Thrown when a persisted [DoubleRatchetSession] file fails to load: wrong size, bad header, or a
 * structural inconsistency in the decrypted body (an out-of-range presence byte, a non-zero "absent"
 * slot, an inconsistent skipped-entry count). Deliberately distinct from
 * [net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException] (wrong passphrase / tampered
 * ciphertext), mirroring [CorruptedPrekeyStoreException]'s identical split for
 * [PrekeyStoreFileFormat]. */
class CorruptedRatchetSessionException(
    message: String,
) : RuntimeException(message)

/** The full decoded contents of a persisted [DoubleRatchetSession] - an immutable, ephemeral
 * transfer object between [DoubleRatchetSessionCodec] (pure codec) and
 * [DoubleRatchetSession.fromDecodedState]/[DoubleRatchetSession.stateForCodec]. Every array is a
 * defensive copy of whatever was handed in; [zeroAll] zeroes this object's OWN copies only - it
 * never reaches into a live [DoubleRatchetSession]'s or a freshly-constructed one's fields, because
 * [DoubleRatchetSessionCodec] always hands FRESH copies (or independently-derived objects) across
 * that boundary, never this object's own backing arrays by reference. */
internal class DoubleRatchetSessionState(
    associatedData: ByteArray,
    rootKey: ByteArray,
    sendingChainKey: ByteArray?,
    receivingChainKey: ByteArray?,
    ourRatchetPrivateKeyBytes: ByteArray,
    val theirRatchetPublicKey: X25519PublicKey?,
    val sendMessageNumber: Int,
    val receiveMessageNumber: Int,
    val previousSendChainLength: Int,
    skippedEntries: List<Triple<ByteArray, Int, ByteArray>>,
) {
    val associatedData: ByteArray = associatedData.copyOf()
    val rootKey: ByteArray = rootKey.copyOf()
    val sendingChainKey: ByteArray? = sendingChainKey?.copyOf()
    val receivingChainKey: ByteArray? = receivingChainKey?.copyOf()
    val ourRatchetPrivateKeyBytes: ByteArray = ourRatchetPrivateKeyBytes.copyOf()
    val skippedEntries: List<Triple<ByteArray, Int, ByteArray>> =
        skippedEntries.map { Triple(it.first.copyOf(), it.second, it.third.copyOf()) }

    init {
        require(this.associatedData.size == X3DH_ASSOCIATED_DATA_SIZE) {
            "associatedData must be $X3DH_ASSOCIATED_DATA_SIZE bytes, was ${this.associatedData.size}"
        }
        require(this.rootKey.size == ROOT_KEY_SIZE) { "rootKey must be $ROOT_KEY_SIZE bytes" }
        this.sendingChainKey?.let {
            require(it.size == CHAIN_KEY_SIZE) { "sendingChainKey must be $CHAIN_KEY_SIZE bytes" }
        }
        this.receivingChainKey?.let {
            require(it.size == CHAIN_KEY_SIZE) { "receivingChainKey must be $CHAIN_KEY_SIZE bytes" }
        }
        require(this.ourRatchetPrivateKeyBytes.size == 32) { "ourRatchetPrivateKeyBytes must be 32 bytes" }
        require(sendMessageNumber in 0..RatchetMessageCodec.MAX_CHAIN_LENGTH) {
            "sendMessageNumber must be in 0..${RatchetMessageCodec.MAX_CHAIN_LENGTH}, was $sendMessageNumber"
        }
        require(receiveMessageNumber in 0..RatchetMessageCodec.MAX_CHAIN_LENGTH) {
            "receiveMessageNumber must be in 0..${RatchetMessageCodec.MAX_CHAIN_LENGTH}, was $receiveMessageNumber"
        }
        require(previousSendChainLength in 0..RatchetMessageCodec.MAX_CHAIN_LENGTH) {
            "previousSendChainLength must be in 0..${RatchetMessageCodec.MAX_CHAIN_LENGTH}, was $previousSendChainLength"
        }
        require(this.skippedEntries.size <= DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED) {
            "at most ${DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED} skipped entries allowed, " +
                "was ${this.skippedEntries.size}"
        }
        // Cannot have a receiving chain without knowing the peer's ratchet key it was derived
        // against - mirrors the live session's own invariant, never actually reachable from a live
        // DoubleRatchetSession, but enforced here too as a decode-time tamper check.
        require(this.receivingChainKey == null || theirRatchetPublicKey != null) {
            "cannot have a receiving chain without a peer ratchet key"
        }
        // Legal ONLY for a never-yet-used receiver session (initializeReceiver's initial state).
        if (this.sendingChainKey == null && this.receivingChainKey == null && theirRatchetPublicKey == null) {
            require(sendMessageNumber == 0 && receiveMessageNumber == 0) {
                "a session with no chains and no peer ratchet key must have zero message counters " +
                    "(a never-yet-used receiver session) - had sendMessageNumber=$sendMessageNumber, " +
                    "receiveMessageNumber=$receiveMessageNumber"
            }
        }
    }

    /** Zeroes every secret byte array THIS OBJECT owns. Never reaches into a live session - see
     * this class's own doc comment for why that is safe. */
    internal fun zeroAll() {
        rootKey.fill(0)
        sendingChainKey?.fill(0)
        receivingChainKey?.fill(0)
        ourRatchetPrivateKeyBytes.fill(0)
        skippedEntries.forEach { it.third.fill(0) }
    }
}

/**
 * At-rest persistence for a [DoubleRatchetSession]: encrypted with the identity's own
 * keystore-derived key, reusing [KeystoreEncryption] (Argon2id + AES-256-GCM) verbatim - **no new
 * at-rest crypto is invented for this wave** - mirroring [PrekeyStoreFileFormat]'s identical stance
 * and header-assembly discipline (the header is built FIRST and used as the GCM AAD, resolving what
 * would otherwise be a circular dependency).
 *
 * **This is where forward secrecy most often actually dies in real Double Ratchet implementations -
 * see [DoubleRatchetSession]'s own "persist and destroy ordering" doc-comment section for the full
 * five-rule analysis.** In short: [encode] is a PURE READ, mutating and destroying nothing; the
 * ordering that actually matters (persist the post-encrypt/post-decrypt state BEFORE acting on its
 * result) is the CALLER's, because this wave performs no file I/O of its own.
 *
 * Inner plaintext body ("body v1"), all integers big-endian, fixed offsets with PRESENCE FLAGS
 * rather than conditional field placement (so there is no offset arithmetic to get wrong, and the
 * decoder can tamper-check absent slots):
 * ```
 * off    len   field
 *   0      4   magic  "LNRB"   (inner BODY magic - deliberately DIFFERENT from the file magic below)
 *   4      1   bodyVersion = 1
 *   5      1   flags - reserved, must be zero
 *   6      2   associatedDataLength  (unsigned short; MUST equal 71)
 *   8     71   associatedData
 *  79     32   rootKey
 * 111      1   sendingChainKeyPresent      (0 or 1; anything else is corruption)
 * 112     32   sendingChainKey             (MUST be all-zero when the flag is 0)
 * 144      1   receivingChainKeyPresent    (0 or 1)
 * 145     32   receivingChainKey           (MUST be all-zero when the flag is 0)
 * 177     32   ourRatchetPrivateKey
 * 209      1   theirRatchetPublicKeyPresent(0 or 1)
 * 210     32   theirRatchetPublicKey       (MUST be all-zero when the flag is 0)
 * 242      4   sendMessageNumber        (Int, 0..MAX_CHAIN_LENGTH)
 * 246      4   receiveMessageNumber     (Int, 0..MAX_CHAIN_LENGTH)
 * 250      4   previousSendChainLength  (Int, 0..MAX_CHAIN_LENGTH)
 * 254      2   skippedKeyCount  (unsigned short; MUST be <= MAX_SKIPPED_KEYS_STORED - checked BEFORE
 *                                 the entry loop)
 * --- FIXED_BODY_PREFIX_SIZE = 256 ---
 * 256    ...   (ratchetPublicKey(32) | messageNumber(4) | keyMaterial(32)) * skippedKeyCount
 * ```
 * `SKIPPED_ENTRY_SIZE = 68`. Only `ourRatchetPrivateKey` is stored, never its public half - derived
 * on decode via `X25519KeyPair.fromPrivateKeyBytes`, mirroring `PrekeyStore`'s identical approach
 * (cheaper, and the two can never disagree).
 *
 * Outer encrypted file layout ("file v1"), byte-identical SHAPE to `PrekeyStoreFileFormat`'s v2
 * header:
 * ```
 * off   len   field
 *   0     4   magic  "LNRS"   (Lapis Net Ratchet Session - the FILE magic)
 *   4     1   fileVersion = 1
 *   5     1   kdfId = 1 (Argon2id)
 *   6     4   argon2 memoryKiB   (Int)
 *  10     4   argon2 iterations  (Int)
 *  14     1   argon2 parallelism
 *  15    16   salt
 *  31    12   GCM nonce
 * --- V1_HEADER_SIZE = 43; the whole 43-byte prefix is the GCM AAD ---
 *  43   ...   ciphertext = AES-256-GCM(body v1) + 16-byte tag
 * ```
 *
 * **Two deliberate divergences from [PrekeyStoreFileFormat], both stated here rather than left to
 * be discovered:**
 * 1. **There is NO plaintext variant and therefore no `decodeAuto`.** `KeystoreFileFormat`/
 *    `PrekeyStoreFileFormat` both keep a v1 plaintext form for legacy migration; there is no legacy
 *    here, and a Double Ratchet session's state is PURE forward-secrecy-bearing key material with no
 *    legitimate reason ever to hit the disk in the clear. [encode] therefore takes a non-null
 *    `CharArray` passphrase. Offering a plaintext option would be a footgun with no migration
 *    benefit.
 * 2. **The inner body carries its OWN distinct magic (`"LNRB"`) rather than reusing the file
 *    magic.** `PrekeyStoreFileFormat` uses `"LNPS"` for both, which is unambiguous only because its
 *    v1 body genuinely IS a whole file. Here the body is never standalone, so a distinct magic makes
 *    "someone fed me a decrypted body as if it were a file" (or vice versa) a loud, immediate
 *    rejection.
 */
object DoubleRatchetSessionCodec {
    private val FILE_MAGIC = "LNRS".toByteArray(Charsets.US_ASCII)
    private const val FILE_VERSION: Byte = 1
    private val BODY_MAGIC = "LNRB".toByteArray(Charsets.US_ASCII)
    private const val BODY_VERSION: Byte = 1

    private const val KDF_ID_OFFSET = 5
    private const val MEMORY_OFFSET = 6
    private const val ITERATIONS_OFFSET = 10
    private const val PARALLELISM_OFFSET = 14
    private const val SALT_OFFSET = 15
    private const val NONCE_OFFSET = 31
    private const val CIPHERTEXT_OFFSET = 43
    private const val V1_HEADER_SIZE = CIPHERTEXT_OFFSET

    private const val ASSOCIATED_DATA_LENGTH_SIZE = 2
    private const val PRESENCE_BYTE_SIZE = 1
    private const val COUNTER_SIZE = 4
    private const val SKIPPED_COUNT_SIZE = 2

    /** `4+1+1 + 2+71 + 32 + 1+32 + 1+32 + 32 + 1+32 + 4+4+4 + 2 = 256`. */
    private const val FIXED_BODY_PREFIX_SIZE =
        4 + 1 + 1 +
            ASSOCIATED_DATA_LENGTH_SIZE + X3DH_ASSOCIATED_DATA_SIZE +
            ROOT_KEY_SIZE +
            PRESENCE_BYTE_SIZE + CHAIN_KEY_SIZE +
            PRESENCE_BYTE_SIZE + CHAIN_KEY_SIZE +
            32 +
            PRESENCE_BYTE_SIZE + 32 +
            COUNTER_SIZE + COUNTER_SIZE + COUNTER_SIZE +
            SKIPPED_COUNT_SIZE

    /** `32 (ratchetPublicKey) + 4 (messageNumber) + 32 (keyMaterial) = 68`. */
    private const val SKIPPED_ENTRY_SIZE = 32 + 4 + MESSAGE_KEY_MATERIAL_SIZE

    const val MAX_BODY_SIZE = FIXED_BODY_PREFIX_SIZE + DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED * SKIPPED_ENTRY_SIZE

    private const val GCM_TAG_SIZE_FILE = GCM_TAG_SIZE

    /** Hard cap on total file size BEFORE ever attempting decryption - the same reasoning
     * [PrekeyStoreFileFormat.MAX_STORE_FILE_BYTES] states: this format's ciphertext is variable
     * length (the skipped-key list grows), so a total-size cap is genuinely needed. */
    const val MAX_SESSION_FILE_BYTES = V1_HEADER_SIZE + MAX_BODY_SIZE + GCM_TAG_SIZE_FILE

    private val ZERO_CHAIN_KEY = ByteArray(CHAIN_KEY_SIZE)
    private val ZERO_PUBLIC_KEY = ByteArray(32)

    /** AUDIT-GRADE test seam (V0.8.3 security review, round 2 major finding), mirroring
     * [DoubleRatchetSession.onKeyMaterialSupersededForTest]'s reasoning for a case that hook cannot
     * cover: [decodeBody]'s locals are STACK locals inside a `private` method, unreachable by
     * reflection once the method returns, so there is no [RatchetTestFixtures.privateField]-style way
     * to observe them independent of a hook. To avoid round 1's exact failure mode (a hook call
     * silently vanishing alongside the destruction site it was meant to prove), this hook fires
     * UNCONDITIONALLY with EVERY local this method is responsible for zeroing, named individually in
     * [DecodedBodyLocalsForTest] - a test asserts each named array is captured (so a dropped
     * assignment is a compile error, not a silently-missing entry) AND, independently, that each is
     * genuinely all-zero once [decodeBody] returns - never through this hook, only via the identity of
     * the arrays the hook handed it. Never set outside tests; production code never touches it. */
    internal data class DecodedBodyLocalsForTest(
        val rootKey: ByteArray,
        val sendingChainKeyBytes: ByteArray,
        val receivingChainKeyBytes: ByteArray,
        val ourRatchetPrivateKeyBytes: ByteArray,
        val skippedKeyMaterials: List<ByteArray>,
    )

    internal var onDecodeBodyLocalsCapturedForTest: ((DecodedBodyLocalsForTest) -> Unit)? = null

    /** Assembles the plaintext body directly into a single pre-sized [ByteArray] via [ByteBuffer],
     * rather than a [ByteArrayOutputStream]. A `ByteArrayOutputStream` keeps its own internal buffer
     * separate from whatever `toByteArray()` returns - `toByteArray()` COPIES the internal buffer, so
     * the internal buffer itself (which by the end holds the root key, both chain keys, the ratchet
     * private scalar and every skipped message key) would be abandoned un-zeroed on the heap on every
     * call. Writing straight into the buffer that becomes the returned array (no intermediate,
     * nothing left behind) avoids that duplicate entirely; the caller ([encode]) already zeroes the
     * returned array in a `finally`. */
    private fun encodeBody(state: DoubleRatchetSessionState): ByteArray {
        require(state.skippedEntries.size <= DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED) {
            "at most ${DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED} skipped entries allowed, " +
                "was ${state.skippedEntries.size}"
        }
        val bodySize = FIXED_BODY_PREFIX_SIZE + state.skippedEntries.size * SKIPPED_ENTRY_SIZE
        require(bodySize <= MAX_BODY_SIZE) { "encoded session body exceeds $MAX_BODY_SIZE bytes: $bodySize" }
        val buffer = ByteBuffer.allocate(bodySize)
        buffer.put(BODY_MAGIC)
        buffer.put(BODY_VERSION)
        buffer.put(0) // flags: reserved, must be zero
        buffer.putShort(state.associatedData.size.toShort())
        buffer.put(state.associatedData)
        buffer.put(state.rootKey)
        buffer.put(if (state.sendingChainKey != null) 1.toByte() else 0.toByte())
        buffer.put(state.sendingChainKey ?: ZERO_CHAIN_KEY)
        buffer.put(if (state.receivingChainKey != null) 1.toByte() else 0.toByte())
        buffer.put(state.receivingChainKey ?: ZERO_CHAIN_KEY)
        buffer.put(state.ourRatchetPrivateKeyBytes)
        buffer.put(if (state.theirRatchetPublicKey != null) 1.toByte() else 0.toByte())
        buffer.put(state.theirRatchetPublicKey?.bytes ?: ZERO_PUBLIC_KEY)
        buffer.putInt(state.sendMessageNumber)
        buffer.putInt(state.receiveMessageNumber)
        buffer.putInt(state.previousSendChainLength)
        buffer.putShort(state.skippedEntries.size.toShort())
        state.skippedEntries.forEach { (ratchetPublicKeyBytes, messageNumber, keyMaterial) ->
            buffer.put(ratchetPublicKeyBytes)
            buffer.putInt(messageNumber)
            buffer.put(keyMaterial)
        }
        check(!buffer.hasRemaining()) {
            "session body assembly under-filled the buffer: ${buffer.remaining()} bytes left"
        }
        val body = buffer.array()
        check(body.size == bodySize) {
            "session body assembly produced an unexpected size: ${body.size}"
        }
        return body
    }

    private fun readPresenceByte(
        input: DataInputStream,
        name: String,
    ): Boolean =
        when (val b = input.readUnsignedByte()) {
            0 -> false
            1 -> true
            else -> throw CorruptedRatchetSessionException("$name must be 0 or 1, was $b")
        }

    /** Parses [bytes] into a [DoubleRatchetSessionState]. [DoubleRatchetSessionState]'s constructor
     * copies every array handed to it AGAIN into its own storage, so this method's OWN locals
     * (`rootKey`, the two chain-key arrays, the ratchet private scalar, and every skipped entry's key
     * material) become redundant duplicates the instant the constructor returns. The outer
     * `try`/`finally` zeroes exactly those locals - after the constructor has taken its copies,
     * whether decoding succeeded or an exception is about to propagate - mirroring
     * [DoubleRatchetSession.stateForCodec]'s identical "zero the intermediate the instant the
     * constructor no longer needs it" discipline. */
    private fun decodeBody(bytes: ByteArray): DoubleRatchetSessionState {
        var rootKey: ByteArray? = null
        var sendingChainKeyBytes: ByteArray? = null
        var receivingChainKeyBytes: ByteArray? = null
        var ourRatchetPrivateKeyBytes: ByteArray? = null
        var skippedEntries: List<Triple<ByteArray, Int, ByteArray>> = emptyList()
        try {
            try {
                val input = DataInputStream(ByteArrayInputStream(bytes))

                val magic = ByteArray(BODY_MAGIC.size).also { input.readFully(it) }
                if (!magic.contentEquals(BODY_MAGIC)) throw CorruptedRatchetSessionException("bad session body magic")

                val version = input.readByte()
                if (version != BODY_VERSION) {
                    throw CorruptedRatchetSessionException("unsupported session body version $version")
                }

                val flags = input.readUnsignedByte()
                if (flags != 0) throw CorruptedRatchetSessionException("reserved flag bits must be zero: $flags")

                val associatedDataLength = input.readUnsignedShort()
                if (associatedDataLength != X3DH_ASSOCIATED_DATA_SIZE) {
                    throw CorruptedRatchetSessionException(
                        "associatedDataLength must be $X3DH_ASSOCIATED_DATA_SIZE, was $associatedDataLength",
                    )
                }
                val associatedData = ByteArray(associatedDataLength).also { input.readFully(it) }
                val rootKeyLocal = ByteArray(ROOT_KEY_SIZE).also { input.readFully(it) }
                rootKey = rootKeyLocal

                val sendingChainKeyPresent = readPresenceByte(input, "sendingChainKeyPresent")
                val sendingChainKeyBytesLocal = ByteArray(CHAIN_KEY_SIZE).also { input.readFully(it) }
                sendingChainKeyBytes = sendingChainKeyBytesLocal
                if (!sendingChainKeyPresent && sendingChainKeyBytesLocal.any { it != 0.toByte() }) {
                    throw CorruptedRatchetSessionException("sendingChainKey bytes must be all-zero when absent")
                }

                val receivingChainKeyPresent = readPresenceByte(input, "receivingChainKeyPresent")
                val receivingChainKeyBytesLocal = ByteArray(CHAIN_KEY_SIZE).also { input.readFully(it) }
                receivingChainKeyBytes = receivingChainKeyBytesLocal
                if (!receivingChainKeyPresent && receivingChainKeyBytesLocal.any { it != 0.toByte() }) {
                    throw CorruptedRatchetSessionException("receivingChainKey bytes must be all-zero when absent")
                }

                val ourRatchetPrivateKeyBytesLocal = ByteArray(32).also { input.readFully(it) }
                ourRatchetPrivateKeyBytes = ourRatchetPrivateKeyBytesLocal

                val theirRatchetPublicKeyPresent = readPresenceByte(input, "theirRatchetPublicKeyPresent")
                val theirRatchetPublicKeyBytes = ByteArray(32).also { input.readFully(it) }
                if (!theirRatchetPublicKeyPresent && theirRatchetPublicKeyBytes.any { it != 0.toByte() }) {
                    throw CorruptedRatchetSessionException("theirRatchetPublicKey bytes must be all-zero when absent")
                }

                val sendMessageNumber = input.readInt()
                val receiveMessageNumber = input.readInt()
                val previousSendChainLength = input.readInt()

                val skippedKeyCount = input.readUnsignedShort()
                if (skippedKeyCount > DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED) {
                    throw CorruptedRatchetSessionException("too many skipped key entries: $skippedKeyCount")
                }
                val expectedSize = FIXED_BODY_PREFIX_SIZE + skippedKeyCount * SKIPPED_ENTRY_SIZE
                if (bytes.size != expectedSize) {
                    throw CorruptedRatchetSessionException(
                        "declared skippedKeyCount $skippedKeyCount does not match body size ${bytes.size} " +
                            "(expected $expectedSize)",
                    )
                }
                val skippedEntriesLocal =
                    (0 until skippedKeyCount).map {
                        val ratchetPublicKeyBytes = ByteArray(32).also { buf -> input.readFully(buf) }
                        val messageNumber = input.readInt()
                        if (messageNumber !in 0..RatchetMessageCodec.MAX_CHAIN_LENGTH) {
                            throw CorruptedRatchetSessionException(
                                "skipped entry messageNumber out of range: $messageNumber",
                            )
                        }
                        val keyMaterial = ByteArray(MESSAGE_KEY_MATERIAL_SIZE).also { buf -> input.readFully(buf) }
                        Triple(ratchetPublicKeyBytes, messageNumber, keyMaterial)
                    }
                skippedEntries = skippedEntriesLocal
                if (input.available() > 0) throw CorruptedRatchetSessionException("trailing bytes after session body")

                return DoubleRatchetSessionState(
                    associatedData = associatedData,
                    rootKey = rootKeyLocal,
                    sendingChainKey = if (sendingChainKeyPresent) sendingChainKeyBytesLocal else null,
                    receivingChainKey = if (receivingChainKeyPresent) receivingChainKeyBytesLocal else null,
                    ourRatchetPrivateKeyBytes = ourRatchetPrivateKeyBytesLocal,
                    theirRatchetPublicKey =
                        if (theirRatchetPublicKeyPresent) {
                            X25519PublicKey(
                                theirRatchetPublicKeyBytes,
                            )
                        } else {
                            null
                        },
                    sendMessageNumber = sendMessageNumber,
                    receiveMessageNumber = receiveMessageNumber,
                    previousSendChainLength = previousSendChainLength,
                    skippedEntries = skippedEntriesLocal,
                )
            } catch (e: EOFException) {
                throw CorruptedRatchetSessionException("truncated session body: ${e.message}")
            } catch (e: IOException) {
                throw CorruptedRatchetSessionException("failed to decode session body: ${e.message}")
            } catch (e: CorruptedRatchetSessionException) {
                throw e
            } catch (e: OutOfMemoryError) {
                throw CorruptedRatchetSessionException(
                    "session body field declared an oversized allocation: ${e.message}",
                )
            } catch (e: RuntimeException) {
                throw CorruptedRatchetSessionException("invalid session body field: ${e.message}")
            }
        } finally {
            val capturedRootKey = rootKey
            val capturedSendingChainKeyBytes = sendingChainKeyBytes
            val capturedReceivingChainKeyBytes = receivingChainKeyBytes
            val capturedOurRatchetPrivateKeyBytes = ourRatchetPrivateKeyBytes
            if (capturedRootKey != null &&
                capturedSendingChainKeyBytes != null &&
                capturedReceivingChainKeyBytes != null &&
                capturedOurRatchetPrivateKeyBytes != null
            ) {
                onDecodeBodyLocalsCapturedForTest?.invoke(
                    DecodedBodyLocalsForTest(
                        rootKey = capturedRootKey,
                        sendingChainKeyBytes = capturedSendingChainKeyBytes,
                        receivingChainKeyBytes = capturedReceivingChainKeyBytes,
                        ourRatchetPrivateKeyBytes = capturedOurRatchetPrivateKeyBytes,
                        skippedKeyMaterials = skippedEntries.map { it.third },
                    ),
                )
            }
            rootKey?.fill(0)
            sendingChainKeyBytes?.fill(0)
            receivingChainKeyBytes?.fill(0)
            ourRatchetPrivateKeyBytes?.fill(0)
            skippedEntries.forEach { it.third.fill(0) }
        }
    }

    /** Serialises [session]'s CURRENT state and encrypts it at rest under [passphrase], reusing
     * [KeystoreEncryption] (Argon2id + AES-256-GCM) verbatim. The 43-byte header is assembled FIRST
     * and used as the GCM AAD.
     *
     * **This function is a PURE READ of [session]: it mutates nothing and destroys nothing.** See
     * [DoubleRatchetSession]'s persist/destroy-ordering doc-comment section for why that is the
     * correct contract and where the ordering that actually matters lives instead (the caller's).
     *
     * **Zeroes its own plaintext body in a `finally`**, unlike `KeystoreFileFormat.encodeEncrypted`
     * and `PrekeyStoreFileFormat.encodeEncrypted`, both of which leave theirs on the heap - a
     * pre-existing gap in those two, deliberately not touched by this wave (different files,
     * different waves); noted here so the divergence reads as intentional. */
    fun encode(
        session: DoubleRatchetSession,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        val state = session.stateForCodec()
        try {
            val plaintext = encodeBody(state)
            try {
                val salt = ByteArray(KeystoreEncryption.SALT_SIZE).also(random::nextBytes)
                val nonce = ByteArray(KeystoreEncryption.NONCE_SIZE).also(random::nextBytes)

                val header = ByteBuffer.allocate(V1_HEADER_SIZE)
                header.put(FILE_MAGIC)
                header.put(FILE_VERSION)
                header.put(KeystoreEncryption.KDF_ID_ARGON2ID)
                header.putInt(KeystoreEncryption.DEFAULT_MEMORY_KIB)
                header.putInt(KeystoreEncryption.DEFAULT_ITERATIONS)
                header.put(KeystoreEncryption.DEFAULT_PARALLELISM.toByte())
                header.put(salt)
                header.put(nonce)
                val headerBytes = header.array()
                check(headerBytes.size == V1_HEADER_SIZE) { "v1 header assembly produced an unexpected size" }

                val params =
                    KeystoreEncryption.Params(
                        memoryKiB = KeystoreEncryption.DEFAULT_MEMORY_KIB,
                        iterations = KeystoreEncryption.DEFAULT_ITERATIONS,
                        parallelism = KeystoreEncryption.DEFAULT_PARALLELISM,
                        salt = salt,
                    )
                val ciphertext = KeystoreEncryption.encrypt(plaintext, passphrase, params, nonce, headerBytes)

                val out = ByteArray(V1_HEADER_SIZE + ciphertext.size)
                headerBytes.copyInto(out, 0)
                ciphertext.copyInto(out, V1_HEADER_SIZE)
                return out
            } finally {
                plaintext.fill(0)
            }
        } finally {
            state.zeroAll()
        }
    }

    /**
     * @throws CorruptedRatchetSessionException on any structural problem, checked BEFORE decryption
     *   is attempted (size cap, magic, version, kdfId, Argon2 cost-parameter sanity caps) and again
     *   after (body magic/version/flags/ranges/presence bytes).
     * @throws net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException for a wrong
     *   passphrase or ANY tampered byte anywhere in the 43-byte header or the ciphertext - propagated
     *   UNCHANGED from [KeystoreEncryption.decrypt], mirroring
     *   [PrekeyStoreFileFormat.decodeEncrypted]'s identical split.
     */
    fun decode(
        bytes: ByteArray,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom(),
    ): DoubleRatchetSession {
        if (bytes.size > MAX_SESSION_FILE_BYTES) {
            throw CorruptedRatchetSessionException("session file exceeds $MAX_SESSION_FILE_BYTES bytes: ${bytes.size}")
        }
        if (bytes.size < V1_HEADER_SIZE + GCM_TAG_SIZE_FILE) {
            throw CorruptedRatchetSessionException("session file too short to be a valid v1 session")
        }
        if (!bytes.copyOfRange(0, 4).contentEquals(FILE_MAGIC)) throw CorruptedRatchetSessionException("bad magic")
        if (bytes[4] != FILE_VERSION) {
            throw CorruptedRatchetSessionException("unsupported session file version ${bytes[4]}")
        }
        if (bytes[KDF_ID_OFFSET] != KeystoreEncryption.KDF_ID_ARGON2ID) {
            throw CorruptedRatchetSessionException("unsupported KDF id ${bytes[KDF_ID_OFFSET]}")
        }

        val header = ByteBuffer.wrap(bytes, 0, V1_HEADER_SIZE)
        val memoryKiB = header.getInt(MEMORY_OFFSET)
        val iterations = header.getInt(ITERATIONS_OFFSET)
        val parallelism = bytes[PARALLELISM_OFFSET].toInt() and 0xFF
        // Sanity-cap the KDF cost parameters read off disk BEFORE ever handing them to Argon2.
        if (memoryKiB <= 0 || memoryKiB > KeystoreEncryption.DEFAULT_MEMORY_KIB * 16) {
            throw CorruptedRatchetSessionException("implausible Argon2 memoryKiB $memoryKiB in session file header")
        }
        if (iterations <= 0 || iterations > KeystoreEncryption.DEFAULT_ITERATIONS * 16) {
            throw CorruptedRatchetSessionException("implausible Argon2 iterations $iterations in session file header")
        }
        if (parallelism <= 0 || parallelism > KeystoreEncryption.DEFAULT_PARALLELISM * 16) {
            throw CorruptedRatchetSessionException("implausible Argon2 parallelism $parallelism in session file header")
        }
        val salt = bytes.copyOfRange(SALT_OFFSET, NONCE_OFFSET)
        val nonce = bytes.copyOfRange(NONCE_OFFSET, CIPHERTEXT_OFFSET)
        val aadHeader = bytes.copyOfRange(0, V1_HEADER_SIZE)
        val ciphertext = bytes.copyOfRange(CIPHERTEXT_OFFSET, bytes.size)

        val params =
            try {
                KeystoreEncryption.Params(memoryKiB, iterations, parallelism, salt)
            } catch (e: IllegalArgumentException) {
                throw CorruptedRatchetSessionException("malformed KDF params in session file header: ${e.message}")
            }
        val plaintext = KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, aadHeader)
        try {
            val state = decodeBody(plaintext)
            try {
                val ownedKeyPair = X25519KeyPair.fromPrivateKeyBytes(state.ourRatchetPrivateKeyBytes)
                val skippedStore = SkippedMessageKeyStore()
                state.skippedEntries.forEach { (ratchetPublicKeyBytes, messageNumber, keyMaterial) ->
                    skippedStore.put(SkippedMessageKeyId(ratchetPublicKeyBytes, messageNumber), keyMaterial)
                }
                return DoubleRatchetSession.fromDecodedState(
                    associatedData = state.associatedData.copyOf(),
                    rootKey = state.rootKey.copyOf(),
                    sendingChainKey = state.sendingChainKey?.copyOf(),
                    receivingChainKey = state.receivingChainKey?.copyOf(),
                    ourRatchetKeyPair = ownedKeyPair,
                    theirRatchetPublicKey = state.theirRatchetPublicKey,
                    sendMessageNumber = state.sendMessageNumber,
                    receiveMessageNumber = state.receiveMessageNumber,
                    previousSendChainLength = state.previousSendChainLength,
                    skippedKeys = skippedStore,
                    random = random,
                )
            } finally {
                state.zeroAll()
            }
        } finally {
            plaintext.fill(0)
        }
    }
}
