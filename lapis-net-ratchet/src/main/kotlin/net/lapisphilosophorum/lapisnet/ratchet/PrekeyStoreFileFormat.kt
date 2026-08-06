package net.lapisphilosophorum.lapisnet.ratchet

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer
import java.security.SecureRandom

private val logger = KotlinLogging.logger {}

/** Thrown when a [PrekeyStore] file fails to load: wrong size, bad header, or a structural
 * inconsistency (duplicate one-time-prekey id, a rewound `nextOneTimePrekeyId` counter, an
 * out-of-range consumption state byte). Deliberately distinct from [KeystoreDecryptionException]
 * (wrong passphrase / tampered ciphertext), mirroring [net.lapisphilosophorum.lapisnet.identity.CorruptedIdentityFileException]'s
 * identical split for [net.lapisphilosophorum.lapisnet.identity.KeystoreFileFormat]. */
class CorruptedPrekeyStoreException(
    message: String,
) : RuntimeException(message)

/** One stored one-time-prekey record: its stable [id], its [state] (`AVAILABLE` or `CONSUMED`),
 * and its private key bytes - all-zero once [state] is [OneTimePrekeyState.CONSUMED] (see
 * [PrekeyStore.consumeOneTimePrekey]'s doc comment for why the private bytes are erased rather than
 * merely flagged). */
internal enum class OneTimePrekeyState(
    val wireValue: Byte,
) {
    AVAILABLE(0),
    CONSUMED(1),
}

internal class OneTimePrekeyStoreEntry(
    val id: Int,
    val state: OneTimePrekeyState,
    privateKeyBytes: ByteArray,
) {
    val privateKeyBytes: ByteArray = privateKeyBytes.copyOf()

    init {
        require(id >= 0) { "one-time prekey entry id must be >= 0" }
        require(this.privateKeyBytes.size == 32) { "one-time prekey entry private key must be 32 bytes" }
        if (state == OneTimePrekeyState.CONSUMED) {
            require(this.privateKeyBytes.all { it == 0.toByte() }) {
                "a CONSUMED one-time prekey entry must have its private key bytes zeroed"
            }
        }
    }
}

/** The full decoded contents of a [PrekeyStore]'s persisted file - an immutable snapshot handed
 * between [PrekeyStoreFileFormat] (pure codec) and [PrekeyStore] (the stateful, file-backed
 * wrapper around it). */
internal class PrekeyStoreState(
    val ownerIdentity: Secp256k1PublicKey,
    x25519IdentityPrivateKeyBytes: ByteArray,
    val signedPrekeyId: Int,
    signedPrekeyPrivateKeyBytes: ByteArray,
    val nextOneTimePrekeyId: Int,
    val nextBundleSequenceNumber: Long,
    val entries: List<OneTimePrekeyStoreEntry>,
) {
    val x25519IdentityPrivateKeyBytes: ByteArray = x25519IdentityPrivateKeyBytes.copyOf()
    val signedPrekeyPrivateKeyBytes: ByteArray = signedPrekeyPrivateKeyBytes.copyOf()

    init {
        require(this.x25519IdentityPrivateKeyBytes.size == 32) { "x25519 identity private key must be 32 bytes" }
        require(this.signedPrekeyPrivateKeyBytes.size == 32) { "signed prekey private key must be 32 bytes" }
        require(signedPrekeyId >= 0) { "signedPrekeyId must be >= 0" }
        require(nextOneTimePrekeyId >= 0) { "nextOneTimePrekeyId must be >= 0" }
        // >= 1, never 0: PrekeyBundle.sequenceNumber only requires >= 0, but this counter is the
        // NEXT value PrekeyStore.publishBundle will claim, and 0 is reserved to mean "no bundle has
        // ever been published by this store yet" is not a distinction this counter needs to make
        // (every store starts at 1, mirroring PrekeyStore.INITIAL_BUNDLE_SEQUENCE_NUMBER) - so a
        // stored value of 0 can only mean a corrupted/tampered/pre-this-fix file, never a
        // legitimately-reached state.
        require(nextBundleSequenceNumber >= 1) { "nextBundleSequenceNumber must be >= 1" }
        require(entries.size <= PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES) {
            "at most ${PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES} one-time prekey entries allowed"
        }
        require(entries.map { it.id }.toSet().size == entries.size) { "one-time prekey entry ids must be unique" }
        // The rewound-counter guard: a nextOneTimePrekeyId at or below any stored entry id is the
        // on-disk symptom of tampering or a partial/corrupted write - see PrekeyStore's doc comment
        // for why this monotonicity is load-bearing for safe tombstone pruning.
        val maxStoredId = entries.maxOfOrNull { it.id } ?: -1
        require(nextOneTimePrekeyId > maxStoredId) {
            "nextOneTimePrekeyId ($nextOneTimePrekeyId) must be strictly greater than every stored entry id " +
                "(max stored id: $maxStoredId) - a rewound counter would allow a pruned/consumed id to be " +
                "reallocated, reopening one-time-prekey reuse"
        }
    }
}

/**
 * Fixed-layout binary codec for a [PrekeyStoreState] - the PRIVATE halves [PrekeyStore] holds
 * locally (the X25519 identity private key, the signed-prekey private key, and every one-time
 * prekey's private key, tombstoned rather than deleted once consumed). Reuses
 * [net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption] verbatim for encryption at rest -
 * **no new crypto is invented for persistence** - and mirrors
 * [net.lapisphilosophorum.lapisnet.identity.KeystoreFileFormat]'s v1-plaintext/v2-encrypted duality.
 *
 * **No `io.ipfs.cid.Cid` field anywhere in this layout - deliberately**, mirroring
 * [PrekeyBundleCodec]'s own equivalent note: there is nothing here for
 * `net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation` to guard.
 *
 * Inner plaintext body ("body v1"), all integers big-endian:
 * ```
 * magic(4) "LNPS" | version(1) | flags(1, reserved) | ownerIdentity(33) |
 * x25519IdentityPrivateKey(32) | signedPrekeyId(4) | signedPrekeyPrivateKey(32) |
 * nextOneTimePrekeyId(4) | nextBundleSequenceNumber(8) | oneTimePrekeyEntryCount(2) |
 * ( id(4) | state(1) | privateKey(32) ) * oneTimePrekeyEntryCount
 * ```
 * Worst case: `121 + 4096 * 37 = 151,673` bytes.
 */
object PrekeyStoreFileFormat {
    private val MAGIC = "LNPS".toByteArray(Charsets.US_ASCII)
    private const val VERSION_1: Byte = 1
    private const val VERSION_2: Byte = 2

    private const val PUBLIC_KEY_SIZE = 33
    private const val X25519_KEY_SIZE = 32
    private const val ENTRY_SIZE = 4 + 1 + 32 // id + state + privateKey = 37

    /** Live entries PLUS tombstones - see [PrekeyStore]'s doc comment for the pruning discipline
     * that keeps this bounded while never reopening one-time-prekey reuse. */
    const val MAX_ONE_TIME_PREKEY_ENTRIES = 4_096

    private const val BODY_HEADER_SIZE =
        4 + 1 + 1 + PUBLIC_KEY_SIZE + X25519_KEY_SIZE + 4 + X25519_KEY_SIZE + 4 + 8 + 2
    const val MAX_BODY_SIZE = BODY_HEADER_SIZE + MAX_ONE_TIME_PREKEY_ENTRIES * ENTRY_SIZE

    // --- v2 (encrypted-at-rest) header layout - byte-identical shape to KeystoreFileFormat's v2
    // header, own magic/version. See that object's header comment for the field-by-field layout;
    // reproduced here for this format's own header assembly/parsing. ---
    private const val KDF_ID_OFFSET = 5
    private const val MEMORY_OFFSET = 6
    private const val ITERATIONS_OFFSET = 10
    private const val PARALLELISM_OFFSET = 14
    private const val SALT_OFFSET = 15
    private const val NONCE_OFFSET = 31
    private const val CIPHERTEXT_OFFSET = 43
    private const val V2_HEADER_SIZE = CIPHERTEXT_OFFSET
    private const val GCM_TAG_SIZE = 16

    /** Hard cap on total file size BEFORE ever attempting decryption - unlike
     * `KeystoreFileFormat`'s fixed-size v1/v2 files, this format's ciphertext is variable length
     * (the one-time-prekey list grows), so a total-size cap is genuinely needed rather than a fixed
     * equality check. `43` (header) `+ 151,673` (worst-case body) `+ 16` (GCM tag). */
    const val MAX_STORE_FILE_BYTES = V2_HEADER_SIZE + MAX_BODY_SIZE + GCM_TAG_SIZE

    /** Public aliases so callers outside this file (e.g. [PrekeyStore]'s v1-to-v2 migration check)
     * can compare against these without this file needing to expose the raw private constants. */
    const val FORMAT_VERSION_1: Byte = VERSION_1
    const val FORMAT_VERSION_2: Byte = VERSION_2

    /** The on-disk format version encoded in [bytes]' header (offset 4). */
    fun formatVersionOf(bytes: ByteArray): Byte {
        require(bytes.size >= 5) { "prekey store file too short to contain a version header" }
        return bytes[4]
    }

    internal fun encode(state: PrekeyStoreState): ByteArray {
        require(state.entries.size <= MAX_ONE_TIME_PREKEY_ENTRIES) {
            "at most $MAX_ONE_TIME_PREKEY_ENTRIES one-time prekey entries allowed, was ${state.entries.size}"
        }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION_1.toInt())
            writeByte(0) // flags: reserved, must be zero
            write(state.ownerIdentity.bytes)
            write(state.x25519IdentityPrivateKeyBytes)
            writeInt(state.signedPrekeyId)
            write(state.signedPrekeyPrivateKeyBytes)
            writeInt(state.nextOneTimePrekeyId)
            writeLong(state.nextBundleSequenceNumber)
            writeShort(state.entries.size)
            state.entries.forEach { entry ->
                writeInt(entry.id)
                writeByte(entry.state.wireValue.toInt())
                write(entry.privateKeyBytes)
            }
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded prekey store body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    internal fun decode(bytes: ByteArray): PrekeyStoreState {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw CorruptedPrekeyStoreException("bad magic")

            val version = input.readByte()
            if (version !=
                VERSION_1
            ) {
                throw CorruptedPrekeyStoreException("unsupported prekey store format version $version")
            }

            val flags = input.readUnsignedByte()
            if (flags != 0) throw CorruptedPrekeyStoreException("reserved flag bits must be zero: $flags")

            val ownerIdentityBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val x25519IdentityPrivateKeyBytes = ByteArray(X25519_KEY_SIZE).also { input.readFully(it) }

            val signedPrekeyId = input.readInt()
            if (signedPrekeyId < 0) throw CorruptedPrekeyStoreException("signedPrekeyId must be >= 0: $signedPrekeyId")
            val signedPrekeyPrivateKeyBytes = ByteArray(X25519_KEY_SIZE).also { input.readFully(it) }

            val nextOneTimePrekeyId = input.readInt()
            if (nextOneTimePrekeyId < 0) {
                throw CorruptedPrekeyStoreException("nextOneTimePrekeyId must be >= 0: $nextOneTimePrekeyId")
            }

            val nextBundleSequenceNumber = input.readLong()
            if (nextBundleSequenceNumber < 1) {
                throw CorruptedPrekeyStoreException(
                    "nextBundleSequenceNumber must be >= 1: $nextBundleSequenceNumber",
                )
            }

            val entryCount = input.readUnsignedShort()
            if (entryCount > MAX_ONE_TIME_PREKEY_ENTRIES) {
                throw CorruptedPrekeyStoreException("too many one-time prekey entries: $entryCount")
            }
            val entries =
                (0 until entryCount).map {
                    val id = input.readInt()
                    if (id < 0) throw CorruptedPrekeyStoreException("one-time prekey entry id must be >= 0: $id")
                    val stateByte = input.readByte()
                    val state =
                        OneTimePrekeyState.entries.find { it.wireValue == stateByte }
                            ?: throw CorruptedPrekeyStoreException(
                                "invalid one-time prekey entry state byte: $stateByte",
                            )
                    val privateKeyBytes = ByteArray(X25519_KEY_SIZE).also { buf -> input.readFully(buf) }
                    OneTimePrekeyStoreEntry(id, state, privateKeyBytes)
                }

            if (input.available() > 0) throw CorruptedPrekeyStoreException("trailing bytes after prekey store body")

            return PrekeyStoreState(
                ownerIdentity = Secp256k1PublicKey(ownerIdentityBytes),
                x25519IdentityPrivateKeyBytes = x25519IdentityPrivateKeyBytes,
                signedPrekeyId = signedPrekeyId,
                signedPrekeyPrivateKeyBytes = signedPrekeyPrivateKeyBytes,
                nextOneTimePrekeyId = nextOneTimePrekeyId,
                nextBundleSequenceNumber = nextBundleSequenceNumber,
                entries = entries,
            )
        } catch (e: EOFException) {
            throw CorruptedPrekeyStoreException("truncated prekey store bytes: ${e.message}")
        } catch (e: IOException) {
            throw CorruptedPrekeyStoreException("failed to decode prekey store: ${e.message}")
        } catch (e: CorruptedPrekeyStoreException) {
            throw e
        } catch (e: OutOfMemoryError) {
            throw CorruptedPrekeyStoreException("prekey store field declared an oversized allocation: ${e.message}")
        } catch (e: RuntimeException) {
            throw CorruptedPrekeyStoreException("invalid prekey store field: ${e.message}")
        }
    }

    /** Encrypts [state] into a v2 store file under [passphrase] - see this object's class doc
     * comment for the header layout. Assembles the header FIRST, then encrypts with that exact
     * header as the GCM AAD, mirroring `KeystoreFileFormat.encodeEncrypted`'s identical ordering
     * discipline (resolves what would otherwise be a circular dependency). */
    internal fun encodeEncrypted(
        state: PrekeyStoreState,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        val plaintext = encode(state)
        val salt = ByteArray(KeystoreEncryption.SALT_SIZE).also(random::nextBytes)
        val nonce = ByteArray(KeystoreEncryption.NONCE_SIZE).also(random::nextBytes)

        val header = ByteBuffer.allocate(V2_HEADER_SIZE)
        header.put(MAGIC)
        header.put(VERSION_2)
        header.put(KeystoreEncryption.KDF_ID_ARGON2ID)
        header.putInt(KeystoreEncryption.DEFAULT_MEMORY_KIB)
        header.putInt(KeystoreEncryption.DEFAULT_ITERATIONS)
        header.put(KeystoreEncryption.DEFAULT_PARALLELISM.toByte())
        header.put(salt)
        header.put(nonce)
        val headerBytes = header.array()
        check(headerBytes.size == V2_HEADER_SIZE) { "v2 header assembly produced an unexpected size" }

        val params =
            KeystoreEncryption.Params(
                memoryKiB = KeystoreEncryption.DEFAULT_MEMORY_KIB,
                iterations = KeystoreEncryption.DEFAULT_ITERATIONS,
                parallelism = KeystoreEncryption.DEFAULT_PARALLELISM,
                salt = salt,
            )
        val ciphertext = KeystoreEncryption.encrypt(plaintext, passphrase, params, nonce, headerBytes)

        val out = ByteArray(V2_HEADER_SIZE + ciphertext.size)
        headerBytes.copyInto(out, 0)
        ciphertext.copyInto(out, V2_HEADER_SIZE)
        return out
    }

    /** Decrypts a v2 store file produced by [encodeEncrypted]. Validates length, magic, version,
     * kdfId, and Argon2 cost-parameter sanity caps BEFORE ever attempting decryption/Argon2 - the
     * same V0.4 lesson `KeystoreFileFormat.decodeEncrypted` already carries, reproduced here rather
     * than re-learned. */
    internal fun decodeEncrypted(
        bytes: ByteArray,
        passphrase: CharArray,
    ): PrekeyStoreState {
        if (bytes.size > MAX_STORE_FILE_BYTES) {
            throw CorruptedPrekeyStoreException("prekey store file exceeds $MAX_STORE_FILE_BYTES bytes: ${bytes.size}")
        }
        if (bytes.size < V2_HEADER_SIZE + GCM_TAG_SIZE) {
            throw CorruptedPrekeyStoreException("prekey store file too short to be a valid v2 store")
        }
        if (!bytes.copyOfRange(0, 4).contentEquals(MAGIC)) throw CorruptedPrekeyStoreException("bad magic")
        if (bytes[4] !=
            VERSION_2
        ) {
            throw CorruptedPrekeyStoreException("unsupported prekey store format version ${bytes[4]}")
        }
        if (bytes[KDF_ID_OFFSET] != KeystoreEncryption.KDF_ID_ARGON2ID) {
            throw CorruptedPrekeyStoreException("unsupported KDF id ${bytes[KDF_ID_OFFSET]}")
        }

        val header = ByteBuffer.wrap(bytes, 0, V2_HEADER_SIZE)
        val memoryKiB = header.getInt(MEMORY_OFFSET)
        val iterations = header.getInt(ITERATIONS_OFFSET)
        val parallelism = bytes[PARALLELISM_OFFSET].toInt() and 0xFF
        // Sanity-cap the KDF cost parameters read off disk BEFORE ever handing them to Argon2 -
        // see KeystoreFileFormat.decodeEncrypted's identical, already-learned V0.4 lesson.
        if (memoryKiB <= 0 || memoryKiB > KeystoreEncryption.DEFAULT_MEMORY_KIB * 16) {
            throw CorruptedPrekeyStoreException("implausible Argon2 memoryKiB $memoryKiB in prekey store header")
        }
        if (iterations <= 0 || iterations > KeystoreEncryption.DEFAULT_ITERATIONS * 16) {
            throw CorruptedPrekeyStoreException("implausible Argon2 iterations $iterations in prekey store header")
        }
        if (parallelism <= 0 || parallelism > KeystoreEncryption.DEFAULT_PARALLELISM * 16) {
            throw CorruptedPrekeyStoreException("implausible Argon2 parallelism $parallelism in prekey store header")
        }
        val salt = bytes.copyOfRange(SALT_OFFSET, NONCE_OFFSET)
        val nonce = bytes.copyOfRange(NONCE_OFFSET, CIPHERTEXT_OFFSET)
        val aadHeader = bytes.copyOfRange(0, V2_HEADER_SIZE)
        val ciphertext = bytes.copyOfRange(CIPHERTEXT_OFFSET, bytes.size)

        val params =
            try {
                KeystoreEncryption.Params(memoryKiB, iterations, parallelism, salt)
            } catch (e: IllegalArgumentException) {
                throw CorruptedPrekeyStoreException("malformed KDF params in prekey store header: ${e.message}")
            }
        val plaintext = KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, aadHeader)
        return decode(plaintext)
    }

    /** Auto-detects the on-disk store version and decodes accordingly - mirrors
     * `KeystoreFileFormat.decodeAuto`'s identical contract, including the reject-oversized-file-
     * before-decrypting guard this format additionally needs (see [MAX_STORE_FILE_BYTES]'s doc
     * comment for why). */
    internal fun decodeAuto(
        bytes: ByteArray,
        passphrase: CharArray?,
    ): PrekeyStoreState {
        if (bytes.size > MAX_STORE_FILE_BYTES) {
            throw CorruptedPrekeyStoreException("prekey store file exceeds $MAX_STORE_FILE_BYTES bytes: ${bytes.size}")
        }
        if (bytes.size <
            5
        ) {
            throw CorruptedPrekeyStoreException("prekey store file too short to contain a version header")
        }
        return when (bytes[4]) {
            VERSION_1 -> {
                logger.warn {
                    "loading a legacy unencrypted (v1) prekey store - consider setting a passphrase to encrypt it at rest"
                }
                decode(bytes)
            }
            VERSION_2 -> {
                if (passphrase == null) {
                    throw KeystoreDecryptionException("passphrase required for encrypted prekey store")
                }
                decodeEncrypted(bytes, passphrase)
            }
            else -> throw CorruptedPrekeyStoreException("unsupported prekey store format version ${bytes[4]}")
        }
    }
}
