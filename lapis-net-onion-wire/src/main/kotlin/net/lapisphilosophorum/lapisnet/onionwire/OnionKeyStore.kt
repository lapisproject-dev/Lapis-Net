package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionKeyRing
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.time.Clock
import kotlin.time.Duration

private val logger = KotlinLogging.logger {}

/** The key file is unreadable, tampered with, wrong-passphrase or belongs to another identity. Messages carry the path
 * but never any content. The relay mode refuses to start on it. */
class OnionKeyStoreException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Persistence and rotation of a relay's onion keys (`<label>.onionkeys`).
 *
 * File format v1, all integers big-endian:
 * ```
 * header (also the AEAD associated data, 76 bytes):
 *   "LNOK" | version=1 | kdf=1 (Argon2id) | memKiB(4) | iterations(4) | parallelism(1) | salt(16) | nonce(12) | identity(33)
 * ciphertext (AES-256-GCM, key = Argon2id(passphrase, salt)):
 *   count(1, 1..2) x [ x25519Private(32) | notValidAfter(8) | bindingSignature(64) ]  |  lastDescriptorSequence(8)
 * ```
 * The identity public key is part of the AAD, so the file is bound to one identity; a fresh random salt AND nonce are drawn
 * for every write (the key is derived per write, so a nonce is never reused under one key). The write is atomic (temp file with
 * `0600`, `fsync`, atomic move); the directory is `0700`. Loading verifies every binding (signature, identity, matching
 * public key); an expired entry is dropped silently, a broken one fails loudly.
 *
 * Without a passphrase there is no file: keys live in memory only ([LoadResult.EPHEMERAL]) and are lost on restart.
 * Plaintext buffers and derived material are zeroised in `finally` blocks (best effort on the JVM).
 */
class OnionKeyStore(
    private val file: Path,
    private val identity: DualKeyIdentity,
    passphrase: CharArray?,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    private val kdfMemoryKiB: Int = KeystoreEncryption.DEFAULT_MEMORY_KIB,
) : AutoCloseable {
    enum class LoadResult { LOADED, CREATED, EPHEMERAL }

    private val passphrase: CharArray? = passphrase?.copyOf()
    private val identityKey: Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey

    /** Highest descriptor sequence number this relay used (persisted so it never goes back). */
    @Volatile var lastDescriptorSequence: Long = -1

    val persistent: Boolean get() = passphrase != null

    @Synchronized
    fun loadOrCreate(
        ring: OnionKeyRing,
        lifetime: Duration,
    ): LoadResult {
        val now = clock.millis() / 1000
        if (passphrase == null) {
            generateAndInstall(ring, lifetime, now)
            return LoadResult.EPHEMERAL
        }
        if (Files.exists(file)) {
            val loaded = readFile(now)
            // oldest first, so the newest ends up as current
            loaded.entries.asReversed().forEach { (binding, scalar) ->
                try {
                    ring.install(binding, X25519PrivateKey(scalar), now)
                } finally {
                    scalar.fill(0)
                }
            }
            lastDescriptorSequence = loaded.lastSequence
            if (ring.current() != null) return LoadResult.LOADED
        }
        generateAndInstall(ring, lifetime, now)
        persist(ring)
        return LoadResult.CREATED
    }

    /** Generates a fresh onion key, installs it as current (the former current stays valid as previous) and persists. */
    @Synchronized
    fun rotate(
        ring: OnionKeyRing,
        lifetime: Duration,
    ) {
        generateAndInstall(ring, lifetime, clock.millis() / 1000)
        persist(ring)
    }

    private fun generateAndInstall(
        ring: OnionKeyRing,
        lifetime: Duration,
        now: Long,
    ) {
        val pair = X25519KeyPair.generate(random)
        val binding = OnionKeyBinding.create(identity.secp256k1KeyPair, pair.publicKey, now + lifetime.inWholeSeconds)
        try {
            ring.install(binding, pair.privateKey, now)
        } catch (e: RuntimeException) {
            pair.privateKey.destroy()
            throw e
        }
    }

    /** Writes the ring (no-op without a passphrase). */
    @OptIn(ExperimentalOnionApi::class)
    @Synchronized
    fun persist(ring: OnionKeyRing) {
        val pass = passphrase ?: return
        ring.snapshotForPersistence { entries ->
            // an empty ring (closed relay) has nothing to persist: no-op, never an exception out of a periodic job
            if (entries.isEmpty()) return@snapshotForPersistence
            require(entries.size <= 2) { "too many keys to persist" }
            val plain = ByteBuffer.allocate(1 + entries.size * ENTRY_SIZE + 8)
            var ciphertext: ByteArray? = null
            try {
                plain.put(entries.size.toByte())
                for ((binding, scalar) in entries) {
                    plain.put(scalar)
                    plain.putLong(binding.notValidAfterEpochSecond)
                    plain.put(binding.signature)
                }
                plain.putLong(lastDescriptorSequence)
                val salt = ByteArray(KeystoreEncryption.SALT_SIZE).also { random.nextBytes(it) }
                val nonce = ByteArray(KeystoreEncryption.NONCE_SIZE).also { random.nextBytes(it) }
                val header = encodeHeader(kdfMemoryKiB, ITERATIONS, PARALLELISM, salt, nonce)
                val params = KeystoreEncryption.Params(kdfMemoryKiB, ITERATIONS, PARALLELISM, salt)
                ciphertext = KeystoreEncryption.encrypt(plain.array(), pass, params, nonce, header)
                writeAtomically(header + ciphertext)
            } finally {
                plain.array().fill(0)
            }
        }
    }

    private class Loaded(
        val entries: List<Pair<OnionKeyBinding, ByteArray>>,
        val lastSequence: Long,
    )

    private fun fail(reason: String): Nothing = throw OnionKeyStoreException("onion key file $file: $reason")

    private fun readFile(now: Long): Loaded {
        val bytes =
            try {
                if (Files.size(file) > MAX_FILE_BYTES) fail("unexpectedly large")
                Files.readAllBytes(file)
            } catch (e: IOException) {
                throw OnionKeyStoreException("onion key file $file: cannot be read", e)
            }
        if (bytes.size < HEADER_SIZE + 1 + ENTRY_SIZE + 8 + 16) fail("truncated")
        val b = ByteBuffer.wrap(bytes)
        val magic = ByteArray(4).also { b.get(it) }
        if (!magic.contentEquals(MAGIC)) fail("not an onion key file")
        if (b.get().toInt() != VERSION) fail("unsupported version")
        if (b.get() != KeystoreEncryption.KDF_ID_ARGON2ID) fail("unsupported key derivation")
        val mem = b.getInt()
        val iter = b.getInt()
        val par = b.get().toInt() and 0xFF
        // a hostile file must not make us allocate an arbitrary amount of memory in Argon2
        if (mem !in 8..MAX_KDF_MEMORY_KIB || iter !in 1..MAX_KDF_ITERATIONS || par !in 1..MAX_KDF_PARALLELISM) {
            fail("key derivation parameters out of range")
        }
        val salt = ByteArray(KeystoreEncryption.SALT_SIZE).also { b.get(it) }
        val nonce = ByteArray(KeystoreEncryption.NONCE_SIZE).also { b.get(it) }
        val fileIdentity = ByteArray(33).also { b.get(it) }
        if (!fileIdentity.contentEquals(identityKey.bytes)) fail("belongs to another identity")
        val header = bytes.copyOfRange(0, HEADER_SIZE)
        val plain =
            try {
                KeystoreEncryption.decrypt(
                    bytes.copyOfRange(HEADER_SIZE, bytes.size),
                    passphrase!!,
                    KeystoreEncryption.Params(mem, iter, par, salt),
                    nonce,
                    header,
                )
            } catch (e: KeystoreDecryptionException) {
                throw OnionKeyStoreException("onion key file $file: wrong passphrase or corrupted/tampered file", e)
            }
        try {
            val p = ByteBuffer.wrap(plain)
            val count = p.get().toInt()
            if (count !in 1..2 || plain.size != 1 + count * ENTRY_SIZE + 8) fail("malformed content")
            val entries = ArrayList<Pair<OnionKeyBinding, ByteArray>>()
            repeat(count) {
                val scalar = ByteArray(32).also { s -> p.get(s) }
                val notValidAfter = p.getLong()
                val sig = ByteArray(64).also { s -> p.get(s) }
                try {
                    val pub =
                        try {
                            X25519KeyPair.fromPrivateKeyBytes(scalar).publicKey
                        } catch (e: IllegalArgumentException) {
                            fail("invalid key material")
                        }
                    val binding = OnionKeyBinding(identityKey, pub, notValidAfter, sig)
                    // signature check independent of expiry (verify at the binding's own expiry second)
                    if (!OnionKeyBinding.verify(binding, notValidAfter)) fail("key binding does not verify")
                    if (now <=
                        notValidAfter
                    ) {
                        entries += binding to scalar.copyOf()
                    } else {
                        logger.debug { "dropped an expired onion key" }
                    }
                } finally {
                    scalar.fill(0)
                }
            }
            val last = p.getLong()
            return Loaded(entries, last)
        } finally {
            plain.fill(0)
        }
    }

    private fun writeAtomically(content: ByteArray) {
        val parent = file.toAbsolutePath().parent
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent)
            runCatching { Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------")) }
        }
        val tmp = file.resolveSibling(file.fileName.toString() + ".tmp")
        try {
            val attrs =
                runCatching { PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")) }
                    .getOrNull()
            Files.deleteIfExists(tmp)
            val channel =
                if (attrs != null) {
                    FileChannel.open(tmp, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attrs)
                } else {
                    FileChannel.open(tmp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
                }
            channel.use {
                it.write(ByteBuffer.wrap(content))
                it.force(true)
            }
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING)
            }
            runCatching { Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------")) }
        } catch (e: IOException) {
            runCatching { Files.deleteIfExists(tmp) }
            throw OnionKeyStoreException("onion key file $file: cannot be written", e)
        }
    }

    private fun encodeHeader(
        mem: Int,
        iter: Int,
        par: Int,
        salt: ByteArray,
        nonce: ByteArray,
    ): ByteArray {
        val b = ByteBuffer.allocate(HEADER_SIZE)
        b.put(MAGIC)
        b.put(VERSION.toByte())
        b.put(KeystoreEncryption.KDF_ID_ARGON2ID)
        b.putInt(mem)
        b.putInt(iter)
        b.put(par.toByte())
        b.put(salt)
        b.put(nonce)
        b.put(identityKey.bytes)
        return b.array()
    }

    override fun close() {
        passphrase?.fill('\u0000')
    }

    companion object {
        private val MAGIC = "LNOK".toByteArray(Charsets.US_ASCII)
        private const val VERSION = 1
        private const val HEADER_SIZE = 4 + 1 + 1 + 4 + 4 + 1 + 16 + 12 + 33
        private const val ENTRY_SIZE = 32 + 8 + 64
        private const val ITERATIONS = KeystoreEncryption.DEFAULT_ITERATIONS
        private const val PARALLELISM = KeystoreEncryption.DEFAULT_PARALLELISM
        private const val MAX_FILE_BYTES = 4096L
        private const val MAX_KDF_MEMORY_KIB = 262_144
        private const val MAX_KDF_ITERATIONS = 10
        private const val MAX_KDF_PARALLELISM = 4
    }
}
