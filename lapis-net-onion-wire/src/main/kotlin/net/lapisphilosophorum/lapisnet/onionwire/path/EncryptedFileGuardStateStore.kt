@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private val logger = KotlinLogging.logger {}

/**
 * Guard state on disk (`onion/guards.bin`), encrypted so that the file reveals neither the guards nor their age:
 *
 * ```
 * "LNGS"(4) | version=1(1) | nonce(12) | AES-256-GCM( plaintext ) + tag(16)
 * key = HKDF-SHA256(ikm = identity secp256k1 private key, salt = empty, info = "LapisNet:guard-state:v1")
 * AAD = "LNGS" | version | SHA-256(own identity public key)
 * ```
 * A fresh nonce is drawn for every write. The write is atomic (temp file `0600`, fsync, atomic move, directory `0700`).
 * The key bytes are zeroised on [close]. The file is NOT protected against an attacker who can read the identity key
 * (it lives next to it) - it only keeps the guard choice out of casual disk forensics and bound to this identity.
 */
@ExperimentalOnionApi
class EncryptedFileGuardStateStore(
    private val file: Path,
    identity: DualKeyIdentity,
    private val random: SecureRandom = SecureRandom(),
    private val clock: Clock = Clock.systemUTC(),
) : GuardStateStore,
    AutoCloseable {
    private val key: ByteArray = deriveKey(identity)
    private val aad: ByteArray = MAGIC + byteArrayOf(VERSION) + sha256(identity.secp256k1KeyPair.publicKey.bytes)

    @Volatile private var closed = false

    @Synchronized
    override fun load(): GuardLoad {
        try {
            if (!Files.exists(file)) return GuardLoad.Missing
            if (!Files.isRegularFile(file) || Files.size(file) > MAX_FILE_BYTES) return GuardLoad.Invalid
            val bytes = Files.readAllBytes(file)
            if (bytes.size < HEADER + TAG) return GuardLoad.Invalid
            val magic = bytes.copyOfRange(0, 4)
            if (!magic.contentEquals(MAGIC) || bytes[4] != VERSION) return GuardLoad.Invalid
            val nonce = bytes.copyOfRange(5, 5 + NONCE)
            val plain =
                try {
                    cipher(Cipher.DECRYPT_MODE, nonce).also { it.updateAAD(aad) }.doFinal(
                        bytes,
                        HEADER,
                        bytes.size - HEADER,
                    )
                } catch (e: GeneralSecurityException) {
                    return GuardLoad.Invalid
                }
            try {
                val state = decode(plain) ?: return GuardLoad.Invalid
                return if (plausible(state)) GuardLoad.Loaded(state) else GuardLoad.Invalid
            } finally {
                plain.fill(0)
            }
        } catch (e: IOException) {
            logger.warn { "guard state could not be read (${e.javaClass.simpleName})" }
            return GuardLoad.Invalid
        } catch (e: RuntimeException) {
            return GuardLoad.Invalid
        }
    }

    @Synchronized
    override fun save(state: GuardState) {
        // after close the key is zeroised: encrypting with it would overwrite the file with undecryptable content
        if (closed) return
        val plain = encode(state)
        try {
            val nonce = ByteArray(NONCE).also(random::nextBytes)
            val c = cipher(Cipher.ENCRYPT_MODE, nonce).also { it.updateAAD(aad) }
            val ct = c.doFinal(plain)
            writeAtomically(MAGIC + byteArrayOf(VERSION) + nonce + ct)
        } finally {
            plain.fill(0)
        }
    }

    @Synchronized
    override fun close() {
        closed = true
        key.fill(0)
    }

    private fun cipher(
        mode: Int,
        nonce: ByteArray,
    ): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").also {
            it.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG * 8, nonce))
        }

    private fun plausible(s: GuardState): Boolean {
        val now = clock.millis() / 1000
        val skew = MAX_CLOCK_SKEW

        fun ok(e: GuardEntry?): Boolean {
            if (e == null) return true
            if (e.chosenAtEpochSecond > now + skew) return false
            val life = e.expiresAtEpochSecond - e.chosenAtEpochSecond
            if (life < GuardManager.MIN_LIFETIME_SECONDS || life > GuardManager.MAX_LIFETIME_SECONDS) return false
            if (e.consecutiveFailures < 0) return false
            if ((e.firstFailureAtEpochSecond ?: 0) > now + skew) return false
            if ((e.descriptorMissingSinceEpochSecond ?: 0) > now + skew) return false
            return true
        }
        if (!ok(s.primary) || !ok(s.backup)) return false
        if (s.primary != null && s.primary.identity == s.backup?.identity) return false
        if (s.backup != null && s.primary == null) return false
        if ((s.lastFailureRotationEpochSecond ?: 0) > now + skew) return false
        return true
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
            throw IOException("guard state file could not be written", e)
        }
    }

    private companion object {
        val MAGIC = "LNGS".toByteArray(Charsets.US_ASCII)
        const val VERSION: Byte = 1
        const val NONCE = 12
        const val TAG = 16
        const val HEADER = 4 + 1 + NONCE
        const val MAX_FILE_BYTES = 4096L
        const val MAX_CLOCK_SKEW = 300L
        const val KEY_SIZE = 33
        val INFO = "LapisNet:guard-state:v1".toByteArray(Charsets.US_ASCII)

        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

        fun deriveKey(identity: DualKeyIdentity): ByteArray {
            val ikm = identity.secp256k1KeyPair.privateKey.bytes
            try {
                val g = HKDFBytesGenerator(SHA256Digest())
                g.init(HKDFParameters(ikm, ByteArray(0), INFO))
                return ByteArray(32).also { g.generateBytes(it, 0, 32) }
            } finally {
                ikm.fill(0)
            }
        }

        fun encode(s: GuardState): ByteArray {
            val b = ByteBuffer.allocate(2 * ENTRY_MAX + 1 + 9)
            for (e in listOf(s.primary, s.backup)) {
                if (e == null) {
                    b.put(0)
                } else {
                    b.put(1)
                    b.put(e.identity.bytes)
                    b.putLong(e.chosenAtEpochSecond)
                    b.putLong(e.expiresAtEpochSecond)
                    b.putInt(e.consecutiveFailures)
                    putOpt(b, e.firstFailureAtEpochSecond)
                    putOpt(b, e.descriptorMissingSinceEpochSecond)
                }
            }
            putOpt(b, s.lastFailureRotationEpochSecond)
            return b.array().copyOf(b.position())
        }

        fun decode(bytes: ByteArray): GuardState? {
            try {
                val b = ByteBuffer.wrap(bytes)
                val entries = ArrayList<GuardEntry?>(2)
                repeat(2) {
                    when (b.get().toInt()) {
                        0 -> entries += null
                        1 -> {
                            val id = ByteArray(KEY_SIZE).also { b.get(it) }
                            val chosen = b.getLong()
                            val expires = b.getLong()
                            val failures = b.getInt()
                            val first = getOpt(b) ?: -1L
                            val missing = getOpt(b) ?: -1L
                            entries +=
                                GuardEntry(
                                    Secp256k1PublicKey(id),
                                    chosen,
                                    expires,
                                    failures,
                                    first.takeIf { it >= 0 },
                                    missing.takeIf { it >= 0 },
                                )
                        }
                        else -> return null
                    }
                }
                val last = getOpt(b)?.takeIf { it >= 0 }
                if (b.hasRemaining()) return null
                return GuardState(entries[0], entries[1], last)
            } catch (e: RuntimeException) {
                return null
            }
        }

        // an optional value: 0 = absent, 1 + 8 bytes = present; getOpt returns -1 for absent
        private fun putOpt(
            b: ByteBuffer,
            v: Long?,
        ) {
            if (v == null) {
                b.put(0)
            } else {
                b.put(1)
                b.putLong(v)
            }
        }

        private fun getOpt(b: ByteBuffer): Long? =
            when (b.get().toInt()) {
                0 -> null
                1 -> b.getLong()
                else -> throw IllegalArgumentException("bad flag")
            }

        const val ENTRY_MAX = 1 + KEY_SIZE + 8 + 8 + 4 + 9 + 9
    }
}
