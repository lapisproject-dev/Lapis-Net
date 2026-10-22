package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_CELLS_PER_DIRECTION
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.PROTOCOL_ID
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.TAG_SIZE
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

internal enum class Direction(
    val code: Byte,
) {
    FORWARD(1),
    BACKWARD(2),
}

/**
 * One direction of one hop: ChaCha20-Poly1305 (RFC 8439) with an IMPLICIT nonce
 * `directionTag(4) | counter(8, big-endian)`. The counter is never transmitted. A replayed,
 * dropped, duplicated or reordered cell is opened with the wrong nonce, fails the tag and is fatal
 * for the circuit: there is no replay window on purpose, because the underlying transport stream is
 * reliable and ordered, so any deviation is an attack. After one failed [open] the cipher is
 * poisoned and every later call throws.
 *
 * Associated data = `PROTOCOL_ID | direction | hopIndex` (the link-local circuit id is NOT bound:
 * it changes per link). A fresh [ChaCha20Poly1305] instance is used per cell (BouncyCastle refuses
 * nonce reuse on one instance). Not thread-safe; the caller serialises (per circuit lock).
 *
 * Takes OWNERSHIP of [key] (zeroised by [close]). ChaCha20 is constant-time in software and does
 * not depend on AES-NI; BouncyCastle copies the key into its own state per cell - see
 * [CircuitHopKeys] for the JVM zeroisation limits.
 */
internal class HopCipher(
    key: ByteArray,
    private val direction: Direction,
    private val hopIndex: Int,
    private val maxCells: Long = MAX_CELLS_PER_DIRECTION,
    startCounter: Long = 0,
) : AutoCloseable {
    internal val keyRaw: ByteArray = key

    private val aad = PROTOCOL_ID.toByteArray(Charsets.US_ASCII) + byteArrayOf(direction.code, hopIndex.toByte())
    private var counter = startCounter
    private var poisoned = false
    private var closed = false

    val cellsProcessed: Long get() = counter

    private fun nonce(): ByteArray {
        val n = ByteArray(12)
        n[0] = direction.code
        for (i in 0 until 8) n[4 + i] = (counter ushr (56 - 8 * i)).toByte()
        return n
    }

    private fun preflight() {
        check(!closed) { "hop cipher is closed" }
        check(!poisoned) { "hop cipher is poisoned" }
        if (counter >= maxCells) throw OnionResourceLimitException("per-direction cell limit reached; rotate circuit")
    }

    private fun newCipher(forEncryption: Boolean): ChaCha20Poly1305 {
        val c = ChaCha20Poly1305()
        c.init(forEncryption, AEADParameters(KeyParameter(keyRaw), TAG_SIZE * 8, nonce(), aad))
        return c
    }

    /** Returns `ciphertext | tag` (plaintext size + 16). */
    fun seal(plaintext: ByteArray): ByteArray {
        preflight()
        val c = newCipher(true)
        val out = ByteArray(c.getOutputSize(plaintext.size))
        var n = c.processBytes(plaintext, 0, plaintext.size, out, 0)
        n += c.doFinal(out, n)
        check(n == out.size) { "unexpected AEAD output length" }
        counter++
        return out
    }

    /** Throws [OnionIntegrityException] (and poisons the cipher) on any failure. */
    fun open(ciphertext: ByteArray): ByteArray {
        preflight()
        if (ciphertext.size < TAG_SIZE) {
            poisoned = true
            throw OnionIntegrityException()
        }
        try {
            val c = newCipher(false)
            val out = ByteArray(c.getOutputSize(ciphertext.size))
            var n = c.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            n += c.doFinal(out, n)
            counter++
            return if (n == out.size) out else out.copyOf(n)
        } catch (e: InvalidCipherTextException) {
            poisoned = true
            throw OnionIntegrityException()
        } catch (e: RuntimeException) {
            poisoned = true
            throw OnionIntegrityException()
        }
    }

    override fun close() {
        closed = true
        keyRaw.fill(0)
    }
}
