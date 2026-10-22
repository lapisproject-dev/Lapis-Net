package net.lapisphilosophorum.lapisnet.onion.fake

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * TEST ONLY. A SHA-256 counter-mode byte stream so that golden vectors are reproducible. Must
 * never be used in production code (it lives in the test source set on purpose).
 */
class DeterministicSecureRandom(
    private val seed: ByteArray,
) : SecureRandom() {
    private var counter = 0L
    private var block = ByteArray(0)
    private var pos = 0

    constructor(seed: Long) : this(seed.toString().toByteArray())

    constructor(seed: String) : this(seed.toByteArray())

    @Synchronized
    override fun nextBytes(bytes: ByteArray) {
        for (i in bytes.indices) {
            if (pos >= block.size) {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(seed)
                md.update(counter.toString().toByteArray())
                block = md.digest()
                counter++
                pos = 0
            }
            bytes[i] = block[pos++]
        }
    }

    override fun generateSeed(numBytes: Int): ByteArray = ByteArray(numBytes).also(::nextBytes)
}
