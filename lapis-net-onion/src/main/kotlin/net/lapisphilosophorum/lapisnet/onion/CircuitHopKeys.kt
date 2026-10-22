package net.lapisphilosophorum.lapisnet.onion

/**
 * The two 32-byte symmetric keys of one circuit hop: [forwardKey] (client to exit direction) and
 * [backwardKey]. [close] zeroises both; any later use throws. [toString] never prints key bytes.
 *
 * JVM limit, stated honestly: zeroising the arrays this object owns cannot reach copies the JVM or
 * a library may have made (GC moves, BouncyCastle key-parameter copies). It narrows the window; it
 * is not a guarantee against a memory-dump attacker.
 */
class CircuitHopKeys internal constructor(
    forward: ByteArray,
    backward: ByteArray,
) : AutoCloseable {
    internal val forwardRaw: ByteArray = forward.copyOf()
    internal val backwardRaw: ByteArray = backward.copyOf()

    @Volatile
    private var closed = false

    init {
        require(forwardRaw.size == 32 && backwardRaw.size == 32) { "hop keys must be 32 bytes" }
    }

    /** A fresh copy; the caller must zero it. */
    internal fun forwardKeyCopy(): ByteArray {
        check(!closed) { "hop keys are closed" }
        return forwardRaw.copyOf()
    }

    /** A fresh copy; the caller must zero it. */
    internal fun backwardKeyCopy(): ByteArray {
        check(!closed) { "hop keys are closed" }
        return backwardRaw.copyOf()
    }

    override fun close() {
        closed = true
        forwardRaw.fill(0)
        backwardRaw.fill(0)
    }

    override fun toString(): String = "CircuitHopKeys(REDACTED)"
}
