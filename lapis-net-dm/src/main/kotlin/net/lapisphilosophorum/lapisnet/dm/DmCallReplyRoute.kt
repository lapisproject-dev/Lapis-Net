package net.lapisphilosophorum.lapisnet.dm

/**
 * Opaque, unguessable handle for answering one inbound call over the connection it arrived on
 * (V0.9.19). Only meaningful to the [DmSessionManager] instance that issued it (registry lookup by
 * token); carries NO PeerId and NO identity authority itself. The constructor is public so that
 * tests in downstream modules can build tokens; forging one achieves nothing, because only tokens
 * present in the issuing manager's registry are ever resolved.
 */
class DmCallReplyRoute(
    val token: ByteArray,
) {
    init {
        require(token.size == TOKEN_SIZE) { "reply route token must be $TOKEN_SIZE bytes" }
    }

    override fun equals(other: Any?): Boolean = other is DmCallReplyRoute && token.contentEquals(other.token)

    override fun hashCode(): Int = token.contentHashCode()

    /** Never logs the token. */
    override fun toString(): String = "DmCallReplyRoute(<redacted>)"

    companion object {
        const val TOKEN_SIZE = 16
    }
}
