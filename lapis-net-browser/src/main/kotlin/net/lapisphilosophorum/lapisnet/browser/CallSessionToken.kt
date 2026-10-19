package net.lapisphilosophorum.lapisnet.browser

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * V0.8.7b - the per-process secret that authorizes the browser call remote control.
 *
 * 32 random bytes, generated once per [BrowserServer] start, handed to the user only through the
 * start URL's fragment (`/call.html#t=<hex>`; a fragment is never sent to a server, never logged by
 * one and never leaks through `Referer`). `call.js` exchanges it for an HttpOnly cookie via
 * `POST /api/call/session`. The token is deliberately excluded from [toString] so it cannot reach
 * a log line or exception message by accident.
 */
class CallSessionToken private constructor(
    private val bytes: ByteArray,
) {
    /** Hex form - ONLY for building the start URL; never log it. */
    val hex: String get() = bytes.toHexString()

    /**
     * Secret URL path segment of every `/api/call` route except `POST /session` (V0.8.7b hardening).
     * Browsers scope cookies by host and path but NOT by port, so the `lapis_call` cookie would also be
     * sent to any other HTTP server on 127.0.0.1. The cookie `Path` is therefore
     * `/api/call/<scope>`: a foreign server cannot make the browser attach the cookie to a URL it can
     * name, because it does not know [scope]. Derived (SHA-256 over a domain label and the token), so it
     * is as unguessable as the token; handed to the page only in the `POST /session` response body.
     */
    val scope: String
        get() {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("lapis-net-call-scope".toByteArray(Charsets.UTF_8))
            digest.update(bytes)
            return digest.digest().copyOf(SCOPE_BYTES).toHexString()
        }

    /** Constant-time comparison against a candidate hex string; malformed input yields `false`. */
    fun matches(candidateHex: String?): Boolean {
        if (candidateHex == null || candidateHex.length != bytes.size * 2) return false
        val decoded = decodeHexOrNull(candidateHex) ?: return false
        return MessageDigest.isEqual(bytes, decoded)
    }

    override fun toString(): String = "CallSessionToken(<redacted>)"

    companion object {
        const val SIZE_BYTES = 32
        private const val SCOPE_BYTES = 16

        fun generate(random: SecureRandom = SecureRandom()): CallSessionToken {
            val bytes = ByteArray(SIZE_BYTES)
            random.nextBytes(bytes)
            return CallSessionToken(bytes)
        }

        private fun decodeHexOrNull(hex: String): ByteArray? {
            if (hex.length % 2 != 0) return null
            val out = ByteArray(hex.length / 2)
            for (i in out.indices) {
                val hi = Character.digit(hex[i * 2], 16)
                val lo = Character.digit(hex[i * 2 + 1], 16)
                if (hi < 0 || lo < 0) return null
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }
    }
}
