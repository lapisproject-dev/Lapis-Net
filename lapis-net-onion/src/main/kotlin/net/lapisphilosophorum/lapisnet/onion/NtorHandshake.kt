package net.lapisphilosophorum.lapisnet.onion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.PROTOCOL_ID
import org.bouncycastle.util.Arrays
import java.security.SecureRandom

private val logger = KotlinLogging.logger {}

private val PROTOID = PROTOCOL_ID.toByteArray(Charsets.US_ASCII)
private val T_KEY_EXTRACT = PROTOID + ":key_extract".toByteArray(Charsets.US_ASCII)
private val T_VERIFY = PROTOID + ":verify".toByteArray(Charsets.US_ASCII)
private val T_MAC = PROTOID + ":mac".toByteArray(Charsets.US_ASCII)
private val T_EXPAND = PROTOID + ":expand".toByteArray(Charsets.US_ASCII)
private val SERVER = "Server".toByteArray(Charsets.US_ASCII)

/** Client-side handshake state: the ephemeral scalar x plus the target relay's public parameters.
 * [close] zeroises x. */
class NtorClientState internal constructor(
    internal val x: X25519PrivateKey,
    internal val clientPublic: X25519PublicKey,
    internal val onionKey: X25519PublicKey,
    internal val relayIdDigest: ByteArray,
) : AutoCloseable {
    override fun close() {
        x.destroy()
    }

    override fun toString(): String = "NtorClientState(REDACTED)"
}

class NtorServerResult internal constructor(
    val created: CreatedBody,
    val keys: CircuitHopKeys,
) {
    override fun toString(): String = "NtorServerResult(REDACTED)"
}

/**
 * The ntor one-way-authenticated key exchange (Goldberg, Stebila, Ustaoglu 2013; Tor spec
 * "ntor"), reimplemented from the published description over this project's X25519 primitive.
 * The wire shapes and labels are Lapis-specific, so the pinned test vector is self-generated
 * regression data, NOT an external known-answer test.
 *
 * ```
 * client: x, X = x*G                    relay: onion key (b, B), identity digest ID
 * CREATE:  X                      ->    y, Y = y*G
 *                                       secret_input = X25519(y,X) | X25519(b,X) | ID | B | X | Y | PROTOID
 * CREATED: Y, AUTH                <-    KEY_SEED = HMAC(PROTOID:key_extract, secret_input)
 * client: secret_input = X25519(x,Y) | X25519(x,B) | ID | B | X | Y | PROTOID
 * verify   = HMAC(PROTOID:verify,  secret_input)
 * AUTH     = HMAC(PROTOID:mac,     verify | ID | B | Y | X | PROTOID | "Server")
 * keys     = HKDF-SHA256(ikm = KEY_SEED, salt = empty, info = PROTOID:expand, L = 64) -> Kf | Kb
 * ```
 * Forward secrecy: both ephemerals x and y are zeroised right after use, so a later compromise of
 * the relay's onion key b alone cannot recompute `X25519(x,Y)`. Agreements run through
 * [x25519SharedSecret] (low-order/all-zero protected). The AUTH comparison is constant-time. Every
 * failure funnels into the single undifferentiated [OnionHandshakeException]; nothing secret is
 * ever logged.
 */
object NtorHandshake {
    fun clientStart(
        binding: OnionKeyBinding,
        hopIndex: Int,
        random: SecureRandom = SecureRandom(),
    ): Pair<NtorClientState, CreateBody> {
        val pair = X25519KeyPair.generate(random)
        val id = binding.relayIdDigest()
        val state = NtorClientState(pair.privateKey, pair.publicKey, binding.onionKey, id)
        return state to CreateBody(hopIndex, id, binding.onionKeyFingerprint(), pair.publicKey)
    }

    /** Throws [OnionHandshakeException] if the CREATE does not address this relay/onion key or the
     * agreement is degenerate. The caller answers with DESTROY(AUTH_FAILED). */
    fun serverRespond(
        create: CreateBody,
        onionPrivate: X25519PrivateKey,
        ownBinding: OnionKeyBinding,
        random: SecureRandom = SecureRandom(),
    ): NtorServerResult {
        val id = ownBinding.relayIdDigest()
        if (!Arrays.constantTimeAreEqual(create.relayIdDigest, id) ||
            !Arrays.constantTimeAreEqual(create.onionKeyFingerprint, ownBinding.onionKeyFingerprint())
        ) {
            logger.debug { "ntor: create does not address this relay" }
            throw OnionHandshakeException()
        }
        val ephemeral = X25519KeyPair.generate(random)
        var s1: ByteArray? = null
        var s2: ByteArray? = null
        try {
            s1 = x25519SharedSecret(ephemeral.privateKey, create.clientEphemeral)
            s2 = x25519SharedSecret(onionPrivate, create.clientEphemeral)
            val (auth, keys) =
                derive(s1, s2, id, ownBinding.onionKey, create.clientEphemeral, ephemeral.publicKey)
            return NtorServerResult(CreatedBody(ephemeral.publicKey, auth), keys)
        } catch (e: OnionHandshakeException) {
            throw e
        } catch (e: RuntimeException) {
            logger.debug { "ntor: server handshake failed" }
            throw OnionHandshakeException()
        } finally {
            s1?.fill(0)
            s2?.fill(0)
            ephemeral.privateKey.destroy()
        }
    }

    /** Always zeroises [state], also on failure. Throws [OnionHandshakeException] if AUTH does not match. */
    fun clientFinish(
        state: NtorClientState,
        created: CreatedBody,
    ): CircuitHopKeys {
        var s1: ByteArray? = null
        var s2: ByteArray? = null
        try {
            s1 = x25519SharedSecret(state.x, created.serverEphemeral)
            s2 = x25519SharedSecret(state.x, state.onionKey)
            val (auth, keys) =
                derive(s1, s2, state.relayIdDigest, state.onionKey, state.clientPublic, created.serverEphemeral)
            try {
                if (!Arrays.constantTimeAreEqual(auth, created.auth)) {
                    logger.debug { "ntor: server authentication failed" }
                    throw OnionHandshakeException()
                }
            } catch (e: OnionHandshakeException) {
                keys.close()
                throw e
            } finally {
                auth.fill(0)
            }
            return keys
        } catch (e: OnionHandshakeException) {
            throw e
        } catch (e: RuntimeException) {
            logger.debug { "ntor: client handshake failed" }
            throw OnionHandshakeException()
        } finally {
            s1?.fill(0)
            s2?.fill(0)
            state.close()
        }
    }

    /** Shared derivation: returns `AUTH` and the hop keys; zeroises every intermediate secret. */
    private fun derive(
        s1: ByteArray,
        s2: ByteArray,
        id: ByteArray,
        b: X25519PublicKey,
        x: X25519PublicKey,
        y: X25519PublicKey,
    ): Pair<ByteArray, CircuitHopKeys> {
        val bBytes = b.bytes
        val xBytes = x.bytes
        val yBytes = y.bytes
        val secretInput = s1 + s2 + id + bBytes + xBytes + yBytes + PROTOID
        var keySeed: ByteArray? = null
        var verify: ByteArray? = null
        var authInput: ByteArray? = null
        var okm: ByteArray? = null
        try {
            keySeed = OnionKdf.hmacSha256(T_KEY_EXTRACT, secretInput)
            verify = OnionKdf.hmacSha256(T_VERIFY, secretInput)
            authInput = verify + id + bBytes + yBytes + xBytes + PROTOID + SERVER
            val auth = OnionKdf.hmacSha256(T_MAC, authInput)
            okm = OnionKdf.hkdfSha256(keySeed, ByteArray(0), T_EXPAND, 64)
            val forward = okm.copyOfRange(0, 32)
            val backward = okm.copyOfRange(32, 64)
            try {
                return auth to CircuitHopKeys(forward, backward)
            } finally {
                forward.fill(0)
                backward.fill(0)
            }
        } finally {
            secretInput.fill(0)
            keySeed?.fill(0)
            verify?.fill(0)
            authInput?.fill(0)
            okm?.fill(0)
        }
    }
}
