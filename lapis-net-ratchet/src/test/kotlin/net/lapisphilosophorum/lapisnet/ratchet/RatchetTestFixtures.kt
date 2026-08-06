package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import java.nio.file.Files
import java.security.SecureRandom

/** `correct horse battery staple`, as a fresh [CharArray] every call - `CharArray` is mutable and
 * several tests zero the passphrase they use, so a single shared constant would break under test
 * ordering; a function avoids that entirely. */
internal fun testPassphrase(): CharArray = "correct horse battery staple".toCharArray()

/** AUDIT-GRADE test seam (V0.8.3 security review, round 1 major finding). Reaches an object's
 * PRIVATE field by reflection - deliberately NOT through [DoubleRatchetSession.onKeyMaterialSupersededForTest]
 * or [DoubleRatchetSession.keyMaterialSnapshotForTest], because a forward-secrecy regression guard
 * built only on those is exactly as trustworthy as the production code remembering to call them: the
 * round-1 audit demonstrated empirically that deleting a key-destruction site in
 * `DoubleRatchetSession.kt` also deletes the ADJACENT hook call in the same commit block, so a
 * hook-based assertion silently degrades instead of failing. Reflection reaches the real backing
 * array/field independent of whether any hook still fires at that site, so it keeps working even if
 * the hook itself is one day removed. Used by `DoubleRatchetAdversarialTest`'s case (a) to assert
 * each of [DoubleRatchetSession]'s four key-destruction sites (rootKey, sendingChainKey,
 * receivingChainKey, the ratchet private key's backing scalar) independently and by identity: the
 * SAME array object captured at time T is asserted all-zero after being superseded. */
internal fun privateField(
    target: Any,
    name: String,
): Any? {
    val field = target.javaClass.getDeclaredField(name)
    field.isAccessible = true
    return field.get(target)
}

/** The write-side counterpart to [privateField] - lets a test force a session into a state that
 * would take an impractical number of real [DoubleRatchetSession.encrypt]/[DoubleRatchetSession.decrypt]
 * calls to reach honestly (e.g. `ns` near [RatchetMessageCodec.MAX_CHAIN_LENGTH]), without inventing a
 * production-facing seam whose only purpose would be to let a test cheat forward. */
internal fun setPrivateField(
    target: Any,
    name: String,
    value: Any?,
) {
    val field = target.javaClass.getDeclaredField(name)
    field.isAccessible = true
    field.set(target, value)
}

/** The real backing 32-byte scalar array inside an [X25519PrivateKey] - reached by reflection past
 * [X25519PrivateKey.bytes]'s deliberate defensive-copy, for the same reason [privateField] bypasses
 * [DoubleRatchetSession]'s own test hooks: proving in-place zeroization requires holding the ACTUAL
 * array `destroy()` mutates, not a copy taken before or after it ran. */
internal fun scalarBytesOf(key: X25519PrivateKey): ByteArray {
    val field = key.javaClass.getDeclaredField("storedBytes")
    field.isAccessible = true
    return field.get(key) as ByteArray
}

/** One party's full material for a V0.8.3 test: a [DualKeyIdentity], a [PrekeyStore] backing it,
 * and the [EncryptionKeyBinding] that vouches for the store's X25519 identity key - everything
 * [handshakeWith] needs to run a REAL [X3dh.initiate]/[X3dh.respond] round trip. */
internal class RatchetTestParty(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    val store: PrekeyStore =
        PrekeyStore.create(
            Files.createTempDirectory("double-ratchet-test"),
            identity,
            oneTimePrekeyCount = 3,
        ),
) {
    val encryptionBinding: EncryptionKeyBinding =
        EncryptionKeyBinding.create(identity.secp256k1KeyPair, store.x25519IdentityPublicKey)

    fun publishBundle(notValidAfterEpochSecond: Long = 500_000L): PrekeyBundle =
        store.publishBundle(identity, notValidAfterEpochSecond, nowEpochSecond = 0)
}

/** The result of a REAL X3DH handshake between two [RatchetTestParty]s - both sides' genuine
 * [X3dhSharedSecret], plus the responder's signed-prekey material in the exact shapes
 * [DoubleRatchetSession.initializeSender]/[DoubleRatchetSession.initializeReceiver] expect. */
internal class RatchetTestHandshake(
    val initiatorSecret: X3dhSharedSecret,
    val responderSecret: X3dhSharedSecret,
    val responderSignedPrekeyPublic: net.lapisphilosophorum.lapisnet.identity.X25519PublicKey,
    val responderSignedPrekeyPair: X25519KeyPair,
)

/** Runs a REAL X3DH handshake ([X3dh.initiate] + [PrekeyStore.consumeOneTimePrekey] +
 * [X3dh.respond]) between [initiator] and [responder] - never a hand-minted [X3dhSharedSecret], so
 * every Double Ratchet session test in this file is anchored to the real V0.8.2 call path. */
internal fun handshake(
    initiator: RatchetTestParty,
    responder: RatchetTestParty,
): RatchetTestHandshake {
    val bundle = responder.publishBundle()
    val initiation =
        X3dh.initiate(
            initiatorIdentity = initiator.identity.secp256k1KeyPair.publicKey,
            initiatorEncryptionBinding = initiator.encryptionBinding,
            initiatorX25519IdentityPrivateKey = initiator.store.x25519IdentityPrivateKey(),
            bundle = bundle,
            nowEpochSecond = 0,
        )
    val oneTimePrekeyId = initiation.header.oneTimePrekeyId
    val consumed = oneTimePrekeyId?.let { responder.store.consumeOneTimePrekey(it) }
    val responderSecret =
        X3dh.respond(
            responderIdentity = responder.identity.secp256k1KeyPair.publicKey,
            responderEncryptionBinding = responder.encryptionBinding,
            responderX25519IdentityPrivateKey = responder.store.x25519IdentityPrivateKey(),
            responderSignedPrekeyId = responder.store.signedPrekeyId,
            responderSignedPrekeyPublicKey = responder.store.signedPrekeyPublicKey,
            responderSignedPrekeyPrivateKey = responder.store.signedPrekeyPrivateKey(),
            header = initiation.header,
            consumedOneTimePrekey = consumed,
        )
    val responderSignedPrekeyPair = X25519KeyPair.fromPrivateKeyBytes(responder.store.signedPrekeyPrivateKey().bytes)
    return RatchetTestHandshake(
        initiatorSecret = initiation.session,
        responderSecret = responderSecret,
        responderSignedPrekeyPublic = responder.store.signedPrekeyPublicKey,
        responderSignedPrekeyPair = responderSignedPrekeyPair,
    )
}

/** A ready-to-use `(alice=sender, bob=receiver)` [DoubleRatchetSession] pair from a fresh, real
 * X3DH handshake between two brand-new [RatchetTestParty]s. */
internal fun establishedPair(random: SecureRandom = SecureRandom()): Pair<DoubleRatchetSession, DoubleRatchetSession> {
    val alice = RatchetTestParty()
    val bob = RatchetTestParty()
    val hs = handshake(alice, bob)
    val aliceSession =
        DoubleRatchetSession.initializeSender(hs.initiatorSecret, hs.responderSignedPrekeyPublic, random)
    val bobSession =
        DoubleRatchetSession.initializeReceiver(hs.responderSecret, hs.responderSignedPrekeyPair, random)
    return aliceSession to bobSession
}

/** A [SecureRandom] that hands back a FIXED, caller-supplied byte sequence from [nextBytes] instead
 * of actual randomness - mirrors `X3dhKnownAnswerTest`'s own `FixedSecureRandom`, renamed here to
 * avoid a same-package name collision (both test classes are compiled into the same
 * `net.lapisphilosophorum.lapisnet.ratchet` package). */
internal class FixedRatchetSecureRandom(
    private val fixedBytes: ByteArray,
) : SecureRandom() {
    override fun nextBytes(bytes: ByteArray) {
        require(bytes.size == fixedBytes.size) {
            "FixedRatchetSecureRandom is pinned to exactly ${fixedBytes.size} bytes, was asked for ${bytes.size}"
        }
        fixedBytes.copyInto(bytes)
    }
}

/** A [SecureRandom] that serves a FIXED QUEUE of caller-supplied byte sequences from successive
 * [nextBytes] calls, each of which must ask for exactly the queued entry's length - needed because
 * [DoubleRatchetSession.initializeSender] draws a 32-byte ratchet keypair scalar and then
 * [DoubleRatchetSession.encrypt] draws a 12-byte nonce from the SAME injected [SecureRandom], so a
 * single fixed value (as `X3dhKnownAnswerTest`'s `FixedSecureRandom` provides) is not enough for an
 * end-to-end pinned vector spanning both calls.
 *
 * **Same BouncyCastle-clamping caveat as `X3dhKnownAnswerTest`'s own `FixedSecureRandom`**: when
 * BouncyCastle's `X25519PrivateKeyParameters(SecureRandom)` constructor draws from this queue for a
 * keypair, it CLAMPS the drawn bytes internally before storing them - so the stored private scalar
 * is NOT byte-identical to the queued value, only equivalent under X25519 scalar multiplication
 * (same public key, same DH outputs). Bytes drawn for a NONCE (via `random.nextBytes(bytes)`
 * directly, never through a BouncyCastle key constructor) are NOT clamped and ARE returned
 * byte-identical. */
internal class QueuedFixedSecureRandom(
    vararg outputs: ByteArray,
) : SecureRandom() {
    private val queue = ArrayDeque(outputs.map { it.copyOf() })

    override fun nextBytes(bytes: ByteArray) {
        val next = queue.removeFirstOrNull() ?: throw IllegalStateException("QueuedFixedSecureRandom queue exhausted")
        require(bytes.size == next.size) {
            "QueuedFixedSecureRandom's next queued output is ${next.size} bytes, was asked for ${bytes.size}"
        }
        next.copyInto(bytes)
    }
}

private fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        (
            (Character.digit(s[i * 2], 16) shl 4) +
                Character.digit(s[i * 2 + 1], 16)
        ).toByte()
    }

internal fun hexBytes(s: String): ByteArray = hex(s)
