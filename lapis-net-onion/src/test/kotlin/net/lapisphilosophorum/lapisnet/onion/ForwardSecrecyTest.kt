package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import net.lapisphilosophorum.lapisnet.onion.fake.DeterministicSecureRandom
import net.lapisphilosophorum.lapisnet.onion.fake.hex

private val PROTOID = OnionConstants.PROTOCOL_ID.toByteArray(Charsets.US_ASCII)

/** Independent re-implementation of the documented key schedule, used to test the production code
 * against the specification text rather than against itself. */
private fun schedule(
    s1: ByteArray,
    s2: ByteArray,
    id: ByteArray,
    b: ByteArray,
    x: ByteArray,
    y: ByteArray,
): Pair<ByteArray, ByteArray> {
    val secretInput = s1 + s2 + id + b + x + y + PROTOID
    val keySeed = OnionKdf.hmacSha256(PROTOID + ":key_extract".toByteArray(), secretInput)
    val okm = OnionKdf.hkdfSha256(keySeed, ByteArray(0), PROTOID + ":expand".toByteArray(), 64)
    return okm.copyOfRange(0, 32) to okm.copyOfRange(32, 64)
}

/**
 * These tests show that the session keys DEPEND on both ephemerals; they are property checks of the
 * construction, not a proof of forward secrecy (that follows from the ntor security argument and
 * from both ephemerals being zeroised after use - see ZeroizationTest).
 */
class ForwardSecrecyTest :
    FunSpec({
        val identity = Secp256k1KeyPair.fromPrivateKeyBytes(ByteArray(32) { 0x33 })
        val onion = X25519KeyPair.generate()
        val binding = OnionKeyBinding.create(identity, onion.publicKey, 2_000_000_000)

        test("the production key schedule matches an independent implementation of the specification") {
            val (state, create) = NtorHandshake.clientStart(binding, 1, DeterministicSecureRandom("c"))
            val x = state.x
            val y = X25519KeyPair.generate(DeterministicSecureRandom("s"))
            val server = NtorHandshake.serverRespond(create, onion.privateKey, binding, DeterministicSecureRandom("s"))
            val s1 = x25519SharedSecret(y.privateKey, create.clientEphemeral)
            val s2 = x25519SharedSecret(onion.privateKey, create.clientEphemeral)
            val (kf, kb) =
                schedule(
                    s1,
                    s2,
                    binding.relayIdDigest(),
                    onion.publicKey.bytes,
                    create.clientEphemeral.bytes,
                    y.publicKey.bytes,
                )
            hex(kf) shouldBe hex(server.keys.forwardRaw)
            hex(kb) shouldBe hex(server.keys.backwardRaw)
            x.bytes.size shouldBe 32
            state.close()
        }

        test("an attacker holding the onion key b and the transcript, but neither ephemeral, derives different keys") {
            val (state, create) = NtorHandshake.clientStart(binding, 1)
            val server = NtorHandshake.serverRespond(create, onion.privateKey, binding)
            val xPub = create.clientEphemeral
            val yPub = server.created.serverEphemeral
            // The attacker can compute X25519(b, X) but not X25519(y, X); the best substitute it can
            // build from public data and b is X25519(b, Y).
            val s2 = x25519SharedSecret(onion.privateKey, xPub)
            val guess = x25519SharedSecret(onion.privateKey, yPub)
            val (kf, _) = schedule(guess, s2, binding.relayIdDigest(), onion.publicKey.bytes, xPub.bytes, yPub.bytes)
            (hex(kf) == hex(server.keys.forwardRaw)) shouldBe false
            state.close()
        }

        test("two circuits through the same relay get unrelated keys, and keys do not cross over") {
            fun handshake(): CircuitHopKeys {
                val (state, create) = NtorHandshake.clientStart(binding, 1)
                val server = NtorHandshake.serverRespond(create, onion.privateKey, binding)
                return NtorHandshake.clientFinish(state, server.created)
            }
            val k1 = handshake()
            val k2 = handshake()
            (hex(k1.forwardRaw) == hex(k2.forwardRaw)) shouldBe false
            (hex(k1.backwardRaw) == hex(k2.backwardRaw)) shouldBe false
            val ct = HopCipher(k2.forwardKeyCopy(), Direction.FORWARD, 1).seal(ByteArray(20))
            shouldThrow<OnionIntegrityException> { HopCipher(k1.forwardKeyCopy(), Direction.FORWARD, 1).open(ct) }
        }
    })
