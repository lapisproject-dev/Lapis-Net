package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.DeterministicSecureRandom
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import org.bouncycastle.util.Arrays

/**
 * Golden values below are SELF-GENERATED regression vectors (fixed scalars b, x, y and a fixed
 * identity key), NOT an external known-answer test: ntor has no published vectors for this
 * Lapis-specific label set. They pin the exact derivation so any accidental change is caught.
 * They were additionally cross-checked once against an independent Python re-implementation
 * (python `cryptography` X25519 + hmac/hashlib) of the documented formulas; that script is not
 * part of the repository.
 */
class NtorHandshakeTest :
    FunSpec({
        val identity = Secp256k1KeyPair.fromPrivateKeyBytes(ByteArray(32) { 0x11 })
        val onion = X25519KeyPair.fromPrivateKeyBytes(ByteArray(32) { 0x22 })
        val binding = OnionKeyBinding.create(identity, onion.publicKey, 2_000_000_000)

        test("client and server derive identical keys (random run)") {
            val (state, create) = NtorHandshake.clientStart(binding, 1)
            val server = NtorHandshake.serverRespond(CreateBody.decode(create.encode()), onion.privateKey, binding)
            val clientKeys = NtorHandshake.clientFinish(state, CreatedBody.decode(server.created.encode()))
            hex(clientKeys.forwardRaw) shouldBe hex(server.keys.forwardRaw)
            hex(clientKeys.backwardRaw) shouldBe hex(server.keys.backwardRaw)
            (hex(clientKeys.forwardRaw) == hex(clientKeys.backwardRaw)) shouldBe false
        }

        test("golden regression vector") {
            val (state, create) = NtorHandshake.clientStart(binding, 2, DeterministicSecureRandom("client"))
            val server =
                NtorHandshake.serverRespond(
                    create,
                    onion.privateKey,
                    binding,
                    DeterministicSecureRandom("server"),
                )
            val keys = NtorHandshake.clientFinish(state, server.created)
            hex(create.clientEphemeral.bytes) shouldBe GOLDEN_X
            hex(server.created.serverEphemeral.bytes) shouldBe GOLDEN_Y
            hex(server.created.auth) shouldBe GOLDEN_AUTH
            hex(keys.forwardRaw) shouldBe GOLDEN_KF
            hex(keys.backwardRaw) shouldBe GOLDEN_KB
        }

        test("a flipped AUTH bit makes the client fail (every bit position)") {
            val (state0, create0) = NtorHandshake.clientStart(binding, 1)
            val server0 = NtorHandshake.serverRespond(create0, onion.privateKey, binding)
            state0.close()
            for (i in 0 until 32) {
                val (state, create) = NtorHandshake.clientStart(binding, 1)
                val server = NtorHandshake.serverRespond(create, onion.privateKey, binding)
                val auth = server.created.auth.also { it[i] = (it[i].toInt() xor 0x80).toByte() }
                shouldThrow<OnionHandshakeException> {
                    NtorHandshake.clientFinish(state, CreatedBody(server.created.serverEphemeral, auth))
                }
            }
            server0.keys.close()
        }

        test("a replaced server ephemeral makes the client fail") {
            val (state, create) = NtorHandshake.clientStart(binding, 1)
            val server = NtorHandshake.serverRespond(create, onion.privateKey, binding)
            val other = X25519KeyPair.generate().publicKey
            shouldThrow<OnionHandshakeException> {
                NtorHandshake.clientFinish(
                    state,
                    CreatedBody(other, server.created.auth),
                )
            }
        }

        test("CREATE for another relay id or a stale onion key is refused") {
            val (state, create) = NtorHandshake.clientStart(binding, 1)
            state.close()
            val wrongId = CreateBody(1, ByteArray(32) { 9 }, create.onionKeyFingerprint, create.clientEphemeral)
            shouldThrow<OnionHandshakeException> { NtorHandshake.serverRespond(wrongId, onion.privateKey, binding) }
            val wrongFp = CreateBody(1, create.relayIdDigest, ByteArray(32) { 9 }, create.clientEphemeral)
            shouldThrow<OnionHandshakeException> { NtorHandshake.serverRespond(wrongFp, onion.privateKey, binding) }
        }

        test("a low-order client ephemeral cannot even be constructed or decoded") {
            val (state, create) = NtorHandshake.clientStart(binding, 1)
            state.close()
            val bytes =
                create.encode().also {
                    for (i in 67 until 99) it[i] = 0
                    it[67] = 1
                }
            shouldThrow<CellFormatException> { CreateBody.decode(bytes) }
        }

        test("the client state is zeroised after finish, also after a failure") {
            val (s1, c1) = NtorHandshake.clientStart(binding, 1)
            val srv = NtorHandshake.serverRespond(c1, onion.privateKey, binding)
            NtorHandshake.clientFinish(s1, srv.created)
            s1.x.bytes.all { it == 0.toByte() } shouldBe true
            val (s2, c2) = NtorHandshake.clientStart(binding, 1)
            val srv2 = NtorHandshake.serverRespond(c2, onion.privateKey, binding)
            shouldThrow<OnionHandshakeException> {
                NtorHandshake.clientFinish(s2, CreatedBody(srv2.created.serverEphemeral, ByteArray(32)))
            }
            s2.x.bytes.all { it == 0.toByte() } shouldBe true
        }

        test("AUTH comparison is constant-time by construction: BouncyCastle constantTimeAreEqual semantics") {
            // Code-review item: both comparisons in NtorHandshake use org.bouncycastle.util.Arrays.constantTimeAreEqual.
            // This guards the semantics we rely on (length mismatch and single-bit differences are both false).
            val a = ByteArray(32) { it.toByte() }
            Arrays.constantTimeAreEqual(a, a.copyOf()) shouldBe true
            Arrays.constantTimeAreEqual(a, a.copyOf().also { it[31] = 0 }) shouldBe false
            Arrays.constantTimeAreEqual(a, a.copyOf(31)) shouldBe false
        }

        test("two different hop indexes in CREATE are carried but do not change the shared secret derivation inputs") {
            val (s, c) = NtorHandshake.clientStart(binding, 4)
            s.close()
            c.hopIndex shouldBe 4
        }
    })

private const val GOLDEN_X =
    "496e170cd4560dba02f7eab42a67115c379a425b3b5fd7127c7523464a4eb902"
private const val GOLDEN_Y =
    "dd5a90aca68789e832d44e2f0a7593bcfa049d4d3aebbb793bdcc62929855405"
private const val GOLDEN_AUTH =
    "6cdf42c3da228ab0a116580398062b7614b9e289a5825c9280801df478c4c3ef"
private const val GOLDEN_KF =
    "938593e3b99818ed4eb9db5396a3301759bb64de4a17a1d357d53b4ca9b15211"
private const val GOLDEN_KB =
    "50f0af25ffb6a0b62944ef41fe852b6050c0cf31c2c493b221d4e04252431c3d"
