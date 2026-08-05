package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.x25519SharedSecret
import java.security.SecureRandom

private fun hex(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        (
            (Character.digit(s[i * 2], 16) shl 4) +
                Character.digit(s[i * 2 + 1], 16)
        ).toByte()
    }

/** A [SecureRandom] that hands back a FIXED, caller-supplied byte sequence from [nextBytes] instead
 * of actual randomness - used ONLY to pin [X3dh.initiate]'s internally-generated ephemeral X25519
 * keypair to a reproducible scalar for the known-answer test below.
 *
 * **`X25519KeyPair.generate(FixedSecureRandom(fixedBytes))` does NOT store `fixedBytes` verbatim -
 * it stores the CLAMPED scalar.** Decompiling the resolved `bcprov-jdk18on:1.85` jar confirms
 * `X25519PrivateKeyParameters(SecureRandom)` calls `X25519.generatePrivateKey(random, data)`, whose
 * bytecode is `random.nextBytes(k)` immediately followed by `invokestatic clampPrivateKey([B)V` -
 * so this does NOT produce byte-for-byte the same private key as directly constructing
 * `X25519KeyPair.fromPrivateKeyBytes(fixedBytes)` would. (That constructor's own overload taking
 * raw bytes IS a plain `System.arraycopy`, unclamped - see
 * [net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey]'s doc comment; only the
 * `SecureRandom`-driven generation path clamps.) This is harmless for what this test actually
 * asserts: clamping is idempotent under X25519 scalar multiplication, so `clamp(fixedBytes)` and
 * `fixedBytes` derive the IDENTICAL public key and IDENTICAL DH outputs - which is exactly why
 * `initiation.header.ephemeralPublicKey shouldBe X25519KeyPair.fromPrivateKeyBytes(ephemeralScalar).publicKey`
 * holds below despite the stored scalar bytes themselves differing. Do not rely on byte-for-byte
 * equality of the STORED ephemeral scalar anywhere else - only public-key/DH-output equivalence is
 * guaranteed. */
private class FixedSecureRandom(
    private val fixedBytes: ByteArray,
) : SecureRandom() {
    override fun nextBytes(bytes: ByteArray) {
        require(bytes.size == fixedBytes.size) {
            "FixedSecureRandom is pinned to exactly ${fixedBytes.size} bytes, was asked for ${bytes.size}"
        }
        fixedBytes.copyInto(bytes)
    }
}

/**
 * Dependency-pinning regressions the plan mandates: known-answer test vectors from the PUBLIC
 * specifications (RFC 7748 for X25519, RFC 5869 for HKDF-SHA256), asserted directly against this
 * module's/`lapis-net-identity`'s own call paths - never against BouncyCastle directly - so a
 * future dependency bump that silently changes semantics fails loudly here, not in production.
 *
 * **Plus a genuine END-TO-END X3DH known-answer test, which an earlier version of this file did
 * NOT have.** That earlier version asserted only literal arithmetic (`(32 + 32 * 3) shouldBe 128`)
 * that touches no production code at all, and re-declared the HKDF info label as a disconnected
 * LOCAL string constant instead of asserting against the production one - so changing
 * [F_PREFIX]'s fill byte, [HKDF_SALT], [HKDF_INFO_LABEL], or the DH1-DH4 ordering/assembly in
 * [X3dh] would have left this entire suite green. This version instead:
 * 1. Asserts [F_PREFIX]/[HKDF_SALT]/[HKDF_INFO_LABEL] directly (now `internal`, not re-declared).
 * 2. Fixes every input scalar for a full handshake - both parties' secp256k1/Ed25519 identities,
 *    both parties' X25519 sub-keys (including the actual RFC 7748 section 6.1 "Alice" scalar for
 *    the initiator's X25519 identity key), and the initiator's ephemeral key (via
 *    [FixedSecureRandom]) - and runs the REAL [X3dh.initiate]/[X3dh.respond] call paths against
 *    them, not a reimplementation.
 * 3. Independently recomputes the expected shared secret from the exposed production constants
 *    plus the already-pinned [x25519SharedSecret]/[X3dh.hkdfSha256] helpers (never by calling
 *    [X3dh]'s private `deriveSharedSecret` directly), and asserts it against [X3dh.initiate]'s
 *    actual output.
 * 4. Pins that same derived secret against a HARDCODED hex constant, computed once from this exact
 *    fixed input set - the genuinely load-bearing regression, since step 3's recomputation alone
 *    would still pass if a future change moved BOTH the test's recomputation and [X3dh]'s
 *    production code to the same new (wrong) construction; a hardcoded literal cannot silently
 *    track such a change.
 */
class X3dhKnownAnswerTest :
    FunSpec({
        test("RFC 7748 section 6.1 X25519 vector, asserted against this project's own x25519SharedSecret") {
            val alicePrivate = X25519PrivateKey(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
            val bobPublic = X25519PublicKey(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
            val expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
            x25519SharedSecret(alicePrivate, bobPublic) shouldBe expected
        }

        test("RFC 5869 test case 1, asserted against this module's own hkdfSha256 helper") {
            val ikm = ByteArray(22) { 0x0b }
            val salt = hex("000102030405060708090a0b0c")
            val info = hex("f0f1f2f3f4f5f6f7f8f9")
            val expected =
                hex(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                )
            X3dh.hkdfSha256(ikm, salt, info, 42) shouldBe expected
        }

        test("RFC 5869 test case 3 (empty salt, empty info), asserted against this module's own hkdfSha256 helper") {
            val ikm = ByteArray(22) { 0x0b }
            val salt = ByteArray(0)
            val info = ByteArray(0)
            val expected =
                hex(
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                )
            X3dh.hkdfSha256(ikm, salt, info, 42) shouldBe expected
        }

        test(
            "this wave's own pinned constants: F prefix, HKDF salt, and info label, asserted DIRECTLY against " +
                "production (internal) values - not a disconnected local re-declaration",
        ) {
            F_PREFIX.size shouldBe 32
            F_PREFIX.all { it == 0xFF.toByte() } shouldBe true

            HKDF_SALT.size shouldBe 32
            HKDF_SALT.all { it == 0.toByte() } shouldBe true

            HKDF_INFO_LABEL shouldBe "LapisNet:x3dh:v1:X25519:SHA-256".toByteArray(Charsets.US_ASCII)
            HKDF_INFO_LABEL.size shouldBe 31

            val ad =
                X3dh.associatedData(
                    Secp256k1KeyPair.generate().publicKey,
                    Secp256k1KeyPair.generate().publicKey,
                )
            ad.size shouldBe 71
            (HKDF_INFO_LABEL.size + ad.size) shouldBe 102

            // IKM = F_PREFIX (32) + 32*3 (DH1-DH3) = 128 bytes without a one-time prekey, 160 with one.
            (F_PREFIX.size + 32 * 3) shouldBe 128
            (F_PREFIX.size + 32 * 4) shouldBe 160
        }

        test(
            "end-to-end X3DH known-answer test: every input scalar fixed, X3dh.initiate/respond's derived " +
                "secret is pinned against a hardcoded hex constant computed once from this exact input set",
        ) {
            // --- Fixed secp256k1 + Ed25519 identities. Arbitrary but fixed, distinct repeated-byte
            // scalars - X3DH's own spec has no secp256k1 identity layer to pin against, so there is
            // no external vector for these; only the X25519 sub-keys below use a real RFC vector. ---
            val aliceSecp256k1 = Secp256k1KeyPair.fromPrivateKeyBytes(hex("11".repeat(32)))
            val aliceEd25519 = Ed25519KeyPair.fromPrivateKeySeed(hex("22".repeat(32)))
            val aliceIdentity =
                DualKeyIdentity(
                    aliceSecp256k1,
                    aliceEd25519,
                    IdentityBinding.create(aliceSecp256k1, aliceEd25519.publicKey),
                )

            val bobSecp256k1 = Secp256k1KeyPair.fromPrivateKeyBytes(hex("33".repeat(32)))
            val bobEd25519 = Ed25519KeyPair.fromPrivateKeySeed(hex("44".repeat(32)))
            val bobIdentity =
                DualKeyIdentity(
                    bobSecp256k1,
                    bobEd25519,
                    IdentityBinding.create(bobSecp256k1, bobEd25519.publicKey),
                )
            // Silence "unused variable" for the DualKeyIdentity.secp256k1KeyPair.publicKey identity
            // check inside PrekeyBundle.create/EncryptionKeyBinding.create below - both identities
            // are exercised through those calls, not directly referenced again here.
            aliceIdentity.verifyBinding() shouldBe true
            bobIdentity.verifyBinding() shouldBe true

            // --- Fixed X25519 sub-keys. aliceX25519Identity is the actual RFC 7748 section 6.1
            // "Alice" scalar (reused from the vector above); every other X25519 scalar is a fixed,
            // distinct, non-degenerate repeated-byte value. ---
            val aliceX25519Identity =
                X25519PrivateKey(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
            val bobX25519Identity = X25519PrivateKey(hex("66".repeat(32)))
            val bobSignedPrekey = X25519PrivateKey(hex("77".repeat(32)))
            val bobOneTimePrekey = X25519PrivateKey(hex("88".repeat(32)))
            val ephemeralScalar = hex("99".repeat(32))

            val aliceEncryptionBinding =
                EncryptionKeyBinding.create(aliceSecp256k1, X25519KeyPair.publicKeyFor(aliceX25519Identity))
            val bobEncryptionBinding =
                EncryptionKeyBinding.create(bobSecp256k1, X25519KeyPair.publicKeyFor(bobX25519Identity))

            val bundle =
                PrekeyBundle.create(
                    identity = bobIdentity,
                    encryptionBinding = bobEncryptionBinding,
                    signedPrekeyId = 0,
                    signedPrekey = X25519KeyPair.publicKeyFor(bobSignedPrekey),
                    oneTimePrekeys = listOf(OneTimePrekey(0, X25519KeyPair.publicKeyFor(bobOneTimePrekey))),
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 500_000L,
                    nowEpochSecond = 0,
                )

            val initiation =
                X3dh.initiate(
                    initiatorIdentity = aliceSecp256k1.publicKey,
                    initiatorEncryptionBinding = aliceEncryptionBinding,
                    initiatorX25519IdentityPrivateKey = aliceX25519Identity,
                    bundle = bundle,
                    nowEpochSecond = 0,
                    preferredOneTimePrekeyId = 0,
                    random = FixedSecureRandom(ephemeralScalar),
                )
            initiation.header.ephemeralPublicKey shouldBe X25519KeyPair.fromPrivateKeyBytes(ephemeralScalar).publicKey

            // --- Independent recomputation of the expected secret, built directly from the
            // production F_PREFIX/HKDF_SALT/HKDF_INFO_LABEL constants and the already-pinned
            // x25519SharedSecret/X3dh.hkdfSha256 helpers - NOT by calling X3dh's own private
            // deriveSharedSecret, so this genuinely exercises the same public primitives from a
            // completely separate assembly path. ---
            val expectedAd = X3dh.associatedData(aliceSecp256k1.publicKey, bobSecp256k1.publicKey)
            val dh1 = x25519SharedSecret(aliceX25519Identity, X25519KeyPair.publicKeyFor(bobSignedPrekey))
            val dh2 =
                x25519SharedSecret(X25519PrivateKey(ephemeralScalar), X25519KeyPair.publicKeyFor(bobX25519Identity))
            val dh3 = x25519SharedSecret(X25519PrivateKey(ephemeralScalar), X25519KeyPair.publicKeyFor(bobSignedPrekey))
            val dh4 =
                x25519SharedSecret(X25519PrivateKey(ephemeralScalar), X25519KeyPair.publicKeyFor(bobOneTimePrekey))
            val expectedIkm = F_PREFIX + dh1 + dh2 + dh3 + dh4
            expectedIkm.size shouldBe 160
            val expectedInfo = HKDF_INFO_LABEL + expectedAd
            val expectedSecret = X3dh.hkdfSha256(expectedIkm, HKDF_SALT, expectedInfo, 32)

            initiation.session.sharedSecret shouldBe expectedSecret

            // --- Hardcoded known-answer hex, computed once from this exact fixed input set (see
            // this class's own doc comment for why this literal - not just the recomputation above -
            // is the genuinely load-bearing regression). ---
            initiation.session.sharedSecret shouldBe
                hex("d5123e80a6d68b4d3afc5c0005d2bdfa24963fa92a40669651e79d5a231dfe53")

            // --- Responder-side mirror: byte-identical secret from the real X3dh.respond call path. ---
            val responderSession =
                X3dh.respond(
                    responderIdentity = bobSecp256k1.publicKey,
                    responderX25519IdentityPrivateKey = bobX25519Identity,
                    responderSignedPrekeyId = 0,
                    responderSignedPrekeyPrivateKey = bobSignedPrekey,
                    header = initiation.header,
                    consumedOneTimePrekey = ConsumedOneTimePrekey(0, bobOneTimePrekey),
                )
            responderSession.sharedSecret shouldBe initiation.session.sharedSecret
        }
    })
