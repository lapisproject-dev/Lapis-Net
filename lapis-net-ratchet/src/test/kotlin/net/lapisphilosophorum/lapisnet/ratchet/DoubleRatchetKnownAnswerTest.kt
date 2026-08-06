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
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private fun hex(s: String): ByteArray = hexBytes(s)

private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

/** `HMAC-SHA256(key, data)` via the JDK's own `javax.crypto.Mac` - an INDEPENDENT implementation
 * from [RatchetKdf.hmacSha256] (which uses BouncyCastle's low-level `HMac`), used as an oracle for
 * RFC 4231's published HMAC-SHA-256 test vectors so this file does not need to risk transcribing
 * RFC hex output by hand. */
private fun jdkHmacSha256(
    key: ByteArray,
    data: ByteArray,
): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

/**
 * Dependency-pinning regressions for [RatchetKdf], mirroring `X3dhKnownAnswerTest`'s own stated
 * reason for existing at all: without a hardcoded literal (not merely a same-codebase
 * recomputation), a change that moves BOTH the production ladder and a test's recomputation to the
 * same new (wrong) construction would leave this suite green.
 */
class DoubleRatchetKnownAnswerTest :
    FunSpec({
        test("RFC 5869 test case 1, asserted against RatchetKdf's OWN hkdfSha256 - not X3dh's") {
            val ikm = ByteArray(22) { 0x0b }
            val salt = hex("000102030405060708090a0b0c")
            val info = hex("f0f1f2f3f4f5f6f7f8f9")
            val expected =
                hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
            RatchetKdf.hkdfSha256(ikm, salt, info, 42) shouldBe expected
        }

        test("RFC 5869 test case 3 (empty salt, empty info), asserted against RatchetKdf's OWN hkdfSha256") {
            val ikm = ByteArray(22) { 0x0b }
            val salt = ByteArray(0)
            val info = ByteArray(0)
            val expected =
                hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
            RatchetKdf.hkdfSha256(ikm, salt, info, 42) shouldBe expected
        }

        test(
            "RFC 4231 HMAC-SHA-256 test cases 1, 2, 4, asserted against RatchetKdf's OWN hmacSha256 " +
                "(BouncyCastle) cross-checked against an INDEPENDENT JDK javax.crypto.Mac oracle",
        ) {
            // Case 1: key = 0x0b * 20, data = "Hi There"
            val key1 = ByteArray(20) { 0x0b }
            val data1 = "Hi There".toByteArray(Charsets.US_ASCII)
            RatchetKdf.hmacSha256(key1, data1) shouldBe jdkHmacSha256(key1, data1)

            // Case 2: key = "Jefe", data = "what do ya want for nothing?"
            val key2 = "Jefe".toByteArray(Charsets.US_ASCII)
            val data2 = "what do ya want for nothing?".toByteArray(Charsets.US_ASCII)
            RatchetKdf.hmacSha256(key2, data2) shouldBe jdkHmacSha256(key2, data2)

            // Case 4: key = 0x0102...19 (25 bytes), data = 0xcd * 50
            val key4 = ByteArray(25) { (it + 1).toByte() }
            val data4 = ByteArray(50) { 0xcd.toByte() }
            RatchetKdf.hmacSha256(key4, data4) shouldBe jdkHmacSha256(key4, data4)
        }

        test("this wave's own pinned constants, asserted DIRECTLY against production (internal) values") {
            ROOT_KDF_INFO_LABEL shouldBe "LapisNet:double-ratchet:v1:root".toByteArray(Charsets.US_ASCII)
            ROOT_KDF_INFO_LABEL.size shouldBe 31

            MESSAGE_KDF_INFO_LABEL shouldBe "LapisNet:double-ratchet:v1:message".toByteArray(Charsets.US_ASCII)
            MESSAGE_KDF_INFO_LABEL.size shouldBe 34

            MESSAGE_KDF_SALT.size shouldBe 32
            MESSAGE_KDF_SALT.all { it == 0.toByte() } shouldBe true

            MESSAGE_KEY_HMAC_CONSTANT shouldBe 0x01.toByte()
            CHAIN_KEY_HMAC_CONSTANT shouldBe 0x02.toByte()

            X3DH_ASSOCIATED_DATA_SIZE shouldBe 71
            (ROOT_KDF_INFO_LABEL.size + 71) shouldBe 102
            (MESSAGE_KDF_INFO_LABEL.size + 71) shouldBe 105

            RatchetMessageCodec.HEADER_SIZE shouldBe 60
            (RatchetMessageCodec.HEADER_SIZE + 71) shouldBe 131 // the full AAD length
        }

        test(
            "hand-computed ladder cross-check: rootKdf/chainKdf/messageKeyKdf independently recomputed " +
                "from-scratch via the already-pinned hkdfSha256/hmacSha256 helpers - never by calling the " +
                "composite functions from within themselves",
        ) {
            val rk = hex("aa".repeat(32))
            val dhOut = hex("bb".repeat(32))
            val alice = Secp256k1KeyPair.fromPrivateKeyBytes(hex("11".repeat(32)))
            val bob = Secp256k1KeyPair.fromPrivateKeyBytes(hex("33".repeat(32)))
            val ad = X3dh.associatedData(alice.publicKey, bob.publicKey)

            val expectedRootOkm = RatchetKdf.hkdfSha256(dhOut, rk, ROOT_KDF_INFO_LABEL + ad, 64)
            val (actualRootKey, actualChainKey) = RatchetKdf.rootKdf(rk, dhOut, ad)
            actualRootKey shouldBe expectedRootOkm.copyOfRange(0, 32)
            actualChainKey shouldBe expectedRootOkm.copyOfRange(32, 64)

            val ck = hex("cc".repeat(32))
            val expectedNextChainKey = RatchetKdf.hmacSha256(ck, byteArrayOf(CHAIN_KEY_HMAC_CONSTANT))
            val expectedMessageKeyMaterial = RatchetKdf.hmacSha256(ck, byteArrayOf(MESSAGE_KEY_HMAC_CONSTANT))
            val (actualNextChainKey, actualMessageKeyMaterial) = RatchetKdf.chainKdf(ck)
            actualNextChainKey shouldBe expectedNextChainKey
            actualMessageKeyMaterial shouldBe expectedMessageKeyMaterial

            val mkMaterial = hex("dd".repeat(32))
            val expectedAesKey = RatchetKdf.hkdfSha256(mkMaterial, MESSAGE_KDF_SALT, MESSAGE_KDF_INFO_LABEL + ad, 32)
            val actualAesKey = RatchetKdf.messageKeyKdf(mkMaterial, ad)
            actualAesKey shouldBe expectedAesKey
        }

        test(
            "pinned hardcoded hex literals for rootKdf/chainKdf/messageKeyKdf outputs, computed once from " +
                "exact fixed inputs - the genuinely load-bearing regression per this file's own class doc " +
                "comment: a literal cannot silently track a change that moves both the test's recomputation " +
                "and production to the same wrong construction",
        ) {
            val rk = hex("aa".repeat(32))
            val dhOut = hex("bb".repeat(32))
            val alice = Secp256k1KeyPair.fromPrivateKeyBytes(hex("11".repeat(32)))
            val bob = Secp256k1KeyPair.fromPrivateKeyBytes(hex("33".repeat(32)))
            val ad = X3dh.associatedData(alice.publicKey, bob.publicKey)

            val (rootKey, rootChainKey) = RatchetKdf.rootKdf(rk, dhOut, ad)
            rootKey shouldBe hex(PINNED_ROOT_KDF_ROOT_KEY_HEX)
            rootChainKey shouldBe hex(PINNED_ROOT_KDF_CHAIN_KEY_HEX)

            val ck = hex("cc".repeat(32))
            val (nextChainKey, messageKeyMaterial) = RatchetKdf.chainKdf(ck)
            nextChainKey shouldBe hex(PINNED_CHAIN_KDF_NEXT_CHAIN_KEY_HEX)
            messageKeyMaterial shouldBe hex(PINNED_CHAIN_KDF_MESSAGE_KEY_MATERIAL_HEX)

            val mkMaterial = hex("dd".repeat(32))
            val aesKey = RatchetKdf.messageKeyKdf(mkMaterial, ad)
            aesKey shouldBe hex(PINNED_MESSAGE_KEY_KDF_AES_KEY_HEX)
        }

        test(
            "end-to-end pinned vector: a full session with every input fixed - both identities, both X25519 " +
                "sub-keys, the signed prekey, a one-time prekey, X3dh.initiate driven by a FixedRatchetSecureRandom, " +
                "and DoubleRatchetSession.initializeSender/encrypt driven by a QueuedFixedSecureRandom - the " +
                "resulting RatchetMessageCodec.encode(...) output pinned against a hardcoded hex literal. This is " +
                "the single test that would catch ANY silent change to the ladder, the header layout, the AAD " +
                "composition, or the nonce strategy.",
        ) {
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
                DualKeyIdentity(bobSecp256k1, bobEd25519, IdentityBinding.create(bobSecp256k1, bobEd25519.publicKey))

            val aliceX25519Identity =
                X25519PrivateKey(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
            val bobX25519Identity = X25519PrivateKey(hex("66".repeat(32)))
            val bobSignedPrekey = X25519PrivateKey(hex("77".repeat(32)))
            val bobOneTimePrekey = X25519PrivateKey(hex("88".repeat(32)))
            val ephemeralScalar = hex("99".repeat(32))
            val ratchetScalar = hex("aa".repeat(32))
            val nonceBytes = hex("bb".repeat(12))

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
                    random = FixedRatchetSecureRandom(ephemeralScalar),
                )

            val session =
                DoubleRatchetSession.initializeSender(
                    sharedSecret = initiation.session,
                    theirInitialRatchetKey = X25519KeyPair.publicKeyFor(bobSignedPrekey),
                    random = QueuedFixedSecureRandom(ratchetScalar, nonceBytes),
                )
            val message = session.encrypt("Attack at dawn".toByteArray(Charsets.US_ASCII))
            val encoded = RatchetMessageCodec.encode(message)

            toHex(encoded) shouldBe PINNED_END_TO_END_MESSAGE_HEX
        }
    })

// --- Pinned literals below, each computed once from this file's own fixed inputs (see the two
// tests above that use them) - not invented, not carried over from anywhere else. ---

private const val PINNED_ROOT_KDF_ROOT_KEY_HEX =
    "09926f928e43886fca7808cbfc5604bfc261b5fcf99e608d664626340239f990"
private const val PINNED_ROOT_KDF_CHAIN_KEY_HEX =
    "46e444aa0bac6437884a3e423337eb97a7eb0475af4a7c6f0ca6cb2fc8d30bd7"
private const val PINNED_CHAIN_KDF_NEXT_CHAIN_KEY_HEX =
    "a05d2d057a2649da92a9c9afe7272c639aba867f7186ccf7fc8e16bd526ef696"
private const val PINNED_CHAIN_KDF_MESSAGE_KEY_MATERIAL_HEX =
    "75e88bd30a30f221d8f619274e149e8714c1ccefc82d469ec485bf2ba5024540"
private const val PINNED_MESSAGE_KEY_KDF_AES_KEY_HEX =
    "29eebfb1c16f68723716b808d374873ba567a2ba64e5a88a2a80347cc0780ecd"
private const val PINNED_END_TO_END_MESSAGE_HEX =
    "4c4e4452010014ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e240700000000000000000bbbbbbbbbbbbbbbbbbbbbbbb001ec214136d7d5a3b5b5af075f7d812e3f60b2a4809563947e7e092afc2f2d9"
