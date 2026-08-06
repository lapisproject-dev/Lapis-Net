package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption
import java.nio.ByteBuffer

/** Body-plaintext field offsets, transcribed verbatim from [DoubleRatchetSessionCodec]'s own class
 * doc comment ("Inner plaintext body" table) - duplicated here rather than exposed from the codec
 * because the codec deliberately keeps `encodeBody`/`decodeBody`/every offset constant `private`: this
 * format has NO legitimate plaintext-producing entry point other than "decrypt a real ciphertext",
 * so a test that wants to reach [DoubleRatchetSessionCodec.decodeBody]'s defensive branches must go
 * through the SAME [KeystoreEncryption] round trip a real tampering attacker would, exactly as
 * [PrekeyStoreTest] does for its v1-plaintext-format equivalent. */
private const val BODY_VERSION_OFFSET = 4
private const val FLAGS_OFFSET = 5
private const val AD_LENGTH_OFFSET = 6
private const val SENDING_PRESENT_OFFSET = 111
private const val SENDING_KEY_OFFSET = 112
private const val RECEIVING_KEY_OFFSET = 145
private const val SKIPPED_COUNT_OFFSET = 254
private const val FIXED_BODY_PREFIX_SIZE = 256

/** Header field offsets, transcribed verbatim from the same class doc comment's "Outer encrypted
 * file layout" table. */
private const val HEADER_SIZE = 43
private const val MEMORY_OFFSET = 6
private const val ITERATIONS_OFFSET = 10
private const val PARALLELISM_OFFSET = 14
private const val SALT_OFFSET = 15
private const val NONCE_OFFSET = 31

/** Decrypts a genuine [DoubleRatchetSessionCodec.encode] blob's body back to plaintext, hands it to
 * [mutate] for a single targeted tamper, then RE-encrypts it under the SAME header/salt/nonce/params
 * (a nonce reused across two plaintexts under the same key is a non-issue for a throwaway test
 * ciphertext that is never used as real key material) and reassembles a full blob. Exercises
 * [DoubleRatchetSessionCodec.decode]'s POST-decryption structural checks exactly as an attacker who
 * has the passphrase (or a legitimate holder whose disk corrupted a single byte) would trigger them -
 * every case below is rejected only AFTER a successful AEAD decryption, never confused with a wrong
 * passphrase or a tampered ciphertext. */
private fun tamperedBody(
    original: ByteArray,
    passphrase: CharArray,
    mutate: (ByteArray) -> Unit,
): ByteArray {
    val header = original.copyOfRange(0, HEADER_SIZE)
    val memoryKiB = ByteBuffer.wrap(original, MEMORY_OFFSET, 4).int
    val iterations = ByteBuffer.wrap(original, ITERATIONS_OFFSET, 4).int
    val parallelism = original[PARALLELISM_OFFSET].toInt() and 0xFF
    val salt = original.copyOfRange(SALT_OFFSET, NONCE_OFFSET)
    val nonce = original.copyOfRange(NONCE_OFFSET, HEADER_SIZE)
    val ciphertext = original.copyOfRange(HEADER_SIZE, original.size)
    val params = KeystoreEncryption.Params(memoryKiB, iterations, parallelism, salt)
    val plaintext = KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, header)
    try {
        val mutated = plaintext.copyOf()
        mutate(mutated)
        val newCiphertext = KeystoreEncryption.encrypt(mutated, passphrase, params, nonce, header)
        return header + newCiphertext
    } finally {
        plaintext.fill(0)
    }
}

private fun putShort(
    bytes: ByteArray,
    offset: Int,
    value: Int,
) {
    bytes[offset] = (value ushr 8).toByte()
    bytes[offset + 1] = value.toByte()
}

private fun putInt(
    bytes: ByteArray,
    offset: Int,
    value: Int,
) {
    bytes[offset] = (value ushr 24).toByte()
    bytes[offset + 1] = (value ushr 16).toByte()
    bytes[offset + 2] = (value ushr 8).toByte()
    bytes[offset + 3] = value.toByte()
}

class DoubleRatchetSessionCodecTest :
    FunSpec({
        test("round trip through the identity's keystore encryption, session usable afterwards") {
            val (alice, bob) = establishedPair()
            repeat(3) { i -> bob.decrypt(alice.encrypt("a$i".toByteArray())) }
            repeat(3) { i -> alice.decrypt(bob.encrypt("b$i".toByteArray())) }
            // Two skipped keys outstanding on alice's side.
            val more = (0..2).map { bob.encrypt("more$it".toByteArray()) }
            alice.decrypt(more[2])
            alice.skippedKeyCount() shouldBe 2

            val expectedSendKey = alice.sendMessageNumber()
            val expectedReceiveKey = alice.receiveMessageNumber()
            val expectedPreviousSendChainLength = alice.previousSendChainLength()
            val expectedSkippedCount = alice.skippedKeyCount()
            val expectedSendingRatchetKey = alice.sendingRatchetPublicKey()

            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val restored = DoubleRatchetSessionCodec.decode(blob, testPassphrase())

            restored.sendMessageNumber() shouldBe expectedSendKey
            restored.receiveMessageNumber() shouldBe expectedReceiveKey
            restored.previousSendChainLength() shouldBe expectedPreviousSendChainLength
            restored.skippedKeyCount() shouldBe expectedSkippedCount
            restored.sendingRatchetPublicKey() shouldBe expectedSendingRatchetKey

            // Still decrypts the remaining skipped messages.
            restored.decrypt(more[0]).decodeToString() shouldBe "more0"
            restored.decrypt(more[1]).decodeToString() shouldBe "more1"
        }

        test("a restored session can send, and the peer decrypts it") {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("prime".toByteArray()))

            val blob = DoubleRatchetSessionCodec.encode(bob, testPassphrase())
            val restoredBob = DoubleRatchetSessionCodec.decode(blob, testPassphrase())

            val reply = restoredBob.encrypt("from restored bob".toByteArray())
            alice.decrypt(reply).decodeToString() shouldBe "from restored bob"
        }

        test("round trip of a never-yet-used receiver session - the all-absent case") {
            val (_, bob) = establishedPair()
            bob.canSend shouldBe false

            val blob = DoubleRatchetSessionCodec.encode(bob, testPassphrase())
            val restored = DoubleRatchetSessionCodec.decode(blob, testPassphrase())
            restored.canSend shouldBe false
            restored.sendMessageNumber() shouldBe 0
            restored.receiveMessageNumber() shouldBe 0
        }

        test("two encode calls of the same session produce different bytes but equivalent state") {
            val (alice, _) = establishedPair()
            val blob1 = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val blob2 = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            blob1 shouldNotBe blob2

            val restored1 = DoubleRatchetSessionCodec.decode(blob1, testPassphrase())
            val restored2 = DoubleRatchetSessionCodec.decode(blob2, testPassphrase())
            restored1.sendingRatchetPublicKey() shouldBe restored2.sendingRatchetPublicKey()
            restored1.sendMessageNumber() shouldBe restored2.sendMessageNumber()
        }

        test("wrong passphrase throws KeystoreDecryptionException") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            shouldThrow<KeystoreDecryptionException> {
                DoubleRatchetSessionCodec.decode(blob, "wrong passphrase entirely".toCharArray())
            }
        }

        test("a single-bit tamper anywhere in the header or ciphertext is rejected cleanly, never a crash") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val sampledOffsets = (blob.indices step 37).toList() + listOf(blob.size - 1)
            sampledOffsets.forEach { offset ->
                val tampered = blob.copyOf()
                tampered[offset] = (tampered[offset] + 1).toByte()
                shouldThrow<RuntimeException> { DoubleRatchetSessionCodec.decode(tampered, testPassphrase()) }
            }
        }

        test("a truncated blob is rejected cleanly") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            shouldThrow<CorruptedRatchetSessionException> {
                DoubleRatchetSessionCodec.decode(blob.copyOf(10), testPassphrase())
            }
        }

        test("an oversized blob is rejected before Argon2 ever runs") {
            val oversized = ByteArray(DoubleRatchetSessionCodec.MAX_SESSION_FILE_BYTES + 1)
            shouldThrow<CorruptedRatchetSessionException> {
                DoubleRatchetSessionCodec.decode(oversized, testPassphrase())
            }
        }

        test("absurd Argon2 params in the header are rejected before Argon2 ever runs") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())

            val absurdMemory = blob.copyOf()
            absurdMemory[6] = (Int.MAX_VALUE ushr 24).toByte()
            absurdMemory[7] = (Int.MAX_VALUE ushr 16).toByte()
            absurdMemory[8] = (Int.MAX_VALUE ushr 8).toByte()
            absurdMemory[9] = Int.MAX_VALUE.toByte()
            shouldThrow<CorruptedRatchetSessionException> {
                DoubleRatchetSessionCodec.decode(absurdMemory, testPassphrase())
            }

            val zeroParallelism = blob.copyOf()
            zeroParallelism[14] = 0
            shouldThrow<CorruptedRatchetSessionException> {
                DoubleRatchetSessionCodec.decode(zeroParallelism, testPassphrase())
            }
        }

        test("encode does not mutate the session") {
            val (alice, _) = establishedPair()
            val before = alice.keyMaterialSnapshotForTest()
            DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val after = alice.keyMaterialSnapshotForTest()
            before.size shouldBe after.size
            before.zip(after).forEach { (b, a) -> b shouldBe a }
            // still usable afterwards
            alice.encrypt("still alive".toByteArray())
        }

        test("encode on a destroyed session throws IllegalStateException") {
            val (alice, _) = establishedPair()
            alice.destroy()
            shouldThrow<IllegalStateException> { DoubleRatchetSessionCodec.encode(alice, testPassphrase()) }
        }

        // -----------------------------------------------------------------------------------
        // Round 2 MAJOR fix: decodeBody/stateForCodec each allocated a FIRST-generation copy of
        // every secret (root key, both chain keys, ratchet private scalar, every skipped key
        // material) that DoubleRatchetSessionState's constructor then copied AGAIN into its own
        // storage - the first-generation copy was abandoned un-zeroed on the heap. These locals are
        // stack-local to a `private`/`internal` method, so - exactly like
        // DoubleRatchetSession.onKeyMaterialSupersededForTest already does for decrypt()'s own
        // scratch locals - a dedicated test-only hook is the only way to reach them independent of
        // whatever the returned object happens to expose. See DoubleRatchetSessionCodec's own doc
        // comment on onDecodeBodyLocalsCapturedForTest for why this hook does not repeat round 1's
        // "silently degrades if the destruction site vanishes" failure mode.
        // -----------------------------------------------------------------------------------

        test(
            "decode() zeroes every locally-decoded secret array - root key, both chain keys, ratchet " +
                "private scalar, every skipped key material - after DoubleRatchetSessionState has " +
                "taken its own copies",
        ) {
            val (alice, bob) = establishedPair()
            // Bob's bootstrap DH step populates rootKey/sendingChainKey/receivingChainKey and leaves
            // two skipped keys outstanding, so every optional slot below is genuinely non-empty.
            val messages = (0..2).map { alice.encrypt("m$it".toByteArray()) }
            bob.decrypt(messages[2])
            bob.skippedKeyCount() shouldBe 2

            val blob = DoubleRatchetSessionCodec.encode(bob, testPassphrase())
            val captured = mutableListOf<DoubleRatchetSessionCodec.DecodedBodyLocalsForTest>()
            DoubleRatchetSessionCodec.onDecodeBodyLocalsCapturedForTest = { captured += it }
            try {
                DoubleRatchetSessionCodec.decode(blob, testPassphrase())
            } finally {
                DoubleRatchetSessionCodec.onDecodeBodyLocalsCapturedForTest = null
            }

            captured.size shouldBe 1
            val locals = captured.single()
            locals.rootKey.all { it == 0.toByte() } shouldBe true
            locals.sendingChainKeyBytes.all { it == 0.toByte() } shouldBe true
            locals.receivingChainKeyBytes.all { it == 0.toByte() } shouldBe true
            locals.ourRatchetPrivateKeyBytes.all { it == 0.toByte() } shouldBe true
            locals.skippedKeyMaterials.size shouldBe 2
            locals.skippedKeyMaterials.forEach { material -> material.all { it == 0.toByte() } shouldBe true }
        }

        test(
            "encode() zeroes stateForCodec's own intermediate copies - ratchet private scalar and " +
                "every skipped key material - after DoubleRatchetSessionState has taken its own " +
                "copies, and leaves the live session fully usable afterwards",
        ) {
            val (alice, bob) = establishedPair()
            val messages = (0..2).map { alice.encrypt("m$it".toByteArray()) }
            bob.decrypt(messages[2])
            bob.skippedKeyCount() shouldBe 2

            var capturedScalar: ByteArray? = null
            var capturedSkipped: List<ByteArray>? = null
            bob.onStateForCodecLocalsCapturedForTest = { scalar, skipped ->
                capturedScalar = scalar
                capturedSkipped = skipped
            }
            try {
                DoubleRatchetSessionCodec.encode(bob, testPassphrase())
            } finally {
                bob.onStateForCodecLocalsCapturedForTest = null
            }

            val scalar = capturedScalar
            val skipped = capturedSkipped
            scalar.shouldNotBe(null)
            skipped.shouldNotBe(null)
            scalar!!.all { it == 0.toByte() } shouldBe true
            skipped!!.size shouldBe 2
            skipped.forEach { material -> material.all { it == 0.toByte() } shouldBe true }

            // The live session itself is untouched: stateForCodec now passes rootKey/sendingChainKey/
            // receivingChainKey to the state constructor WITHOUT an extra .copyOf() (the constructor
            // already copies), so this also proves that change never started mutating the live arrays.
            bob.skippedKeyCount() shouldBe 2
            bob.encrypt("still alive after encode".toByteArray())
        }

        // -----------------------------------------------------------------------------------
        // decodeBody()'s post-decryption structural checks - all ten defensive branches this
        // class's doc comment lists as previously untested. Each case here decrypts successfully
        // (proving the check is NOT a disguised wrong-passphrase/AEAD failure) and is rejected only
        // by decodeBody's own structural validation, as CorruptedRatchetSessionException.
        // -----------------------------------------------------------------------------------

        test("decodeBody rejects a bad body magic") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> body[0] = (body[0] + 1).toByte() }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects an unsupported body version") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> body[BODY_VERSION_OFFSET] = 2 }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects non-zero reserved flag bits") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> body[FLAGS_OFFSET] = 1 }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a wrong associatedDataLength") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> putShort(body, AD_LENGTH_OFFSET, 70) }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a presence byte that is neither 0 nor 1") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> body[SENDING_PRESENT_OFFSET] = 2 }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a non-all-zero sendingChainKey slot when marked absent") {
            // bob, freshly initializeReceiver()'d, has NO sending chain yet - the "absent" case.
            val (_, bob) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(bob, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> body[SENDING_KEY_OFFSET] = 1 }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a non-all-zero receivingChainKey slot when marked absent") {
            // bob, freshly initializeReceiver()'d, has NO receiving chain yet either.
            val (_, bob) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(bob, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> body[RECEIVING_KEY_OFFSET] = 1 }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a skippedKeyCount above MAX_SKIPPED_KEYS_STORED") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body ->
                    putShort(body, SKIPPED_COUNT_OFFSET, DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED + 1)
                }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a declared skippedKeyCount inconsistent with the actual body size") {
            // alice's freshly-initialized state has zero skipped entries - declare one anyway.
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val tampered =
                tamperedBody(blob, passphrase) { body -> putShort(body, SKIPPED_COUNT_OFFSET, 1) }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }
        }

        test("decodeBody rejects a skipped entry with an out-of-range messageNumber") {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("prime".toByteArray())) // bob cannot send until this happens
            // Leave exactly one skipped key outstanding on alice's side.
            val messages = (0..1).map { bob.encrypt("m$it".toByteArray()) }
            alice.decrypt(messages[1])
            alice.skippedKeyCount() shouldBe 1

            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val messageNumberOffset = FIXED_BODY_PREFIX_SIZE + 32 // past the entry's ratchetPublicKey field
            val tampered =
                tamperedBody(blob, passphrase) { body -> putInt(body, messageNumberOffset, -1) }
            shouldThrow<CorruptedRatchetSessionException> { DoubleRatchetSessionCodec.decode(tampered, passphrase) }

            // The un-tampered blob still round-trips, proving the offset above is correct rather
            // than accidentally landing on a byte that never gets checked.
            val restored = DoubleRatchetSessionCodec.decode(blob, passphrase)
            restored.skippedKeyCount() shouldBe 1
        }

        // "trailing bytes after session body" (decodeBody's final check) is deliberately NOT
        // exercised here: it sits behind an earlier check (declared skippedKeyCount must match the
        // body's actual byte length) that runs first and computes the exact same invariant this one
        // guards - by the time that earlier check passes, the stream is mathematically guaranteed to
        // have zero bytes left. It is unreachable through decode() (the only production entry point,
        // and the only one this codec exposes - see this class's own doc comment on why there is no
        // plaintext/legacy path), kept purely as defence in depth against a future refactor that
        // decouples those two checks.

        test("a genuinely malformed but otherwise-untampered blob still round-trips (control for the cases above)") {
            val (alice, _) = establishedPair()
            val blob = DoubleRatchetSessionCodec.encode(alice, testPassphrase())
            val passphrase = testPassphrase()
            val untouched = tamperedBody(blob, passphrase) { /* no mutation */ }
            val restored = DoubleRatchetSessionCodec.decode(untouched, passphrase)
            restored.sendingRatchetPublicKey() shouldBe alice.sendingRatchetPublicKey()
        }
    })
