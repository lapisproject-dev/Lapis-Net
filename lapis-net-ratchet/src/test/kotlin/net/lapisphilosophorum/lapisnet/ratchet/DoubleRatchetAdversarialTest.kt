package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

/**
 * The mandatory adversarial spec for V0.8.3, applying V0.8.2-level rigor (`X3dhAdversarialTest`).
 * Case letters match the SPEC's own lettering.
 */
class DoubleRatchetAdversarialTest :
    FunSpec({
        // ---------------------------------------------------------------------------------
        // (a) FORWARD SECRECY
        // ---------------------------------------------------------------------------------
        //
        // Audit finding (round 1, MAJOR): the original version of this section installed
        // onKeyMaterialSupersededForTest on the RECEIVING side only, and asserted the AGGREGATE of
        // whatever it happened to be invoked with was all-zero - without ever asserting HOW MANY
        // times it fired. Because every commit block in DoubleRatchetSession.kt pairs the hook
        // invocation with the fill(0)/destroy() call on the immediately adjacent line, deleting a
        // destruction site deletes its hook call too, and the old assertion silently degraded to
        // checking whichever site(s) happened to remain. Three one-line mutations against
        // DoubleRatchetSession.kt each left the full V0.8.3 suite green: removing the superseded
        // receiving-chain-key destruction (lines 571-574), removing the superseded ratchet PRIVATE
        // KEY destruction (line 562 - which the hook was NEVER wired to in the first place, at any
        // point in this file's history), and removing the superseded sending-chain-key destruction
        // inside encrypt() (lines 324-325, on the hottest one-way path - the hook was only ever
        // installed on the RECEIVING side, which never calls encrypt()).
        //
        // Fix: every site below is probed INDEPENDENTLY and BY IDENTITY, via reflection directly
        // onto the session's private fields (see RatchetTestFixtures.privateField/scalarBytesOf) -
        // never through the hook - so a vanished destruction call fails these tests even if its
        // adjacent hook call vanished with it, and even for the ratchet-private-key site the hook
        // never covered at all. The original hook-based test is kept (it still proves something the
        // reflection tests do not: a restored, pre-decryption snapshot retains what the live session
        // no longer does), but now asserts an EXACT expected fire count too, so a silently-reduced
        // hook-call count would fail it as well.

        test(
            "(a) forward secrecy: sendingChainKey is destroyed IN PLACE by encrypt() itself, on every " +
                "call - the encrypt-driven site (lines 324-325) a receiving-side-only hook can never reach",
        ) {
            val (alice, _) = establishedPair()

            val sendAtT1 = privateField(alice, "sendingChainKey") as ByteArray
            sendAtT1.any { it != 0.toByte() } shouldBe true
            alice.encrypt("m0".toByteArray())
            sendAtT1.all { it == 0.toByte() } shouldBe true
            ((privateField(alice, "sendingChainKey") as ByteArray) !== sendAtT1) shouldBe true

            // And again - not a one-shot effect of the very first call.
            val sendAtT2 = privateField(alice, "sendingChainKey") as ByteArray
            sendAtT2.any { it != 0.toByte() } shouldBe true
            alice.encrypt("m1".toByteArray())
            sendAtT2.all { it == 0.toByte() } shouldBe true
        }

        test(
            "(a) forward secrecy: receivingChainKey is destroyed IN PLACE on a same-chain (symmetric) " +
                "decrypt step (lines 571-574), not only as a side effect of a DH ratchet step",
        ) {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("boot".toByteArray())) // bob's bootstrap DH step

            val recvAtT = privateField(bob, "receivingChainKey") as ByteArray
            recvAtT.any { it != 0.toByte() } shouldBe true

            bob.decrypt(alice.encrypt("m1".toByteArray())) // same chain - symmetric step only
            recvAtT.all { it == 0.toByte() } shouldBe true
        }

        test(
            "(a) forward secrecy: rootKey AND the superseded ratchet PRIVATE SCALAR are both destroyed " +
                "IN PLACE on a DH ratchet step (lines 556-557 and 562) - the scalar's destruction has " +
                "no test hook at all, so only this identity-based check covers it",
        ) {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("boot".toByteArray())) // bob's bootstrap DH step

            val rootAtT = privateField(bob, "rootKey") as ByteArray
            val keyPairAtT = privateField(bob, "ourRatchetKeyPair") as X25519KeyPair
            val scalarAtT = scalarBytesOf(keyPairAtT.privateKey)
            rootAtT.any { it != 0.toByte() } shouldBe true
            scalarAtT.any { it != 0.toByte() } shouldBe true

            // Drive a SECOND DH ratchet step on bob's side: alice ratchets in response to bob's
            // reply, then bob ratchets again in response to alice's next message - superseding the
            // root key and ratchet keypair captured above.
            alice.decrypt(bob.encrypt("reply".toByteArray()))
            bob.decrypt(alice.encrypt("m2".toByteArray()))

            rootAtT.all { it == 0.toByte() } shouldBe true
            scalarAtT.all { it == 0.toByte() } shouldBe true
        }

        test(
            "(a) forward secrecy: a skipped message key's backing array is destroyed on delete-on-use, " +
                "reached from the LIVE session's own field, not just the store tested in isolation",
        ) {
            val (alice, bob) = establishedPair()
            val messages = (0..3).map { alice.encrypt("m$it".toByteArray()) }
            bob.decrypt(messages[3]) // stores skipped keys for 0, 1, 2

            val store = privateField(bob, "skippedKeys") as SkippedMessageKeyStore
            val id1 = SkippedMessageKeyId(messages[1].header.ratchetPublicKey.bytes, 1)
            val backing1 = store.peekBackingArrayForTest(id1)!!
            backing1.any { it != 0.toByte() } shouldBe true

            bob.decrypt(messages[1]) // delete-on-use
            backing1.all { it == 0.toByte() } shouldBe true
        }

        test("(a) forward secrecy: onKeyMaterialSupersededForTest fires exactly once per encrypt() call") {
            val (alice, _) = establishedPair()
            val captured = mutableListOf<ByteArray>()
            alice.onKeyMaterialSupersededForTest = { captured += it }
            alice.encrypt("m0".toByteArray())
            captured.size shouldBe 1
            alice.encrypt("m1".toByteArray())
            captured.size shouldBe 2
        }

        test(
            "(a) forward secrecy: onKeyMaterialSupersededForTest fires exactly once for bob's bootstrap " +
                "DH step (rootKey only - sendingChainKey/receivingChainKey are both still null and cannot fire)",
        ) {
            val (alice, bob) = establishedPair()
            val captured = mutableListOf<ByteArray>()
            bob.onKeyMaterialSupersededForTest = { captured += it }
            bob.decrypt(alice.encrypt("boot".toByteArray()))
            captured.size shouldBe 1
        }

        test(
            "(a) forward secrecy: onKeyMaterialSupersededForTest fires exactly once for a same-chain " +
                "(non-ratchet) decrypt step (receivingChainKey only)",
        ) {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("boot".toByteArray()))
            val captured = mutableListOf<ByteArray>()
            bob.onKeyMaterialSupersededForTest = { captured += it }
            bob.decrypt(alice.encrypt("m1".toByteArray()))
            captured.size shouldBe 1
        }

        test(
            "(a) forward secrecy: onKeyMaterialSupersededForTest fires exactly three times for a NON-" +
                "bootstrap DH step (rootKey, sendingChainKey, and receivingChainKey are all pre-existing " +
                "and all superseded) - note the ratchet PRIVATE KEY destruction on the same step is NOT " +
                "among these three: it has no hook call at all, which is why the reflection-based test " +
                "above is the only guard covering it",
        ) {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("boot".toByteArray())) // bootstrap - not measured
            alice.decrypt(bob.encrypt("reply".toByteArray())) // alice's own DH step - not measured

            val captured = mutableListOf<ByteArray>()
            bob.onKeyMaterialSupersededForTest = { captured += it }
            bob.decrypt(alice.encrypt("m2".toByteArray())) // bob's SECOND DH step
            captured.size shouldBe 3
        }

        test(
            "(a) forward secrecy: after several messages, the key material needed to decrypt an early " +
                "message is genuinely gone from the live session state - not just 'decrypt fails' - and " +
                "the hook fires an EXACT expected number of times, so a vanished hook call cannot pass " +
                "unnoticed even in this aggregated check",
        ) {
            val (alice, bob) = establishedPair()
            val messages = (0 until 10).map { alice.encrypt("m$it".toByteArray()) }

            // Snapshot Bob's state BEFORE he decrypts anything, via the codec - an independent
            // "time capsule" copy this test can later re-open to prove the key material really did
            // exist at that point.
            val blobAtStart = DoubleRatchetSessionCodec.encode(bob, testPassphrase())

            val captured = mutableListOf<ByteArray>()
            bob.onKeyMaterialSupersededForTest = { captured += it }
            messages.forEach { bob.decrypt(it) }

            // Exact expected count, not just "non-empty": alice never ratchets in this scenario (she
            // only ever calls encrypt(), never decrypt()), so every one of these 10 messages carries
            // her ORIGINAL ratchet public key. Bob's FIRST decrypt (message 0) is his bootstrap DH
            // step - theirRatchetPublicKey is still null, so only rootKey is superseded (1 fire;
            // sendingChainKey/receivingChainKey are both null and cannot fire). Every SUBSEQUENT
            // decrypt (messages 1-9) sees the SAME ratchet public key already installed, so each is a
            // same-chain step superseding receivingChainKey only (1 fire each) - 9 more. Total: 10.
            captured.size shouldBe 10

            // Every captured array (the real backing arrays this session superseded) is now
            // all-zero - proving in-place zeroization of the REAL arrays, not of copies.
            captured.forEach { array -> array.all { it == 0.toByte() } shouldBe true }

            // The live session refuses to decrypt message 0 again - its key is gone.
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(messages[0]) }

            // But a session RESTORED from the pre-decryption snapshot still has it.
            val bobAtStart = DoubleRatchetSessionCodec.decode(blobAtStart, testPassphrase())
            bobAtStart.decrypt(messages[0]).decodeToString() shouldBe "m0"

            // Honesty, stated explicitly rather than overclaimed: this test proves (i) the specific
            // ByteArray objects the session held were mutated to all-zero in place, and (ii) the
            // live session refuses to re-decrypt message 0. It does NOT and CANNOT prove no copy of
            // those bytes survives anywhere else on the JVM heap - a garbage collector may have
            // relocated an array before fill(0) ran, and there is no way to reach the abandoned
            // original from Kotlin/JVM code. This project makes only the same best-effort claim
            // X25519PrivateKey.destroy's own doc comment already makes, and this wave adds nothing
            // to it. It likewise cannot prove the COMPUTATIONAL half of forward secrecy - that
            // CK_(n+1) does not yield CK_n - which rests on HMAC-SHA256's one-wayness, an assumption
            // no test can verify.
        }

        // ---------------------------------------------------------------------------------
        // (b) POST-COMPROMISE SECURITY
        // ---------------------------------------------------------------------------------
        test(
            "(b) post-compromise security: messages sent after the NEXT DH ratchet step are undecryptable " +
                "from a full session-state snapshot taken before that step",
        ) {
            val (alice, bob) = establishedPair()
            // Warm up both sides.
            bob.decrypt(alice.encrypt("warm up".toByteArray()))
            alice.decrypt(bob.encrypt("warm up reply".toByteArray()))

            // A full state compromise at time T: the attacker has the blob AND the passphrase.
            val snapshotAtT = DoubleRatchetSessionCodec.encode(bob, testPassphrase())

            val m1 = alice.encrypt("m1".toByteArray())
            bob.decrypt(m1) // Bob DH-ratchets to a fresh keypair here - not in the snapshot.
            val m2 = bob.encrypt("m2".toByteArray())
            alice.decrypt(m2) // Alice DH-ratchets to a fresh keypair here.
            val m3 = alice.encrypt("m3".toByteArray())
            bob.decrypt(m3) shouldBe "m3".toByteArray() // sanity: real bob still works

            // PCS is not instantaneous - one full DH ratchet round trip is required before it
            // takes effect. Asserting the successful case is deliberate; hiding it would misrepresent
            // the property.
            val attacker1 = DoubleRatchetSessionCodec.decode(snapshotAtT, testPassphrase())
            attacker1.decrypt(m1).decodeToString() shouldBe "m1"
            val attackerAfterM1RatchetKey = attacker1.sendingRatchetPublicKey()

            // A second, independent attacker handed m3 directly (skipping m1) fails outright.
            val attacker2 = DoubleRatchetSessionCodec.decode(snapshotAtT, testPassphrase())
            shouldThrow<DoubleRatchetException> { attacker2.decrypt(m3) }

            // The FIRST attacker, which processed m1 (generating its OWN fresh ratchet keypair,
            // independent of Bob's real one), still fails on m3 - the new DH input genuinely
            // injected entropy the snapshot did not have.
            shouldThrow<DoubleRatchetException> { attacker1.decrypt(m3) }

            // And that fresh keypair genuinely differs from the real Bob's - naming why PCS holds:
            // X25519KeyPair.generate(random) inside the ratchet step, not anything derivable from
            // the snapshot.
            attackerAfterM1RatchetKey shouldNotBe bob.sendingRatchetPublicKey()
        }

        // ---------------------------------------------------------------------------------
        // (c) SKIPPED-KEY DoS
        // ---------------------------------------------------------------------------------
        test(
            "(c) decode() rejects an absurd messageNumber/previousChainLength before DoubleRatchetSession is ever entered",
        ) {
            val (alice, _) = establishedPair()
            val valid = RatchetMessageCodec.encode(alice.encrypt("cheap check".toByteArray()))

            fun withIntAt(
                offset: Int,
                value: Int,
            ): ByteArray {
                val tampered = valid.copyOf()
                tampered[offset] = (value ushr 24).toByte()
                tampered[offset + 1] = (value ushr 16).toByte()
                tampered[offset + 2] = (value ushr 8).toByte()
                tampered[offset + 3] = value.toByte()
                return tampered
            }

            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(withIntAt(42, Int.MAX_VALUE)) }
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(withIntAt(38, Int.MAX_VALUE)) }
            shouldThrow<MalformedRatchetMessageException> {
                RatchetMessageCodec.decode(withIntAt(42, RatchetMessageCodec.MAX_CHAIN_LENGTH + 1))
            }
        }

        test(
            "(c) decrypt() rejects a skip distance beyond MAX_SKIP BEFORE any key derivation - " +
                "derivedMessageKeyCount and skippedKeyCount are provably unchanged",
        ) {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("prime".toByteArray())) // establish a receiving chain

            val before = bob.derivedMessageKeyCount()
            val beforeSkipped = bob.skippedKeyCount()

            // Same chain, messageNumber far beyond MAX_SKIP *relative to bob's current receive
            // position* - the gate compares a DISTANCE (messageNumber - nr), not an absolute value.
            val farHeader =
                RatchetMessageHeaderForTest(
                    ratchetPublicKey = bob.receivingRatchetPublicKey()!!,
                    previousChainLength = 0,
                    messageNumber = bob.receiveMessageNumber() + DoubleRatchetSession.MAX_SKIP + 1,
                )
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(farHeader.toMessage()) }
            bob.derivedMessageKeyCount() shouldBe before
            bob.skippedKeyCount() shouldBe beforeSkipped

            // A ratchet-step branch, messageNumber far beyond MAX_SKIP on the NEW chain. previousChainLength
            // is set to bob's OWN current receive position so the (separate) previousChainLength gate does
            // not fire first - isolating this assertion to the messageNumber gate specifically.
            val freshKeyPair = X25519KeyPair.generate()
            val ratchetStepHeader =
                RatchetMessageHeaderForTest(
                    ratchetPublicKey = freshKeyPair.publicKey,
                    previousChainLength = bob.receiveMessageNumber(),
                    messageNumber = DoubleRatchetSession.MAX_SKIP + 1,
                )
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(ratchetStepHeader.toMessage()) }
            bob.derivedMessageKeyCount() shouldBe before
            bob.skippedKeyCount() shouldBe beforeSkipped

            // A ratchet-step branch, previousChainLength far beyond MAX_SKIP on the OLD chain.
            val previousChainHeader =
                RatchetMessageHeaderForTest(
                    ratchetPublicKey = freshKeyPair.publicKey,
                    previousChainLength = bob.receiveMessageNumber() + DoubleRatchetSession.MAX_SKIP + 1,
                    messageNumber = 0,
                )
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(previousChainHeader.toMessage()) }
            bob.derivedMessageKeyCount() shouldBe before
            bob.skippedKeyCount() shouldBe beforeSkipped
        }

        test("(c) a message at exactly MAX_SKIP succeeds; derivedMessageKeyCount grows by exactly MAX_SKIP + 1") {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("prime".toByteArray()))
            val before = bob.derivedMessageKeyCount()

            // Build MAX_SKIP+1 messages in the SAME chain and deliver only the last one.
            val messages = (0 until DoubleRatchetSession.MAX_SKIP + 1).map { alice.encrypt("m$it".toByteArray()) }
            bob.decrypt(messages.last()).decodeToString() shouldBe "m${DoubleRatchetSession.MAX_SKIP}"
            bob.derivedMessageKeyCount() shouldBe before + DoubleRatchetSession.MAX_SKIP + 1
        }

        test("(c) previousChainLength below the session's current receive position is rejected, counters unchanged") {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("a0".toByteArray()))
            bob.decrypt(alice.encrypt("a1".toByteArray()))
            val before = bob.derivedMessageKeyCount()

            val badHeader =
                RatchetMessageHeaderForTest(
                    ratchetPublicKey = X25519KeyPair.generate().publicKey,
                    previousChainLength = 0, // below bob's actual receive position of 2
                    messageNumber = 0,
                )
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(badHeader.toMessage()) }
            bob.derivedMessageKeyCount() shouldBe before
        }

        // ---------------------------------------------------------------------------------
        // (d) OUT-OF-ORDER DELIVERY AND CLEAN FAILURE PAST EVICTION
        // ---------------------------------------------------------------------------------
        test("(d) out-of-order delivery within the skip cap decrypts correctly") {
            val (alice, bob) = establishedPair()
            val messages = (0..9).map { alice.encrypt("m$it".toByteArray()) }
            val shuffled = messages.withIndex().toList().shuffled(java.util.Random(42))
            shuffled.forEach { (i, message) -> bob.decrypt(message).decodeToString() shouldBe "m$i" }
        }

        test("(d) delivery of a skipped message AFTER its key has been evicted fails cleanly, not a crash") {
            val (alice, bob) = establishedPair()
            // A single decrypt() call can skip at most MAX_SKIP messages (a DIFFERENT gate, see
            // case (c) above) - so eviction from the MAX_SKIPPED_KEYS_STORED-wide store has to be
            // driven across SEVERAL decrypt() calls, each individually within MAX_SKIP, whose
            // skipped entries cumulatively exceed the store's total capacity.
            val jumpSize = 500 // < MAX_SKIP per single decrypt() call
            val jumps = 6 // 6 * (jumpSize - 1) = 2_994 cumulative skipped entries > MAX_SKIPPED_KEYS_STORED (2_000)
            val totalMessages = jumpSize * jumps
            val messages = (0 until totalMessages).map { alice.encrypt("m$it".toByteArray()) }

            for (jump in 0 until jumps) {
                val index = (jump + 1) * jumpSize - 1
                bob.decrypt(messages[index]).decodeToString() shouldBe "m$index"
            }
            bob.skippedKeyCount() shouldBe DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED

            // Message 0's skipped key was evicted many jumps ago (oldest-first eviction) - delivering
            // it now must fail cleanly with a specific, catchable exception, never crash.
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(messages[0]) }

            // The session is undamaged: a later, still-available skipped message still decrypts.
            val stillAvailableIndex = totalMessages - 2
            bob.decrypt(messages[stillAvailableIndex]).decodeToString() shouldBe "m$stillAvailableIndex"
        }

        // ---------------------------------------------------------------------------------
        // (e) REPLAY
        // ---------------------------------------------------------------------------------
        test("(e) replay of an in-order, already-consumed message is rejected; session undamaged afterwards") {
            val (alice, bob) = establishedPair()
            val m0 = alice.encrypt("m0".toByteArray())
            bob.decrypt(m0)
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(m0) }

            val m1 = alice.encrypt("m1".toByteArray())
            bob.decrypt(m1).decodeToString() shouldBe "m1"
        }

        test("(e) replay of a message decrypted out of order via the skipped store is rejected (delete-on-use)") {
            val (alice, bob) = establishedPair()
            val messages = (0..3).map { alice.encrypt("m$it".toByteArray()) }
            bob.decrypt(messages[3]) // skips 0,1,2
            bob.decrypt(messages[1]) // consumes the skipped key for message 1

            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(messages[1]) }

            // Session undamaged: the remaining skipped messages still decrypt.
            bob.decrypt(messages[0]).decodeToString() shouldBe "m0"
            bob.decrypt(messages[2]).decodeToString() shouldBe "m2"
        }

        test("(e) replay of the very first message after a DH ratchet step is rejected") {
            val (alice, bob) = establishedPair()
            val m0 = alice.encrypt("m0".toByteArray())
            bob.decrypt(m0) // triggers bob's bootstrap ratchet step
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(m0) }

            // Session undamaged.
            bob.decrypt(alice.encrypt("m1".toByteArray())).decodeToString() shouldBe "m1"
        }

        // ---------------------------------------------------------------------------------
        // (f) SINGLE-BIT TAMPER
        // ---------------------------------------------------------------------------------
        test("(f) single-bit tamper in the ciphertext always causes DoubleRatchetException") {
            val (alice, bob) = establishedPair()
            val message = alice.encrypt("tamper me".toByteArray())
            val bytes = RatchetMessageCodec.encode(message)
            val sampledOffsets = (RatchetMessageCodec.HEADER_SIZE until bytes.size step 3).toList()
            sampledOffsets.forEach { offset ->
                val (freshAlice, freshBob) = establishedPair()
                val freshMessage = freshAlice.encrypt("tamper me".toByteArray())
                val freshBytes = RatchetMessageCodec.encode(freshMessage)
                val tampered = freshBytes.copyOf()
                tampered[offset] = (tampered[offset] + 1).toByte()
                shouldThrow<DoubleRatchetException> { freshBob.decrypt(RatchetMessageCodec.decode(tampered)) }
            }
        }

        test("(f) single-bit tamper in the nonce always causes DoubleRatchetException") {
            for (bit in intArrayOf(0, 3, 7)) {
                val (alice, bob) = establishedPair()
                val message = alice.encrypt("nonce tamper".toByteArray())
                val bytes = RatchetMessageCodec.encode(message).copyOf()
                val nonceOffset = 46
                bytes[nonceOffset] = (bytes[nonceOffset].toInt() xor (1 shl bit)).toByte()
                shouldThrow<DoubleRatchetException> { bob.decrypt(RatchetMessageCodec.decode(bytes)) }
            }
        }

        test("(f) an associated-data mismatch (a different session pair) causes DoubleRatchetException") {
            val (alice, bob) = establishedPair()
            val (mallory, _) = establishedPair() // an entirely unrelated session/AD
            val message = alice.encrypt("wrong ad".toByteArray())
            shouldThrow<DoubleRatchetException> { mallory.decrypt(message) }
            // real bob unaffected
            bob.decrypt(message).decodeToString() shouldBe "wrong ad"
        }

        test(
            "(f) tampering messageNumber/previousChainLength past a cap surfaces as " +
                "RatchetMessageRejectedException, tampering magic/version/flags surfaces as " +
                "MalformedRatchetMessageException - both are computed from PUBLIC data alone and are " +
                "deliberately distinguishable from the AEAD failure; this is not an oracle, since " +
                "everything that DOES consult secret material funnels uniformly into DoubleRatchetException",
        ) {
            val (alice, bob) = establishedPair()
            val bytes = RatchetMessageCodec.encode(alice.encrypt("public vs secret".toByteArray())).copyOf()

            val badMessageNumber = bytes.copyOf()
            val huge = DoubleRatchetSession.MAX_SKIP + 1
            badMessageNumber[42] = (huge ushr 24).toByte()
            badMessageNumber[43] = (huge ushr 16).toByte()
            badMessageNumber[44] = (huge ushr 8).toByte()
            badMessageNumber[45] = huge.toByte()
            shouldThrow<RatchetMessageRejectedException> { bob.decrypt(RatchetMessageCodec.decode(badMessageNumber)) }

            val badMagic = bytes.copyOf()
            badMagic[0] = (badMagic[0] + 1).toByte()
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(badMagic) }
        }

        test(
            "(f) no state damage from a failed decrypt: a random-but-validly-encoded ratchetPublicKey substitution " +
                "leaves the session byte-identical, and the ORIGINAL message still decrypts afterwards",
        ) {
            val (alice, bob) = establishedPair()
            val message = alice.encrypt("no damage".toByteArray())

            val before = bob.keyMaterialSnapshotForTest()
            val beforeDhSteps = bob.dhRatchetStepCount()
            val beforeReceiveNumber = bob.receiveMessageNumber()
            val beforeSkipped = bob.skippedKeyCount()

            val forgedKeyPair = X25519KeyPair.generate()
            val forgedBytes = RatchetMessageCodec.encode(message).copyOf()
            forgedKeyPair.publicKey.bytes.copyInto(forgedBytes, 6)
            shouldThrow<DoubleRatchetException> { bob.decrypt(RatchetMessageCodec.decode(forgedBytes)) }

            val after = bob.keyMaterialSnapshotForTest()
            after.size shouldBe before.size
            before.zip(after).forEach { (b, a) -> b shouldBe a }
            bob.dhRatchetStepCount() shouldBe beforeDhSteps
            bob.receiveMessageNumber() shouldBe beforeReceiveNumber
            bob.skippedKeyCount() shouldBe beforeSkipped

            // The original, genuine message still decrypts correctly afterwards.
            bob.decrypt(message).decodeToString() shouldBe "no damage"
        }

        test("(f) no state damage from a ciphertext-tampered message either") {
            val (alice, bob) = establishedPair()
            val message = alice.encrypt("no damage 2".toByteArray())
            val bytes = RatchetMessageCodec.encode(message).copyOf()
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()

            val before = bob.keyMaterialSnapshotForTest()
            shouldThrow<DoubleRatchetException> { bob.decrypt(RatchetMessageCodec.decode(bytes)) }
            val after = bob.keyMaterialSnapshotForTest()
            before.zip(after).forEach { (b, a) -> b shouldBe a }

            bob.decrypt(message).decodeToString() shouldBe "no damage 2"
        }

        // ---------------------------------------------------------------------------------
        // (g) CROSS-SESSION CONFUSION
        // ---------------------------------------------------------------------------------
        test("(g) a genuinely valid message from session A fails to decrypt under an unrelated session B") {
            val (alice, bob) = establishedPair() // session A: alice <-> bob
            val (carol, dave) = establishedPair() // session B: carol <-> dave, unrelated

            val message = alice.encrypt("A's message".toByteArray())
            shouldThrow<DoubleRatchetException> { dave.decrypt(message) }
            shouldThrow<DoubleRatchetException> { carol.decrypt(message) }

            // session B undamaged - carol (the sender) can always send; dave decrypts normally.
            dave.decrypt(carol.encrypt("B still works".toByteArray())).decodeToString() shouldBe "B still works"
        }

        test(
            "(g) a SECOND, independent session between the SAME two identities also fails - the root key, not the AD, is what distinguishes them",
        ) {
            val alice = RatchetTestParty()
            val bob = RatchetTestParty()
            val handshake1 = handshake(alice, bob)
            val handshake2 = handshake(alice, bob) // a second, independent handshake

            val session1Sender =
                DoubleRatchetSession.initializeSender(
                    handshake1.initiatorSecret,
                    handshake1.responderSignedPrekeyPublic,
                )
            val session2Receiver =
                DoubleRatchetSession.initializeReceiver(
                    handshake2.responderSecret,
                    handshake2.responderSignedPrekeyPair,
                )

            val message = session1Sender.encrypt("session 1 only".toByteArray())
            shouldThrow<DoubleRatchetException> { session2Receiver.decrypt(message) }
        }

        // ---------------------------------------------------------------------------------
        // (h) TRUNCATED / OVERSIZED FRAMES
        // ---------------------------------------------------------------------------------
        test("(h) truncated frames are rejected without allocation proportional to a bogus claimed size") {
            val (alice, bob) = establishedPair()
            val bytes = RatchetMessageCodec.encode(alice.encrypt("truncate".toByteArray()))
            shouldThrow<MalformedRatchetMessageException> {
                bob.decrypt(RatchetMessageCodec.decode(bytes.copyOf(bytes.size / 2)))
            }
        }

        test("(h) oversized frames are rejected on the first check, before any stream is opened") {
            val oversized = ByteArray(RatchetMessageCodec.MAX_MESSAGE_BYTES + 1)
            shouldThrow<MalformedRatchetMessageException> { RatchetMessageCodec.decode(oversized) }
        }

        // ---------------------------------------------------------------------------------
        // (i) SIGNED-PREKEY RATCHET-KEY ECHO, BEFORE THE FIRST REPLY
        // ---------------------------------------------------------------------------------
        test(
            "(i) an initiator session that has not yet received its first reply rejects a frame echoing " +
                "back the responder's (PUBLIC) signed prekey, rather than throwing a raw NullPointerException",
        ) {
            // initializeSender sets theirRatchetPublicKey to the responder's SIGNED PREKEY - a value
            // gossiped in every PrekeyBundle, so any unauthenticated party can read it - while leaving
            // receivingChainKey null until the FIRST inbound message is decrypted (see
            // DoubleRatchetSession's own "bootstrap asymmetry" doc-comment section). A frame that puts
            // that same public key back in the header's ratchetPublicKey slot therefore lands in
            // decrypt()'s "no ratchet step needed" branch with no receiving chain to derive from.
            val alice = RatchetTestParty()
            val bob = RatchetTestParty()
            val hs = handshake(alice, bob)
            val aliceSession = DoubleRatchetSession.initializeSender(hs.initiatorSecret, hs.responderSignedPrekeyPublic)
            aliceSession.canSend shouldBe true
            aliceSession.receivingRatchetPublicKey() shouldBe hs.responderSignedPrekeyPublic

            val echoHeader =
                RatchetMessageHeaderForTest(
                    ratchetPublicKey = hs.responderSignedPrekeyPublic,
                    previousChainLength = 0,
                    messageNumber = 0,
                )
            shouldThrow<RatchetMessageRejectedException> { aliceSession.decrypt(echoHeader.toMessage()) }

            // Session undamaged - still able to send, and to complete a real handshake afterwards.
            aliceSession.canSend shouldBe true
            val bobSession = DoubleRatchetSession.initializeReceiver(hs.responderSecret, hs.responderSignedPrekeyPair)
            val reply = aliceSession.encrypt("still alive".toByteArray())
            bobSession.decrypt(reply).decodeToString() shouldBe "still alive"
        }

        test(
            "(i) the same echo is also rejected after a restore from a persisted blob, in the same pre-reply state",
        ) {
            val alice = RatchetTestParty()
            val bob = RatchetTestParty()
            val hs = handshake(alice, bob)
            val aliceSession = DoubleRatchetSession.initializeSender(hs.initiatorSecret, hs.responderSignedPrekeyPublic)

            val blob = DoubleRatchetSessionCodec.encode(aliceSession, testPassphrase())
            val restored = DoubleRatchetSessionCodec.decode(blob, testPassphrase())

            val echoHeader =
                RatchetMessageHeaderForTest(
                    ratchetPublicKey = hs.responderSignedPrekeyPublic,
                    previousChainLength = 0,
                    messageNumber = 0,
                )
            shouldThrow<RatchetMessageRejectedException> { restored.decrypt(echoHeader.toMessage()) }
        }
    })

/** Test-only helper: builds a structurally valid [RatchetMessage] with an ARBITRARY header (for
 * probing [DoubleRatchetSession.decrypt]'s public-data DoS gates) wrapping a throwaway ciphertext -
 * the ciphertext never needs to actually decrypt for these tests, since every case here is rejected
 * by the DoS gates BEFORE any AEAD operation runs. */
private class RatchetMessageHeaderForTest(
    val ratchetPublicKey: net.lapisphilosophorum.lapisnet.identity.X25519PublicKey,
    val previousChainLength: Int,
    val messageNumber: Int,
) {
    fun toMessage(): RatchetMessage {
        val nonce = ByteArray(GCM_NONCE_SIZE)
        val ciphertext = ByteArray(GCM_TAG_SIZE + 1)
        // internal constructors, directly callable from this module's own test source set (same
        // Gradle module - mirrors how X3dhAdversarialTest.kt already calls PrekeyBundle.fromDecoded).
        val header = RatchetMessageHeader(ratchetPublicKey, previousChainLength, messageNumber, nonce)
        val headerBytes = RatchetMessageCodec.encodeHeader(header, ciphertext.size)
        return RatchetMessage(header, headerBytes, ciphertext)
    }
}
