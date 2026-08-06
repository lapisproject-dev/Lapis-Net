package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class DoubleRatchetSessionTest :
    FunSpec({
        test("basic round trip: sender encrypts, receiver decrypts") {
            val (alice, bob) = establishedPair()
            val message = alice.encrypt("hello".toByteArray())
            val wire = RatchetMessageCodec.decode(RatchetMessageCodec.encode(message))
            bob.decrypt(wire).decodeToString() shouldBe "hello"
        }

        test("a receiver-initialised session cannot send until it has decrypted its first inbound message") {
            val (alice, bob) = establishedPair()
            bob.canSend shouldBe false
            shouldThrow<DoubleRatchetException> { bob.encrypt("too early".toByteArray()) }

            val message = alice.encrypt("hello".toByteArray())
            bob.decrypt(message)
            bob.canSend shouldBe true
            bob.encrypt("now I can reply".toByteArray()) // does not throw
        }

        test("many messages in one direction: all decrypt in order, no skipping") {
            val (alice, bob) = establishedPair()
            repeat(50) { i ->
                val message = alice.encrypt("message $i".toByteArray())
                bob.decrypt(message).decodeToString() shouldBe "message $i"
            }
            bob.receiveMessageNumber() shouldBe 50
            bob.skippedKeyCount() shouldBe 0
            bob.dhRatchetStepCount() shouldBe 1 // the single bootstrap step on Bob's first inbound message
        }

        test("alternating conversation: each reply triggers an explicit DH ratchet step") {
            val (alice, bob) = establishedPair()

            val bobInitialSendingKey = bob.sendingRatchetPublicKey()
            val m1 = alice.encrypt("A -> B, round 1".toByteArray())
            bob.decrypt(m1).decodeToString() shouldBe "A -> B, round 1"
            bob.dhRatchetStepCount() shouldBe 1
            bob.sendingRatchetPublicKey() shouldNotBe bobInitialSendingKey

            val aliceInitialSendingKey = alice.sendingRatchetPublicKey()
            val m2 = bob.encrypt("B -> A, round 1".toByteArray())
            alice.decrypt(m2).decodeToString() shouldBe "B -> A, round 1"
            alice.dhRatchetStepCount() shouldBe 1
            alice.sendingRatchetPublicKey() shouldNotBe aliceInitialSendingKey

            val aliceSecondSendingKey = alice.sendingRatchetPublicKey()
            val m3 = bob.encrypt("B -> A, round 2".toByteArray()) // same direction again, no ratchet step
            alice.decrypt(m3).decodeToString() shouldBe "B -> A, round 2"
            alice.dhRatchetStepCount() shouldBe 1
            alice.sendingRatchetPublicKey() shouldBe aliceSecondSendingKey

            val m4 = alice.encrypt("A -> B, round 2".toByteArray())
            bob.decrypt(m4).decodeToString() shouldBe "A -> B, round 2"
            bob.dhRatchetStepCount() shouldBe 2
        }

        test("out-of-order delivery within the skip cap: last message first, then the rest in reverse") {
            val (alice, bob) = establishedPair()
            val messages = (0..4).map { alice.encrypt("m$it".toByteArray()) }

            bob.decrypt(messages[4]).decodeToString() shouldBe "m4"
            bob.skippedKeyCount() shouldBe 4

            for (i in 3 downTo 0) {
                bob.decrypt(messages[i]).decodeToString() shouldBe "m$i"
            }
            bob.skippedKeyCount() shouldBe 0
        }

        test("bidirectional interleave: cross-chain skipped keys keyed by (ratchetPublicKey, N)") {
            val (alice, bob) = establishedPair()
            val aliceMessages = (0..2).map { alice.encrypt("alice $it".toByteArray()) }
            // Bob decrypts only alice's FIRST message before replying three times himself.
            bob.decrypt(aliceMessages[0]).decodeToString() shouldBe "alice 0"
            val bobMessages = (0..2).map { bob.encrypt("bob $it".toByteArray()) }

            // Alice decrypts Bob's replies out of order.
            alice.decrypt(bobMessages[2]).decodeToString() shouldBe "bob 2"
            alice.decrypt(bobMessages[0]).decodeToString() shouldBe "bob 0"
            alice.decrypt(bobMessages[1]).decodeToString() shouldBe "bob 1"

            // Bob still has alice's messages 1 and 2 to decrypt, from the OLD chain (pre-ratchet).
            bob.decrypt(aliceMessages[1]).decodeToString() shouldBe "alice 1"
            bob.decrypt(aliceMessages[2]).decodeToString() shouldBe "alice 2"
        }

        test("destroy is idempotent and every other method throws afterwards") {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("prime bob's sending chain".toByteArray()))

            alice.destroy()
            alice.destroy() // idempotent, does not throw

            shouldThrow<IllegalStateException> { alice.encrypt("x".toByteArray()) }
            val message = bob.encrypt("hello".toByteArray()) // bob still usable independently
            shouldThrow<IllegalStateException> { alice.decrypt(message) }
        }

        test("encrypt rejects an empty plaintext") {
            val (alice, _) = establishedPair()
            shouldThrow<IllegalArgumentException> { alice.encrypt(ByteArray(0)) }
        }

        test("encrypt rejects a plaintext exceeding MAX_PLAINTEXT_BYTES") {
            val (alice, _) = establishedPair()
            shouldThrow<IllegalArgumentException> {
                alice.encrypt(ByteArray(RatchetMessageCodec.MAX_PLAINTEXT_BYTES + 1))
            }
        }

        // Round 2 minor fix: an exhausted sending chain (ns > MAX_CHAIN_LENGTH) used to escape
        // encrypt() as a raw IllegalArgumentException thrown out of RatchetMessageHeader's own init
        // block - undocumented, and typed inconsistently with encrypt()'s declared
        // DoubleRatchetException-only contract. `ns` is forced via reflection rather than driving a
        // million real encrypt() calls (RatchetTestFixtures.setPrivateField mirrors privateField's
        // existing read-side reflection seam).
        test(
            "encrypt throws DoubleRatchetException - not a raw IllegalArgumentException - once ns " +
                "exceeds MAX_CHAIN_LENGTH, and leaves the session otherwise undamaged",
        ) {
            val (alice, _) = establishedPair()
            setPrivateField(alice, "ns", RatchetMessageCodec.MAX_CHAIN_LENGTH + 1)

            shouldThrow<DoubleRatchetException> { alice.encrypt("one message too many".toByteArray()) }

            // No partial state change: ns untouched, session still reports the same (unusable) count,
            // and a DIFFERENT, healthy session is completely unaffected.
            alice.sendMessageNumber() shouldBe RatchetMessageCodec.MAX_CHAIN_LENGTH + 1
            val (bob, _) = establishedPair()
            bob.sendMessageNumber() shouldBe 0
            bob.encrypt("still fine".toByteArray()) // does not throw
        }

        // Concurrency regression for the round-1 review MAJOR finding: stateForCodec() was missing
        // @Synchronized while every mutator (encrypt/decrypt/destroy) carries it, so a concurrent
        // reader could observe rootKey mid-commit - decrypt()'s commit zeroes the live rootKey array
        // in place and only rebinds it a few lines later. Reproduced here with a real background
        // thread reading stateForCodec() while the foreground thread drives an alternating
        // conversation that forces a DH ratchet step (and therefore a rootKey commit) on almost
        // every decrypt() call - the same shape as the review's own probe (2,186 all-zero observations
        // out of 4,000 rounds against the unsynchronized method).
        test(
            "stateForCodec() is safe to call concurrently with decrypt() - never observes a torn or " +
                "all-zero rootKey, and skippedKeys.entriesOldestFirst() never throws ConcurrentModificationException",
        ) {
            val (alice, bob) = establishedPair()
            bob.decrypt(alice.encrypt("prime".toByteArray())) // give bob a sending chain too

            val rounds = 2_000
            val stop = AtomicBoolean(false)
            val readerObservedZeroRootKey = AtomicBoolean(false)
            val readerFailure = AtomicReference<Throwable?>(null)
            var readerIterations = 0L

            val reader =
                Thread {
                    try {
                        while (!stop.get()) {
                            val state = bob.stateForCodec()
                            if (state.rootKey.all { it == 0.toByte() }) {
                                readerObservedZeroRootKey.set(true)
                            }
                            state.zeroAll()
                            readerIterations++
                        }
                    } catch (e: Throwable) {
                        readerFailure.set(e)
                    }
                }
            reader.isDaemon = true
            reader.start()

            try {
                repeat(rounds) { i ->
                    bob.decrypt(alice.encrypt("a$i".toByteArray()))
                    alice.decrypt(bob.encrypt("b$i".toByteArray()))
                }
            } finally {
                stop.set(true)
                reader.join(30_000)
            }

            readerIterations shouldNotBe 0L // the reader thread genuinely raced the writer, not a no-op
            readerFailure.get() shouldBe null
            readerObservedZeroRootKey.get() shouldBe false
        }
    })
