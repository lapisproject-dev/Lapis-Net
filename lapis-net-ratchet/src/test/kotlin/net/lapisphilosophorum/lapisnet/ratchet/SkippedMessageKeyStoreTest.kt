package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private fun keyId(
    ratchetKeyTag: Byte,
    messageNumber: Int,
): SkippedMessageKeyId = SkippedMessageKeyId(ByteArray(32) { ratchetKeyTag }, messageNumber)

private fun material(tag: Byte): ByteArray = ByteArray(32) { tag }

class SkippedMessageKeyStoreTest :
    FunSpec({
        test("put/peek round trip; peek returns a copy and does not remove") {
            val store = SkippedMessageKeyStore(maxStored = 10)
            val id = keyId(1, 0)
            store.put(id, material(0xAA.toByte()))

            val first = store.peek(id)
            first.shouldNotBeNull()
            first shouldBe material(0xAA.toByte())
            first.fill(0) // mutating the returned copy must not affect the store

            store.peek(id) shouldBe material(0xAA.toByte())
            store.size() shouldBe 1
        }

        test("remove removes and returns true; a second remove returns false; peek is null afterwards") {
            val store = SkippedMessageKeyStore(maxStored = 10)
            val id = keyId(2, 0)
            store.put(id, material(0xBB.toByte()))

            store.remove(id) shouldBe true
            store.remove(id) shouldBe false
            store.peek(id).shouldBeNull()
        }

        test("distinct (ratchetPublicKey, N) pairs never collide") {
            val store = SkippedMessageKeyStore(maxStored = 10)
            val a = keyId(1, 5)
            val b = keyId(2, 5) // same N, different key
            val c = keyId(1, 6) // same key, different N
            store.put(a, material(1))
            store.put(b, material(2))
            store.put(c, material(3))

            store.peek(a) shouldBe material(1)
            store.peek(b) shouldBe material(2)
            store.peek(c) shouldBe material(3)
            store.size() shouldBe 3
        }

        test("eviction at the cap: insertion order, not access order") {
            val store = SkippedMessageKeyStore(maxStored = 4)
            val ids = (0 until 5).map { keyId(it.toByte(), it) }
            ids.forEach { store.put(it, material(it.hashCode().toByte())) }

            store.size() shouldBe 4
            store.peek(ids[0]).shouldBeNull() // first inserted is gone

            // Peeking the oldest SURVIVING entry must NOT refresh it - inserting one more evicts
            // that same entry next, proving eviction order is insertion order, not access order.
            store.peek(ids[1]).shouldNotBeNull()
            store.put(keyId(9, 9), material(9))
            store.peek(ids[1]).shouldBeNull()
        }

        test("evicted key material is zeroed in the backing array") {
            val store = SkippedMessageKeyStore(maxStored = 1)
            val first = keyId(1, 0)
            val second = keyId(2, 0)
            store.put(first, material(0xCC.toByte()))
            val backing = store.peekBackingArrayForTest(first)
            backing.shouldNotBeNull()

            store.put(second, material(0xDD.toByte()))
            backing.all { it == 0.toByte() } shouldBe true
        }

        test("replacing an existing id zeroes the previously-stored array") {
            val store = SkippedMessageKeyStore(maxStored = 10)
            val id = keyId(1, 0)
            store.put(id, material(0xEE.toByte()))
            val backing = store.peekBackingArrayForTest(id)
            backing.shouldNotBeNull()

            store.put(id, material(0xFF.toByte()))
            backing.all { it == 0.toByte() } shouldBe true
            store.peek(id) shouldBe material(0xFF.toByte())
        }

        test("destroyAll zeroes every backing array and empties the store") {
            val store = SkippedMessageKeyStore(maxStored = 10)
            val id1 = keyId(1, 0)
            val id2 = keyId(2, 0)
            store.put(id1, material(1))
            store.put(id2, material(2))
            val backing1 = store.peekBackingArrayForTest(id1)!!
            val backing2 = store.peekBackingArrayForTest(id2)!!

            store.destroyAll()

            store.size() shouldBe 0
            backing1.all { it == 0.toByte() } shouldBe true
            backing2.all { it == 0.toByte() } shouldBe true
        }

        test("entriesOldestFirst returns fresh copies matching what was stored") {
            val store = SkippedMessageKeyStore(maxStored = 10)
            val id = keyId(7, 3)
            store.put(id, material(0x11))
            val entries = store.entriesOldestFirst()
            entries.size shouldBe 1
            entries[0].second shouldBe 3
            entries[0].third shouldBe material(0x11)
        }
    })
