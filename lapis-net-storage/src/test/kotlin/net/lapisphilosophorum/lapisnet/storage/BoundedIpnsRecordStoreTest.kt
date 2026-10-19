package net.lapisphilosophorum.lapisnet.storage

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.time.Duration
import java.time.Instant

class BoundedIpnsRecordStoreTest :
    FunSpec({
        val now = Instant.now()
        val alice = IpnsIdentity.generate()

        test("a stored record is found and a newer one replaces it") {
            val store = BoundedIpnsRecordStore(8)
            store.putIfNewer(alice.validated(sequence = 1), now) shouldBe true
            store.get(alice.peerId, now)!!.sequence shouldBe 1
            store.putIfNewer(alice.validated(sequence = 2), now) shouldBe true
            store.get(alice.peerId, now)!!.sequence shouldBe 2
        }

        test("an older record is ignored") {
            val store = BoundedIpnsRecordStore(8)
            store.putIfNewer(alice.validated(sequence = 5), now) shouldBe true
            store.putIfNewer(alice.validated(sequence = 4), now) shouldBe false
            store.get(alice.peerId, now)!!.sequence shouldBe 5
        }

        test("equal sequence: a later expiry wins, equal expiry with other content keeps the held record") {
            val store = BoundedIpnsRecordStore(8)
            val expiry = now.plusSeconds(3600)
            val held = alice.validated(value = "first".toByteArray(), sequence = 3, notValidAfter = expiry)
            store.putIfNewer(held, now) shouldBe true
            val sameExpiryOtherContent =
                alice.validated(
                    value = "second".toByteArray(),
                    sequence = 3,
                    notValidAfter = expiry,
                )
            store.putIfNewer(sameExpiryOtherContent, now) shouldBe false
            String(store.get(alice.peerId, now)!!.value) shouldBe "first"
            val later =
                alice.validated(
                    value = "third".toByteArray(),
                    sequence = 3,
                    notValidAfter = expiry.plusSeconds(60),
                )
            store.putIfNewer(later, now) shouldBe true
            String(store.get(alice.peerId, now)!!.value) shouldBe "third"
        }

        test("the very same record again is acknowledged (idempotent republish)") {
            val store = BoundedIpnsRecordStore(8)
            val record = alice.validated(sequence = 7)
            store.putIfNewer(record, now) shouldBe true
            store.putIfNewer(record, now) shouldBe true
            store.size() shouldBe 1
        }

        test("an expired record is dropped on read and does not block a lower sequence afterwards") {
            val store = BoundedIpnsRecordStore(8)
            store.putIfNewer(alice.validated(sequence = 9, notValidAfter = now.plusSeconds(60)), now) shouldBe true
            val later = now.plus(Duration.ofHours(1))
            store.get(alice.peerId, later) shouldBe null
            store.size() shouldBe 0
            store.putIfNewer(alice.validated(sequence = 1, notValidAfter = later.plusSeconds(60)), later) shouldBe true
        }

        test("an expired held record is replaced by a lower sequence on write, without a read in between") {
            val store = BoundedIpnsRecordStore(8)
            store.putIfNewer(alice.validated(sequence = 9, notValidAfter = now.plusSeconds(60)), now) shouldBe true
            val later = now.plus(Duration.ofHours(1))
            store.putIfNewer(alice.validated(sequence = 1, notValidAfter = later.plusSeconds(60)), later) shouldBe true
            store.get(alice.peerId, later)!!.sequence shouldBe 1
        }

        test("the store is bounded and evicts the least recently used publisher") {
            val store = BoundedIpnsRecordStore(3)
            val ids = List(5) { IpnsIdentity.generate() }
            ids.take(3).forEach { store.putIfNewer(it.validated(), now) shouldBe true }
            store.get(ids[0].peerId, now) shouldNotBe null // touch: ids[1] is now the eldest
            store.putIfNewer(ids[3].validated(), now) shouldBe true
            store.size() shouldBe 3
            store.get(ids[1].peerId, now) shouldBe null
            store.get(ids[0].peerId, now) shouldNotBe null
            store.putIfNewer(ids[4].validated(), now) shouldBe true
            store.size() shouldBe 3
        }

        test("keys built from two different byte arrays with the same content name the same publisher") {
            val store = BoundedIpnsRecordStore(8)
            store.putIfNewer(alice.validated(), now) shouldBe true
            val copy = parseIpnsKey(alice.key.copyOf())!!
            store.get(copy, now) shouldNotBe null
        }

        test("a non-positive capacity is refused") {
            shouldThrow<IllegalArgumentException> { BoundedIpnsRecordStore(0) }
        }
    })
