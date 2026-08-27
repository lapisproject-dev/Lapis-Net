package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun pointerFor(
    sender: Secp256k1KeyPair,
    recipient: Secp256k1KeyPair,
    seed: Byte,
    notValidAfterEpochSecond: Long = 1_000_000L,
): MailboxPointer =
    MailboxPointer.create(
        sender = sender,
        recipientIdentity = recipient.publicKey,
        blobCid = testCid(seed),
        notValidAfterEpochSecond = notValidAfterEpochSecond,
        nowEpochSecond = 0,
    )

class MailboxPointerIndexTest :
    FunSpec({
        test("add tracks a newly-added pointer and rejects an exact duplicate") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val pointer = pointerFor(sender, recipient, 1)

            index.add(pointer) shouldBe true
            index.add(pointer) shouldBe false
            index.size() shouldBe 1
        }

        test("canAccept mirrors add's dedup decision without mutating state") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val pointer = pointerFor(sender, recipient, 1)

            index.canAccept(pointer) shouldBe true
            index.size() shouldBe 0
            index.add(pointer)
            index.canAccept(pointer) shouldBe false
        }

        test("add rejects a signature-invalid pointer without throwing") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val impostor = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val genuine = pointerFor(sender, recipient, 1)
            val forged =
                MailboxPointer.fromDecoded(
                    recipientIdentity = genuine.recipientIdentity,
                    senderIdentity = genuine.senderIdentity,
                    blobCid = genuine.blobCid,
                    notValidAfterEpochSecond = genuine.notValidAfterEpochSecond,
                    signature = pointerFor(impostor, recipient, 2).signature,
                )

            index.add(forged) shouldBe false
            index.size() shouldBe 0
        }

        test("pending returns only unresolved pointers, oldest first") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val first = pointerFor(sender, recipient, 1)
            val second = pointerFor(sender, recipient, 2)
            index.add(first)
            index.add(second)

            index.pending().map { it.blobCid } shouldBe listOf(first.blobCid, second.blobCid)

            index.markResolved(first)
            index.pending().map { it.blobCid } shouldBe listOf(second.blobCid)
        }

        test("markResolved on an untracked (e.g. already-evicted) pointer is a harmless no-op") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val pointer = pointerFor(sender, recipient, 1)
            index.markResolved(pointer) // never added - must not throw
        }

        test("a recipient can have many distinct pending pointers at once (not latest-wins-per-identity)") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            repeat(5) { i -> index.add(pointerFor(sender, recipient, i.toByte())) }
            index.pending().size shouldBe 5
            index.pointersFrom(sender.publicKey).size shouldBe 5
        }

        test("evictExpired removes only pointers whose TTL has passed, leaves the rest tracked") {
            val index = MailboxPointerIndex()
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val expired = pointerFor(sender, recipient, 1, notValidAfterEpochSecond = 100)
            val fresh = pointerFor(sender, recipient, 2, notValidAfterEpochSecond = 10_000)
            index.add(expired)
            index.add(fresh)

            val evicted = index.evictExpired(nowEpochSecond = 500)

            evicted shouldBe 1
            index.size() shouldBe 1
            index.pending().map { it.blobCid } shouldBe listOf(fresh.blobCid)
        }

        test("tryReservePersistence is idempotent per content id and enforces its own cap") {
            val index = MailboxPointerIndex(maxTracked = 100, maxPersisted = 2)
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val a = pointerFor(sender, recipient, 1)
            val b = pointerFor(sender, recipient, 2)
            val c = pointerFor(sender, recipient, 3)

            index.tryReservePersistence(a) shouldBe true
            index.tryReservePersistence(a) shouldBe true // idempotent - same content id
            index.tryReservePersistence(b) shouldBe true
            index.tryReservePersistence(c) shouldBe false // cap of 2 reached
        }

        test(
            "releaseReservedPersistence frees a reservation for reuse rather than burning it " +
                "permanently - security audit round 1 minor finding regression",
        ) {
            // maxPersisted = 1: the tightest possible window to prove RELEASE, not merely
            // non-exhaustion - mirrors the "cap of 2 reached" test above but at cap = 1, since a
            // single successful reservation would otherwise permanently exhaust a cap of 1 forever
            // if release() were a no-op.
            val index = MailboxPointerIndex(maxTracked = 100, maxPersisted = 1)
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val a = pointerFor(sender, recipient, 1)
            val b = pointerFor(sender, recipient, 2)

            // This mirrors what MailboxGossip.onGossipMessage does on a storage.put() failure: call
            // tryReservePersistence (which unconditionally inserts into the never-evicting
            // persistedContentIds the moment it is called), THEN releaseReservedPersistence when the
            // actual durable write never went through - see MailboxGossip.kt's own
            // `catch (e: NabuStorageException)` block around `storage.put(bytes)`.
            index.tryReservePersistence(a) shouldBe true
            index.releaseReservedPersistence(a)

            // THE CENTRAL ASSERTION: a wholly different, later pointer can still claim the cap's ONE
            // slot - proving `a`'s failed/released reservation did not permanently burn it. Without
            // releaseReservedPersistence (or if it were a no-op), this would fail: the cap would
            // already be exhausted by `a` alone.
            index.tryReservePersistence(b) shouldBe true

            // releaseReservedPersistence is a no-op for a content id that was never reserved (or was
            // already released) - safe to call defensively, exactly like MailboxGossip.kt's own doc
            // comment on the method states.
            index.releaseReservedPersistence(a) // already released above - must not throw or corrupt state
            index.tryReservePersistence(pointerFor(sender, recipient, 3)) shouldBe false // cap still enforced
        }

        test("two-cap eviction: tracking cap bounds size(), independent of the (larger) persistence cap") {
            val index = MailboxPointerIndex(maxTracked = 3, maxPersisted = 100)
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            repeat(10) { i -> index.add(pointerFor(sender, recipient, i.toByte())) }
            index.size() shouldBe 3
        }

        test("eviction from the tracking cap also removes the entry from pointersFrom's per-sender bucket") {
            val index = MailboxPointerIndex(maxTracked = 2, maxPersisted = 100)
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val recipient = DualKeyIdentity.generate().secp256k1KeyPair
            val first = pointerFor(sender, recipient, 1)
            index.add(first)
            index.add(pointerFor(sender, recipient, 2))
            index.add(pointerFor(sender, recipient, 3)) // evicts `first`

            index.pointersFrom(sender.publicKey).map { it.blobCid } shouldBe
                listOf(pointerFor(sender, recipient, 2).blobCid, pointerFor(sender, recipient, 3).blobCid)
        }
    })
