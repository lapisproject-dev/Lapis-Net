package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId

private fun cidOf(i: Int): Cid =
    Cid.buildCidV1(
        Cid.Codec.Raw,
        Multihash.Type.sha2_256,
        ByteArray(32) { (i shr ((it % 4) * 8)).toByte() },
    )

class InboxDhtPendingIndexTest :
    FunSpec({
        val sender = DualKeyIdentity.generate()
        val senderKey = sender.secp256k1KeyPair.publicKey
        val peerId = sender.deriveLibp2pPeerId()

        fun entry(
            i: Int,
            nva: Long = 1000,
        ) = InboxDhtPendingIndex.Entry(senderKey, peerId, cidOf(i), nva)

        fun entryFrom(
            id: DualKeyIdentity,
            i: Int,
        ) = InboxDhtPendingIndex.Entry(id.secp256k1KeyPair.publicKey, id.deriveLibp2pPeerId(), cidOf(i), 1000)

        test("a pointer is queued once per sender and envelope CID") {
            val index = InboxDhtPendingIndex()
            index.add(entry(1)) shouldBe true
            index.add(entry(1)) shouldBe false
            index.add(entry(2)) shouldBe true
            index.pending().size shouldBe 2
        }

        test("the queue is bounded; resolved entries go first, then the oldest") {
            val index = InboxDhtPendingIndex(maxPending = 3)
            val e1 = entry(1)
            index.add(e1)
            index.add(entry(2))
            index.add(entry(3))
            index.markResolved(index.pending()[1])
            index.add(entry(4))
            index.size() shouldBe 3
            index.pending().map { it.envelopeCid } shouldBe listOf(cidOf(1), cidOf(3), cidOf(4))
            index.add(entry(5))
            index.size() shouldBe 3
            (e1 in index.pending()) shouldBe false
        }

        test("the production bound holds under a flood") {
            val index = InboxDhtPendingIndex()
            val senders = List(InboxDhtPendingIndex.MAX_PENDING / 8) { DualKeyIdentity.generate() }
            var n = 0
            repeat(InboxDhtPendingIndex.MAX_PENDING + 500) { index.add(entryFrom(senders[n % senders.size], n++)) }
            index.size() shouldBe InboxDhtPendingIndex.MAX_PENDING
        }

        test("one sender cannot hold more than the per-sender cap") {
            val index = InboxDhtPendingIndex()
            repeat(InboxDhtPendingIndex.MAX_PENDING_PER_SENDER + 10) { index.add(entry(it)) }
            index.size() shouldBe InboxDhtPendingIndex.MAX_PENDING_PER_SENDER
        }

        test("when full, a heavy sender is trimmed for a newcomer; a newcomer cannot displace evenly spread entries") {
            val index = InboxDhtPendingIndex(maxPending = 4, maxPerSender = 4)
            val heavy = DualKeyIdentity.generate()
            val heavyKey = heavy.secp256k1KeyPair.publicKey
            repeat(3) { index.add(entryFrom(heavy, it)) }
            index.add(entryFrom(DualKeyIdentity.generate(), 10)) shouldBe true
            // full: heavy holds 3, newcomer 0 -> heavy's oldest is dropped
            index.add(entryFrom(DualKeyIdentity.generate(), 20)) shouldBe true
            index.pending().count { it.sender == heavyKey } shouldBe 2
            // heavy holds 2, newcomer 0 -> still trimmed
            index.add(entryFrom(DualKeyIdentity.generate(), 30)) shouldBe true
            index.pending().count { it.sender == heavyKey } shouldBe 1
            // now spread evenly (1 each): a newcomer is refused
            index.add(entryFrom(DualKeyIdentity.generate(), 40)) shouldBe false
            index.size() shouldBe 4
        }

        test("a pointer claiming a validity far beyond the window is evicted") {
            val index = InboxDhtPendingIndex()
            index.add(entry(1, nva = Long.MAX_VALUE))
            index.add(entry(2, nva = 100 + InboxDhtPendingIndex.MAX_POINTER_VALIDITY_SECONDS))
            index.evictExpired(100) shouldBe 1
            index.pending().single().envelopeCid shouldBe cidOf(2)
        }

        test("recorded attempts back off exponentially up to the cap") {
            val index = InboxDhtPendingIndex()
            val e = entry(1)
            index.add(e)
            index.recordAttempt(e, 1000)
            e.nextAttemptEpochSecond shouldBe 1000 + InboxDhtPendingIndex.BACKOFF_BASE_SECONDS
            index.recordAttempt(e, 1000)
            e.nextAttemptEpochSecond shouldBe 1000 + 2 * InboxDhtPendingIndex.BACKOFF_BASE_SECONDS
            repeat(30) { index.recordAttempt(e, 1000) }
            e.nextAttemptEpochSecond shouldBe 1000 + InboxDhtPendingIndex.BACKOFF_CAP_SECONDS
        }

        test("expired entries are evicted, resolved entries are not pending") {
            val index = InboxDhtPendingIndex()
            index.add(entry(1, nva = 10))
            index.add(entry(2, nva = 100))
            index.evictExpired(50) shouldBe 1
            index.size() shouldBe 1
            index.markResolved(index.pending().single())
            index.pending().size shouldBe 0
        }
    })
