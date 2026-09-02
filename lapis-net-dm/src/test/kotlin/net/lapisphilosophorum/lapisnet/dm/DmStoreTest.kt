package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class DmStoreTest :
    FunSpec({
        test("recordInbound/recordOutbound are visible via historyFor, oldest first") {
            val store = DmStore()
            val peer = Secp256k1KeyPair.generate().publicKey
            store.recordOutbound(peer, DmContent(body = "hi"), DmDeliveryState.SENT, epochSecond = 1)
            store.recordInbound(
                DmInboundMessage(
                    peer,
                    ByteArray(0),
                    DmContent(body = "hello back"),
                    false,
                    ByteArray(32),
                    receivedAtEpochSecond = 2,
                ),
            )
            store.recordOutbound(peer, DmContent(body = "how are you"), DmDeliveryState.SENT, epochSecond = 3)

            val history = store.historyFor(peer)
            history.size shouldBe 3
            (history[0] as DmHistoryEntry.Outbound).content.body shouldBe "hi"
            (history[1] as DmHistoryEntry.Inbound).content.body shouldBe "hello back"
            (history[2] as DmHistoryEntry.Outbound).content.body shouldBe "how are you"
        }

        test("history for an unknown peer is empty, never throws") {
            val store = DmStore()
            store.historyFor(Secp256k1KeyPair.generate().publicKey) shouldBe emptyList()
        }

        test("history is bounded per peer - oldest entries evicted first") {
            val store = DmStore(maxHistoryPerPeer = 3)
            val peer = Secp256k1KeyPair.generate().publicKey
            (0 until 5).forEach { i ->
                store.recordOutbound(peer, DmContent(body = "m$i"), DmDeliveryState.SENT, epochSecond = i.toLong())
            }

            val history = store.historyFor(peer)
            history.size shouldBe 3
            history.map { (it as DmHistoryEntry.Outbound).content.body } shouldBe listOf("m2", "m3", "m4")
        }

        test("different peers' histories are independent") {
            val store = DmStore()
            val peerA = Secp256k1KeyPair.generate().publicKey
            val peerB = Secp256k1KeyPair.generate().publicKey
            store.recordOutbound(peerA, DmContent(body = "to A"), DmDeliveryState.SENT)
            store.recordOutbound(peerB, DmContent(body = "to B"), DmDeliveryState.SENT)

            store.historyFor(peerA).size shouldBe 1
            store.historyFor(peerB).size shouldBe 1
            (store.historyFor(peerA).single() as DmHistoryEntry.Outbound).content.body shouldBe "to A"
            (store.historyFor(peerB).single() as DmHistoryEntry.Outbound).content.body shouldBe "to B"
        }

        test("peers() sorts by most recently active conversation, not map access order") {
            val store = DmStore()
            val peerA = Secp256k1KeyPair.generate().publicKey
            val peerB = Secp256k1KeyPair.generate().publicKey
            val peerC = Secp256k1KeyPair.generate().publicKey
            store.recordOutbound(peerA, DmContent(body = "a"), DmDeliveryState.SENT, epochSecond = 10)
            store.recordOutbound(peerB, DmContent(body = "b"), DmDeliveryState.SENT, epochSecond = 30)
            store.recordOutbound(peerC, DmContent(body = "c"), DmDeliveryState.SENT, epochSecond = 20)

            // Read peerA's history - on an access-ordered LinkedHashMap this would move peerA to the
            // "most recently accessed" end, which must NOT change peers()'s activity-based ordering.
            store.historyFor(peerA)

            store.peers() shouldBe listOf(peerB, peerC, peerA)
        }

        test("lastEntryFor returns the most recent entry, null for an unknown peer") {
            val store = DmStore()
            val peer = Secp256k1KeyPair.generate().publicKey
            store.lastEntryFor(peer) shouldBe null

            store.recordOutbound(peer, DmContent(body = "first"), DmDeliveryState.SENT, epochSecond = 1)
            store.recordOutbound(peer, DmContent(body = "second"), DmDeliveryState.SENT, epochSecond = 2)

            (store.lastEntryFor(peer) as DmHistoryEntry.Outbound).content.body shouldBe "second"
        }
    })
