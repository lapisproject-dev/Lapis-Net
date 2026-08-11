package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class DmStoreTest :
    FunSpec({
        test("recordInbound/recordOutbound are visible via historyFor, oldest first") {
            val store = DmStore()
            val peer = Secp256k1KeyPair.generate().publicKey
            store.recordOutbound(peer, "hi".toByteArray(), epochSecond = 1)
            store.recordInbound(
                DmInboundMessage(peer, "hello back".toByteArray(), ByteArray(32), receivedAtEpochSecond = 2),
            )
            store.recordOutbound(peer, "how are you".toByteArray(), epochSecond = 3)

            val history = store.historyFor(peer)
            history.size shouldBe 3
            (history[0] as DmHistoryEntry.Outbound).plaintext.decodeToString() shouldBe "hi"
            (history[1] as DmHistoryEntry.Inbound).plaintext.decodeToString() shouldBe "hello back"
            (history[2] as DmHistoryEntry.Outbound).plaintext.decodeToString() shouldBe "how are you"
        }

        test("history for an unknown peer is empty, never throws") {
            val store = DmStore()
            store.historyFor(Secp256k1KeyPair.generate().publicKey) shouldBe emptyList()
        }

        test("history is bounded per peer - oldest entries evicted first") {
            val store = DmStore(maxHistoryPerPeer = 3)
            val peer = Secp256k1KeyPair.generate().publicKey
            (0 until 5).forEach { i -> store.recordOutbound(peer, "m$i".toByteArray(), epochSecond = i.toLong()) }

            val history = store.historyFor(peer)
            history.size shouldBe 3
            history.map { (it as DmHistoryEntry.Outbound).plaintext.decodeToString() } shouldBe listOf("m2", "m3", "m4")
        }

        test("different peers' histories are independent") {
            val store = DmStore()
            val peerA = Secp256k1KeyPair.generate().publicKey
            val peerB = Secp256k1KeyPair.generate().publicKey
            store.recordOutbound(peerA, "to A".toByteArray())
            store.recordOutbound(peerB, "to B".toByteArray())

            store.historyFor(peerA).size shouldBe 1
            store.historyFor(peerB).size shouldBe 1
            (store.historyFor(peerA).single() as DmHistoryEntry.Outbound).plaintext.decodeToString() shouldBe "to A"
            (store.historyFor(peerB).single() as DmHistoryEntry.Outbound).plaintext.decodeToString() shouldBe "to B"
        }
    })
