package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * V0.9.11 / finding B: every DHT exchange used to leave streams behind. Nabu's `KademliaProtocol`
 * `ReplyHandler.onMessage` only `closeWrite()`s the initiator's end, `Kademlia.getCloserPeers` /
 * `findProviders` / `provideBlock` never close anything, and the responder never closed after
 * `ADD_PROVIDER` - so each lookup leaked a stream (and its Netty channel) on both nodes. This runs
 * hundreds of real exchanges between three nodes and requires the live stream count of ALL THREE
 * to return to where it started, while the announcements themselves still arrive.
 */
class DhtStreamLifecycleTest :
    FunSpec({
        test("200 provide, 50 findProviders and 10 connectToDhtPeer calls leave no stream behind on any node").config(
            timeout = 120.seconds,
        ) {
            val nodeA = newNode()
            val nodeB = newNode()
            val nodeC = newNode()
            try {
                val storageA = storageOn(nodeA)
                storageOn(nodeB)
                val storageC = storageOn(nodeC)
                storageA.connectToDhtPeer(addressOf(nodeB)) shouldBe true
                storageC.connectToDhtPeer(addressOf(nodeB)) shouldBe true
                val cid = storageA.put("stream lifecycle".toByteArray())

                fun streams() = listOf(nodeA, nodeB, nodeC).map { it.host.streams.size }
                awaitCondition { streams().all { it <= 4 } } // let the connection set-up settle
                val baseline = streams()

                repeat(200) { storageA.provide(cid, Duration.ofSeconds(3)) }
                repeat(50) { storageA.findProviders(cid, timeout = Duration.ofSeconds(3)) }
                repeat(10) { storageA.connectToDhtPeer(addressOf(nodeB)) shouldBe true }

                val settled =
                    awaitCondition(15_000) {
                        streams().zip(baseline).all { (now, before) -> now <= before + 2 }
                    }
                if (!settled) throw AssertionError("streams did not return to baseline $baseline: now ${streams()}")

                // the announcements were not lost to the closing: C resolves A through B
                storageC.findProviders(cid, timeout = Duration.ofSeconds(5)) shouldBe setOf(nodeA.peerId)
            } finally {
                listOf(nodeA, nodeB, nodeC).forEach { runCatching { it.stop() } }
            }
        }
        test("the responder closes its end after ADD_PROVIDER by itself, without waiting for the initiator").config(
            timeout = 120.seconds,
        ) {
            val nodeA = newNode()
            val nodeB = newNode()
            try {
                // A would wait a whole minute for B to close before resetting; B must not need that
                val storageA = storageOn(nodeA, DhtLimits(streamCloseGrace = Duration.ofSeconds(60)))
                storageOn(nodeB)
                storageA.connectToDhtPeer(addressOf(nodeB)) shouldBe true
                val cid = storageA.put("responder closes".toByteArray())

                fun streams() = listOf(nodeA, nodeB).map { it.host.streams.size }
                awaitCondition { streams().all { it <= 4 } }
                val baseline = streams()

                repeat(20) { storageA.provide(cid, Duration.ofSeconds(3)) shouldBe 1 }

                val settled =
                    awaitCondition(10_000) { streams().zip(baseline).all { (now, before) -> now <= before + 2 } }
                if (!settled) throw AssertionError("streams did not return to baseline $baseline: now ${streams()}")
            } finally {
                listOf(nodeA, nodeB).forEach { runCatching { it.stop() } }
            }
        }

        test(
            "the initiator resets an announcement stream that a responder never closes",
        ).config(timeout = 120.seconds) {
            val victim = newNode()
            val silentCloser = ScriptedDhtPeer.start()
            try {
                // answers FIND_NODE so that it is announced to, then never closes anything
                silentCloser.answer(Dht.Message.MessageType.FIND_NODE) { it }
                val storage = storageOn(victim, DhtLimits(streamCloseGrace = Duration.ofMillis(500)))
                storage.connectToDhtPeer(silentCloser.address) shouldBe true
                val cid = storage.put("initiator resets".toByteArray())

                fun streams() = victim.host.streams.size
                awaitCondition { streams() <= 4 }
                val baseline = streams()

                repeat(20) { storage.provide(cid, Duration.ofSeconds(3)) shouldBe 1 }

                val settled = awaitCondition(10_000) { streams() <= baseline + 2 }
                if (!settled) throw AssertionError("streams did not return to baseline $baseline: now ${streams()}")
            } finally {
                silentCloser.stop()
                runCatching { victim.stop() }
            }
        }

        test("the responder closes its end after PING and after an unanswerable PUT_VALUE").config(
            timeout = 120.seconds,
        ) {
            val victim = newNode()
            val attacker = ScriptedDhtPeer.start()
            try {
                storageOn(victim)

                fun streams() = victim.host.streams.size
                // the attacker never closes anything it opens, and none of these requests is answered
                attacker.send(
                    victim,
                    Dht.Message
                        .newBuilder()
                        .setType(Dht.Message.MessageType.PING)
                        .build(),
                )
                awaitCondition { streams() <= 4 }
                val baseline = streams()

                val key = "/ipns/".toByteArray() + byteArrayOf(0x12, 0x20) + ByteArray(32) { 7 }
                repeat(20) {
                    attacker.send(
                        victim,
                        Dht.Message
                            .newBuilder()
                            .setType(Dht.Message.MessageType.PING)
                            .build(),
                    )
                    attacker.send(
                        victim,
                        Dht.Message
                            .newBuilder()
                            .setType(Dht.Message.MessageType.PUT_VALUE)
                            .keyBytes(key)
                            .setRecord(
                                Dht.Record
                                    .newBuilder()
                                    .setKey(ByteString.copyFrom(key))
                                    .setValue(ByteString.copyFrom(ByteArray(16) { 1 }))
                                    .build(),
                            ).build(),
                    )
                }

                val settled = awaitCondition(10_000) { streams() <= baseline + 2 }
                if (!settled) {
                    throw AssertionError("responder streams did not return to baseline $baseline: now ${streams()}")
                }
            } finally {
                attacker.stop()
                runCatching { victim.stop() }
            }
        }

        test("the responder does not keep an answered FIND_NODE, GET_PROVIDERS or GET_VALUE stream open").config(
            timeout = 120.seconds,
        ) {
            val victim = newNode()
            val attacker = ScriptedDhtPeer.start()
            try {
                storageOn(victim, DhtLimits(streamCloseGrace = Duration.ofMillis(500)))

                fun streams() = victim.host.streams.size

                fun request(
                    type: Dht.Message.MessageType,
                    key: ByteArray,
                ) = Dht.Message
                    .newBuilder()
                    .setType(type)
                    .keyBytes(key)
                    .build()

                val multihash = byteArrayOf(0x12, 0x20) + ByteArray(32) { 5 }
                val ipnsKey = "/ipns/".toByteArray() + byteArrayOf(0x12, 0x20) + ByteArray(32) { 7 }
                val requests =
                    listOf(
                        request(Dht.Message.MessageType.FIND_NODE, multihash),
                        request(Dht.Message.MessageType.GET_PROVIDERS, multihash),
                        request(Dht.Message.MessageType.GET_VALUE, ipnsKey),
                    )
                // the attacker never reads a reply and never closes anything it opens
                attacker.send(victim, requests[0])
                awaitCondition { streams() <= 4 }
                val baseline = streams()

                repeat(20) { requests.forEach { attacker.send(victim, it) } }

                val settled = awaitCondition(10_000) { streams() <= baseline + 2 }
                if (!settled) {
                    throw AssertionError("responder streams did not return to baseline $baseline: now ${streams()}")
                }
            } finally {
                attacker.stop()
                runCatching { victim.stop() }
            }
        }
    })
