package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * V0.9.11 / finding E, over real connections. Nabu's responder deserializes the key of a request with
 * `Multihash.deserialize` / `Cid.cast`, which allocate `new byte[declaredLength]` before checking the
 * length. Any connected peer can therefore make an honest node attempt a multi-gigabyte allocation -
 * on the Netty event loop - with a ten-byte key. Reachable from production today: [NabuStorage.attach]
 * registers the responder on every browser and CLI node.
 *
 * The declared length here is 64 MiB: large enough to be unmistakably "the bug", small enough that a
 * MUTATED build (guard removed) allocates it harmlessly instead of killing the test worker; the
 * 0x7FFFFFF0 / 0x7FFFFFFF cases are covered by [InboundDhtRequestPolicyTest], which allocates nothing.
 */
class KademliaResponderMultihashOverflowTest :
    FunSpec({
        // LEB128 of 64 MiB
        val declared64MiB = byteArrayOf(0x80.toByte(), 0x80.toByte(), 0x80.toByte(), 0x20)
        val badMultihash = byteArrayOf(0x12) + declared64MiB + ByteArray(4)
        val ipns = "/ipns/".toByteArray()

        fun request(
            type: Dht.Message.MessageType,
            key: ByteArray,
        ): Dht.Message.Builder =
            Dht.Message
                .newBuilder()
                .setType(type)
                .keyBytes(key)

        test(
            "a key declaring a 64 MiB multihash is rejected for every request type, and the node keeps answering",
        ).config(
            timeout = 90.seconds,
        ) {
            val victim = newNode()
            val attacker = ScriptedDhtPeer.start()
            val honest = newNode()
            try {
                val storage = storageOn(victim)

                attacker.send(victim, request(Dht.Message.MessageType.ADD_PROVIDER, badMultihash).build())
                attacker.send(victim, request(Dht.Message.MessageType.GET_PROVIDERS, badMultihash).build())
                // GET_VALUE hands the suffix to Cid.cast: version | codec | multihash type | length ...
                attacker.send(
                    victim,
                    request(
                        Dht.Message.MessageType.GET_VALUE,
                        ipns + byteArrayOf(1, 0x55) + badMultihash,
                    ).build(),
                )
                val putKey = ipns + badMultihash
                attacker.send(
                    victim,
                    request(Dht.Message.MessageType.PUT_VALUE, putKey)
                        .setRecord(
                            Dht.Record
                                .newBuilder()
                                .setKey(ByteString.copyFrom(putKey))
                                .build(),
                        ).build(),
                )

                awaitCondition { storage.inboundRejectedCount() >= 4 } shouldBe true
                storage.inboundRejectedCount() shouldBe 4
                storage.inboundFailedCount() shouldBe 0

                // still serving: an honest node connects and runs a full lookup against it
                val honestStorage = storageOn(honest)
                honestStorage.connectToDhtPeer(addressOf(victim)) shouldBe true
                val cid = storage.put("still answering".toByteArray())
                honestStorage.findProviders(cid, timeout = Duration.ofSeconds(5)) shouldBe setOf(victim.peerId)
            } finally {
                attacker.stop()
                victim.stop()
                honest.stop()
            }
        }

        test("an ADD_PROVIDER naming a provider with an oversized multihash ID is rejected before it is stored").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            val attacker = ScriptedDhtPeer.start()
            try {
                val storage = storageOn(victim)
                val cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 1 })
                val badId = byteArrayOf(0x12) + declared64MiB + ByteArray(30)
                attacker.send(
                    victim,
                    request(Dht.Message.MessageType.ADD_PROVIDER, cid.bareMultihash().toBytes())
                        .addProviderPeers(
                            Dht.Message.Peer
                                .newBuilder()
                                .setId(ByteString.copyFrom(badId))
                                .build(),
                        ).build(),
                )
                awaitCondition { storage.inboundRejectedCount() >= 1 } shouldBe true
                storage.localProviderRecords(cid) shouldBe emptyList()
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test(
            "a response entry with an oversized or malformed ID is skipped while the honest entries still count",
        ).config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            val liar = ScriptedDhtPeer.start()
            val honest = newNode()
            try {
                val storage = storageOn(victim, DhtLimits(perRpcTimeout = Duration.ofMillis(800)))
                val honestStorage = storageOn(honest)
                val cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 2 })

                // 35 bytes: the right size for a peer ID, the wrong structure
                val oversizedId = byteArrayOf(0x12) + declared64MiB + ByteArray(30)
                val tooShort = ByteArray(10) { 1 }
                val goodEntry = peerProto(honest.peerId, honest.listenAddresses().map { it.serialize() })
                liar.answer(Dht.Message.MessageType.FIND_NODE) {
                    it
                        .toBuilder()
                        .addCloserPeers(
                            Dht.Message.Peer
                                .newBuilder()
                                .setId(ByteString.copyFrom(oversizedId))
                                .build(),
                        ).addCloserPeers(
                            Dht.Message.Peer
                                .newBuilder()
                                .setId(ByteString.copyFrom(tooShort))
                                .build(),
                        ).addCloserPeers(goodEntry)
                        .build()
                }
                storage.connectToDhtPeer(liar.address) shouldBe true

                // M (the liar) and the honest node found through its answer
                storage.provide(cid, Duration.ofSeconds(4)) shouldBe 2
                awaitCondition { honestStorage.localProviderRecords(cid).isNotEmpty() } shouldBe true
            } finally {
                liar.stop()
                victim.stop()
                honest.stop()
            }
        }
    })
