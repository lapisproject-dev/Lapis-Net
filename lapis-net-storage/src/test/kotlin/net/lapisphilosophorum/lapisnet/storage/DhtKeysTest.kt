package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class DhtKeysTest :
    FunSpec({
        val cidV1 = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { it.toByte() })

        test("the DHT key of a CID is its bare multihash, not the full CID bytes") {
            dhtKeyFor(cidV1).toList() shouldBe cidV1.bareMultihash().toBytes().toList()
            dhtKeyFor(cidV1).toList() shouldNotBe cidV1.toBytes().toList()
        }

        test("a CIDv0 and the CIDv1 of the same content share one DHT key") {
            val v0 = Cid(0L, Cid.Codec.DagProtobuf, Multihash.Type.sha2_256, ByteArray(32) { it.toByte() })
            dhtKeyFor(v0).toList() shouldBe dhtKeyFor(cidV1).toList()
        }

        test("keyDistance is deterministic and depends on both the key and the peer") {
            val key = dhtKeyFor(cidV1)
            val peerA = ByteArray(34) { 1 }
            val peerB = ByteArray(34) { 2 }
            keyDistance(key, peerA) shouldBe keyDistance(key, peerA)
            keyDistance(key, peerA) shouldNotBe keyDistance(key, peerB)
            keyDistance(key, peerA) shouldNotBe keyDistance(ByteArray(34) { 9 }, peerA)
        }
    })
