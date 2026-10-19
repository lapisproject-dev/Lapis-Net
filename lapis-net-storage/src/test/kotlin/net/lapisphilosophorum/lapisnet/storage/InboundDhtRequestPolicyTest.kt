package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.peergos.protocol.dht.pb.Dht

class InboundDhtRequestPolicyTest :
    FunSpec({
        val type = Dht.Message.MessageType.entries

        /** sha2-256 type (0x12), then a declared hash length varint, then [padding] bytes. */
        fun multihashDeclaring(
            lengthVarint: ByteArray,
            padding: Int,
        ): ByteArray = byteArrayOf(0x12) + lengthVarint + ByteArray(padding)

        // 0x7FFFFFF0 / 0x7FFFFFFF as LEB128
        val hugeA = byteArrayOf(0xF0.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x07)
        val hugeB = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x07)
        val valid = multihashDeclaring(byteArrayOf(32), 32)
        val ipns = "/ipns/".toByteArray()

        fun msg(
            t: Dht.Message.MessageType,
            key: ByteArray,
        ): Dht.Message.Builder =
            Dht.Message
                .newBuilder()
                .setType(t)
                .setKey(ByteString.copyFrom(key))

        test("a valid sha256 multihash key is accepted for ADD_PROVIDER and GET_PROVIDERS") {
            val provider =
                Dht.Message.Peer
                    .newBuilder()
                    .setId(
                        ByteString.copyFrom(multihashDeclaring(byteArrayOf(32), 32)),
                    ).build()
            InboundDhtRequestPolicy.isAcceptable(
                msg(Dht.Message.MessageType.ADD_PROVIDER, valid).addProviderPeers(provider).build(),
            ) shouldBe true
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_PROVIDERS, valid).build()) shouldBe
                true
        }

        for ((label, huge) in listOf("0x7FFFFFF0" to hugeA, "0x7FFFFFFF" to hugeB)) {
            test("a key declaring a multihash length of $label is rejected for every key-parsing request type") {
                val bad = multihashDeclaring(huge, 4)
                InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.ADD_PROVIDER, bad).build()) shouldBe
                    false
                InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_PROVIDERS, bad).build()) shouldBe
                    false
                InboundDhtRequestPolicy.isAcceptable(
                    msg(Dht.Message.MessageType.GET_VALUE, ipns + byteArrayOf(1, 0x55) + bad).build(),
                ) shouldBe
                    false
                val put = msg(Dht.Message.MessageType.PUT_VALUE, ipns + bad)
                put.setRecord(
                    Dht.Record
                        .newBuilder()
                        .setKey(ByteString.copyFrom(ipns + bad))
                        .build(),
                )
                InboundDhtRequestPolicy.isAcceptable(put.build()) shouldBe false
            }
        }

        test("ADD_PROVIDER with a provider ID declaring an oversized length is rejected") {
            val bad =
                Dht.Message.Peer
                    .newBuilder()
                    .setId(ByteString.copyFrom(multihashDeclaring(hugeA, 4)))
                    .build()
            InboundDhtRequestPolicy.isAcceptable(
                msg(Dht.Message.MessageType.ADD_PROVIDER, valid).addProviderPeers(bad).build(),
            ) shouldBe false
        }

        test("GET_VALUE and PUT_VALUE need the /ipns/ prefix and a non-empty suffix") {
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_VALUE, valid).build()) shouldBe false
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_VALUE, ipns).build()) shouldBe false
            InboundDhtRequestPolicy.isAcceptable(
                msg(Dht.Message.MessageType.GET_VALUE, "/ip".toByteArray()).build(),
            ) shouldBe
                false
            val short = msg(Dht.Message.MessageType.PUT_VALUE, ipns)
            short.setRecord(
                Dht.Record
                    .newBuilder()
                    .setKey(ByteString.copyFrom(ipns))
                    .build(),
            )
            InboundDhtRequestPolicy.isAcceptable(short.build()) shouldBe false
        }

        // V0.9.13: the only IPNS name is an Ed25519 identity multihash; the old shape (any CID) is refused.
        val ed25519Key = ipns + byteArrayOf(0x00, 0x24, 0x08, 0x01, 0x12, 0x20) + ByteArray(32) { (it + 1).toByte() }

        test("GET_VALUE with an Ed25519 IPNS name is accepted") {
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_VALUE, ed25519Key).build()) shouldBe
                true
        }

        test("GET_VALUE with a CIDv0-shaped (sha256) IPNS suffix is now rejected: it is no name this node serves") {
            val cidV0 = multihashDeclaring(byteArrayOf(32), 32)
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_VALUE, ipns + cidV0).build()) shouldBe
                false
        }

        test("GET_VALUE and PUT_VALUE keys of the wrong size or shape are rejected") {
            val tooLong = ed25519Key + byteArrayOf(0)
            val tooShort = ed25519Key.copyOf(ed25519Key.size - 1)
            val secp = ipns + byteArrayOf(0x00, 0x25, 0x08, 0x02, 0x12, 0x21) + ByteArray(33) { 2 }
            val zeroKey = ipns + byteArrayOf(0x00, 0x24, 0x08, 0x01, 0x12, 0x20) + ByteArray(32)
            for (bad in listOf(tooLong, tooShort, secp, zeroKey)) {
                InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.GET_VALUE, bad).build()) shouldBe false
                val put =
                    msg(Dht.Message.MessageType.PUT_VALUE, bad).setRecord(
                        Dht.Record
                            .newBuilder()
                            .setKey(ByteString.copyFrom(bad))
                            .build(),
                    )
                InboundDhtRequestPolicy.isAcceptable(put.build()) shouldBe false
            }
        }

        test("PUT_VALUE needs a record whose key equals the request key and whose value fits the limit") {
            val key = ed25519Key

            fun put(
                recordKey: ByteArray,
                value: ByteArray = ByteArray(0),
            ) = msg(Dht.Message.MessageType.PUT_VALUE, key)
                .setRecord(
                    Dht.Record
                        .newBuilder()
                        .setKey(ByteString.copyFrom(recordKey))
                        .setValue(ByteString.copyFrom(value))
                        .build(),
                ).build()

            InboundDhtRequestPolicy.isAcceptable(put(key)) shouldBe true
            InboundDhtRequestPolicy.isAcceptable(put(key.reversedArray())) shouldBe false
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.PUT_VALUE, key).build()) shouldBe false

            val limits = DhtLimits(maxIpnsRecordBytes = 1024)
            InboundDhtRequestPolicy.isAcceptable(put(key, ByteArray(1024)), limits) shouldBe true
            InboundDhtRequestPolicy.isAcceptable(put(key, ByteArray(1025)), limits) shouldBe false
        }

        test("FIND_NODE and PING are accepted whatever the key") {
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.FIND_NODE, hugeA).build()) shouldBe true
            InboundDhtRequestPolicy.isAcceptable(msg(Dht.Message.MessageType.PING, ByteArray(0)).build()) shouldBe true
        }

        test("an unrecognised message type is rejected") {
            val unknown =
                Dht.Message
                    .newBuilder()
                    .setTypeValue(99)
                    .build()
            unknown.type shouldBe Dht.Message.MessageType.UNRECOGNIZED
            InboundDhtRequestPolicy.isAcceptable(unknown) shouldBe false
        }

        test("every declared message type is handled explicitly") {
            // guards against a future Nabu adding a type that would fall into the reject-all branch silently
            type.filter { it != Dht.Message.MessageType.UNRECOGNIZED }.map { it.name }.toSet() shouldBe
                setOf("PUT_VALUE", "GET_VALUE", "ADD_PROVIDER", "GET_PROVIDERS", "FIND_NODE", "PING")
        }
    })
