package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private fun expiry(): Instant = Instant.now().plus(Duration.ofHours(1))

/**
 * Real loopback nodes: A publishes a value under its own peer ID, B stores it, C (which never talks to A)
 * resolves it through B. The responder side is [IpnsValueResponder]; the initiator side is
 * [DhtWalker.putValue] / [DhtWalker.getValue].
 */
class MultiNodeIpnsValueTest :
    FunSpec({
        test("A publishes, C resolves the value through B without ever contacting A").config(timeout = 60.seconds) {
            val a = newTestNode()
            val b = newTestNode()
            val c = newTestNode()
            try {
                val storageA = storageOn(a.node)
                val storageB = storageOn(b.node)
                val storageC = storageOn(c.node)
                storageA.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageC.connectToDhtPeer(addressOf(b.node)) shouldBe true

                val result = storageA.publishIpnsValue(a.signingKey, "directory value".toByteArray(), 1, expiry())
                result shouldBe IpnsPublishResult(acknowledged = 1, attempted = 1)
                storageB.heldIpnsRecords() shouldBe 1

                val resolved = storageC.resolveIpnsValue(a.peerId, Duration.ofSeconds(5))
                resolved shouldNotBe null
                resolved!!.publisher shouldBe a.peerId
                String(resolved.value) shouldBe "directory value"
                resolved.sequence shouldBe 1
                storageB.ipnsGetsAnswered() shouldBe 1
            } finally {
                listOf(a, b, c).forEach { runCatching { it.node.stop() } }
            }
        }

        test("a newer sequence supersedes the older value; a stale publication is refused locally").config(
            timeout = 60.seconds,
        ) {
            val a = newTestNode()
            val b = newTestNode()
            val c = newTestNode()
            try {
                val storageA = storageOn(a.node)
                storageOn(b.node)
                val storageC = storageOn(c.node)
                storageA.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageC.connectToDhtPeer(addressOf(b.node)) shouldBe true

                storageA.publishIpnsValue(a.signingKey, "v1".toByteArray(), 1, expiry()).acknowledged shouldBe 1
                storageA.publishIpnsValue(a.signingKey, "v2".toByteArray(), 2, expiry()).acknowledged shouldBe 1
                String(storageC.resolveIpnsValue(a.peerId, Duration.ofSeconds(5))!!.value) shouldBe "v2"

                val stale = runCatching { storageA.publishIpnsValue(a.signingKey, "old".toByteArray(), 1, expiry()) }
                (stale.exceptionOrNull() is NabuStorageException) shouldBe true
                String(storageC.resolveIpnsValue(a.peerId, Duration.ofSeconds(5))!!.value) shouldBe "v2"
            } finally {
                listOf(a, b, c).forEach { runCatching { it.node.stop() } }
            }
        }

        test("the value is still resolvable after the publisher went away").config(timeout = 60.seconds) {
            val a = newTestNode()
            val b = newTestNode()
            val c = newTestNode()
            try {
                val storageA = storageOn(a.node)
                storageOn(b.node)
                val storageC = storageOn(c.node)
                storageA.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageC.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageA.publishIpnsValue(a.signingKey, "still here".toByteArray(), 1, expiry()).acknowledged shouldBe 1

                storageA.stop()
                a.node.stop()

                String(storageC.resolveIpnsValue(a.peerId, Duration.ofSeconds(5))!!.value) shouldBe "still here"
            } finally {
                listOf(a, b, c).forEach { runCatching { it.node.stop() } }
            }
        }

        test("an unknown name resolves to null, and so does one whose only answer is not valid").config(
            timeout = 60.seconds,
        ) {
            val b = newTestNode()
            val c = newTestNode()
            try {
                storageOn(b.node)
                val storageC = storageOn(c.node)
                storageC.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageC.resolveIpnsValue(IpnsIdentity.generate().peerId, Duration.ofSeconds(3)) shouldBe null
            } finally {
                listOf(b, c).forEach { runCatching { it.node.stop() } }
            }
        }

        test("a hostile responder with forged and older records cannot beat the honest answer").config(
            timeout = 60.seconds,
        ) {
            val a = newTestNode()
            val b = newTestNode()
            val c = newTestNode()
            val mallory = ScriptedDhtPeer.start()
            try {
                val storageA = storageOn(a.node)
                storageOn(b.node)
                val storageC = storageOn(c.node)
                storageA.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageC.connectToDhtPeer(addressOf(b.node)) shouldBe true
                storageC.connectToDhtPeer(mallory.address) shouldBe true

                val aliceKey = IpnsIdentity(a.signingKey)
                val older = aliceKey.record("OLD".toByteArray(), sequence = 1, notValidAfter = expiry())
                val forged =
                    IpnsIdentity.generate().record(
                        "FORGED".toByteArray(),
                        sequence = 99,
                        notValidAfter = expiry(),
                    )
                var attempt = 0
                mallory.engine.responder = { msg, stream ->
                    if (msg.type == Dht.Message.MessageType.FIND_NODE) {
                        stream.writeAndFlush(msg)
                    } else if (msg.type == Dht.Message.MessageType.GET_VALUE) {
                        // first an older (validly signed) record, then a forged one: the second resolve below
                        val record = if (attempt++ % 2 == 0) older else forged
                        stream.writeAndFlush(
                            msg
                                .toBuilder()
                                .setRecord(
                                    Dht.Record
                                        .newBuilder()
                                        .setKey(msg.key)
                                        .setValue(ByteString.copyFrom(record))
                                        .build(),
                                ).build(),
                        )
                    }
                }

                storageA.publishIpnsValue(a.signingKey, "GENUINE".toByteArray(), 5, expiry()).acknowledged shouldBe 1

                repeat(2) {
                    val resolved = storageC.resolveIpnsValue(a.peerId, Duration.ofSeconds(5))
                    String(resolved!!.value) shouldBe "GENUINE"
                    resolved.sequence shouldBe 5
                }
                mallory.engine.received.any { it.type == Dht.Message.MessageType.GET_VALUE } shouldBe true
            } finally {
                mallory.stop()
                listOf(a, b, c).forEach { runCatching { it.node.stop() } }
            }
        }

        test("acknowledged counts the echoes that carry the record, not the requests that were sent").config(
            timeout = 60.seconds,
        ) {
            val a = newTestNode()
            val honest = newTestNode()
            val silent = ScriptedDhtPeer.start()
            val liar = ScriptedDhtPeer.start()
            try {
                val storageA = storageOn(a.node)
                storageOn(honest.node)
                storageA.connectToDhtPeer(addressOf(honest.node)) shouldBe true
                storageA.connectToDhtPeer(silent.address) shouldBe true
                storageA.connectToDhtPeer(liar.address) shouldBe true
                silent.answer(Dht.Message.MessageType.FIND_NODE) { it }
                liar.engine.responder = { msg, stream ->
                    when (msg.type) {
                        Dht.Message.MessageType.FIND_NODE -> stream.writeAndFlush(msg)
                        Dht.Message.MessageType.PUT_VALUE ->
                            stream.writeAndFlush(
                                msg
                                    .toBuilder()
                                    .setRecord(
                                        msg.record
                                            .toBuilder()
                                            .setValue(ByteString.copyFromUtf8("not it"))
                                            .build(),
                                    ).build(),
                            )
                        else -> {}
                    }
                }

                val result =
                    storageA.publishIpnsValue(
                        a.signingKey,
                        "x".toByteArray(),
                        1,
                        expiry(),
                        timeout = Duration.ofSeconds(8),
                    )

                result.attempted shouldBe 3
                result.acknowledged shouldBe 1
                silent.engine.received.any { it.type == Dht.Message.MessageType.PUT_VALUE } shouldBe true
            } finally {
                silent.stop()
                liar.stop()
                listOf(a, honest).forEach { runCatching { it.node.stop() } }
            }
        }

        test("publishing with no DHT peers known stores the value locally and reports nothing attempted").config(
            timeout = 30.seconds,
        ) {
            val a = newTestNode()
            try {
                val storageA = storageOn(a.node)
                storageA.publishIpnsValue(a.signingKey, "alone".toByteArray(), 1, expiry()) shouldBe
                    IpnsPublishResult(0, 0)
                String(storageA.resolveIpnsValue(a.peerId, Duration.ofSeconds(2))!!.value) shouldBe "alone"
            } finally {
                runCatching { a.node.stop() }
            }
        }

        test("only Ed25519 names and sane records are accepted by the API").config(timeout = 30.seconds) {
            val a = newTestNode()
            try {
                val storageA = storageOn(a.node)
                val tooFar = Instant.now().plus(Duration.ofDays(30))
                runCatching { storageA.publishIpnsValue(a.signingKey, "x".toByteArray(), 1, tooFar) }
                    .exceptionOrNull()
                    .let { (it is IllegalArgumentException) shouldBe true }
                runCatching { storageA.publishIpnsValue(a.signingKey, ByteArray(0), 1, expiry()) }
                    .exceptionOrNull()
                    .let { (it is IllegalArgumentException) shouldBe true }
                runCatching {
                    storageA.resolveIpnsValue(
                        io.libp2p.core.PeerId(
                            byteArrayOf(0x12, 0x20) + ByteArray(32) { 1 },
                        ),
                    )
                }.exceptionOrNull()
                    .let { (it is IllegalArgumentException) shouldBe true }
                runCatching { storageA.resolveIpnsValue(a.peerId, Duration.ZERO) }
                    .exceptionOrNull()
                    .let { (it is IllegalArgumentException) shouldBe true }
            } finally {
                runCatching { a.node.stop() }
            }
        }
    })
