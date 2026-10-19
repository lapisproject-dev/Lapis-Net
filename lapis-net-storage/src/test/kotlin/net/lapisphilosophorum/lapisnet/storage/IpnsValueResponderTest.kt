package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.host.MemoryAddressBook
import org.peergos.blockstore.RamBlockstore
import org.peergos.protocol.dht.pb.Dht
import java.lang.reflect.Proxy
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicLong

/** A [Stream] that records what is written to it and which close methods are called. */
private class RecordingStream(
    private val failWrites: Boolean = false,
) {
    val written = mutableListOf<Any>()
    val calls = mutableListOf<String>()
    val stream: Stream =
        Proxy.newProxyInstance(Stream::class.java.classLoader, arrayOf(Stream::class.java)) { _, method, args ->
            calls += method.name
            when {
                method.name == "writeAndFlush" -> {
                    if (failWrites) throw IllegalStateException("write failed")
                    written += args[0]
                    null
                }
                method.returnType == CompletableFuture::class.java -> CompletableFuture<Unit>()
                else -> null
            }
        } as Stream
}

private fun putMessage(
    key: ByteArray,
    record: ByteArray,
): Dht.Message =
    Dht.Message
        .newBuilder()
        .setType(Dht.Message.MessageType.PUT_VALUE)
        .setKey(ByteString.copyFrom(key))
        .setRecord(
            Dht.Record
                .newBuilder()
                .setKey(ByteString.copyFrom(key))
                .setValue(ByteString.copyFrom(record))
                .build(),
        ).build()

private fun getMessage(key: ByteArray): Dht.Message =
    Dht.Message
        .newBuilder()
        .setType(Dht.Message.MessageType.GET_VALUE)
        .setKey(ByteString.copyFrom(key))
        .build()

class IpnsValueResponderTest :
    FunSpec({
        val limits = DhtLimits(maxAddressesPerPeer = 4, maxAddressesPerIp = 4, maxCloserPeersPerResponse = 2)
        val alice = IpnsIdentity.generate()

        fun engine(l: DhtLimits = limits): Pair<LapisKademliaEngine, MemoryAddressBook> {
            val book = MemoryAddressBook()
            val engine =
                LapisKademliaEngine(
                    Multihash.deserialize(realPeerId().bytes),
                    BoundedProviderStore(l),
                    BoundedIpnsRecordStore(l.recordStoreCapacity),
                    RamBlockstore(),
                    l,
                )
            engine.setAddressBook(book)
            return engine to book
        }

        test("a PUT from the publisher itself is stored and answered with an echo") {
            val (engine, _) = engine()
            val stream = RecordingStream()
            val request = putMessage(alice.key, alice.record())

            engine.receiveRequest(request, alice.peerId, stream.stream)

            stream.written shouldBe listOf(request)
            engine.ipnsStore.get(alice.peerId, Instant.now()) shouldNotBe null
            engine.ipnsResponder.ipnsPutsAccepted shouldBe 1
            engine.failedInboundRequests shouldBe 0
            // answered: half-closed (closeWrite), not reset right away
            stream.calls.contains("closeWrite") shouldBe true
        }

        test("a PUT whose source is not the publisher is rejected: nothing stored, nothing written, stream closed") {
            val (engine, _) = engine()
            val stream = RecordingStream()
            val mallory = realPeerId()

            engine.receiveRequest(putMessage(alice.key, alice.record()), mallory, stream.stream)

            stream.written shouldHaveSize 0
            stream.calls shouldBe listOf("close")
            engine.ipnsStore.size() shouldBe 0
            engine.ipnsResponder.ipnsPutsRejected shouldBe 1
        }

        test("an invalid record, a tampered one and an older one are rejected, a newer one replaces") {
            val (engine, _) = engine()

            fun put(record: ByteArray): RecordingStream {
                val s = RecordingStream()
                engine.receiveRequest(putMessage(alice.key, record), alice.peerId, s.stream)
                return s
            }
            put(alice.record(sequence = 5)).written shouldHaveSize 1
            put(alice.record(sequence = 4)).written shouldHaveSize 0
            put(tamper(alice.record(sequence = 9)) { it.setValue(ByteString.copyFromUtf8("x")) }).written shouldHaveSize
                0
            put(alice.record(sequence = 5, notValidAfter = Instant.now().minusSeconds(3600))).written shouldHaveSize 0
            engine.ipnsStore.get(alice.peerId, Instant.now())!!.sequence shouldBe 5
            put(alice.record(sequence = 6)).written shouldHaveSize 1
            engine.ipnsStore.get(alice.peerId, Instant.now())!!.sequence shouldBe 6
            // an identical republish is acknowledged again
            val same = alice.record(sequence = 6)
            put(same).written shouldHaveSize 1
        }

        test("a PUT whose key is not an Ed25519 IPNS name never reaches the responder") {
            val (engine, _) = engine()
            val stream = RecordingStream()
            val key = "/ipns/".toByteArray() + byteArrayOf(0x12, 0x20) + ByteArray(32) { 4 }

            engine.receiveRequest(putMessage(key, alice.record()), alice.peerId, stream.stream)

            stream.written shouldHaveSize 0
            engine.rejectedInboundRequests shouldBe 1
            engine.ipnsResponder.ipnsPutsRejected shouldBe 0
        }

        test("rate limit per source: the bucket empties, refills over time, and is shared by all keys of one source") {
            val clock = AtomicLong(0)
            val store = BoundedIpnsRecordStore(16)
            val l = DhtLimits(maxValuePutsPerSourcePerMinute = 3)
            val responder =
                IpnsValueResponder(store, l, { _, _ -> emptyList() }, nanoClock = { clock.get() })

            fun put(seq: Long): Int {
                val s = RecordingStream()
                responder.handlePut(putMessage(alice.key, alice.record(sequence = seq)), alice.peerId, s.stream)
                return s.written.size
            }
            put(1) shouldBe 1
            put(2) shouldBe 1
            put(3) shouldBe 1
            put(4) shouldBe 0 // bucket empty
            clock.addAndGet(Duration.ofSeconds(21).toNanos()) // 3 per minute = one per 20 s
            put(5) shouldBe 1
            put(6) shouldBe 0
        }

        test("a rejected request still costs a token, so garbage cannot be used to probe for free") {
            val clock = AtomicLong(0)
            val l = DhtLimits(maxValuePutsPerSourcePerMinute = 2)
            val responder =
                IpnsValueResponder(BoundedIpnsRecordStore(16), l, { _, _ -> emptyList() }, nanoClock = { clock.get() })
            val bad = tamper(alice.record()) { it.setSequence(77) }
            repeat(2) { responder.handlePut(putMessage(alice.key, bad), alice.peerId, RecordingStream().stream) }
            val s = RecordingStream()
            responder.handlePut(putMessage(alice.key, alice.record()), alice.peerId, s.stream)
            s.written shouldHaveSize 0
        }

        test("the rate tracker stays bounded however many sources there are") {
            val l = DhtLimits(valueRateTrackerCapacity = 4)
            val responder = IpnsValueResponder(BoundedIpnsRecordStore(64), l, { _, _ -> emptyList() })
            repeat(40) {
                val id = IpnsIdentity.generate()
                responder.handlePut(putMessage(id.key, id.record()), id.peerId, RecordingStream().stream)
            }
            responder.trackedSources() shouldBe 4
        }

        test("a GET returns the held record and at most maxCloserPeersPerResponse closest peers") {
            val (engine, book) = engine()
            repeat(5) { i ->
                val peer = realPeerId()
                engine.addOutgoingConnection(peer)
                book.setAddrs(peer, 0, Multiaddr("/ip4/1.2.3.${i + 1}/tcp/4001")).join()
            }
            engine.receiveRequest(
                putMessage(alice.key, alice.record(value = "held".toByteArray())),
                alice.peerId,
                RecordingStream().stream,
            )

            val stream = RecordingStream()
            engine.receiveRequest(getMessage(alice.key), realPeerId(), stream.stream)

            val reply = stream.written.single() as Dht.Message
            reply.type shouldBe Dht.Message.MessageType.GET_VALUE
            reply.key shouldBe ByteString.copyFrom(alice.key)
            reply.hasRecord() shouldBe true
            val validated =
                IpnsRecordCodec.validate(
                    alice.key,
                    reply.record.value.toByteArray(),
                    Instant.now(),
                    limits,
                )!!
            String(validated.value) shouldBe "held"
            reply.closerPeersList shouldHaveSize limits.maxCloserPeersPerResponse
            engine.ipnsResponder.ipnsGetsAnswered shouldBe 1
        }

        test("a GET for an unknown name returns closer peers and no record") {
            val (engine, book) = engine()
            val peer = realPeerId()
            engine.addOutgoingConnection(peer)
            book.setAddrs(peer, 0, Multiaddr("/ip4/1.2.3.4/tcp/4001")).join()

            val stream = RecordingStream()
            engine.receiveRequest(getMessage(IpnsIdentity.generate().key), realPeerId(), stream.stream)

            val reply = stream.written.single() as Dht.Message
            reply.hasRecord() shouldBe false
            reply.closerPeersList shouldHaveSize 1
        }

        test("a routing-table entry without an address-book entry does not break a GET (no NPE)") {
            val (engine, _) = engine()
            engine.addOutgoingConnection(realPeerId())

            val stream = RecordingStream()
            engine.receiveRequest(getMessage(alice.key), realPeerId(), stream.stream)

            stream.written shouldHaveSize 1
            engine.failedInboundRequests shouldBe 0
        }

        test("an expired held record is not served") {
            val (engine, _) = engine()
            val soon = Instant.now().plusSeconds(1)
            engine.ipnsStore.putIfNewer(alice.validated(notValidAfter = soon), Instant.now()) shouldBe true
            engine.ipnsStore.get(alice.peerId, Instant.now().plusSeconds(30)) shouldBe null
        }

        test("an exception inside the handler is counted and the stream is closed, not propagated") {
            val (engine, _) = engine()
            val stream = RecordingStream(failWrites = true)

            engine.receiveRequest(putMessage(alice.key, alice.record()), alice.peerId, stream.stream)

            engine.failedInboundRequests shouldBe 1
            stream.calls.contains("close") shouldBe true
        }

        test("PUT_VALUE and GET_VALUE are never delegated to Nabu's record handling") {
            val (engine, _) = engine()
            // Nabu's own handler would have put this into the store it was given; that store is empty
            // and ignores writes, so a stored-through-Nabu path could never serve it back
            val stream = RecordingStream()
            engine.receiveRequest(putMessage(alice.key, alice.record()), alice.peerId, stream.stream)
            val reply = RecordingStream()
            engine.receiveRequest(getMessage(alice.key), PeerId.random(), reply.stream)
            (reply.written.single() as Dht.Message).hasRecord() shouldBe true
        }
    })
