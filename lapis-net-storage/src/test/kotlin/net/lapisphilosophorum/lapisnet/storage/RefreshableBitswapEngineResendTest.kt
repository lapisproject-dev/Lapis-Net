package net.lapisphilosophorum.lapisnet.storage

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.google.protobuf.ByteString
import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.prometheus.client.Counter
import org.peergos.BlockRequestAuthoriser
import org.peergos.blockstore.RamBlockstore
import org.peergos.protocol.bitswap.BitswapEngine
import org.peergos.protocol.bitswap.pb.MessageOuterClass.Message
import org.slf4j.LoggerFactory
import java.lang.reflect.Proxy
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Fix wave F6: the HOLDER side. Nabu's responder skips a WANT_BLOCK for a block it already sent to the same peer -
 * forever, silently. [RefreshableBitswapEngine] answers such a re-send again, within [BitswapResendLimits].
 */
class RefreshableBitswapEngineResendTest :
    FunSpec({
        val now = AtomicLong()
        val authoriser = BlockRequestAuthoriser { _, _, _ -> CompletableFuture.completedFuture(true) }
        val counter: Counter =
            Counter
                .build()
                .name("f6_test_sent_bytes")
                .help("bytes")
                .create()

        /** A stream from [peer] whose writes are recorded. */
        class FakeStream(
            val peer: PeerId,
        ) {
            val written = CopyOnWriteArrayList<Message>()
            val stream: Stream =
                Proxy.newProxyInstance(
                    Stream::class.java.classLoader,
                    arrayOf(Stream::class.java),
                ) { proxy, method, args ->
                    when (method.name) {
                        "remotePeerId" -> peer
                        "writeAndFlush" -> {
                            written += args[0] as Message
                            null
                        }
                        "close" -> CompletableFuture.completedFuture(Unit)
                        "hashCode" -> System.identityHashCode(proxy)
                        "equals" -> proxy === args?.get(0)
                        "toString" -> "FakeStream"
                        else -> throw UnsupportedOperationException(method.name)
                    }
                } as Stream

            fun blocksReceived(): Int = written.sumOf { it.payloadCount }
        }

        fun wantBlock(
            cid: Cid,
            typeValue: Int = 0,
            cancel: Boolean = false,
        ): Message.Wantlist.Entry =
            Message.Wantlist.Entry
                .newBuilder()
                .setBlock(ByteString.copyFrom(cid.toBytes()))
                .setWantTypeValue(typeValue)
                .setCancel(cancel)
                .build()

        fun messageOf(vararg entries: Message.Wantlist.Entry): Message =
            Message
                .newBuilder()
                .setWantlist(Message.Wantlist.newBuilder().addAllEntries(entries.toList()))
                .build()

        fun blockstoreWith(payload: ByteArray): Pair<RamBlockstore, Cid> {
            val store = RamBlockstore()
            return store to store.put(payload, Cid.Codec.Raw).join()
        }

        fun engine(
            store: RamBlockstore,
            limits: BitswapResendLimits = BitswapResendLimits(),
        ) = RefreshableBitswapEngine(store, authoriser, 2 * 1024 * 1024, limits) { now.get() }

        fun advance(d: Duration) = now.addAndGet(d.toNanos())

        test("the workaround is active against this Nabu version") {
            val (store, _) = blockstoreWith("active".toByteArray())
            engine(store).resendWorkaroundActive shouldBe true
        }

        test("Nabu alone never sends a block twice to the same peer; the engine does after the minimum interval") {
            now.set(0)
            val (store, cid) = blockstoreWith("twice".toByteArray())
            val peer = realPeerId()

            val nabu = BitswapEngine(store, authoriser, 2 * 1024 * 1024, false)
            val nabuStream = FakeStream(peer)
            nabu.receiveMessage(messageOf(wantBlock(cid)), nabuStream.stream, counter)
            nabu.receiveMessage(messageOf(wantBlock(cid)), nabuStream.stream, counter)
            nabuStream.blocksReceived() shouldBe 1 // the cause of the gap

            val ours = engine(store)
            val s = FakeStream(peer)
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter)
            advance(Duration.ofSeconds(6))
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter)
            s.blocksReceived() shouldBe 2
            ours.resendStats().allowed shouldBe 1
        }

        test("within the minimum interval only one re-send goes out") {
            now.set(0)
            val (store, cid) = blockstoreWith("interval".toByteArray())
            val ours = engine(store)
            val s = FakeStream(realPeerId())
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter) // first send: Nabu's own
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter) // first re-send: no stamp yet, allowed
            repeat(5) {
                advance(Duration.ofMillis(500))
                ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter)
            }
            s.blocksReceived() shouldBe 2
            ours.resendStats().allowed shouldBe 1
            ours.resendStats().deniedInterval shouldBe 5
        }

        test("another peer is independent") {
            now.set(0)
            val (store, cid) = blockstoreWith("independent".toByteArray())
            val ours = engine(store)
            val a = FakeStream(realPeerId())
            val b = FakeStream(realPeerId())
            ours.receiveMessage(messageOf(wantBlock(cid)), a.stream, counter)
            ours.receiveMessage(messageOf(wantBlock(cid)), a.stream, counter)
            ours.receiveMessage(messageOf(wantBlock(cid)), a.stream, counter) // denied: interval
            ours.receiveMessage(messageOf(wantBlock(cid)), b.stream, counter) // B's first send
            ours.receiveMessage(messageOf(wantBlock(cid)), b.stream, counter) // B's first re-send
            a.blocksReceived() shouldBe 2
            b.blocksReceived() shouldBe 2
        }

        test("the per-peer bucket bounds re-sends of many blocks") {
            now.set(0)
            val store = RamBlockstore()
            val cids = List(5) { store.put("bucket-$it".toByteArray(), Cid.Codec.Raw).join() }
            val ours = engine(store, BitswapResendLimits(perPeerPerMinute = 2, perPeerBurst = 2))
            val s = FakeStream(realPeerId())
            ours.receiveMessage(messageOf(*cids.map { wantBlock(it) }.toTypedArray()), s.stream, counter)
            s.blocksReceived() shouldBe 5
            ours.receiveMessage(messageOf(*cids.map { wantBlock(it) }.toTypedArray()), s.stream, counter)
            s.blocksReceived() shouldBe 7
            ours.resendStats().deniedPeer shouldBe 3
        }

        test("WANT_HAVE and cancel entries pass unchanged") {
            now.set(0)
            val (store, cid) = blockstoreWith("have".toByteArray())
            val ours = engine(store)
            val s = FakeStream(realPeerId())
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter)
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter)
            // both entries name a block already sent, and the interval would deny a WANT_BLOCK now
            val have = messageOf(wantBlock(cid, typeValue = 1))
            ours.prepareResends(have, s.peer) shouldBeSameInstanceAs have
            val cancel = messageOf(wantBlock(cid, cancel = true))
            ours.prepareResends(cancel, s.peer) shouldBeSameInstanceAs cancel
            ours.resendStats().deniedInterval shouldBe 0
        }

        test("an entry with a malformed CID takes Nabu's own path") {
            now.set(0)
            val (store, cid) = blockstoreWith("malformed".toByteArray())
            val peer = realPeerId()
            val broken =
                messageOf(
                    Message.Wantlist.Entry
                        .newBuilder()
                        .setBlock(ByteString.copyFrom(byteArrayOf(0x7f, 0x01, 0x02)))
                        .setWantTypeValue(0)
                        .build(),
                )

            val ours = engine(store)
            val s = FakeStream(peer)
            ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter) // the peer's map exists now
            ours.prepareResends(broken, peer) shouldBeSameInstanceAs broken
            val oursFailure = runCatching { ours.receiveMessage(broken, s.stream, counter) }.exceptionOrNull()

            val nabu = BitswapEngine(store, authoriser, 2 * 1024 * 1024, false)
            val n = FakeStream(peer)
            nabu.receiveMessage(messageOf(wantBlock(cid)), n.stream, counter)
            val nabuFailure = runCatching { nabu.receiveMessage(broken, n.stream, counter) }.exceptionOrNull()

            oursFailure?.javaClass shouldBe nabuFailure?.javaClass
            s.written.size shouldBe n.written.size
        }

        test("nothing about a CID or a peer is logged") {
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            try {
                now.set(0)
                val (store, cid) = blockstoreWith("log".toByteArray())
                val peer = realPeerId()
                val ours = engine(store, BitswapResendLimits(perPeerPerMinute = 1, perPeerBurst = 1))
                val s = FakeStream(peer)
                repeat(10) { ours.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter) }
                val ours2 = engine(store, BitswapResendLimits(perPeerPerMinute = 1, perPeerBurst = 1))
                ours2.receiveMessage(messageOf(wantBlock(cid)), s.stream, counter)
                ours.resendStats().deniedInterval shouldBe 8
                val leaks =
                    appender.list.filter {
                        val text = it.formattedMessage
                        text.contains(cid.toString()) || text.contains(peer.toBase58()) || text.contains(peer.toHex())
                    }
                leaks.shouldBeEmpty()
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
            }
        }
    })
