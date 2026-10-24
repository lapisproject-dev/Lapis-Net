package net.lapisphilosophorum.lapisnet.mailonion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dmonion.FakeChannel
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch

class OnionMailInboundHandlerTest :
    FunSpec({
        val frame = ByteArray(500) { it.toByte() }

        fun bundle(blobs: List<ByteArray> = emptyList()) = MailCircuitBundleCodec.encode(frame, blobs)

        fun send(
            client: FakeChannel,
            bundle: ByteArray,
        ) = MailCircuitFraming
            .chunks(
                MailCircuitFraming.bundleFrame(bundle),
                client.maxPayload,
            ).forEach { client.send(it) }

        fun headerFor(length: Int): ByteArray =
            ByteBuffer
                .allocate(5)
                .put(3)
                .putInt(length)
                .array()

        fun acks(client: FakeChannel): Int =
            client.peer!!.sent.count { it.contentEquals(MailCircuitFraming.ackFrame()) }

        test("a bundle is acknowledged and handed to the sink; the ack does not wait for the sink") {
            val sink = CollectingMailSink()
            val gate = CountDownLatch(1)
            sink.gate = gate
            val handler = OnionMailInboundHandler(sink)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                send(client, bundle(listOf(ByteArray(2000) { 9 })))
                acks(client) shouldBe 1
                sink.received.size shouldBe 0
                gate.countDown()
                waitFor { sink.received.size == 1 } shouldBe true
                sink.received
                    .single()
                    .frame
                    .contentEquals(frame) shouldBe true
                sink.received
                    .single()
                    .blobs
                    .single()
                    .size shouldBe 2000
            } finally {
                gate.countDown()
                handler.close()
            }
        }

        test("the acknowledgement is identical whatever the sink decides, and a malformed bundle is acknowledged too") {
            val refusing = CollectingMailSink()
            val handler = OnionMailInboundHandler(refusing)
            try {
                val (c1, s1) = FakeChannel.pair()
                val (c2, s2) = FakeChannel.pair()
                handler.handleChannel(s1)
                handler.handleChannel(s2)
                send(c1, bundle())
                send(c2, ByteArray(100) { 3 }) // not a bundle at all
                c1.peer!!.sent.map { it.toList() } shouldBe c2.peer!!.sent.map { it.toList() }
                acks(c1) shouldBe 1
                acks(c2) shouldBe 1
                s1.isClosed shouldBe false
                s2.isClosed shouldBe false
                waitFor { refusing.received.size == 1 } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("the fifth concurrent stream is closed at once, the first four are served") {
            val handler = OnionMailInboundHandler(CollectingMailSink())
            try {
                val pairs = List(5) { FakeChannel.pair() }
                pairs.forEach { handler.handleChannel(it.second) }
                pairs.take(4).all { !it.second.isClosed } shouldBe true
                pairs[4].second.isClosed shouldBe true
                handler.openStreams() shouldBe 4
                handler.refusedStreamCount() shouldBe 1
            } finally {
                handler.close()
            }
        }

        test("a second bundle on the same stream ends the stream and does not reach the sink") {
            val sink = CollectingMailSink()
            val handler = OnionMailInboundHandler(sink)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                send(client, bundle())
                send(client, bundle())
                waitFor { server.isClosed } shouldBe true
                waitFor { sink.received.size == 1 } shouldBe true
                Thread.sleep(100)
                sink.received.size shouldBe 1
            } finally {
                handler.close()
            }
        }

        test("a declared length beyond the maximum closes the stream before anything is allocated or queued") {
            val sink = CollectingMailSink()
            val handler = OnionMailInboundHandler(sink)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                client.send(
                    ByteBuffer
                        .allocate(5)
                        .put(3)
                        .putInt(MailCircuitFraming.MAX_FRAME_BYTES + 1)
                        .array(),
                )
                waitFor { server.isClosed } shouldBe true
                sink.received.size shouldBe 0
                acks(client) shouldBe 0
            } finally {
                handler.close()
            }
        }

        test(
            "the byte budget is reserved from the header length: an over-budget bundle is refused before its body arrives",
        ) {
            val sink = CollectingMailSink()
            val handler = OnionMailInboundHandler(sink, maxBytesPerMinute = 1000)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                client.send(
                    ByteBuffer
                        .allocate(5)
                        .put(3)
                        .putInt(5000)
                        .array(),
                ) // header only
                waitFor { server.isClosed } shouldBe true
                sink.received.size shouldBe 0
            } finally {
                handler.close()
            }
        }

        test("the bundle rate limit closes further bundles within the minute and refills afterwards") {
            val clock = SteppingClock()
            val sink = CollectingMailSink()
            val handler = OnionMailInboundHandler(sink, clock = clock, maxBundlesPerMinute = 2)
            try {
                val results =
                    List(3) {
                        val (client, server) = FakeChannel.pair()
                        handler.handleChannel(server)
                        send(client, bundle())
                        server.isClosed
                    }
                results shouldBe listOf(false, false, true)
                clock.millis += 61_000
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                send(client, bundle())
                server.isClosed shouldBe false
            } finally {
                handler.close()
            }
        }

        test("an idle gap inside a frame and an overlong stream are cut by the sweeper") {
            val clock = SteppingClock()
            val handler = OnionMailInboundHandler(CollectingMailSink(), clock = clock, sweepMillis = 20)
            try {
                val (idleClient, idleServer) = FakeChannel.pair()
                handler.handleChannel(idleServer)
                idleClient.send(byteArrayOf(3, 0, 0)) // half a header
                clock.millis += 10_001
                waitFor { idleServer.isClosed } shouldBe true

                val (quiet, quietServer) = FakeChannel.pair()
                handler.handleChannel(quietServer)
                quiet.sent.size shouldBe 0
                clock.millis += 120_001
                waitFor { quietServer.isClosed } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("a stream that never sends a byte is closed after the first-byte deadline and frees its slot") {
            val clock = SteppingClock()
            val handler = OnionMailInboundHandler(CollectingMailSink(), clock = clock, sweepMillis = 20)
            try {
                val pairs = List(4) { FakeChannel.pair() }
                pairs.forEach { handler.handleChannel(it.second) }
                handler.openStreams() shouldBe 4
                clock.millis += OnionMailInboundHandler.FIRST_BYTE_MILLIS + 1
                waitFor { pairs.all { it.second.isClosed } } shouldBe true
                waitFor { handler.openStreams() == 0 } shouldBe true
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                send(client, bundle())
                server.isClosed shouldBe false
                acks(client) shouldBe 1
            } finally {
                handler.close()
            }
        }

        test("a trickle of one byte per idle interval is cut long before the stream lifetime and frees the slot") {
            val clock = SteppingClock()
            val handler = OnionMailInboundHandler(CollectingMailSink(), clock = clock, sweepMillis = 20)
            try {
                val pairs = List(4) { FakeChannel.pair() }
                pairs.forEach { handler.handleChannel(it.second) }
                val header = headerFor(400_000)
                var elapsed = 0L
                var step = 0
                while (elapsed < OnionMailInboundHandler.LIFETIME_MILLIS && !pairs.all { it.second.isClosed }) {
                    pairs.forEach { (client, server) ->
                        if (!server.isClosed) client.send(byteArrayOf(if (step < 5) header[step] else 7))
                    }
                    step++
                    clock.millis += OnionMailInboundHandler.IDLE_MILLIS - 1
                    elapsed += OnionMailInboundHandler.IDLE_MILLIS - 1
                    Thread.sleep(60)
                }
                waitFor { pairs.all { it.second.isClosed } } shouldBe true
                (elapsed < OnionMailInboundHandler.LIFETIME_MILLIS) shouldBe true
                waitFor { handler.openStreams() == 0 } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("a body trickled one byte per idle interval after a complete header is cut and frees the slot") {
            val clock = SteppingClock()
            val handler = OnionMailInboundHandler(CollectingMailSink(), clock = clock, sweepMillis = 20)
            try {
                val pairs = List(4) { FakeChannel.pair() }
                pairs.forEach { handler.handleChannel(it.second) }
                // the header arrives at once and satisfies the header deadline
                pairs.forEach { (client, _) -> client.send(headerFor(400_000)) }
                var elapsed = 0L
                while (elapsed < OnionMailInboundHandler.LIFETIME_MILLIS && !pairs.all { it.second.isClosed }) {
                    pairs.forEach { (client, server) -> if (!server.isClosed) client.send(byteArrayOf(7)) }
                    clock.millis += OnionMailInboundHandler.IDLE_MILLIS - 1
                    elapsed += OnionMailInboundHandler.IDLE_MILLIS - 1
                    Thread.sleep(60)
                }
                waitFor { pairs.all { it.second.isClosed } } shouldBe true
                // idle grace plus a few intervals, far before the stream lifetime
                (elapsed < OnionMailInboundHandler.LIFETIME_MILLIS / 2) shouldBe true
                waitFor { handler.openStreams() == 0 } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("a body arriving above the minimum rate is not cut and is acknowledged") {
            val clock = SteppingClock()
            val sink = CollectingMailSink()
            val handler = OnionMailInboundHandler(sink, clock = clock, sweepMillis = 20)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                val chunks =
                    MailCircuitFraming.chunks(
                        MailCircuitFraming.bundleFrame(bundle(listOf(ByteArray(300_000) { 5 }))),
                        client.maxPayload,
                    )
                // about 20 KB/s: well above the minimum, and long enough to pass the grace period
                chunks.forEachIndexed { index, chunk ->
                    client.send(chunk)
                    clock.millis += chunk.size * 1000L / 20_000L
                    if (index % 20 == 19) Thread.sleep(40)
                }
                server.isClosed shouldBe false
                acks(client) shouldBe 1
                waitFor { sink.received.size == 1 } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("a stream is closed by the receiver shortly after its single bundle was acknowledged") {
            val clock = SteppingClock()
            val handler = OnionMailInboundHandler(CollectingMailSink(), clock = clock, sweepMillis = 20)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                send(client, bundle())
                acks(client) shouldBe 1
                server.isClosed shouldBe false
                clock.millis += OnionMailInboundHandler.ACK_GRACE_MILLIS + 1
                waitFor { server.isClosed } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("budget reserved by a header whose body never arrives is returned when the stream is cut") {
            val clock = SteppingClock()
            val sink = CollectingMailSink()
            val handler =
                OnionMailInboundHandler(
                    sink,
                    clock = clock,
                    maxBytesPerMinute = 1000,
                    maxBundlesPerMinute = 2,
                    sweepMillis = 20,
                )
            try {
                repeat(3) {
                    val (client, server) = FakeChannel.pair()
                    handler.handleChannel(server)
                    client.send(
                        ByteBuffer
                            .allocate(5)
                            .put(3)
                            .putInt(900)
                            .array(),
                    ) // header only, reserves 900 bytes and 1 bundle
                    clock.millis += 10_001
                    waitFor { server.isClosed } shouldBe true
                }
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                send(client, bundle())
                server.isClosed shouldBe false
                acks(client) shouldBe 1
                waitFor { sink.received.size == 1 } shouldBe true
            } finally {
                handler.close()
            }
        }

        test("a full work queue closes the stream without an acknowledgement") {
            val sink = CollectingMailSink()
            val gate = CountDownLatch(1)
            sink.gate = gate
            val handler = OnionMailInboundHandler(sink, queueCapacity = 1)
            try {
                // core thread, queue slot, second worker thread, then the pool is full
                val pairs = List(4) { FakeChannel.pair() }
                pairs.forEach { (client, server) ->
                    handler.handleChannel(server)
                    send(client, bundle())
                }
                acks(pairs[0].first) shouldBe 1
                acks(pairs[1].first) shouldBe 1
                acks(pairs[2].first) shouldBe 1
                acks(pairs[3].first) shouldBe 0
                pairs[3].second.isClosed shouldBe true
            } finally {
                gate.countDown()
                handler.close()
            }
        }

        test("close releases every stream and is idempotent; a stream arriving afterwards is closed") {
            val handler = OnionMailInboundHandler(CollectingMailSink())
            val (_, s1) = FakeChannel.pair()
            handler.handleChannel(s1)
            handler.close()
            handler.close()
            s1.isClosed shouldBe true
            val (_, s2) = FakeChannel.pair()
            handler.handleChannel(s2)
            s2.isClosed shouldBe true
            handler.toString() shouldBe "OnionMailInboundHandler(REDACTED)"
        }
    })
