package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec
import net.lapisphilosophorum.lapisnet.dm.DmInboundSink
import java.nio.ByteBuffer
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private class RecordingSink : DmInboundSink {
    val envelopes = CopyOnWriteArrayList<ByteArray>()
    val sealed = CopyOnWriteArrayList<ByteArray>()

    @Volatile var gate: CountDownLatch? = null

    override fun acceptCircuitEnvelope(envelopeBytes: ByteArray) {
        gate?.await(20, TimeUnit.SECONDS)
        envelopes += envelopeBytes
    }

    override fun acceptSealedMailboxItem(itemBytes: ByteArray) {
        sealed += itemBytes
    }
}

private class SteppingClock(
    @Volatile var millis: Long = 1_000_000L,
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

private fun waitFor(condition: () -> Boolean): Boolean {
    val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (System.nanoTime() < end) {
        if (condition()) return true
        Thread.sleep(10)
    }
    return condition()
}

class OnionDmInboundHandlerTest :
    FunSpec({
        fun send(
            client: FakeChannel,
            payload: ByteArray,
        ) = DmCircuitFraming
            .chunks(
                DmCircuitFraming.envelopeFrame(payload),
                client.maxPayload,
            ).forEach { client.send(it) }

        fun acks(client: FakeChannel): Int = client.peer!!.sent.count { it.contentEquals(DmCircuitFraming.ackFrame()) }

        test("an envelope is acknowledged and handed to the sink; the ack does not wait for the sink") {
            val sink = RecordingSink()
            val gate = CountDownLatch(1)
            sink.gate = gate
            val handler = OnionDmInboundHandler(sink)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                val envelope = ByteArray(3_000) { it.toByte() }
                send(client, envelope)
                // the sink is still blocked, yet the constant acknowledgement is already out
                acks(client) shouldBe 1
                sink.envelopes.size shouldBe 0
                gate.countDown()
                waitFor { sink.envelopes.size == 1 } shouldBe true
                sink.envelopes[0].contentEquals(envelope) shouldBe true
            } finally {
                gate.countDown()
                handler.close()
            }
        }

        test("a padded envelope is acknowledged only after the whole size class, and the sink gets the exact bytes") {
            val sink = RecordingSink()
            val handler = OnionDmInboundHandler(sink)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                val envelope = ByteArray(3_000) { (it * 7).toByte() }
                val chunks =
                    DmCircuitFraming.chunks(
                        DmCircuitFraming.paddedEnvelopeFrame(envelope, client.maxPayload),
                        client.maxPayload,
                    )
                chunks.size shouldBe 4
                chunks.dropLast(1).forEach { client.send(it) }
                Thread.sleep(100)
                acks(client) shouldBe 0
                sink.envelopes.size shouldBe 0
                client.send(chunks.last())
                waitFor { acks(client) == 1 } shouldBe true
                waitFor { sink.envelopes.size == 1 } shouldBe true
                sink.envelopes[0].contentEquals(envelope) shouldBe true
            } finally {
                handler.close()
            }
        }

        test(
            "a padded frame that stops short of its class is never acknowledged and the idle sweep closes the stream",
        ) {
            val sink = RecordingSink()
            val handler = OnionDmInboundHandler(sink, idleMillis = 300, sweepMillis = 50)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                val chunks =
                    DmCircuitFraming.chunks(
                        DmCircuitFraming.paddedEnvelopeFrame(ByteArray(3_000), client.maxPayload),
                        client.maxPayload,
                    )
                chunks.dropLast(1).forEach { client.send(it) }
                waitFor { server.isClosed } shouldBe true
                acks(client) shouldBe 0
                sink.envelopes.size shouldBe 0
            } finally {
                handler.close()
            }
        }

        test("an oversize length closes the stream and nothing reaches the sink") {
            val sink = RecordingSink()
            val handler = OnionDmInboundHandler(sink)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                client.send(
                    ByteBuffer
                        .allocate(5)
                        .put(1)
                        .putInt(DmEnvelopeCodec.MAX_ENVELOPE_BYTES + 1)
                        .array(),
                )
                waitFor { server.isClosed } shouldBe true
                acks(client) shouldBe 0
                sink.envelopes.size shouldBe 0
                handler.openStreams() shouldBe 0
            } finally {
                handler.close()
            }
        }

        test("the seventeenth envelope on one stream closes it") {
            val sink = RecordingSink()
            val handler = OnionDmInboundHandler(sink, maxEnvelopesPerMinute = 1000)
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                repeat(16) { send(client, ByteArray(10) { 1 }) }
                server.isClosed shouldBe false
                send(client, ByteArray(10) { 1 })
                server.isClosed shouldBe true
                acks(client) shouldBe 16
            } finally {
                handler.close()
            }
        }

        test("the global inbound rate is enforced without an acknowledgement for the excess") {
            val sink = RecordingSink()
            val handler = OnionDmInboundHandler(sink, maxEnvelopesPerMinute = 3)
            try {
                val streams = List(5) { FakeChannel.pair() }
                streams.forEach { (client, server) ->
                    handler.handleChannel(server)
                    send(client, ByteArray(10) { 1 })
                }
                streams.count { acks(it.first) == 1 } shouldBe 3
                streams.count { it.second.isClosed } shouldBe 2
            } finally {
                handler.close()
            }
        }

        test("a full work queue closes the stream without an acknowledgement") {
            val sink = RecordingSink()
            val gate = CountDownLatch(1)
            sink.gate = gate
            val handler = OnionDmInboundHandler(sink, queueCapacity = 1, maxEnvelopesPerMinute = 1000)
            try {
                // two worker threads are busy on the gate and one slot is queued: the next ones are refused
                val outcomes =
                    List(8) {
                        val (client, server) = FakeChannel.pair()
                        handler.handleChannel(server)
                        send(client, ByteArray(10) { 1 })
                        client to server
                    }
                outcomes.count { it.second.isClosed } shouldBe outcomes.count { acks(it.first) == 0 }
                (outcomes.count { it.second.isClosed } > 0) shouldBe true
            } finally {
                gate.countDown()
                handler.close()
            }
        }

        test("a stalled partial frame is closed after the idle time and an old stream after its lifetime") {
            val clock = SteppingClock()
            val handler =
                OnionDmInboundHandler(
                    RecordingSink(),
                    clock,
                    idleMillis = 10_000,
                    lifetimeMillis = 100_000,
                    sweepMillis = 20,
                )
            try {
                val (stalled, stalledServer) = FakeChannel.pair()
                handler.handleChannel(stalledServer)
                stalled.send(DmCircuitFraming.envelopeFrame(ByteArray(100)).copyOfRange(0, 20))
                val (idleClient, idleServer) = FakeChannel.pair()
                handler.handleChannel(idleServer)
                clock.millis += 11_000
                waitFor { stalledServer.isClosed } shouldBe true
                idleServer.isClosed shouldBe false
                clock.millis += 100_000
                waitFor { idleServer.isClosed } shouldBe true
                idleClient.isClosed shouldBe true
            } finally {
                handler.close()
            }
        }

        test("a type other than ENVELOPE closes the stream") {
            val handler = OnionDmInboundHandler(RecordingSink())
            try {
                val (client, server) = FakeChannel.pair()
                handler.handleChannel(server)
                client.send(DmCircuitFraming.ackFrame())
                server.isClosed shouldBe true
            } finally {
                handler.close()
            }
        }
    })
