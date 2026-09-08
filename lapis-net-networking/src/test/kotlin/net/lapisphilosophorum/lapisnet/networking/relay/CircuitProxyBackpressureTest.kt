package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.netty.bootstrap.Bootstrap
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.WriteBufferWaterMark
import io.netty.channel.embedded.EmbeddedChannel
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture

/** One forwarded chunk. Small enough that the water marks bite long before a single write does. */
private const val CHUNK_BYTES = 16 * 1024

/**
 * Hard stop for the feeding loop. If flow control did not engage, the test would push this much
 * through and fail on the assertions below rather than run forever - it is deliberately far larger
 * than any amount a working proxy should ever accept from a stalled peer.
 */
private const val MAX_OFFERED_BYTES = 64L * 1024 * 1024

/**
 * Proves the relay's forwarding path is genuinely flow-controlled: a circuit whose far end does not
 * read makes the relay **stop reading** from the near end, instead of buffering everything the near
 * end sends.
 *
 * Before this, `CircuitProxyHandler` forwarded with no backpressure at all, and the only ceilings
 * were `RelayServerLimits.circuitMaxBytes` (64 MiB) and `maxConcurrentCircuits` (128) - so a peer
 * that opened circuits and simply never read could park several GiB of relay heap at no cost to
 * itself. The node multiplexes with mplex, which has no send-buffer bound of its own, so nothing
 * below this layer caught it either.
 *
 * The setup is the real thing rather than a stand-in for it: a real TCP connection whose peer never
 * reads, so the socket really does back up and Netty's outbound buffer really does grow. The test
 * only offers more bytes while the source channel's `autoRead` is still on - which is exactly what
 * Netty itself would do - so "the proxy stopped reading" is observable as the loop ending, and
 * "memory stayed bounded" is observable as the target's queued-byte high-water sample.
 */
class CircuitProxyBackpressureTest :
    FunSpec({
        test("forwarding pauses the source and keeps queued bytes bounded when the target does not read") {
            val serverGroup = NioEventLoopGroup(1)
            val clientGroup = NioEventLoopGroup(1)
            val accepted = CompletableFuture<Channel>()
            try {
                // A server that accepts the connection and never reads a byte from it: autoRead off
                // and no read() ever issued. Its receive window closes, then the client's send
                // buffer fills, then Netty starts queueing on the heap - the exact escalation a
                // malicious or merely slow circuit peer causes.
                val server =
                    ServerBootstrap()
                        .group(serverGroup)
                        .channel(NioServerSocketChannel::class.java)
                        .childOption(ChannelOption.AUTO_READ, false)
                        .childOption(ChannelOption.SO_RCVBUF, 4 * 1024)
                        .childHandler(
                            object : ChannelInitializer<SocketChannel>() {
                                override fun initChannel(ch: SocketChannel) {
                                    accepted.complete(ch)
                                }
                            },
                        ).bind(InetSocketAddress("127.0.0.1", 0))
                        .sync()
                        .channel()
                val port = (server.localAddress() as InetSocketAddress).port

                val target =
                    Bootstrap()
                        .group(clientGroup)
                        .channel(NioSocketChannel::class.java)
                        .option(ChannelOption.SO_SNDBUF, 4 * 1024)
                        .handler(object : ChannelInboundHandlerAdapter() {})
                        .connect(InetSocketAddress("127.0.0.1", port))
                        .sync()
                        .channel()
                target.config().writeBufferWaterMark =
                    WriteBufferWaterMark(
                        CIRCUIT_WRITE_BUFFER_LOW_WATER_MARK_BYTES,
                        CIRCUIT_WRITE_BUFFER_HIGH_WATER_MARK_BYTES,
                    )

                // Stands in for the *other* leg's connection channel - the one the relay stops
                // reading from. Only its autoRead flag matters, which is precisely the lever the
                // production code pulls.
                val sourceTransport = EmbeddedChannel()
                // Stands in for the near leg's substream: this is where CircuitProxyHandler sits.
                val sourceStream =
                    EmbeddedChannel(
                        CircuitProxyHandler(
                            target = target,
                            targetTransport = target,
                            sourceTransport = sourceTransport,
                        ),
                    )
                target.pipeline().addLast(CircuitReadResumer(sourceTransport))

                var offered = 0L
                var peakQueuedBytes = 0L
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                // Feed only while the proxy still wants to read - the loop *is* the assertion that
                // autoRead is honoured, because Netty would stop delivering at exactly this point.
                while (sourceTransport.config().isAutoRead &&
                    offered < MAX_OFFERED_BYTES &&
                    Instant.now().isBefore(deadline)
                ) {
                    sourceStream.writeInbound(Unpooled.wrappedBuffer(ByteArray(CHUNK_BYTES)))
                    offered += CHUNK_BYTES
                    peakQueuedBytes = maxOf(peakQueuedBytes, queuedBytes(target))
                }

                // 1. Flow control engaged at all: the relay stopped pulling bytes in.
                sourceTransport.config().isAutoRead shouldBe false
                // 2. It engaged *early*. Everything the loop offered had to fit in the socket
                //    buffers plus one water mark's worth of heap, so it is nowhere near the
                //    circuitMaxBytes-sized flood the unbounded version accepted.
                offered shouldBeLessThan 8L * 1024 * 1024
                // 3. The heap footprint itself - what a relay pays per circuit - stayed at the
                //    water mark plus at most the write in flight when it tripped.
                peakQueuedBytes shouldBeGreaterThan 0L
                peakQueuedBytes shouldBeLessThan
                    (CIRCUIT_WRITE_BUFFER_HIGH_WATER_MARK_BYTES + 2L * CHUNK_BYTES)

                // 4. And it lifts again: once the far end drains, the resumer re-enables reading, so
                //    a merely slow peer is throttled rather than cut off.
                val consumer = accepted.get()
                consumer.pipeline().addLast(
                    object : ChannelInboundHandlerAdapter() {
                        override fun channelRead(
                            ctx: ChannelHandlerContext,
                            msg: Any,
                        ) {
                            io.netty.util.ReferenceCountUtil
                                .release(msg)
                            ctx.read()
                        }
                    },
                )
                consumer.config().isAutoRead = true
                val resumeDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (!sourceTransport.config().isAutoRead && Instant.now().isBefore(resumeDeadline)) {
                    Thread.sleep(50)
                }
                sourceTransport.config().isAutoRead shouldBe true

                sourceStream.finishAndReleaseAll()
                sourceTransport.finishAndReleaseAll()
                target.close().sync()
                server.close().sync()
            } finally {
                serverGroup.shutdownGracefully()
                clientGroup.shutdownGracefully()
            }
        }
    })

/** Bytes Netty currently holds on the heap for [channel], read on its own event loop. */
private fun queuedBytes(channel: Channel): Long =
    channel
        .eventLoop()
        .submit<Long> { channel.unsafe().outboundBuffer()?.totalPendingWriteBytes() ?: 0L }
        .get()
