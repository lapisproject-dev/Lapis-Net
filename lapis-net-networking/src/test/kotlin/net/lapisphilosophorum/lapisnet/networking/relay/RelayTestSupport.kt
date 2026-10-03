package net.lapisphilosophorum.lapisnet.networking.relay

import io.netty.bootstrap.Bootstrap
import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.WriteBufferWaterMark
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** One forwarded chunk. Small enough that the water marks bite long before a single write does. */
internal const val CHUNK_BYTES = 16 * 1024

/** Bytes Netty currently holds on the heap for [channel], read on its own event loop. */
internal fun queuedBytes(channel: Channel): Long =
    channel
        .eventLoop()
        .submit<Long> { channel.unsafe().outboundBuffer()?.totalPendingWriteBytes() ?: 0L }
        .get()

/** Polls [condition] every 20 ms until it holds or [timeout] elapses; returns whether it held. */
internal fun awaitCondition(
    timeout: Duration,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(20)
    }
    return condition()
}

/**
 * A real loopback TCP connection whose far end can be told to stop reading - the only honest way to
 * make Netty's outbound buffer grow the way a non-reading circuit peer makes it grow.
 *
 * [client] is what a relay would write to (its write buffer is the one whose writability matters;
 * its water marks match production). [accepted] is the far end: it starts with `autoRead` off and
 * reads nothing until [startDraining] / [drainBriefly] is called, so its receive window closes, then
 * [client]'s send buffer fills, then Netty queues on the heap.
 */
internal class NonReadingLink(
    group: NioEventLoopGroup,
    serverAutoRead: Boolean = false,
    applyProductionWaterMarks: Boolean = true,
    /** Tiny socket buffers make the heap queue grow almost immediately - what the bound tests want.
     * A slow-reader test wants the opposite: with a closed 4 KiB window the kernel's own
     * window-update/persist behaviour, not the code under test, would dominate how fast it drains. */
    smallBuffers: Boolean = true,
) : AutoCloseable {
    private val acceptedFuture = CompletableFuture<Channel>()
    private val server: Channel =
        ServerBootstrap()
            .group(group)
            .channel(NioServerSocketChannel::class.java)
            .childOption(ChannelOption.AUTO_READ, serverAutoRead)
            .also { if (smallBuffers) it.childOption(ChannelOption.SO_RCVBUF, 4 * 1024) }
            .childHandler(
                object : ChannelInitializer<SocketChannel>() {
                    override fun initChannel(ch: SocketChannel) {
                        // A discarding sink: whatever it reads is released, never kept.
                        ch.pipeline().addLast(
                            object : ChannelInboundHandlerAdapter() {
                                override fun channelRead(
                                    ctx: io.netty.channel.ChannelHandlerContext,
                                    msg: Any,
                                ) {
                                    io.netty.util.ReferenceCountUtil
                                        .release(msg)
                                }
                            },
                        )
                        acceptedFuture.complete(ch)
                    }
                },
            ).bind(InetSocketAddress("127.0.0.1", 0))
            .sync()
            .channel()

    val client: Channel =
        Bootstrap()
            .group(group)
            .channel(NioSocketChannel::class.java)
            .also { if (smallBuffers) it.option(ChannelOption.SO_SNDBUF, 4 * 1024) }
            .handler(object : ChannelInboundHandlerAdapter() {})
            .connect(server.localAddress() as InetSocketAddress)
            .sync()
            .channel()
            .also { channel ->
                if (applyProductionWaterMarks) {
                    channel.config().writeBufferWaterMark =
                        WriteBufferWaterMark(
                            CIRCUIT_WRITE_BUFFER_LOW_WATER_MARK_BYTES,
                            CIRCUIT_WRITE_BUFFER_HIGH_WATER_MARK_BYTES,
                        )
                }
            }

    val accepted: Channel get() = acceptedFuture.get(10, TimeUnit.SECONDS)

    /** Makes the far end read for good. */
    fun startDraining() {
        accepted.config().isAutoRead = true
    }

    /** Reads for [millis] ms, then stops again - a slow but live consumer. */
    fun drainBriefly(millis: Long) {
        val far = accepted
        far.eventLoop().execute {
            far.config().isAutoRead = true
            far.eventLoop().schedule({ far.config().isAutoRead = false }, millis, TimeUnit.MILLISECONDS)
        }
    }

    override fun close() {
        runCatching { client.close().sync() }
        runCatching { acceptedFuture.getNow(null)?.close()?.sync() }
        runCatching { server.close().sync() }
    }
}
