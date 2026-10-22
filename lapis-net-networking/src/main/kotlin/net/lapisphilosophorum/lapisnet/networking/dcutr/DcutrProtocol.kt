package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.Stream
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.etc.util.netty.InboundTrafficLimitHandler
import io.libp2p.etc.util.netty.TotalTimeoutHandler
import io.libp2p.protocol.ProtocolHandler
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.handler.codec.protobuf.ProtobufVarint32FrameDecoder
import io.netty.handler.codec.protobuf.ProtobufVarint32LengthFieldPrepender
import io.netty.util.ReferenceCountUtil
import java.time.Duration
import java.util.concurrent.CompletableFuture

private val logger = KotlinLogging.logger {}

const val DCUTR_PROTOCOL_ID = "/libp2p/dcutr"

/** One dcutr stream, as the state machine sees it. */
internal interface DcutrWire {
    fun send(message: HolePunchMessage): CompletableFuture<Unit>

    /** The next message; fails when the stream closes, errors or carries an invalid message. */
    fun receive(): CompletableFuture<HolePunchMessage>

    fun close()
}

/** Stream-level limits: a legitimate exchange is CONNECT + CONNECT + SYNC, each at most 4 KiB plus framing. */
private const val STREAM_INBOUND_LIMIT_BYTES = 3L * (HolePunchCodec.MAX_MESSAGE_BYTES + 8)

internal class DcutrStream(
    private val stream: Stream,
) : ChannelInboundHandlerAdapter(),
    DcutrWire {
    private val lock = Any()
    private val inbox = ArrayDeque<HolePunchMessage>()
    private val waiters = ArrayDeque<CompletableFuture<HolePunchMessage>>()
    private var failure: Throwable? = null

    override fun send(message: HolePunchMessage): CompletableFuture<Unit> =
        try {
            stream.writeAndFlush(Unpooled.wrappedBuffer(HolePunchCodec.encode(message)))
            CompletableFuture.completedFuture(Unit)
        } catch (e: RuntimeException) {
            CompletableFuture.failedFuture(e)
        }

    override fun receive(): CompletableFuture<HolePunchMessage> {
        val future = CompletableFuture<HolePunchMessage>()
        synchronized(lock) {
            when {
                inbox.isNotEmpty() -> future.complete(inbox.removeFirst())
                failure != null -> future.completeExceptionally(failure)
                else -> waiters.addLast(future)
            }
        }
        return future
    }

    override fun close() {
        runCatching { stream.close() }
        fail(IllegalStateException("dcutr stream closed locally"))
    }

    override fun channelRead(
        ctx: ChannelHandlerContext,
        msg: Any,
    ) {
        try {
            val buf = msg as? ByteBuf ?: return
            val bytes = ByteArray(buf.readableBytes())
            buf.readBytes(bytes)
            val decoded = HolePunchCodec.decode(bytes)
            synchronized(lock) {
                val waiter = waiters.removeFirstOrNull()
                if (waiter != null) waiter.complete(decoded) else inbox.addLast(decoded)
            }
        } catch (e: HolePunchProtocolException) {
            logger.debug { "invalid dcutr message: ${e.message}" }
            fail(e)
            ctx.close()
        } finally {
            ReferenceCountUtil.release(msg)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        fail(IllegalStateException("dcutr stream closed"))
        ctx.fireChannelInactive()
    }

    @Deprecated("Deprecated in Java")
    override fun exceptionCaught(
        ctx: ChannelHandlerContext,
        cause: Throwable,
    ) {
        fail(cause)
        ctx.close()
    }

    private fun fail(cause: Throwable) {
        val pending: List<CompletableFuture<HolePunchMessage>>
        synchronized(lock) {
            if (failure == null) failure = cause
            pending = waiters.toList()
            waiters.clear()
        }
        pending.forEach { it.completeExceptionally(cause) }
    }
}

/**
 * The `/libp2p/dcutr` stream handler. [onInbound] is invoked for every stream a peer opens to us
 * (the responder, "A", side); it is the state machine's job to refuse it.
 */
internal class DcutrProtocol(
    private val streamTimeout: Duration,
    @Volatile var onInbound: (Connection, DcutrWire) -> Unit = { _, wire -> wire.close() },
) : ProtocolHandler<DcutrWire>(Long.MAX_VALUE, Long.MAX_VALUE) {
    override fun initProtocolStream(stream: Stream) {
        // Order matters: inbound bytes pass the handlers first-pushed to last-pushed.
        stream.pushHandler(InboundTrafficLimitHandler(STREAM_INBOUND_LIMIT_BYTES))
        stream.pushHandler(TotalTimeoutHandler(streamTimeout))
        stream.pushHandler(ProtobufVarint32FrameDecoder())
        stream.pushHandler(ProtobufVarint32LengthFieldPrepender())
        super.initProtocolStream(stream)
    }

    override fun onStartInitiator(stream: Stream): CompletableFuture<DcutrWire> {
        val wire = DcutrStream(stream)
        stream.pushHandler(wire)
        return CompletableFuture.completedFuture(wire)
    }

    override fun onStartResponder(stream: Stream): CompletableFuture<DcutrWire> {
        val wire = DcutrStream(stream)
        stream.pushHandler(wire)
        runCatching { onInbound(stream.connection, wire) }
            .onFailure {
                logger.warn { "dcutr inbound handler failed: ${it.javaClass.simpleName}" }
                wire.close()
            }
        return CompletableFuture.completedFuture(wire)
    }
}

internal class DcutrBinding(
    private val handler: DcutrProtocol,
) : StrictProtocolBinding<DcutrWire>(DCUTR_PROTOCOL_ID, handler)
