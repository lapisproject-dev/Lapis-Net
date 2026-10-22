package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Stream
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.protocol.ProtocolHandler
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.timeout.ReadTimeoutHandler
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.CELL_SIZE
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

private val logger = KotlinLogging.logger {}

/** libp2p protocol id of the onion link stream. */
const val ONION_PROTOCOL_ID = "/lapis/onion/1.0.0"

/** Controller returned to the dialer of a link; the id is random and carries no address information. */
interface OnionLinkHandle {
    val linkId: LinkId
}

/** Returned when a stream was refused (link limit, relay mode off, closing). */
internal object RejectedLinkHandle : OnionLinkHandle {
    override val linkId: LinkId = LinkId(0)
}

/**
 * Cuts the stream into exactly [CELL_SIZE]-byte frames. There is NO length field on the wire, so a frame size can never be
 * attacker-chosen (no off-by-length class of bug, unlike a length-prefixed codec). A started frame that does not
 * complete within [partialTimeoutMillis] closes the channel (slowloris).
 */
internal class CellFrameDecoder(
    private val partialTimeoutMillis: Long,
) : ByteToMessageDecoder() {
    private var partial = false
    private var token = 0L

    override fun decode(
        ctx: ChannelHandlerContext,
        input: ByteBuf,
        out: MutableList<Any>,
    ) {
        var emitted = false
        while (input.readableBytes() >= CELL_SIZE) {
            out.add(input.readRetainedSlice(CELL_SIZE))
            emitted = true
        }
        if (emitted) partial = false
        if (input.isReadable && !partial) {
            partial = true
            val mine = ++token
            ctx.executor().schedule(
                {
                    if (partial && token == mine) {
                        logger.debug { "onion link closed: incomplete cell" }
                        ctx.close()
                    }
                },
                partialTimeoutMillis,
                TimeUnit.MILLISECONDS,
            )
        } else if (!input.isReadable) {
            partial = false
        }
    }
}

/** Netty side of one link: hands complete cells to the manager, reports closing, never logs content. */
internal class OnionLinkChannelHandler(
    private val manager: OnionLinkManager,
    private val link: OnionLink,
) : SimpleChannelInboundHandler<ByteBuf>() {
    override fun handlerAdded(ctx: ChannelHandlerContext) {
        link.attach(ctx)
    }

    override fun channelRead0(
        ctx: ChannelHandlerContext,
        msg: ByteBuf,
    ) {
        manager.onInboundBytes(link, ByteBufUtil.getBytes(msg))
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        manager.linkEnded(link)
        ctx.fireChannelInactive()
    }

    override fun exceptionCaught(
        ctx: ChannelHandlerContext,
        cause: Throwable,
    ) {
        logger.debug { "onion link error: ${cause.javaClass.simpleName}" }
        manager.close(link.id)
    }
}

/**
 * Stream handler of `/lapis/onion/1.0.0`. The traffic limits of [ProtocolHandler] are disabled (`Long.MAX_VALUE`):
 * a link is long-lived and its volume is bounded per second by the manager instead.
 */
internal class OnionProtocolHandler(
    private val manager: OnionLinkManager,
    private val config: OnionWireConfig,
) : ProtocolHandler<OnionLinkHandle>(Long.MAX_VALUE, Long.MAX_VALUE) {
    override fun initProtocolStream(stream: Stream) {
        stream.pushHandler(ReadTimeoutHandler(config.linkIdleTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS))
        stream.pushHandler(CellFrameDecoder(config.linkHandshakeTimeout.inWholeMilliseconds))
    }

    override fun onStartResponder(stream: Stream): CompletableFuture<OnionLinkHandle> {
        val link = manager.admit(stream, inbound = true)
        if (link == null) {
            stream.reset()
            return CompletableFuture.completedFuture(RejectedLinkHandle)
        }
        stream.pushHandler(OnionLinkChannelHandler(manager, link))
        return CompletableFuture.completedFuture(link)
    }

    override fun onStartInitiator(stream: Stream): CompletableFuture<OnionLinkHandle> {
        val link = manager.admit(stream, inbound = false)
        if (link == null) {
            stream.reset()
            return CompletableFuture.completedFuture(RejectedLinkHandle)
        }
        stream.pushHandler(OnionLinkChannelHandler(manager, link))
        return link.ready.thenApply { link }
    }
}

internal class OnionProtocolBinding(
    handler: OnionProtocolHandler,
) : StrictProtocolBinding<OnionLinkHandle>(ONION_PROTOCOL_ID, handler)
