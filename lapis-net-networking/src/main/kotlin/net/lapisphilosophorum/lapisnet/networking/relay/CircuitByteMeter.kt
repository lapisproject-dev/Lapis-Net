package net.lapisphilosophorum.lapisnet.networking.relay

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import java.util.concurrent.atomic.AtomicLong

/**
 * Counts the bytes read on one stream and passes every message on untouched. Never blocks, never
 * allocates per message, never retains a buffer: it only reads [ByteBuf.readableBytes]. Used to
 * feed the [RelayUsageLedger] (relay side: bytes each circuit leg delivered; client side: bytes a
 * relay delivered to us). Must be installed BEFORE the handler that consumes the bytes.
 */
internal class CircuitByteMeter : ChannelInboundHandlerAdapter() {
    private val counted = AtomicLong(0)

    /** Total bytes seen so far. Safe to read from any thread. */
    fun bytes(): Long = counted.get()

    override fun channelRead(
        ctx: ChannelHandlerContext,
        msg: Any,
    ) {
        if (msg is ByteBuf) {
            val size = msg.readableBytes().toLong()
            // Saturating: a counter overflow must never turn into a negative (negative bytes are rejected by the ledger).
            counted.updateAndGet { current -> if (Long.MAX_VALUE - current < size) Long.MAX_VALUE else current + size }
        }
        ctx.fireChannelRead(msg)
    }
}
