package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.NoSuchProtocolException
import io.libp2p.core.Stream
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.etc.util.netty.TotalTimeoutHandler
import io.libp2p.multistream.ProtocolNegotiationException
import io.libp2p.protocol.ProtocolHandler
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.ReferenceCountUtil
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

private val logger = KotlinLogging.logger {}

/** What [OnionRelayDirectoryClient.fetch] produced. Carries no peer id or address. */
sealed interface RelayDirectoryFetchResult {
    class Ok(
        val snapshot: RelayDirectorySnapshot,
    ) : RelayDirectoryFetchResult

    /** The peer does not speak the protocol (for example a v0.12.0 node): try the next source. */
    data object Unsupported : RelayDirectoryFetchResult

    /** The answer violated the format; nothing of it was used. */
    data object Malformed : RelayDirectoryFetchResult

    data object Timeout : RelayDirectoryFetchResult

    /** The stream or connection failed otherwise. */
    data object Failed : RelayDirectoryFetchResult
}

/**
 * The asking side of `/lapis/onion-relay-directory/1.0.0` (wave V0.10.0-J1b). Opens the stream directly on an
 * existing [Connection] (`muxerSession().createStream`), so the protocol is never registered on the host and the
 * protocol set a node in anonymity mode answers does not grow. The answer is read with a hard byte limit
 * ([OnionRelayDirectoryCodec.MAX_SNAPSHOT_RESPONSE_BYTES], also enforced by the stream's inbound traffic limit) and
 * decided complete from its length fields; a total timeout of [timeout] closes the stream and completes with
 * [RelayDirectoryFetchResult.Timeout]. Never throws: every failure is a result.
 */
class OnionRelayDirectoryClient(
    private val timeout: Duration = Duration.ofSeconds(15),
) {
    private val binding = Binding(Handler())

    fun fetch(connection: Connection): CompletableFuture<RelayDirectoryFetchResult> {
        val result = CompletableFuture<RelayDirectoryFetchResult>()
        val promise =
            try {
                connection.muxerSession().createStream(binding)
            } catch (e: RuntimeException) {
                return CompletableFuture.completedFuture(RelayDirectoryFetchResult.Failed)
            }
        promise.controller.whenComplete { reader, error ->
            if (error != null) {
                result.complete(classify(error))
            } else {
                reader.sendRequest()
                reader.response.whenComplete { snapshot, readError ->
                    result.complete(
                        when {
                            readError == null -> RelayDirectoryFetchResult.Ok(snapshot)
                            readError is MalformedRelayDirectorySnapshotException ||
                                readError.cause is MalformedRelayDirectorySnapshotException ->
                                RelayDirectoryFetchResult.Malformed
                            else -> classify(readError)
                        },
                    )
                }
            }
        }
        result.completeOnTimeout(RelayDirectoryFetchResult.Timeout, timeout.toMillis(), TimeUnit.MILLISECONDS)
        // every outcome closes the stream (a timed-out one included): no stream outlives its fetch
        result.whenComplete { _, _ -> promise.stream.thenAccept { runCatching { it.close() } } }
        return result
    }

    private fun classify(error: Throwable): RelayDirectoryFetchResult {
        val chain = generateSequence(error) { it.cause }.toList()
        return when {
            chain.any { it is ProtocolNegotiationException || it is NoSuchProtocolException } ->
                RelayDirectoryFetchResult.Unsupported
            chain.any { it is MalformedRelayDirectorySnapshotException } -> RelayDirectoryFetchResult.Malformed
            else -> RelayDirectoryFetchResult.Failed
        }
    }

    /** The initiator controller: [response] completes with the decoded snapshot or a failure. */
    internal class Reader(
        private val stream: Stream,
    ) : ChannelInboundHandlerAdapter() {
        val response = CompletableFuture<RelayDirectorySnapshot>()
        private var buffer = ByteArray(1024)

        @Volatile private var context: ChannelHandlerContext? = null

        override fun handlerAdded(ctx: ChannelHandlerContext) {
            context = ctx
        }

        /**
         * Writes the request on the channel's event loop, AFTER the current task: when the controller completes, the
         * multistream negotiation handlers (with their varint length prepender) are still in the pipeline and would
         * frame the request (observed: `05 4c4e5244 01`); they are removed within the current event-loop task.
         */
        fun sendRequest() {
            val ctx = context ?: return fail(IllegalStateException("snapshot stream not ready"))
            ctx.channel().eventLoop().execute {
                try {
                    ctx.channel().writeAndFlush(Unpooled.wrappedBuffer(OnionRelayDirectoryCodec.encodeRequest()))
                } catch (e: RuntimeException) {
                    fail(IllegalStateException("snapshot request could not be sent", e))
                }
            }
        }

        private var filled = 0

        override fun channelRead(
            ctx: ChannelHandlerContext,
            msg: Any,
        ) {
            try {
                val buf = msg as? ByteBuf ?: return
                if (response.isDone) return
                val n = buf.readableBytes()
                if (filled + n > OnionRelayDirectoryCodec.MAX_SNAPSHOT_RESPONSE_BYTES) {
                    fail(MalformedRelayDirectorySnapshotException("snapshot response too large"))
                    return
                }
                if (filled + n > buffer.size) {
                    buffer =
                        buffer.copyOf(
                            maxOf(
                                filled + n,
                                buffer.size * 2,
                            ).coerceAtMost(OnionRelayDirectoryCodec.MAX_SNAPSHOT_RESPONSE_BYTES),
                        )
                }
                buf.readBytes(buffer, filled, n)
                filled += n
                val expected = OnionRelayDirectoryCodec.expectedResponseLength(buffer, filled) ?: return
                if (filled < expected) return
                // filled > expected: trailing bytes, rejected by the decoder
                response.complete(OnionRelayDirectoryCodec.decodeResponse(buffer.copyOf(filled)))
            } catch (e: MalformedRelayDirectorySnapshotException) {
                fail(e)
            } catch (e: RuntimeException) {
                fail(MalformedRelayDirectorySnapshotException("unreadable snapshot response", e))
            } finally {
                ReferenceCountUtil.release(msg)
            }
        }

        override fun channelInactive(ctx: ChannelHandlerContext) {
            if (!response.isDone) fail(MalformedRelayDirectorySnapshotException("truncated snapshot response"))
            ctx.fireChannelInactive()
        }

        @Deprecated("Deprecated in Java")
        override fun exceptionCaught(
            ctx: ChannelHandlerContext,
            cause: Throwable,
        ) {
            fail(IllegalStateException("snapshot stream failed", cause))
            ctx.close()
        }

        private fun fail(e: Throwable) {
            // the messages of this module's exceptions carry no bytes, peer ids or addresses
            logger.debug { "relay directory snapshot read failed: ${e.javaClass.simpleName}: ${e.message}" }
            if (response.completeExceptionally(e)) runCatching { stream.close() }
        }
    }

    // ProtocolHandler(initiatorTrafficLimit, responderTrafficLimit): the second bounds what an INITIATOR stream accepts
    // from the responder (checked against the bytecode of jvm-libp2p 1.3.5)
    private inner class Handler :
        ProtocolHandler<Reader>(0L, OnionRelayDirectoryCodec.MAX_SNAPSHOT_RESPONSE_BYTES.toLong()) {
        override fun initProtocolStream(stream: Stream) {
            stream.pushHandler(TotalTimeoutHandler(timeout))
        }

        override fun onStartInitiator(stream: Stream): CompletableFuture<Reader> {
            val reader = Reader(stream)
            stream.pushHandler(reader)
            return CompletableFuture.completedFuture(reader)
        }

        override fun onStartResponder(stream: Stream): CompletableFuture<Reader> {
            // never registered on a host; a responder stream can not arrive here
            stream.reset()
            return CompletableFuture.failedFuture(IllegalStateException("client only"))
        }
    }

    private class Binding(
        handler: ProtocolHandler<Reader>,
    ) : StrictProtocolBinding<Reader>(ONION_RELAY_DIRECTORY_PROTOCOL_ID, handler)
}
