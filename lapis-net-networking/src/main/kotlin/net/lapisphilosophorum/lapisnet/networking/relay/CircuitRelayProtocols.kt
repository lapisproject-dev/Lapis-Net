package net.lapisphilosophorum.lapisnet.networking.relay

import com.google.protobuf.ByteString
import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.multistream.ProtocolBinding
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.etc.util.netty.InboundTrafficLimitHandler
import io.libp2p.etc.util.netty.TotalTimeoutHandler
import io.libp2p.protocol.ProtobufProtocolHandler
import io.libp2p.protocol.ProtocolMessageHandler
import io.libp2p.protocol.circuit.pb.Circuit
import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.WriteBufferWaterMark
import io.netty.handler.codec.protobuf.ProtobufDecoder
import io.netty.handler.codec.protobuf.ProtobufEncoder
import io.netty.handler.codec.protobuf.ProtobufVarint32FrameDecoder
import io.netty.handler.codec.protobuf.ProtobufVarint32LengthFieldPrepender
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.TimeUnit

private val logger = KotlinLogging.logger {}

/**
 * Where relay control-plane continuations run - and the reason they must not run inline.
 *
 * A `CompletableFuture` returned by `io.libp2p.core.Host.newStream` is completed **from inside**
 * jvm-libp2p's own multistream negotiation / pipeline-initialisation call stack, on the stream's
 * Netty event loop, at a moment when that stream's outbound protobuf encoder is not yet reachable
 * from the pipeline's tail. A `writeAndFlush` issued inline from such a continuation is therefore
 * silently dropped: it never reaches the wire, the peer never answers, and the exchange dies at a
 * timeout with nothing in any log to explain it. Observed on both halves of a circuit setup (the
 * `CONNECT` a dialler sends the relay, and the `STOP CONNECT` a relay sends the destination) while
 * building this wave; a `RESERVE` sent from an ordinary caller thread after `get()` was never
 * affected, which is exactly what made the failure look mysterious at first.
 *
 * Every continuation that writes on a freshly-negotiated relay stream therefore hops onto this
 * executor first. It is deliberately a small, dedicated, daemon pool rather than
 * `ForkJoinPool.commonPool()`: these tasks are short and non-blocking, but they are also
 * latency-sensitive network control-plane work that should not queue behind unrelated parallel
 * streams a host application happens to be running.
 *
 * Process-wide and never shut down, deliberately: it is shared by every [
 * net.lapisphilosophorum.lapisnet.networking.LapisNode] in a JVM (several, in tests), so no single
 * node's `stop()` may take it away from the others. Its threads are daemons and it is created
 * lazily on first use, so a process that never opens a circuit never pays for it and a process that
 * did is never held open by it.
 */
internal val relayControlExecutor: java.util.concurrent.Executor by lazy {
    java.util.concurrent.Executors.newFixedThreadPool(2) { runnable ->
        Thread(runnable, "lapis-relay-control").apply { isDaemon = true }
    }
}

/** Wire protocol id of Circuit-Relay-v2's hop (client <-> relay) protocol. */
internal const val HOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/hop"

/** Wire protocol id of Circuit-Relay-v2's stop (relay <-> destination) protocol. */
internal const val STOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/stop"

private const val CONTROL_HANDLER_NAME = "LAPIS_CIRCUIT_CONTROL"
private const val CONTROL_LIMIT_HANDLER_NAME = "LAPIS_CIRCUIT_CONTROL_LIMIT"
private const val CONTROL_CLEARER_NAME = "LAPIS_CIRCUIT_CONTROL_CLEARER"

/**
 * Inbound byte ceiling on a relay **control** stream while it is still speaking protobuf. Circuit
 * Relay v2 control messages are tiny (a `RESERVE` is a handful of bytes, the largest realistic
 * reply is a reservation carrying a voucher and a few multiaddrs), so a small cap costs nothing and
 * bounds what an unauthenticated peer can push at a node that may not even be a relay. Removed
 * again by [ControlStreamClearer] at the exact moment the stream stops being a control stream and
 * becomes a raw relayed byte pipe - which is precisely the bug that makes the library's own
 * handlers unusable, see this file's [LapisCircuitHopProtocol] doc comment.
 */
private const val CONTROL_STREAM_INBOUND_LIMIT_BYTES = 16L * 1024

/** A reservation this node holds **on** a relay - the client-side view. */
data class RelayReservation(
    /** The relay that granted it. */
    val relay: PeerId,
    /** Addresses this node reached [relay] at - the basis of the `/p2p-circuit` address this node
     * then advertises. Deliberately the addresses **this node dialled**, never the ones the relay
     * announced about itself in its reservation reply: a relay has no business deciding what
     * address its clients publish, and taking the dialled ones removes a whole trust question for
     * free. */
    val relayAddresses: List<Multiaddr>,
    /** When the reservation stops being valid, already clamped to
     * [RelayClientLimits.maxReservationTtl]. */
    val expiresAt: Instant,
)

/**
 * Removes every handler that made a stream a *control* stream, turning it back into a raw byte
 * pipe. Pushed at the moment a hop/stop exchange succeeds and the stream is handed over to become
 * one leg of a circuit.
 *
 * **This is the single most important deviation from the library's own implementation.**
 * `io.libp2p.protocol.ProtocolHandler.initChannel` installs an
 * `InboundTrafficLimitHandler(2048)` on every hop and stop stream, and neither
 * `CircuitHopProtocol.HopRemover` nor `CircuitStopProtocol.StopRemover` removes it again - so with
 * the stock classes every relayed connection is killed by a `ProtocolViolationException` after
 * 2 KiB of inbound traffic, which a Noise handshake plus an mplex-multiplexed identify exchange
 * already exceeds. This class removes the limiter along with the protobuf codecs, and the relay
 * then installs its own, far larger, deliberately-chosen budget
 * ([RelayServerLimits.circuitMaxBytes]) instead.
 */
private class ControlStreamClearer : ChannelInitializer<Channel>() {
    override fun initChannel(ch: Channel) {
        val pipeline = ch.pipeline()
        pipeline.remove(ProtobufDecoder::class.java)
        pipeline.remove(ProtobufEncoder::class.java)
        pipeline.remove(ProtobufVarint32FrameDecoder::class.java)
        pipeline.remove(ProtobufVarint32LengthFieldPrepender::class.java)
        pipeline.remove(CONTROL_HANDLER_NAME)
        pipeline.remove(CONTROL_LIMIT_HANDLER_NAME)
        // This initializer removes itself: Netty's ChannelInitializer does that for us once
        // initChannel returns, so removing CONTROL_CLEARER_NAME here would be redundant.
    }
}

/**
 * Low water mark of the write buffer on a transport channel carrying a circuit leg: below this many
 * queued bytes the channel is writable again and the paused leg resumes reading.
 */
internal const val CIRCUIT_WRITE_BUFFER_LOW_WATER_MARK_BYTES = 64 * 1024

/**
 * High water mark of the write buffer on a transport channel carrying a circuit leg. Once this many
 * bytes are queued for the far peer, [CircuitProxyHandler] stops reading from the near peer, so this
 * - not [RelayServerLimits.circuitMaxBytes] - is what bounds a circuit's memory footprint.
 */
internal const val CIRCUIT_WRITE_BUFFER_HIGH_WATER_MARK_BYTES = 256 * 1024

/**
 * Forwards raw inbound bytes from one leg of a circuit onto the other, **with real backpressure**.
 *
 * Ownership of each [ByteBuf] passes to the target channel's write, which releases it (including
 * when that write fails because the other leg is already gone).
 *
 * **Why this needs flow control at all.** Without it, a peer that reads slowly (or simply never
 * reads) makes the relay queue everything the other side sends: up to
 * [RelayServerLimits.circuitMaxBytes] per circuit, times
 * [RelayServerLimits.maxConcurrentCircuits], all of it live heap on the relay - several GiB at the
 * defaults, from peers that spend nothing. The node multiplexes with mplex, which unlike yamux has
 * no send-buffer bound of its own, so nothing below this layer would have caught it either.
 *
 * **How it works** - the standard Netty proxy-splicing shape, adapted to libp2p's channel
 * structure:
 *  - [target] is the *stream* (mplex substream) the bytes are written to.
 *  - [targetTransport] is the connection channel that stream rides on. Bytes queue there, not on
 *    the substream: `MuxChannel.doWrite` hands each buffer straight to the parent connection, so the
 *    substream's own outbound buffer is always empty and its `isWritable` is always `true`. The
 *    connection channel is therefore the only place where writability means anything.
 *  - [sourceTransport] is the connection channel the bytes arrive on. Turning its `autoRead` off is
 *    what actually stops the flow: a substream cannot be paused on its own either, since
 *    `AbstractChildChannel.doBeginRead` is a no-op and inbound frames are pushed at it by the muxer.
 *
 * Pausing a whole connection is coarser than pausing one circuit, and briefly stalls other streams
 * to that same peer. That is inherent to mplex having no per-stream flow control, and it is the
 * conservative direction to be coarse in: the alternative is unbounded heap.
 */
internal class CircuitProxyHandler(
    private val target: Channel,
    private val targetTransport: Channel,
    private val sourceTransport: Channel,
) : ChannelInboundHandlerAdapter() {
    override fun channelRead(
        ctx: ChannelHandlerContext,
        msg: Any,
    ) {
        if (msg !is ByteBuf) {
            ctx.fireChannelRead(msg)
            return
        }
        target.writeAndFlush(msg)
        if (!targetTransport.isWritable) {
            // Stop pulling bytes in until CircuitReadResumer says the far side drained. The next
            // read after a premature resume re-arms this immediately, so a resume triggered by an
            // unrelated circuit on the same connection costs at most one further chunk.
            sourceTransport.config().isAutoRead = false
        }
    }
}

/**
 * Sits on a circuit leg's **transport** channel and lets the opposite leg start reading again once
 * this one has drained below its low water mark - the other half of [CircuitProxyHandler]'s
 * backpressure.
 *
 * It has to live on the transport channel rather than on the substream because writability events
 * are fired on the channel whose write buffer changed, and that is never the substream (see
 * [CircuitProxyHandler]'s doc comment).
 */
internal class CircuitReadResumer(
    private val sourceTransport: Channel,
) : ChannelInboundHandlerAdapter() {
    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        // Setting autoRead back to true makes Netty issue a read() itself, so no explicit kick.
        if (ctx.channel().isWritable) sourceTransport.config().isAutoRead = true
        ctx.fireChannelWritabilityChanged()
    }
}

/**
 * Degenerate fallback used only if a circuit leg turns out not to be Netty-backed, which no
 * transport in this build produces. Identical to what this file did everywhere before flow control
 * existed, and kept solely so an unexpected [Stream] implementation degrades rather than crashes.
 */
private class UnboundedCircuitProxyHandler(
    private val other: Stream,
) : ChannelInboundHandlerAdapter() {
    override fun channelRead(
        ctx: ChannelHandlerContext,
        msg: Any,
    ) {
        if (msg is ByteBuf) other.writeAndFlush(msg) else ctx.fireChannelRead(msg)
    }
}

/** The Netty channel behind a libp2p [Stream], or `null` for an implementation that is not
 * Netty-backed (none in this build - the fallback exists so an unexpected one degrades to
 * "no flow control" rather than to a crash). */
private fun nettyChannelOf(stream: Stream): Channel? =
    (stream as? io.libp2p.transport.implementation.P2PChannelOverNetty)?.nettyChannel

/** The connection channel a substream rides on - see [CircuitProxyHandler]. Falls back to the
 * channel itself if it has no parent, which would mean it is not a multiplexed substream. */
private fun transportChannelOf(channel: Channel): Channel = channel.parent() ?: channel

/**
 * Writes one final control message and then closes the stream, in that order.
 *
 * Every refusal in this file ends its exchange, and a refused stream that is left open is a free
 * mplex substream held on this node per rejected attempt - trivially accumulated by anyone who
 * likes sending requests that get refused. Closing has to wait for the write to flush, or the peer
 * would be told nothing about why it was refused; hence the write listener rather than a bare
 * `close()` on the next line.
 */
private fun writeAndClose(
    stream: Stream,
    message: Any,
) {
    val channel = nettyChannelOf(stream)
    if (channel != null) {
        channel.writeAndFlush(message).addListener(ChannelFutureListener.CLOSE)
    } else {
        stream.writeAndFlush(message)
        runCatching { stream.close() }
    }
}

// ---------------------------------------------------------------------------------------------
// Hop protocol (client <-> relay)
// ---------------------------------------------------------------------------------------------

/** Controller type of [LapisCircuitHopProtocol]; only [HopSender] is useful to a caller. */
internal interface CircuitHopControl

/**
 * Initiator half of the hop protocol - what a node uses to talk **to** a relay.
 *
 * Unlike `CircuitHopProtocol.Sender`, a pending request is failed (not silently abandoned) when the
 * stream closes or errors: the library's version leaves the caller's future uncompleted forever,
 * which would turn a relay that hangs up mid-handshake into a dial that only ever ends at the outer
 * timeout.
 */
internal class HopSender(
    private val stream: Stream,
) : ProtocolMessageHandler<Circuit.HopMessage>,
    CircuitHopControl {
    private val pending = ConcurrentLinkedDeque<CompletableFuture<Circuit.HopMessage>>()

    override fun onMessage(
        stream: Stream,
        msg: Circuit.HopMessage,
    ) {
        pending.poll()?.complete(msg)
    }

    override fun onClosed(stream: Stream) = failAll(IllegalStateException("relay hop stream closed"))

    override fun onException(cause: Throwable?) = failAll(cause ?: IllegalStateException("relay hop stream failed"))

    private fun failAll(cause: Throwable) {
        while (true) {
            (pending.poll() ?: return).completeExceptionally(cause)
        }
    }

    private fun rpc(req: Circuit.HopMessage): CompletableFuture<Circuit.HopMessage> {
        val result = CompletableFuture<Circuit.HopMessage>()
        pending.add(result)
        stream.writeAndFlush(req)
        return result
    }

    /** Sends `RESERVE` and interprets the reply. [relayAddresses] are echoed into the resulting
     * [RelayReservation] unchanged - see that class's doc comment on why the relay's own announced
     * addresses are ignored. */
    fun reserve(
        relayAddresses: List<Multiaddr>,
        limits: RelayClientLimits,
        now: Instant = Instant.now(),
    ): CompletableFuture<RelayReservation> =
        rpc(
            Circuit.HopMessage
                .newBuilder()
                .setType(Circuit.HopMessage.Type.RESERVE)
                .build(),
        ).thenApply { msg ->
            if (msg.type != Circuit.HopMessage.Type.STATUS || msg.status != Circuit.Status.OK) {
                throw RelayException("relay refused reservation: ${msg.status.name}")
            }
            val claimed = Instant.ofEpochSecond(msg.reservation.expire)
            val ceiling = now.plus(limits.maxReservationTtl)
            // A relay-announced expiry is attacker-controlled input: clamp it into a sane
            // window so a hostile relay can neither suppress renewal by claiming a century nor
            // (via a past timestamp) push this node into a renewal hot loop.
            val expiresAt =
                when {
                    claimed.isAfter(ceiling) -> ceiling
                    !claimed.isAfter(now) -> throw RelayException("relay granted an already-expired reservation")
                    else -> claimed
                }
            RelayReservation(stream.remotePeerId(), relayAddresses, expiresAt)
        }

    /** Sends `CONNECT` and, on success, hands back the same stream stripped down to a raw byte
     * pipe ready for [io.libp2p.protocol.circuit.RelayTransport.upgradeStream]. */
    fun connect(target: PeerId): CompletableFuture<Stream> =
        rpc(
            Circuit.HopMessage
                .newBuilder()
                .setType(Circuit.HopMessage.Type.CONNECT)
                .setPeer(Circuit.Peer.newBuilder().setId(ByteString.copyFrom(target.bytes)))
                .build(),
        ).thenApply { msg ->
            if (msg.type != Circuit.HopMessage.Type.STATUS || msg.status != Circuit.Status.OK) {
                throw RelayException("relay refused to connect to $target: ${msg.status.name}")
            }
            stream.pushHandler(CONTROL_CLEARER_NAME, ControlStreamClearer())
            stream
        }
}

/**
 * Responder half of the hop protocol - what a node runs when somebody talks **to it** as a relay.
 *
 * Refuses everything unless the operator explicitly switched the relay server role on (see
 * [RelayConfig]). Even when enabled it refuses:
 *  - a `RESERVE` arriving over an already-relayed connection (no relay chaining - that would let an
 *    attacker build an arbitrarily long amplification chain out of volunteer relays),
 *  - a `CONNECT` from an already-relayed connection, for the same reason,
 *  - a `CONNECT` naming a target that holds no reservation, or naming the initiator itself,
 *  - anything at all once [RelayServerLimits]' reservation or circuit budgets are exhausted.
 *
 * **Deliberately not `io.libp2p.protocol.circuit.CircuitHopProtocol.Receiver`.** That class's
 * `switch` has no `break` after its `RESERVE` case, so a *successful* reservation falls straight
 * through into the `CONNECT` case and throws `IllegalArgumentException: Invalid peerId length: 0`
 * out of `new PeerId(msg.getPeer().getId().toByteArray())` on an empty peer field - i.e. the one
 * path that must work throws on every single call. It also relies on the traffic-limiter bug
 * described on [ControlStreamClearer].
 */
internal class HopReceiver(
    private val host: Host,
    private val config: RelayConfig,
    private val registry: RelayReservationRegistry,
    private val stopBinding: ProtocolBinding<CircuitStopControl>,
    private val clock: () -> Instant,
) : ProtocolMessageHandler<Circuit.HopMessage>,
    CircuitHopControl {
    override fun onMessage(
        stream: Stream,
        msg: Circuit.HopMessage,
    ) {
        try {
            when (msg.type) {
                Circuit.HopMessage.Type.RESERVE -> handleReserve(stream)
                Circuit.HopMessage.Type.CONNECT -> handleConnect(stream, msg)
                else -> refuse(stream, Circuit.Status.MALFORMED_MESSAGE)
            }
        } catch (e: RuntimeException) {
            // A relay must never let a malformed request from a stranger escape into the Netty
            // pipeline's exception path - answer, log, and keep serving.
            logger.warn(e) { "relay hop request from ${runCatching { stream.remotePeerId() }.getOrNull()} failed" }
            runCatching { refuse(stream, Circuit.Status.MALFORMED_MESSAGE) }
        }
    }

    /** Answers a refused hop request and closes the stream. A refusal ends the exchange, so leaving
     * the stream open would hand every rejected stranger a free, indefinitely-held mplex substream
     * on this node - one per attempt. */
    private fun refuse(
        stream: Stream,
        status: Circuit.Status,
    ) {
        writeAndClose(
            stream,
            Circuit.HopMessage
                .newBuilder()
                .setType(Circuit.HopMessage.Type.STATUS)
                .setStatus(status)
                .build(),
        )
    }

    /**
     * The Circuit-Relay-v2 *reservation voucher*: a `libp2p-relay-rsvp`-domain signed envelope
     * binding this relay, the reserving peer and the expiry, signed with this node's own host key.
     *
     * A standard go-libp2p or rust-libp2p relay client requires one before it will treat a
     * reservation as granted, so omitting it (which this module did at first) made this relay
     * unusable by anything but another Lapis Net node - contradicting the interop that reusing the
     * `Circuit.*` wire types exists to buy. Produced by `CircuitHopProtocol.createVoucher`, which is
     * the one part of the library's hop implementation that is sound and self-contained: it does
     * nothing but build and sign the envelope.
     *
     * Never fatal. A voucher this relay cannot produce is a degraded reservation, not a refused
     * one - a Lapis Net client does not consult it (its trust in the reservation comes from having
     * asked for it over an authenticated connection, not from a token the same party signed).
     */
    private fun signedVoucher(
        requestor: PeerId,
        expiresAt: Instant,
    ): ByteArray? =
        runCatching {
            io.libp2p.protocol.circuit.CircuitHopProtocol
                .createVoucher(
                    host.privKey,
                    host.peerId,
                    requestor,
                    LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC),
                )
        }.getOrElse {
            logger.warn(it) { "could not sign a reservation voucher for $requestor - granting without one" }
            null
        }

    private fun handleReserve(stream: Stream) {
        if (!config.serverEnabled) {
            refuse(stream, Circuit.Status.PERMISSION_DENIED)
            return
        }
        val remoteAddress = stream.connection.remoteAddress()
        if (remoteAddress.has(Protocol.P2PCIRCUIT)) {
            refuse(stream, Circuit.Status.PERMISSION_DENIED)
            return
        }
        val now = clock()
        val reservation = registry.reserve(stream.remotePeerId(), remoteAddress, now)
        if (reservation == null) {
            refuse(stream, Circuit.Status.RESERVATION_REFUSED)
            return
        }
        val limits = config.serverLimits
        val reservationBuilder =
            Circuit.Reservation
                .newBuilder()
                .setExpire(reservation.expiresAt.epochSecond)
                .addAllAddrs(host.listenAddresses().map { ByteString.copyFrom(it.serialize()) })
        signedVoucher(stream.remotePeerId(), reservation.expiresAt)?.let {
            reservationBuilder.voucher = ByteString.copyFrom(it)
        }
        stream.writeAndFlush(
            Circuit.HopMessage
                .newBuilder()
                .setType(Circuit.HopMessage.Type.STATUS)
                .setStatus(Circuit.Status.OK)
                .setReservation(reservationBuilder)
                .setLimit(
                    Circuit.Limit
                        .newBuilder()
                        .setDuration(limits.circuitMaxDuration.seconds.toInt())
                        .setData(limits.circuitMaxBytes),
                ).build(),
        )
        logger.info {
            "granted relay reservation to ${stream.remotePeerId()} until ${reservation.expiresAt} " +
                "(${registry.reservationCount()}/${limits.maxConcurrentReservations} slots used)"
        }
    }

    private fun handleConnect(
        stream: Stream,
        msg: Circuit.HopMessage,
    ) {
        if (!config.serverEnabled) {
            refuse(stream, Circuit.Status.PERMISSION_DENIED)
            return
        }
        if (stream.connection.remoteAddress().has(Protocol.P2PCIRCUIT)) {
            refuse(stream, Circuit.Status.PERMISSION_DENIED)
            return
        }
        val initiator = stream.remotePeerId()
        val targetBytes = msg.peer.id.toByteArray()
        val target =
            try {
                PeerId(targetBytes)
            } catch (e: IllegalArgumentException) {
                logger.debug(e) { "relay CONNECT from $initiator named a structurally invalid target peer id" }
                refuse(stream, Circuit.Status.MALFORMED_MESSAGE)
                return
            }
        if (target == initiator || target == host.peerId) {
            refuse(stream, Circuit.Status.PERMISSION_DENIED)
            return
        }
        val now = clock()
        // Rate-limited BEFORE anything is looked up or dialled: a CONNECT costs the initiator
        // almost nothing and costs the target a full Noise handshake, so an unlimited CONNECT rate
        // turns this relay into a CPU amplifier aimed at whichever peer reserved here. A refused
        // attempt must therefore never reach the target at all - see ConnectRateLimiter.
        if (!registry.allowConnectAttempt(initiator, now)) {
            logger.debug { "rate-limiting relay CONNECT attempts from $initiator" }
            refuse(stream, Circuit.Status.PERMISSION_DENIED)
            return
        }
        // Look up and claim under one lock: between a separate find() and tryClaimCircuit() the
        // reservation could expire and be pruned, leaving a slot claimed against an object nothing
        // consults any more.
        when (val claim = registry.claimCircuitFor(target, now)) {
            is CircuitClaim.NoReservation -> refuse(stream, Circuit.Status.NO_RESERVATION)
            is CircuitClaim.LimitExceeded -> refuse(stream, Circuit.Status.RESOURCE_LIMIT_EXCEEDED)
            is CircuitClaim.Granted -> openCircuit(stream, initiator, target, claim.reservation)
        }
    }

    private fun openCircuit(
        hopStream: Stream,
        initiator: PeerId,
        target: PeerId,
        reservation: GrantedReservation,
    ) {
        val limits = config.serverLimits
        val released =
            java.util.concurrent.atomic
                .AtomicBoolean(false)
        val release = {
            if (released.compareAndSet(false, true)) registry.releaseCircuit(reservation)
        }
        val timeoutMillis = limits.circuitSetupTimeout.toMillis()
        // Held so the stop stream can be closed if setup fails after it was opened - otherwise a
        // destination that accepts the stream and then stalls leaves one stream per refused circuit
        // hanging on this relay, exactly the resource an attacker would aim at.
        val stopStream = CompletableFuture<Stream>()
        val controllerFuture: CompletableFuture<CircuitStopControl> =
            CompletableFuture.completedFuture(Unit).thenCompose {
                val promise = stopBinding.dial(host, target, reservation.observedAddress)
                promise.stream.whenComplete { stream, error ->
                    if (error != null) stopStream.completeExceptionally(error) else stopStream.complete(stream)
                }

                @Suppress("UNCHECKED_CAST")
                promise.controller as CompletableFuture<CircuitStopControl>
            }
        controllerFuture
            .orTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            // thenComposeAsync, never thenCompose - see relayControlExecutor's doc comment.
            .thenComposeAsync({ controller ->
                val sender =
                    controller as? StopSender
                        ?: throw RelayException("stop protocol returned a responder controller")
                sender
                    .connect(initiator, limits)
                    .orTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
                    .thenApply { reply -> sender to reply }
            }, relayControlExecutor)
            .whenComplete { result, error ->
                if (error != null || result == null) {
                    logger.info { "relay could not open circuit $initiator -> $target: ${error?.message}" }
                    release()
                    stopStream.thenAccept { runCatching { it.close() } }
                    runCatching { refuse(hopStream, Circuit.Status.CONNECTION_FAILED) }
                    return@whenComplete
                }
                val (sender, reply) = result
                if (reply.status != Circuit.Status.OK) {
                    release()
                    runCatching { sender.stream.close() }
                    runCatching { refuse(hopStream, reply.status) }
                    return@whenComplete
                }
                runCatching {
                    hopStream.writeAndFlush(
                        Circuit.HopMessage
                            .newBuilder()
                            .setType(Circuit.HopMessage.Type.STATUS)
                            .setStatus(Circuit.Status.OK)
                            .build(),
                    )
                    spliceCircuit(hopStream, sender.stream, limits, release)
                    logger.info {
                        "relaying circuit $initiator -> $target " +
                            "(${registry.circuitCount()}/${limits.maxConcurrentCircuits} circuits live)"
                    }
                }.onFailure {
                    logger.warn(it) { "relay failed to splice circuit $initiator -> $target" }
                    release()
                    runCatching { hopStream.close() }
                    runCatching { sender.stream.close() }
                }
            }
    }

    /**
     * Turns two control streams into a bidirectional byte pipe with this relay's own resource
     * ceilings attached, and makes sure the claimed circuit slot is given back exactly once, no
     * matter which side hangs up (or whether a limit handler tore the stream down).
     *
     * The pipe is flow-controlled in both directions - see [CircuitProxyHandler] for why that is
     * the property that actually bounds this relay's heap, and why the write-buffer water marks and
     * the resumer handlers have to be installed on the *connection* channels rather than on the
     * substreams.
     */
    private fun spliceCircuit(
        a: Stream,
        b: Stream,
        limits: RelayServerLimits,
        release: () -> Unit,
    ) {
        a.pushHandler(CONTROL_CLEARER_NAME, ControlStreamClearer())
        b.pushHandler(CONTROL_CLEARER_NAME, ControlStreamClearer())
        listOf(a, b).forEach { stream ->
            stream.pushHandler(InboundTrafficLimitHandler(limits.circuitMaxBytes))
            stream.pushHandler(TotalTimeoutHandler(limits.circuitMaxDuration))
        }
        val aChannel = nettyChannelOf(a)
        val bChannel = nettyChannelOf(b)
        if (aChannel == null || bChannel == null) {
            // Should be unreachable in this build; forwarding without flow control is still better
            // than refusing an otherwise-valid circuit, but it must be visible if it ever happens.
            logger.warn { "circuit legs are not Netty-backed - forwarding without flow control" }
            return spliceWithoutFlowControl(a, b, release)
        }
        val aTransport = transportChannelOf(aChannel)
        val bTransport = transportChannelOf(bChannel)
        listOf(aTransport, bTransport).forEach { transport ->
            transport.config().writeBufferWaterMark =
                WriteBufferWaterMark(
                    CIRCUIT_WRITE_BUFFER_LOW_WATER_MARK_BYTES,
                    CIRCUIT_WRITE_BUFFER_HIGH_WATER_MARK_BYTES,
                )
        }
        a.pushHandler(CircuitProxyHandler(bChannel, bTransport, aTransport))
        b.pushHandler(CircuitProxyHandler(aChannel, aTransport, bTransport))
        // b drained -> a may read again, and vice versa. Installed on the transport channels, which
        // outlive this circuit, so both are removed again when the circuit ends.
        val resumeA = CircuitReadResumer(aTransport)
        val resumeB = CircuitReadResumer(bTransport)
        bTransport.pipeline().addLast(resumeA)
        aTransport.pipeline().addLast(resumeB)
        val unwireResumers = {
            runCatching { bTransport.pipeline().remove(resumeA) }
            runCatching { aTransport.pipeline().remove(resumeB) }
            // A leg that was paused when its circuit died must not stay paused: nothing would ever
            // resume it, and the connection carries other streams.
            runCatching { aTransport.config().isAutoRead = true }
            runCatching { bTransport.config().isAutoRead = true }
        }
        // Either leg dying must tear down the other, or the survivor would sit there holding a
        // circuit slot and a stream forever.
        a.closeFuture().whenComplete { _, _ ->
            release()
            unwireResumers()
            runCatching { b.close() }
        }
        b.closeFuture().whenComplete { _, _ ->
            release()
            unwireResumers()
            runCatching { a.close() }
        }
    }

    private fun spliceWithoutFlowControl(
        a: Stream,
        b: Stream,
        release: () -> Unit,
    ) {
        a.pushHandler(UnboundedCircuitProxyHandler(b))
        b.pushHandler(UnboundedCircuitProxyHandler(a))
        a.closeFuture().whenComplete { _, _ ->
            release()
            runCatching { b.close() }
        }
        b.closeFuture().whenComplete { _, _ ->
            release()
            runCatching { a.close() }
        }
    }
}

/**
 * Hop protocol handler. Traffic limits are `Long.MAX_VALUE` **on purpose**: that is the documented
 * way to stop [io.libp2p.protocol.ProtocolHandler] from installing an un-removable
 * `InboundTrafficLimitHandler` on a stream that is about to stop being a control stream (see
 * [ControlStreamClearer]). A removable limiter of our own is installed instead, and the relay's
 * real forwarding budget comes from [RelayServerLimits].
 */
internal class LapisCircuitHopProtocol(
    private val config: RelayConfig,
    private val registry: RelayReservationRegistry,
    private val stopBinding: ProtocolBinding<CircuitStopControl>,
    private val clock: () -> Instant,
) : ProtobufProtocolHandler<CircuitHopControl>(
        Circuit.HopMessage.getDefaultInstance(),
        Long.MAX_VALUE,
        Long.MAX_VALUE,
    ) {
    @Volatile
    private var host: Host? = null

    fun setHost(host: Host) {
        this.host = host
    }

    override fun initProtocolStream(stream: Stream) {
        // Pushed BEFORE super's protobuf codecs on purpose: pushHandler appends, and inbound
        // messages travel first-pushed to last-pushed, so a limiter added afterwards would be
        // handed decoded HopMessages instead of the ByteBufs it casts to.
        stream.pushHandler(
            CONTROL_LIMIT_HANDLER_NAME,
            InboundTrafficLimitHandler(CONTROL_STREAM_INBOUND_LIMIT_BYTES),
        )
        super.initProtocolStream(stream)
    }

    override fun onStartInitiator(stream: Stream): CompletableFuture<CircuitHopControl> {
        val sender = HopSender(stream)
        stream.pushHandler(CONTROL_HANDLER_NAME, io.libp2p.protocol.ProtocolMessageHandlerAdapter(stream, sender))
        return CompletableFuture.completedFuture(sender)
    }

    override fun onStartResponder(stream: Stream): CompletableFuture<CircuitHopControl> {
        val us = host ?: throw IllegalStateException("hop protocol used before its Host was set")
        val receiver = HopReceiver(us, config, registry, stopBinding, clock)
        stream.pushHandler(CONTROL_HANDLER_NAME, io.libp2p.protocol.ProtocolMessageHandlerAdapter(stream, receiver))
        return CompletableFuture.completedFuture(receiver)
    }
}

internal class LapisCircuitHopBinding(
    hop: LapisCircuitHopProtocol,
) : StrictProtocolBinding<CircuitHopControl>(HOP_PROTOCOL_ID, hop)

// ---------------------------------------------------------------------------------------------
// Stop protocol (relay <-> destination)
// ---------------------------------------------------------------------------------------------

/** Controller type of [LapisCircuitStopProtocol]. */
internal interface CircuitStopControl

/** Initiator half of the stop protocol - used by a relay to reach the circuit's destination. */
internal class StopSender(
    val stream: Stream,
) : ProtocolMessageHandler<Circuit.StopMessage>,
    CircuitStopControl {
    private val pending = ConcurrentLinkedDeque<CompletableFuture<Circuit.StopMessage>>()

    override fun onMessage(
        stream: Stream,
        msg: Circuit.StopMessage,
    ) {
        pending.poll()?.complete(msg)
    }

    override fun onClosed(stream: Stream) = failAll(IllegalStateException("relay stop stream closed"))

    override fun onException(cause: Throwable?) = failAll(cause ?: IllegalStateException("relay stop stream failed"))

    private fun failAll(cause: Throwable) {
        while (true) {
            (pending.poll() ?: return).completeExceptionally(cause)
        }
    }

    fun connect(
        initiator: PeerId,
        limits: RelayServerLimits,
    ): CompletableFuture<Circuit.StopMessage> {
        val result = CompletableFuture<Circuit.StopMessage>()
        pending.add(result)
        stream.writeAndFlush(
            Circuit.StopMessage
                .newBuilder()
                .setType(Circuit.StopMessage.Type.CONNECT)
                .setPeer(Circuit.Peer.newBuilder().setId(ByteString.copyFrom(initiator.bytes)))
                .setLimit(
                    Circuit.Limit
                        .newBuilder()
                        .setDuration(limits.circuitMaxDuration.seconds.toInt())
                        .setData(limits.circuitMaxBytes),
                ).build(),
        )
        return result
    }
}

/**
 * Responder half of the stop protocol - a node behind NAT accepting an inbound relayed connection.
 *
 * **Deliberately not `io.libp2p.protocol.circuit.CircuitStopProtocol.Receiver`.** That class calls
 * `RelayTransport.upgradeStream(..., connHandler)` with a literal
 * `ConnectionHandler connHandler = null; // TODO`, so the very last step of accepting a relayed
 * connection throws a `NullPointerException` and the connection is never handed to anything. This
 * one passes a real handler.
 */
internal class StopReceiver(
    private val onCircuitAccepted: (Stream, PeerId) -> Unit,
    private val holdsReservationWith: (PeerId) -> Boolean,
    private val limits: RelayClientLimits,
) : ProtocolMessageHandler<Circuit.StopMessage>,
    CircuitStopControl {
    override fun onMessage(
        stream: Stream,
        msg: Circuit.StopMessage,
    ) {
        // Only a relay this node deliberately reserved a slot with may push an inbound circuit at
        // it. Circuit Relay v2 neither requires nor forbids this check; without it, ANY peer able to
        // open a stop stream could make this node run a Noise handshake and hold a connection open
        // on demand - a free, unauthenticated way to spend this node's resources with no legitimate
        // counterpart, since a circuit can only ever legitimately arrive over a reservation this
        // node itself asked for.
        val relay = stream.remotePeerId()
        if (!holdsReservationWith(relay)) {
            logger.debug { "refusing relayed connection offered by $relay - no reservation held there" }
            // Refusals close the stream - see writeAndClose. Especially here: this is the branch a
            // stranger reaches, so it is exactly the one that must not leave anything behind.
            writeAndClose(
                stream,
                Circuit.StopMessage
                    .newBuilder()
                    .setType(Circuit.StopMessage.Type.STATUS)
                    .setStatus(Circuit.Status.PERMISSION_DENIED)
                    .build(),
            )
            return
        }
        if (msg.type != Circuit.StopMessage.Type.CONNECT) {
            writeAndClose(
                stream,
                Circuit.StopMessage
                    .newBuilder()
                    .setType(Circuit.StopMessage.Type.STATUS)
                    .setStatus(Circuit.Status.UNEXPECTED_MESSAGE)
                    .build(),
            )
            return
        }
        val initiator =
            try {
                PeerId(msg.peer.id.toByteArray())
            } catch (e: IllegalArgumentException) {
                logger.debug(e) { "relay ${stream.remotePeerId()} announced a malformed circuit initiator" }
                writeAndClose(
                    stream,
                    Circuit.StopMessage
                        .newBuilder()
                        .setType(Circuit.StopMessage.Type.STATUS)
                        .setStatus(Circuit.Status.MALFORMED_MESSAGE)
                        .build(),
                )
                return
            }
        stream.writeAndFlush(
            Circuit.StopMessage
                .newBuilder()
                .setType(Circuit.StopMessage.Type.STATUS)
                .setStatus(Circuit.Status.OK)
                .build(),
        )
        stream.pushHandler(CONTROL_CLEARER_NAME, ControlStreamClearer())
        // Locally-chosen, never the relay-announced number: see RelayClientLimits' doc comment.
        stream.pushHandler(InboundTrafficLimitHandler(limits.maxInboundBytesPerCircuit))
        onCircuitAccepted(stream, initiator)
    }
}

/** See [LapisCircuitHopProtocol] for why the traffic limits are `Long.MAX_VALUE`. */
internal class LapisCircuitStopProtocol(
    private val limits: RelayClientLimits,
) : ProtobufProtocolHandler<CircuitStopControl>(
        Circuit.StopMessage.getDefaultInstance(),
        Long.MAX_VALUE,
        Long.MAX_VALUE,
    ) {
    /** Set by [LapisRelayTransport] once it exists - the transport is what knows how to upgrade an
     * accepted circuit into a real [io.libp2p.core.Connection]. */
    @Volatile
    var onCircuitAccepted: ((Stream, PeerId) -> Unit)? = null

    /** Whether this node currently holds a relay reservation with the given peer - wired by
     * `LapisNode` to [RelayReservationClient.holdsReservationWith]. Defaults to refusing
     * everything, so a half-wired node is closed rather than open. See [StopReceiver] for why the
     * check exists at all. */
    @Volatile
    var holdsReservationWith: (PeerId) -> Boolean = { false }

    override fun initProtocolStream(stream: Stream) {
        // See LapisCircuitHopProtocol.initProtocolStream for why this goes before super's codecs.
        stream.pushHandler(
            CONTROL_LIMIT_HANDLER_NAME,
            InboundTrafficLimitHandler(CONTROL_STREAM_INBOUND_LIMIT_BYTES),
        )
        super.initProtocolStream(stream)
    }

    override fun onStartInitiator(stream: Stream): CompletableFuture<CircuitStopControl> {
        val sender = StopSender(stream)
        stream.pushHandler(CONTROL_HANDLER_NAME, io.libp2p.protocol.ProtocolMessageHandlerAdapter(stream, sender))
        return CompletableFuture.completedFuture(sender)
    }

    override fun onStartResponder(stream: Stream): CompletableFuture<CircuitStopControl> {
        val accept =
            onCircuitAccepted
                ?: throw IllegalStateException("stop protocol used before its transport was wired")
        val receiver = StopReceiver(accept, holdsReservationWith, limits)
        stream.pushHandler(CONTROL_HANDLER_NAME, io.libp2p.protocol.ProtocolMessageHandlerAdapter(stream, receiver))
        return CompletableFuture.completedFuture(receiver)
    }
}

internal class LapisCircuitStopBinding(
    stop: LapisCircuitStopProtocol,
) : StrictProtocolBinding<CircuitStopControl>(STOP_PROTOCOL_ID, stop)

/** Raised when a relay refuses, misbehaves, or cannot be reached. */
class RelayException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Splits `<relay addr>/p2p/<relay>/p2p-circuit/p2p/<target>` into its relay and target halves.
 * Returns `null` if [address] is not a well-formed circuit address. */
internal fun splitCircuitAddress(address: Multiaddr): Pair<Multiaddr, PeerId>? {
    val components = address.components
    val circuitIndex = components.indexOfFirst { it.protocol == Protocol.P2PCIRCUIT }
    if (circuitIndex <= 0) return null
    val relayPart = Multiaddr(components.subList(0, circuitIndex))
    if (relayPart.getPeerId() == null) return null
    // Relay chaining is not supported: exactly one /p2p-circuit component, and the target half must
    // name exactly one peer.
    val targetPart = Multiaddr(components.subList(circuitIndex + 1, components.size))
    if (targetPart.has(Protocol.P2PCIRCUIT)) return null
    val target = targetPart.getPeerId() ?: return null
    return relayPart to target
}

/** `<relay addr>/p2p/<relay>` -> `<relay addr>/p2p/<relay>/p2p-circuit`. The trailing
 * `/p2p/<self>` is appended by `io.libp2p.host.HostImpl.listenAddresses`, so it is deliberately
 * absent here. */
internal fun circuitListenAddress(relayAddressWithPeerId: Multiaddr): Multiaddr =
    relayAddressWithPeerId.withComponent(Protocol.P2PCIRCUIT)
