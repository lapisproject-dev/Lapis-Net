package net.lapisphilosophorum.lapisnet.networking.relay

import io.github.oshai.kotlinlogging.KotlinLogging
import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.AttributeKey
import io.netty.util.ReferenceCountUtil
import java.time.Duration
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

private val logger = KotlinLogging.logger {}

/**
 * Key of the per-connection [TransportReadGate]. Created with `valueOf` (never `newInstance`) so
 * every caller in the JVM resolves to the same key; the attribute lives exactly as long as the
 * channel it is attached to, so nothing here outlives a connection.
 */
private val GATE_KEY: AttributeKey<TransportReadGate> = AttributeKey.valueOf("lapis.relay.transport-read-gate")

/**
 * Relay-wide gauges for the forwarding path - one instance per
 * [LapisCircuitHopProtocol], i.e. per node. Exists so the stall bound can be observed (and tested)
 * rather than inferred from "nothing seemed to hang".
 */
internal class CircuitFlowStats {
    private val pausedLegs = AtomicInteger(0)
    private val stallClosures = AtomicLong(0)

    /** Circuit legs whose source connection is paused right now. */
    fun pausedLegs(): Int = pausedLegs.get()

    /** Circuits this relay closed because a leg stayed paused for longer than the stall timeout. */
    fun stallClosures(): Long = stallClosures.get()

    fun onLegPaused() {
        pausedLegs.incrementAndGet()
    }

    fun onLegUnpaused() {
        pausedLegs.decrementAndGet()
    }

    fun onStallClosure() {
        stallClosures.incrementAndGet()
    }
}

/**
 * State shared by both legs of one circuit.
 *
 * [closed] flips exactly once - either because a stall closure ended the circuit
 * ([closeForStall]) or because the circuit ended on its own ([markEnded]). From then on forwarded
 * bytes are dropped (and released) instead of being written to a stream that is going away.
 */
internal class CircuitState(
    /** Peer ids only ("initiator -> target"), safe to log. */
    val description: String,
    private val closeCircuit: () -> Unit,
) {
    val closed = AtomicBoolean(false)

    /** Closes both streams, exactly once. Returns `true` for the one caller that did. */
    fun closeForStall(stats: CircuitFlowStats): Boolean {
        if (!closed.compareAndSet(false, true)) return false
        stats.onStallClosure()
        closeCircuit()
        return true
    }

    /** The circuit ended by itself (a leg closed). Not a stall closure, so nothing is counted. */
    fun markEnded() {
        closed.set(true)
    }
}

/**
 * One direction of one circuit: reads from [sourceTransport], writes to [targetTransport]. Identity
 * equality on purpose - two legs are the same leg only if they are the same object.
 */
internal class CircuitLeg(
    val sourceTransport: Channel,
    val targetTransport: Channel,
    val circuit: CircuitState,
)

/**
 * Pause bookkeeping for one connection channel, shared by every circuit leg that reads from it.
 *
 * Netty's `autoRead` is a single switch per connection, but a connection can be the source of
 * several circuit legs at once. Letting each leg flip the switch directly means one leg's "target
 * drained, resume" silently un-pauses a different leg that is still blocked. This gate keeps the
 * set of paused legs instead: `autoRead` is on exactly when that set is empty.
 *
 * **It also bounds the stall.** Pausing a connection stalls *every other stream on it* (mplex has no
 * per-stream flow control), including reservation renewals and unrelated circuits. A peer that
 * simply never reads would hold that stall forever, so each paused leg carries a timer: when a leg
 * has been paused for [stallTimeout] its circuit is closed - that one circuit, not the connection -
 * and the connection resumes. That alone bounds one pause *episode*, not the connection's total
 * stalled time: a peer that never reads and reopens its circuit starts a fresh episode each time. A
 * **connection-wide stall budget** (a leaky bucket of paused time, see the constructor) therefore
 * caps the cumulative time the connection spends paused in a sliding window; once it is used up, a
 * leg that would pause the connection again may do so only for the grace period and is closed if it
 * is still paused after that.
 *
 * **Grace.** Only the part of a pause episode (a continuous stretch during which at least one leg
 * is paused) beyond the grace period is charged to the budget. Without it every pause counts, so an
 * honest receiver that reads steadily but slower than the sender - whose episodes last
 * milliseconds but occur constantly - would use the budget up and then have its circuits cut. The
 * budget also belongs to the connection, not to whoever caused the stall: once it is used up, every
 * circuit of the connection whose pause outlasts the grace is closed, the guilty one or not. An
 * honest receiver that drains slower than roughly (high - low water mark) / grace is in episodes
 * longer than the grace most of the time, is charged for the excess, and is eventually cut as well.
 *
 * **The grace is not renewed for free after a closure.** A new episode that begins less than one
 * grace after a circuit of this connection was closed for stalling gets only as much free time as
 * the connection has been readable since that closure (see [episodeGrace]). Without that, an
 * attacker could chain circuits from several identities - the `CONNECT` rate limit is per identity
 * - each pausing the connection for a full uncharged grace right after the previous one was cut.
 * What remains: for a chain whose pauses END IN A STALL CLOSURE this holds the connection paused for
 * at most about half of the time. The cap reads only the time of the last stall closure, so it does
 * not apply when the pauses end any other way: a peer that reads (briefly) just before the grace
 * runs out, or an attacker that ends its own pause by resetting its stream or dropping its own relay
 * connection (the circuit then goes through [doRemove], which charges and stamps nothing - no reading
 * needed, and with several identities the next prepared circuit starts a new episode with a full
 * grace straight away). In that regime the victim connection can be paused almost all of the time in
 * pieces of up to the grace: bounded latency per pause, NOT a bounded share. The long-run
 * `budget / window` share only bounds the *charged* part of the pausing. A pause is never longer
 * than the grace once the budget is used up, but pauses of up to the grace that end by themselves
 * are not charged and not counted as closures.
 *
 * **Threading.** All state is confined to [transport]'s event loop; every entry point hops there
 * (inline when already on it). The substream a [CircuitProxyHandler] runs on is registered on its
 * parent connection's event loop (`AbstractMuxHandler` registers each child with
 * `ctx.channel().eventLoop().register(child)`), so `pause` from `channelRead` is synchronous, and a
 * `resume` posted from the *other* connection's loop is ordered after it.
 */
internal class TransportReadGate private constructor(
    private val transport: Channel,
    private val stallTimeout: Duration,
    private val stats: CircuitFlowStats,
    stallBudget: Duration?,
    stallBudgetWindow: Duration,
    stallGrace: Duration,
    private val nanoClock: () -> Long,
) {
    // Loop-confined. Bounded by the number of circuit legs reading from this connection, which the
    // relay's circuit caps already bound; a leg is removed when paused->resumed or its circuit ends.
    private val paused = HashMap<CircuitLeg, ScheduledFuture<*>>()

    // Duration.toMillis() throws for absurdly large values; "practically never" is what those mean.
    private val stallMillis: Long = runCatching { stallTimeout.toMillis() }.getOrDefault(Long.MAX_VALUE / 4)

    // Connection-wide stall budget (leaky bucket, loop-confined). `budgetNanos == null` switches it
    // off. `level` is the cumulative time this connection has recently spent paused; it grows in
    // real time while at least one leg is paused and drains at `budgetNanos / windowNanos` per
    // nanosecond otherwise (and, more slowly, while paused). It is clamped to the budget. The
    // per-leg timer alone only bounds ONE pause episode: a peer that never reads and simply reopens
    // its circuit starts a fresh episode every time, so only this connection-level account bounds
    // how much of its time a connection spends stalled.
    private val budgetNanos: Double? =
        stallBudget?.let { runCatching { it.toNanos().toDouble() }.getOrDefault(Double.MAX_VALUE / 4) }
    private val drainPerNano: Double =
        if (budgetNanos == null) {
            0.0
        } else {
            val windowNanos = runCatching { stallBudgetWindow.toNanos().toDouble() }.getOrDefault(Double.MAX_VALUE / 4)
            (budgetNanos / windowNanos).coerceIn(0.0, 0.999)
        }
    private var level = 0.0
    private var lastSettleNanos = nanoClock()

    // Free part of every pause episode, see the class doc. Negative values are rejected by
    // RelayServerLimits; coerced here so a direct caller cannot invert the arithmetic.
    private val graceNanos: Long =
        runCatching { stallGrace.toNanos() }.getOrDefault(Long.MAX_VALUE / 4).coerceAtLeast(0L)

    // When the current pause episode (paused went from empty to non-empty) began, and how much of
    // it is free. The free part is the full grace unless a stall closure happened on this
    // connection shortly before the episode began, see episodeGrace().
    private var episodeStartNanos = lastSettleNanos
    private var episodeGraceNanos = graceNanos

    // When this connection last had a circuit closed for stalling it (unset until the first one).
    // Every stall closure is immediately followed by the connection resuming, so the time since then
    // is an UPPER bound on how long the connection has been readable again: it is wall-clock time
    // since the closure, and pauses that ended in some other way (the peer read, or the circuit was
    // reset or its connection dropped) lie inside it and count as readable. Only closures stamp it.
    private var hasStallClosure = false
    private var lastStallClosureNanos = 0L

    /** Pauses reading from this connection on behalf of [leg]. No-op if [leg] is already paused
     * (the timer is deliberately NOT re-armed, or the bound would never fire) or its circuit is
     * over. */
    fun pause(leg: CircuitLeg) = onLoop { doPause(leg) }

    /** Lifts [leg]'s pause. Unknown legs are ignored. Reading resumes once no leg is paused. */
    fun resume(leg: CircuitLeg) = onLoop { doRemove(leg) }

    /** Forgets [leg] at the end of its circuit - same effect as [resume], kept separate so call
     * sites say which of the two they mean. */
    fun remove(leg: CircuitLeg) = onLoop { doRemove(leg) }

    private fun onLoop(action: () -> Unit) {
        val loop = transport.eventLoop()
        try {
            if (loop.inEventLoop()) action() else loop.execute(action)
        } catch (_: RejectedExecutionException) {
            // The loop is shutting down; the connection (and with it every timer) is going away.
        }
    }

    /** Brings [level] up to date. Must run before [paused] changes, so the elapsed interval is
     * accounted with the pause state that actually held during it. Only the part of the interval
     * that lies beyond the current episode's grace period is charged. */
    private fun settle() {
        val cap = budgetNanos ?: return
        val now = nanoClock()
        val previous = lastSettleNanos
        val elapsed = (now - previous).coerceAtLeast(0L).toDouble()
        lastSettleNanos = now
        val chargeFrom = maxOf(previous, saturatedAdd(episodeStartNanos, episodeGraceNanos))
        val growth = if (paused.isEmpty()) 0.0 else (now - chargeFrom).coerceAtLeast(0L).toDouble()
        level = (level + growth - elapsed * drainPerNano).coerceIn(0.0, cap)
    }

    private fun saturatedAdd(
        a: Long,
        b: Long,
    ): Long = if (b > Long.MAX_VALUE - a) Long.MAX_VALUE else a + b

    /**
     * Free part of an episode that begins now. A fresh connection gets the full grace. After a stall
     * closure on this connection the grace is capped at the wall-clock time since that closure: a
     * circuit that was just cut because its peer did not read must not be followed by a second
     * circuit (another identity costs one key generation) that gets a full free grace again, or a
     * chain of them would keep the connection paused almost all of the time while being charged
     * nothing. For a chain whose pauses each end in a stall closure the cap means a pause of length p
     * has at least p of time since the previous closure before it, so closure-cycling holds the
     * connection paused for at most half of the time (and for none of it when the episodes follow
     * each other directly).
     *
     * **Limit of the cap.** It sees only stall closures. A pause that ends without one (the peer reads,
     * or the attacker resets its stream / drops its own relay connection, which needs no reading and
     * leaves no timestamp) is neither charged nor stamped, so the next episode - possibly from another
     * identity - gets the full grace again, and the 50 % figure does not hold for such a chain: the
     * connection can be paused almost all of the time in pieces of up to the grace. Honest receivers
     * are unaffected unless a circuit of the same connection was cut less than one grace ago.
     */
    private fun episodeGrace(now: Long): Long {
        if (!hasStallClosure) return graceNanos
        return minOf(graceNanos, (now - lastStallClosureNanos).coerceAtLeast(0L))
    }

    /** Closes [leg]'s circuit for stalling and, for the one caller that actually closed it, notes
     * the time for [episodeGrace]. */
    private fun closeForStall(leg: CircuitLeg): Boolean {
        if (!leg.circuit.closeForStall(stats)) return false
        hasStallClosure = true
        lastStallClosureNanos = nanoClock()
        return true
    }

    private fun doPause(leg: CircuitLeg) {
        if (leg.circuit.closed.get() || paused.containsKey(leg)) return
        var delayMillis = stallMillis
        val cap = budgetNanos
        if (cap != null) {
            settle()
            if (paused.isEmpty()) {
                episodeStartNanos = lastSettleNanos
                episodeGraceNanos = episodeGrace(lastSettleNanos)
            }
            // Free pause time left in the current episode (the whole free part for a new one).
            val freeNanos =
                (saturatedAdd(episodeStartNanos, episodeGraceNanos) - lastSettleNanos).coerceAtLeast(0L)
            if (level >= cap) {
                // Budget used up: this connection has already spent its share of the recent window
                // stalled. A leg that wants to pause it again gets only what is left of the grace
                // period - ordinary backpressure that resolves within it is untouched - and its
                // circuit is cut if it is still paused after that, instead of getting a fresh
                // full-length stall timer.
                if (freeNanos <= 0L) {
                    if (closeForStall(leg)) {
                        logger.info {
                            "closing circuit ${leg.circuit.description}: the connection's stall budget is " +
                                "used up and the receiving peer is not reading"
                        }
                    }
                    return
                }
                delayMillis = minOf(delayMillis, nanosToMillisCeil(freeNanos))
            } else {
                // Time until the budget runs dry if the connection stays paused from now on:
                // the free part of the episode, then the remaining budget at the charge rate (the
                // level keeps draining while nothing is charged).
                val levelWhenCharging = (level - freeNanos.toDouble() * drainPerNano).coerceAtLeast(0.0)
                val untilExhaustedNanos = freeNanos.toDouble() + (cap - levelWhenCharging) / (1.0 - drainPerNano)
                delayMillis = minOf(delayMillis, (untilExhaustedNanos / 1_000_000.0).toLong() + 1)
            }
        }
        transport.config().isAutoRead = false
        // The task cannot run before this method returns (same single-threaded loop), so the
        // reference is always set by the time the timer fires.
        val timerRef = AtomicReference<ScheduledFuture<*>>()
        val timer =
            transport.eventLoop().schedule(
                { onStallTimer(leg, timerRef.get()) },
                delayMillis,
                TimeUnit.MILLISECONDS,
            )
        timerRef.set(timer)
        paused[leg] = timer
        stats.onLegPaused()
        logger.debug {
            "gate ${transport.id().asShortText()}: paused ${leg.circuit.description} " +
                "(${paused.size} paused, autoRead=${transport.config().isAutoRead}, timeout=$delayMillis ms)"
        }
    }

    private fun nanosToMillisCeil(nanos: Long): Long = maxOf(1L, (nanos + 999_999L) / 1_000_000L)

    private fun doRemove(leg: CircuitLeg) {
        if (!paused.containsKey(leg)) return
        settle()
        val timer = paused.remove(leg) ?: return
        timer.cancel(false)
        stats.onLegUnpaused()
        if (paused.isEmpty()) transport.config().isAutoRead = true
        logger.debug {
            "gate ${transport.id().asShortText()}: resumed ${leg.circuit.description} " +
                "(${paused.size} paused, autoRead=${transport.config().isAutoRead})"
        }
    }

    private fun onStallTimer(
        leg: CircuitLeg,
        timer: ScheduledFuture<*>,
    ) {
        // A timer that was cancelled-and-replaced must not act on the leg's newer pause.
        if (paused[leg] !== timer) return
        logger.debug { "gate ${transport.id().asShortText()}: stall timer fired for ${leg.circuit.description}" }
        // Close FIRST, resume second: resuming first would let the source read straight away and
        // pause again under a brand-new timer.
        if (closeForStall(leg)) {
            logger.info {
                "closing circuit ${leg.circuit.description}: forwarding blocked for more than " +
                    "the stall timeout ($stallMillis ms) or the connection's stall budget because the " +
                    "receiving peer is not reading"
            }
        }
        doRemove(leg)
    }

    companion object {
        /** The gate of [transport], created on first use. Called on any thread. */
        fun of(
            transport: Channel,
            stallTimeout: Duration,
            stats: CircuitFlowStats,
            stallBudget: Duration? = null,
            stallBudgetWindow: Duration = Duration.ofMinutes(10),
            stallGrace: Duration = Duration.ZERO,
            nanoClock: () -> Long = System::nanoTime,
        ): TransportReadGate {
            val attribute = transport.attr(GATE_KEY)
            attribute.get()?.let { return it }
            val fresh =
                TransportReadGate(transport, stallTimeout, stats, stallBudget, stallBudgetWindow, stallGrace, nanoClock)
            return attribute.setIfAbsent(fresh) ?: fresh
        }
    }
}

/**
 * Forwards raw inbound bytes from one leg of a circuit onto the other, **with real backpressure and
 * a bounded stall**.
 *
 * Ownership of each [ByteBuf] passes to the target channel's write, which releases it (including
 * when that write fails because the other leg is already gone). Bytes arriving after the circuit
 * was closed are released here and dropped.
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
 *  - [CircuitLeg.targetTransport] is the connection channel that stream rides on. Bytes queue there,
 *    not on the substream: `MuxChannel.doWrite` hands each buffer straight to the parent connection,
 *    so the substream's own outbound buffer is always empty and its `isWritable` is always `true`.
 *    The connection channel is therefore the only place where writability means anything.
 *  - [CircuitLeg.sourceTransport] is the connection channel the bytes arrive on. Turning its
 *    `autoRead` off (through [TransportReadGate]) is what actually stops the flow: a substream
 *    cannot be paused on its own either, since `AbstractChildChannel.doBeginRead` is a no-op and
 *    inbound frames are pushed at it by the muxer.
 *
 * Pausing a whole connection is coarser than pausing one circuit, and stalls the other streams of
 * that connection. That is inherent to mplex having no per-stream flow control. The stall is bounded
 * by [RelayServerLimits.circuitStallTimeout]: after that long the circuit that caused it is closed.
 */
internal class CircuitProxyHandler(
    private val target: Channel,
    private val leg: CircuitLeg,
    private val sourceGate: TransportReadGate,
) : ChannelInboundHandlerAdapter() {
    override fun channelRead(
        ctx: ChannelHandlerContext,
        msg: Any,
    ) {
        if (msg !is ByteBuf) {
            ctx.fireChannelRead(msg)
            return
        }
        if (leg.circuit.closed.get()) {
            ReferenceCountUtil.release(msg)
            return
        }
        target.writeAndFlush(msg)
        if (!leg.targetTransport.isWritable) {
            sourceGate.pause(leg)
            // Lost-wakeup guard. The target may have drained - and its resumer fired - between the
            // check above and the pause taking effect; that resume then found nothing to lift. The
            // re-check sees the drained state, and its resume is ordered after the pause on the
            // source loop, so exactly one of the two orders ends with reading enabled.
            if (leg.targetTransport.isWritable) sourceGate.resume(leg)
        }
    }
}

/**
 * Sits on a circuit leg's **target transport** channel and lifts [leg]'s pause once that channel
 * has drained below its low water mark - the other half of [CircuitProxyHandler]'s backpressure.
 *
 * It has to live on the transport channel rather than on the substream because writability events
 * are fired on the channel whose write buffer changed, and that is never the substream (see
 * [CircuitProxyHandler]'s doc comment). Runs on the target's event loop; the actual state change is
 * posted to the source's loop by [TransportReadGate].
 */
internal class CircuitReadResumer(
    private val leg: CircuitLeg,
    private val sourceGate: TransportReadGate,
) : ChannelInboundHandlerAdapter() {
    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        if (ctx.channel().isWritable) sourceGate.resume(leg)
        ctx.fireChannelWritabilityChanged()
    }
}
