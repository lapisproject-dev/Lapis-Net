package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.StreamPromise
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.protocol.ProtocolHandler
import io.libp2p.protocol.ProtocolMessageHandler
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.handler.codec.LengthFieldBasedFrameDecoder
import io.netty.handler.codec.LengthFieldPrepender
import io.netty.handler.timeout.ReadTimeoutHandler
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/** This wave's custom libp2p stream protocol id - the FIRST protocol binding in this codebase that
 * is not GossipSub. Versioned (`1.0.0`), mirroring `io.libp2p.protocol.Ping`'s own
 * `"/ipfs/ping/1.0.0"` convention. */
const val DM_PROTOCOL_ID = "/lapis/dm/1.0.0"

private const val LENGTH_FIELD_SIZE = 4

/** Netty `ReadTimeoutHandler` idle window - fires if NO read event at all occurs within this many
 * seconds. Catches the classic slowloris shape (open a stream, send nothing more, hold the
 * connection). Does NOT alone catch a peer that drips one byte just before every window expires -
 * see [MAX_STREAM_LIFETIME_SECONDS] for that. */
private const val READ_IDLE_TIMEOUT_SECONDS = 10L

/** Absolute wall-clock cap from stream-open to full-frame-delivered, REGARDLESS of read activity -
 * closes the "drip one byte every [READ_IDLE_TIMEOUT_SECONDS]-minus-one seconds forever" slowloris
 * variant [ReadTimeoutHandler] alone does not catch (it resets on ANY read, however small). A
 * legitimate DM handshake - directory lookup already resolved, TCP+Noise+mplex already established -
 * completes in well under a second on a healthy connection; this generous a budget only ever binds
 * an adversarial or badly broken peer. */
private const val MAX_STREAM_LIFETIME_SECONDS = 20L

/** Per remote [PeerId], enforced in [DmProtocolHandler.onStartResponder] - bounds how many
 * concurrent, not-yet-completed `/lapis/dm/1.0.0` streams a single misbehaving or malicious peer may
 * have open against this node at once, so one peer cannot exhaust this node's stream-handling
 * capacity (adversarial test case (d)). 8 is generous headroom above any legitimate 1:1-DM traffic
 * pattern (this wave's design is one stream per message, fire-and-forget - see
 * [DmProtocolHandler]'s own class doc comment) while still bounding the per-peer resource an
 * attacker can force this node to hold open, mirroring this codebase's usual "generous headroom, not
 * derived from a protocol requirement" numeric-cap convention. */
const val MAX_CONCURRENT_STREAMS_PER_PEER = 8

/** Marker: what [DmProtocolHandler.onStartInitiator]/[DmProtocolHandler.onStartResponder] hand back
 * as this [ProtocolHandler]'s `TController`. Only [DmSendHandle] (the initiator role) has any
 * caller-usable method - nobody dials into themselves, so the responder role's controller is never
 * consulted by anyone; mirrors `io.libp2p.protocol.PingController`'s "one shared type, responder
 * role's implementation is a stub" shape, simplified further since this protocol has no
 * responder-side interactive method at all. */
sealed interface DmStreamRole

/** The responder role's controller - carries no methods, nobody ever calls into it. */
object DmResponderRole : DmStreamRole

/** The initiator role's controller - the ONE thing [DmSessionManager] actually does with a dialled
 * stream: hand it exactly one [DmEnvelope]'s encoded bytes. A narrow interface (rather than the
 * concrete handler class) so [DmSessionManager] depends on a small contract, not an implementation
 * detail. */
interface DmSendHandle : DmStreamRole {
    fun sendEnvelope(bytes: ByteArray)
}

/**
 * This module's custom `/lapis/dm/1.0.0` stream-protocol handler - the FIRST place in this codebase
 * that parses untrusted bytes arriving directly off a raw libp2p stream, with NO GossipSub
 * message-size ceiling backstopping the parser. Built directly against jvm-libp2p's real
 * `ProtocolHandler`/`ProtocolMessageHandler` API (verified against the resolved
 * `jvm-libp2p-1.3.5-RELEASE` jar), mirroring the shape of the bundled reference implementation,
 * `io.libp2p.protocol.Ping`/`PingProtocol` - except this handler explicitly pushes a Netty
 * length-field codec ([LengthFieldBasedFrameDecoder]/[LengthFieldPrepender]) in [initProtocolStream],
 * rather than relying on `Ping`'s implicit "one `writeAndFlush` call = one inbound `ByteBuf`"
 * assumption - an explicit, verifiable frame boundary is what actually gives a
 * length-validated-before-allocation guarantee, regardless of how the underlying mplex substream
 * happens to chunk bytes.
 *
 * **Four independent, layered defenses against the untrusted-raw-stream attack surface, cheapest/
 * earliest first:**
 * 1. `InboundTrafficLimitHandler` - pushed AUTOMATICALLY by the [ProtocolHandler] base class, before
 *    [initProtocolStream] even runs, from the `initiatorTrafficLimit`/`responderTrafficLimit`
 *    constructor arguments below. Caps TOTAL inbound bytes over the stream's lifetime, independent
 *    of and prior to the frame decoder - unlike `Ping` (which disables this with `Long.MAX_VALUE`),
 *    this handler passes sane, non-`MAX_VALUE` limits.
 * 2. [LengthFieldBasedFrameDecoder] with `failFast = true` and `maxFrameLength =`
 *    [DmEnvelopeCodec.MAX_ENVELOPE_BYTES]` + `[LENGTH_FIELD_SIZE] - rejects an oversized declared
 *    frame length BEFORE allocating any buffer proportional to that declared size (adversarial test
 *    case (a)). **The `+ LENGTH_FIELD_SIZE` is load-bearing, not cosmetic** (security audit round 1
 *    finding, 2026-08-11): Netty's `LengthFieldBasedFrameDecoder` compares the FULL frame length -
 *    declared body length PLUS `lengthFieldEndOffset` (`lengthFieldOffset + lengthFieldLength`, `4`
 *    here) - against `maxFrameLength`, not the declared body length alone. Passing bare
 *    [DmEnvelopeCodec.MAX_ENVELOPE_BYTES] here (the codec's OWN body-length ceiling) therefore
 *    rejected any envelope whose encoded size landed in the top 4 bytes of the legitimate range -
 *    proven with a maximum-size (65,459-byte plaintext, [DmEnvelopeCodec.MAX_ENVELOPE_BYTES]-byte
 *    envelope) round trip that [DmEnvelopeCodec.decode] itself accepted cleanly but this handler's
 *    decoder discarded with `TooLongFrameException`, silently, since this wave is fire-and-forget
 *    with no application-level ack. See [TwoNodeDmIntegrationTest] for the regression test.
 * 3. [ReadTimeoutHandler] ([READ_IDLE_TIMEOUT_SECONDS]) - the classic slowloris defense.
 * 4. The absolute [MAX_STREAM_LIFETIME_SECONDS] wall-clock deadline scheduled per stream in
 *    [onStartResponder]/[onStartInitiator] - catches the slow-drip variant #3 alone does not.
 *
 * Plus [MAX_CONCURRENT_STREAMS_PER_PEER], enforced per remote [PeerId] in [onStartResponder].
 *
 * **Design decision, not mandated by the plan, chosen deliberately: one stream per message,
 * fire-and-forget, no application-level ack.** Each [DmSessionManager.send] call dials a FRESH
 * stream (cheap if a `Connection` to the peer already exists - only a new mplex substream, not a new
 * TCP/Noise handshake), writes EXACTLY ONE [DmEnvelope] frame via [DmSendHandle.sendEnvelope], and
 * closes. The responder ([DmInboundMessageHandler]) decodes exactly one frame per stream and closes.
 * This is what makes the length-validated-before-allocation and slowloris defenses simple to reason
 * about (one frame lifecycle per stream, no ongoing multi-frame backpressure bookkeeping) and
 * matches this wave's "no delivery receipts... not even as stubs" scope cut (no response frame is
 * ever written back).
 *
 * **CRITICAL IDENTITY-AUTHORITY NOTE.** The libp2p [PeerId] a stream connection authenticates (via
 * Noise, at the TRANSPORT layer - [Stream.remotePeerId]) is used in [onStartResponder] ONLY as a
 * resource-management key: rate-limiting how many concurrent `/lapis/dm/1.0.0` streams one
 * transport connection may open. It is NEVER treated as a claim about who the [DmEnvelope]'s own
 * `senderIdentity` field is - that claim is authorized ONLY once [DmSessionManager]'s ratchet
 * decrypt succeeds. See [DmSessionManager.handleInboundEnvelope]'s own doc comment for the complete
 * argument this handler defers to.
 */
class DmProtocolHandler(
    private val onInboundEnvelope: (fromPeerId: PeerId, envelopeBytes: ByteArray) -> Unit,
) : ProtocolHandler<DmStreamRole>(
        // NAMING MIRRORS ProtocolHandler's OWN (confusing but verified-against-the-real-jar)
        // convention: "if (stream.isInitiator) responderTrafficLimit else initiatorTrafficLimit".
        // initiatorTrafficLimit bounds what WE ACCEPT AS RESPONDER (bytes an initiator may send us) -
        // must generously cover one full DmEnvelope frame plus its 4-byte length prefix.
        // responderTrafficLimit bounds what WE ACCEPT AS INITIATOR (bytes a responder may send back
        // to us) - kept small, since this wave's design is fire-and-forget one-way (no
        // application-level ack/response frame at all, see this class's own doc comment).
        DmEnvelopeCodec.MAX_ENVELOPE_BYTES.toLong() + LENGTH_FIELD_SIZE + 256,
        256L,
    ) {
    /** Self-cleaning: an entry exists ONLY while [PeerId] currently has at least one open
     * `/lapis/dm/1.0.0` stream against this node - [onStartResponder]/its `onFinished` callback both
     * mutate this atomically via [ConcurrentHashMap.compute]/[ConcurrentHashMap.computeIfPresent], and
     * the latter removes the entry outright once its count reaches zero (see both call sites below).
     * Deliberately NOT an `AtomicInteger`-per-key map that lingers forever once created - unlike
     * [DmSessionManager.peerLockStripes]'s attacker-mintable-key exposure, a distinct [PeerId] here
     * costs a real TCP+Noise-authenticated connection to mint, but a long-lived node talking to many
     * distinct peers over its lifetime would otherwise still accumulate one permanent entry per peer
     * ever seen. Bounded in practice by the number of peers CURRENTLY holding an open DM stream against
     * this node (itself capped per peer by [MAX_CONCURRENT_STREAMS_PER_PEER]), never by total distinct
     * peers ever seen. */
    private val perPeerStreamCounts = ConcurrentHashMap<PeerId, Int>()

    /** Lazily created so a [DmProtocolHandler] that is constructed but never actually used (e.g. a
     * test that only exercises [DmEnvelopeCodec]) never spins up a background thread. Daemon thread
     * so it never blocks JVM shutdown.
     *
     * **Constructed as a bare [ScheduledThreadPoolExecutor], NOT via
     * `Executors.newSingleThreadScheduledExecutor` - load-bearing, not a style choice.**
     * `Executors.newSingleThreadScheduledExecutor` returns a
     * `Executors.DelegatedScheduledExecutorService` WRAPPING a real `ScheduledThreadPoolExecutor` -
     * a deliberate JDK design so callers cannot reconfigure the pool size back up - which means it
     * can NEVER be cast to `ScheduledThreadPoolExecutor` (an earlier revision of this field tried
     * exactly that cast, for `removeOnCancelPolicy` below, and threw `ClassCastException` on first
     * access, silently poisoning EVERY stream on this handler - regression caught by this module's
     * own `TwoNodeDmIntegrationTest` before landing). `corePoolSize = 1` here reproduces the same
     * "single thread" semantics directly, with the real type in hand.
     *
     * **`removeOnCancelPolicy = true`** (security audit round 1 finding, 2026-08-11):
     * `ScheduledThreadPoolExecutor` defaults this to `false`, which leaves every CANCELLED
     * [absoluteDeadline] task sitting in the internal `DelayedWorkQueue` for its full original
     * [MAX_STREAM_LIFETIME_SECONDS] delay rather than removing it immediately - since this wave is
     * one stream per message, a peer completing streams in rapid succession (the normal, legitimate
     * case, not merely an attacker) would otherwise accumulate one dead queue entry per completed
     * stream for up to 20s, with nothing bounding queue growth except the unrelated
     * [MAX_CONCURRENT_STREAMS_PER_PEER] concurrency cap. Setting this true makes `cancel(false)`
     * (both call sites below) actually remove the task from the queue at cancellation time. */
    private val scheduler: ScheduledExecutorService by lazy {
        ScheduledThreadPoolExecutor(1) { runnable ->
            Thread(runnable, "lapis-net-dm-stream-timeout").apply { isDaemon = true }
        }.also { it.removeOnCancelPolicy = true }
    }

    /** Shuts down this handler's background timeout scheduler - mirrors `GossipPubSub.stop()`'s/
     * `PrekeyBundleGossip.stop()`'s lifecycle-symmetry convention. Safe to call even if the
     * scheduler was never lazily created. Idempotent. */
    fun stop() {
        scheduler.shutdownNow()
    }

    /** Test-visibility accessor for [perPeerStreamCounts]'s CURRENT tracked count for [peer] (`0` if
     * no entry exists) - `internal`, never a production API surface, mirrors
     * [DmSessionManager.liveSessionForTest]'s identical test-accessor convention. Lets
     * [DmStreamAbuseTest] observe this map directly rather than inferring its state indirectly
     * through stream-acceptance/rejection timing. */
    internal fun streamCountForTest(peer: PeerId): Int = perPeerStreamCounts[peer] ?: 0

    override fun initProtocolStream(stream: Stream) {
        // ReadTimeoutHandler FIRST so its clock starts covering the entire remaining lifecycle.
        stream.pushHandler(ReadTimeoutHandler(READ_IDLE_TIMEOUT_SECONDS, TimeUnit.SECONDS))
        stream.pushHandler(
            LengthFieldBasedFrameDecoder(
                // + LENGTH_FIELD_SIZE - see this class's own doc comment, point 2, for exactly why
                // the bare codec-level ceiling alone is off by the 4-byte length prefix itself.
                DmEnvelopeCodec.MAX_ENVELOPE_BYTES + LENGTH_FIELD_SIZE,
                0,
                LENGTH_FIELD_SIZE,
                0,
                LENGTH_FIELD_SIZE,
                true,
            ),
        )
        stream.pushHandler(LengthFieldPrepender(LENGTH_FIELD_SIZE))
    }

    override fun onStartResponder(stream: Stream): CompletableFuture<DmStreamRole> {
        val peer = stream.remotePeerId()
        // CRITICAL IDENTITY-AUTHORITY NOTE (restated at the exact call site, see this class's own
        // doc comment for the full argument): `peer` here is the libp2p PeerId this Noise-secured
        // CONNECTION authenticated at the TRANSPORT layer - used BELOW ONLY as a resource-management
        // key (bounding how many concurrent DmProtocol streams one connection may open), NEVER as a
        // claim about who the DmEnvelope's own senderIdentity field is.
        // Atomic increment-and-check via ConcurrentHashMap.compute, not a captured AtomicInteger
        // reference - see perPeerStreamCounts's own doc comment for why (a captured-reference
        // increment racing this map's own self-cleaning removal could otherwise orphan a counter
        // outside the map entirely, silently breaking the cap this exists to enforce).
        var rejected = false
        perPeerStreamCounts.compute(peer) { _, existingCount ->
            val next = (existingCount ?: 0) + 1
            if (next > MAX_CONCURRENT_STREAMS_PER_PEER) {
                rejected = true
                existingCount // leave the tracked count unchanged - this attempt is not counted
            } else {
                next
            }
        }
        if (rejected) {
            logger.debug {
                "rejecting DM stream from $peer - MAX_CONCURRENT_STREAMS_PER_PEER ($MAX_CONCURRENT_STREAMS_PER_PEER) exceeded"
            }
            stream.reset()
            return CompletableFuture.completedFuture(DmResponderRole)
        }
        val absoluteDeadline = scheduler.schedule({ stream.reset() }, MAX_STREAM_LIFETIME_SECONDS, TimeUnit.SECONDS)
        val handler =
            DmInboundMessageHandler(
                onEnvelope = { bytes -> onInboundEnvelope(peer, bytes) },
                onFinished = {
                    absoluteDeadline.cancel(false)
                    // Removes the entry outright once the count reaches zero - see this map's own
                    // doc comment.
                    perPeerStreamCounts.computeIfPresent(peer) { _, existingCount ->
                        val next = existingCount - 1
                        if (next <= 0) null else next
                    }
                },
            )
        stream.pushHandler(handler)
        return CompletableFuture.completedFuture(DmResponderRole)
    }

    override fun onStartInitiator(stream: Stream): CompletableFuture<DmStreamRole> {
        val absoluteDeadline = scheduler.schedule({ stream.reset() }, MAX_STREAM_LIFETIME_SECONDS, TimeUnit.SECONDS)
        val handler = DmOutboundHandler(onFinished = { absoluteDeadline.cancel(false) })
        stream.pushHandler(handler)
        return handler.activeFuture
    }
}

private class DmOutboundHandler(
    private val onFinished: () -> Unit,
) : ProtocolMessageHandler<ByteBuf>,
    DmSendHandle {
    val activeFuture = CompletableFuture<DmStreamRole>()
    private var capturedStream: Stream? = null

    override fun onActivated(stream: Stream) {
        capturedStream = stream
        activeFuture.complete(this)
    }

    override fun sendEnvelope(bytes: ByteArray) {
        require(bytes.size <= DmEnvelopeCodec.MAX_ENVELOPE_BYTES) {
            "envelope exceeds ${DmEnvelopeCodec.MAX_ENVELOPE_BYTES} bytes: ${bytes.size}"
        }
        val stream = checkNotNull(capturedStream) { "sendEnvelope called before the stream was activated" }
        stream.writeAndFlush(Unpooled.wrappedBuffer(bytes))
        stream.closeWrite()
    }

    override fun onClosed(stream: Stream) = onFinished()

    override fun onReadClosed(stream: Stream) = Unit

    override fun onException(cause: Throwable?) {
        // NEVER let a parse/codec/timeout exception leave the stream open in a bad state.
        onFinished()
        capturedStream?.reset()
    }
}

/** One-shot inbound handler: exactly one [DmEnvelope] frame per stream (see [DmProtocolHandler]'s
 * own class doc comment for why), always closing the stream once that frame is processed -
 * successfully or not.
 *
 * **[onFinished] is invoked AT MOST ONCE per stream, guarded by [finishedCalled] - not a cosmetic
 * guard, load-bearing for [DmProtocolHandler.perPeerStreamCounts]'s correctness.** [onMessage]'s own
 * `finally` block explicitly calls [stream].`close()` then [onFinished] once a frame has been fully
 * handed off. jvm-libp2p's `ProtocolMessageHandlerAdapter.channelUnregistered` (verified against the
 * decompiled `jvm-libp2p-1.3.5-RELEASE` sources) ALSO calls [onClosed] - which itself calls
 * [onFinished] - once the Netty channel that `close()` initiated actually finishes tearing down,
 * asynchronously, sometime AFTER [onMessage] already returned. Without this guard, that delayed
 * second invocation double-decrements the shared per-[io.libp2p.core.PeerId] counter in
 * [DmProtocolHandler.onStartResponder] - harmless when a peer holds exactly one stream at a time (the
 * entry is already removed, so the stale second `computeIfPresent` is a no-op on an absent key), but
 * when a peer legitimately holds MULTIPLE concurrent streams, the delayed decrement from an earlier,
 * already-finished stream can land after a NEW stream has re-populated the map entry, erroneously
 * erasing tracking that actually belongs to the new, still-open stream - letting a peer that
 * opens-and-completes streams in rapid succession silently exceed
 * [MAX_CONCURRENT_STREAMS_PER_PEER]'s intended bound on truly-concurrent in-flight parse/decrypt
 * work. [java.util.concurrent.atomic.AtomicBoolean.compareAndSet] makes "first caller wins" exact
 * even if [onMessage]'s `finally` and a concurrent [onClosed]/[onException] callback from the Netty
 * event loop race each other. */
private class DmInboundMessageHandler(
    private val onEnvelope: (ByteArray) -> Unit,
    private val onFinished: () -> Unit,
) : ProtocolMessageHandler<ByteBuf> {
    private var capturedStream: Stream? = null
    private val finishedCalled = AtomicBoolean(false)

    private fun finishOnce() {
        if (finishedCalled.compareAndSet(false, true)) onFinished()
    }

    override fun onActivated(stream: Stream) {
        capturedStream = stream
    }

    override fun onMessage(
        stream: Stream,
        msg: ByteBuf,
    ) {
        try {
            // Non-destructive full-readable-bytes copy - mirrors GossipPubSub.subscribe's own
            // ByteBufUtil.getBytes idiom exactly.
            val bytes = ByteBufUtil.getBytes(msg)
            // Hands off to DmSessionManager.handleInboundEnvelope, which is itself required to catch
            // every exception internally (adversarial test case (f)) - this handler's own catch
            // below exists purely as defense in depth, so a bug in that discipline still can never
            // escape this handler uncaught and crash the node.
            onEnvelope(bytes)
        } catch (e: RuntimeException) {
            logger.warn(
                e,
            ) { "unhandled exception processing inbound DM envelope from ${stream.remotePeerId()} - closing" }
        } finally {
            stream.close()
            finishOnce()
        }
    }

    override fun onClosed(stream: Stream) = finishOnce()

    override fun onReadClosed(stream: Stream) = Unit

    override fun onException(cause: Throwable?) {
        finishOnce()
        capturedStream?.reset()
    }
}

/** [StrictProtocolBinding] is abstract (verified against the resolved jar - `io.libp2p.protocol.Ping`'s
 * own bundled reference implementation subclasses it the identical way, via `PingBinding`) - this is
 * that minimal concrete subclass, carrying no state of its own beyond what the superclass already
 * holds. */
private class ConcreteDmProtocolBinding(
    handler: DmProtocolHandler,
) : StrictProtocolBinding<DmStreamRole>(DM_PROTOCOL_ID, handler)

/**
 * This module's `attach()`-convention entry point, mirroring `NabuStorage.attach`/
 * `GossipPubSub.attach`/`PeerDirectoryGossip.attach`'s established shape, adapted for a stream
 * protocol rather than a pubsub-topic binding: wraps a [DmProtocolHandler] in jvm-libp2p's
 * [StrictProtocolBinding] under [DM_PROTOCOL_ID] and registers it on [LapisNode.host].
 */
class DmProtocol private constructor(
    val binding: StrictProtocolBinding<DmStreamRole>,
    private val handler: DmProtocolHandler,
) {
    /** Dials [peer] on [node]'s host and returns the resulting [StreamPromise] - `controller`
     * resolves to a [DmSendHandle] once the stream is activated on the initiator side. */
    fun dial(
        node: LapisNode,
        peer: PeerId,
        vararg addresses: Multiaddr,
    ): StreamPromise<out DmStreamRole> = binding.dial(node.host, peer, *addresses)

    /** Test-visibility passthrough to [DmProtocolHandler.streamCountForTest] - see that function's
     * own doc comment. */
    internal fun streamCountForTest(peer: PeerId): Int = handler.streamCountForTest(peer)

    /** Stops this protocol's background stream-timeout scheduler - mirrors
     * `PeerDirectoryGossip.stop`/`PrekeyBundleGossip.stop`'s lifecycle-symmetry convention. There is
     * no `Host.removeProtocolHandler` call here, mirroring how `GossipPubSub.stop()` also does not
     * unregister its own protocol handler from the host - [LapisNode.stop] owns tearing down the
     * whole host. */
    fun stop() {
        handler.stop()
    }

    companion object {
        fun attach(
            node: LapisNode,
            onInboundEnvelope: (fromPeerId: PeerId, envelopeBytes: ByteArray) -> Unit,
        ): DmProtocol {
            val handler = DmProtocolHandler(onInboundEnvelope)
            val binding = ConcreteDmProtocolBinding(handler)
            node.host.addProtocolHandler(binding)
            logger.info { "attached DmProtocol ($DM_PROTOCOL_ID) to host ${node.host.peerId}" }
            return DmProtocol(binding, handler)
        }

        /** Test/low-level seam: attaches directly against a [Host] rather than a [LapisNode], for
         * [DmStreamAbuseTest]'s adversarial cases, which need to drive [DmProtocolHandler] against a
         * real Netty pipeline without pulling in the rest of [DmSessionManager]'s wiring. */
        internal fun attachToHost(
            host: Host,
            onInboundEnvelope: (fromPeerId: PeerId, envelopeBytes: ByteArray) -> Unit,
        ): DmProtocol {
            val handler = DmProtocolHandler(onInboundEnvelope)
            val binding = ConcreteDmProtocolBinding(handler)
            host.addProtocolHandler(binding)
            return DmProtocol(binding, handler)
        }
    }
}
