package net.lapisphilosophorum.lapisnet.onion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_HOPS
import org.bouncycastle.util.Arrays
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val logger = KotlinLogging.logger {}

/** Opaque identifier of a link (a connection to a neighbour) assigned by the host. It carries no
 * address and must never be mapped to one in logs. */
@JvmInline
value class LinkId(
    val value: Long,
)

/** Effects requested by the pure [OnionRelay] state machine; the host performs them. */
sealed interface RelayAction {
    data class SendCell(
        val link: LinkId,
        val cell: Cell,
    ) : RelayAction

    /** Open (or reuse) a link to the relay identified by [targetRelayIdDigest] and report the
     * resulting [LinkId] (or null on failure) through [OnionRelay.onExtendResult]. */
    class OpenLinkForExtend(
        val pendingId: Long,
        val targetRelayIdDigest: ByteArray,
        val linkSpecifier: ByteArray,
    ) : RelayAction {
        override fun toString(): String = "OpenLinkForExtend(pendingId=$pendingId)"
    }

    /** A DATA or END message addressed to this relay (exit-side delivery hook; unused until wave B). */
    data class DeliverLocal(
        val circuitHandle: Long,
        val message: RelayMessage,
    ) : RelayAction

    /** The circuit identified by [circuitHandle] is gone. */
    data class CircuitClosed(
        val circuitHandle: Long,
        val reason: DestroyReason,
    ) : RelayAction
}

private data class CircuitKey(
    val link: Long,
    val circuitId: Int,
)

private enum class Notify { PREV, NEXT, BOTH, NONE }

private class RelayCircuit(
    val handle: Long,
    val prevLink: LinkId,
    val prevCircuitId: Int,
    val hop: RelayHopState,
    val createdAtMillis: Long,
    val cellBucket: TokenBucket,
) {
    val lock = ReentrantLock()
    var nextLink: LinkId? = null
    var nextCircuitId = 0
    var extendPending = false
    var extended = false
    var pendingId = 0L
    var pendingExtend: ExtendPayload? = null
    var closed = false
}

/**
 * The relay side of the onion circuit protocol as a PURE state machine: [onCell] and friends
 * consume input and return [RelayAction]s; nothing here touches the network. Thread-safe; the
 * documented contract is that cells of ONE link must be delivered in order (the caller serialises
 * per link, as stream readers do anyway) - the per-hop implicit counters require strict order.
 *
 * Resource bounds ([OnionRelayLimits]): CREATE floods are rate-limited per link and globally
 * BEFORE any X25519 work (no CPU amplification); circuit slots are reserved with a CAS loop before
 * insertion, so a race cannot exceed the cap; there are no per-circuit queues (cells are processed
 * synchronously), cells per circuit are rate-limited (excess closes the circuit, never buffers),
 * lifetime is bounded by [sweepExpired]. Any authentication failure, replay, reorder or protocol
 * violation destroys the circuit on both sides with a coarse reason code.
 *
 * Logging: counters and coarse reasons at debug only; never keys, cell contents or link metadata.
 */
class OnionRelay(
    private val keys: OnionKeyRing,
    private val limits: OnionRelayLimits = OnionRelayLimits(),
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    /** Single-key convenience constructor (wave A API): wraps the key in a one-entry ring. The relay
     * does not own the ring, so [close] never destroys the key passed here. */
    constructor(
        ownBinding: OnionKeyBinding,
        onionPrivate: X25519PrivateKey,
        limits: OnionRelayLimits = OnionRelayLimits(),
        clock: Clock = Clock.systemUTC(),
        random: SecureRandom = SecureRandom(),
    ) : this(OnionKeyRing.single(ownBinding, onionPrivate), limits, clock, random)

    private val ownId = keys.relayIdDigest
    private val table = ConcurrentHashMap<CircuitKey, RelayCircuit>()
    private val byHandle = ConcurrentHashMap<Long, RelayCircuit>()
    private val pending = ConcurrentHashMap<Long, RelayCircuit>()
    private val perLink = ConcurrentHashMap<Long, AtomicInteger>()
    private val linkCreateBuckets = ConcurrentHashMap<Long, TokenBucket>()
    private val globalCreateBucket = TokenBucket(limits.createsPerSecondTotal, clock)
    private val total = AtomicInteger(0)
    private val pendingCount = AtomicInteger(0)
    private val handleSeq = AtomicLong(0)
    private val pendingSeq = AtomicLong(0)
    private val closedFlag = AtomicBoolean(false)

    /** Test hook, invoked immediately before each X25519 handshake is attempted. */
    internal var beforeHandshake: (() -> Unit)? = null

    val circuitCount: Int get() = total.get()

    /** `true` if at least one circuit currently uses [link] as its previous hop. */
    fun hasCircuitsOn(link: LinkId): Boolean = (perLink[link.value]?.get() ?: 0) > 0

    /** `true` if a circuit with [circuitId] currently exists on [link] (as previous or next hop). */
    fun knowsCircuit(
        link: LinkId,
        circuitId: Int,
    ): Boolean = table.containsKey(CircuitKey(link.value, circuitId))

    fun onCell(
        from: LinkId,
        cell: Cell,
    ): List<RelayAction> {
        if (closedFlag.get()) return emptyList()
        return when (cell.command) {
            CellCommand.PADDING -> emptyList()
            CellCommand.CREATE -> handleCreate(from, cell)
            CellCommand.CREATED -> handleCreated(from, cell)
            CellCommand.RELAY -> handleRelay(from, cell)
            CellCommand.DESTROY -> handleDestroy(from, cell)
        }
    }

    fun onLinkClosed(link: LinkId): List<RelayAction> {
        val out = ArrayList<RelayAction>()
        for (c in byHandle.values.toList()) {
            c.lock.withLock {
                if (c.closed) return@withLock
                if (c.prevLink == link) {
                    out += teardown(c, DestroyReason.INTERNAL, Notify.NEXT)
                } else if (c.nextLink == link) {
                    out += teardown(c, DestroyReason.INTERNAL, Notify.PREV)
                }
            }
        }
        perLink.remove(link.value)
        linkCreateBuckets.remove(link.value)
        return out
    }

    /** Called by the host with the outcome of an [RelayAction.OpenLinkForExtend]. */
    fun onExtendResult(
        pendingId: Long,
        link: LinkId?,
    ): List<RelayAction> {
        val c = pending.remove(pendingId) ?: return emptyList()
        pendingCount.decrementAndGet()
        c.lock.withLock {
            if (c.closed) return emptyList()
            c.extendPending = false
            val payload = c.pendingExtend ?: return teardown(c, DestroyReason.INTERNAL, Notify.PREV)
            c.pendingExtend = null
            if (link == null) return teardown(c, DestroyReason.INTERNAL, Notify.PREV)
            var id = 0
            repeat(ID_ATTEMPTS) {
                if (id == 0) {
                    val candidate = random.nextInt()
                    if (candidate != 0 &&
                        table.putIfAbsent(CircuitKey(link.value, candidate), c) == null
                    ) {
                        id = candidate
                    }
                }
            }
            if (id == 0) return teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.PREV)
            c.nextLink = link
            c.nextCircuitId = id
            val body =
                CreateBody(
                    payload.hopIndex,
                    payload.targetRelayIdDigest,
                    payload.onionKeyFingerprint,
                    payload.clientEphemeral,
                ).encode(random)
            return listOf(RelayAction.SendCell(link, Cell(id, CellCommand.CREATE, body)))
        }
    }

    /** Sends [message] backwards on the circuit identified by an earlier [RelayAction.DeliverLocal]
     * handle (exit-side reply). */
    fun reply(
        circuitHandle: Long,
        message: RelayMessage,
    ): List<RelayAction> {
        val c = byHandle[circuitHandle] ?: return emptyList()
        c.lock.withLock {
            if (c.closed) return emptyList()
            return try {
                val body = c.hop.originateBackward(message, random)
                listOf(RelayAction.SendCell(c.prevLink, Cell(c.prevCircuitId, CellCommand.RELAY, body)))
            } catch (e: OnionResourceLimitException) {
                teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            }
        }
    }

    /** Closes circuits older than the configured lifetime; the host calls this periodically. */
    fun sweepExpired(): List<RelayAction> {
        val now = clock.millis()
        val maxAge = limits.circuitMaxLifetime.inWholeMilliseconds
        val out = ArrayList<RelayAction>()
        for (c in byHandle.values.toList()) {
            if (now - c.createdAtMillis >= maxAge) out += teardown(c, DestroyReason.FINISHED, Notify.BOTH)
        }
        return out
    }

    override fun close() {
        closedFlag.set(true)
        for (c in byHandle.values.toList()) teardown(c, DestroyReason.NONE, Notify.NONE)
    }

    // ---- CREATE -------------------------------------------------------------------------------

    private fun handleCreate(
        from: LinkId,
        cell: Cell,
    ): List<RelayAction> {
        fun refuse(reason: DestroyReason) = listOf(destroyCell(from, cell.circuitId, reason))

        // 1. Rate limits BEFORE any decoding or X25519 work.
        val bucket =
            linkCreateBuckets.computeIfAbsent(
                from.value,
            ) { TokenBucket(limits.createsPerSecondPerLink, clock) }
        if (!bucket.tryAcquire() || !globalCreateBucket.tryAcquire()) {
            logger.debug { "create refused: rate limit" }
            return refuse(DestroyReason.RESOURCE_LIMIT)
        }
        // 2. Reserve capacity atomically.
        val linkCounter = perLink.computeIfAbsent(from.value) { AtomicInteger(0) }
        if (!reserve(total, limits.maxCircuitsTotal)) return refuse(DestroyReason.RESOURCE_LIMIT)
        if (!reserve(linkCounter, limits.maxCircuitsPerLink)) {
            total.decrementAndGet()
            return refuse(DestroyReason.RESOURCE_LIMIT)
        }
        var registered = false
        try {
            val body =
                try {
                    CreateBody.decode(cell.body)
                } catch (e: CellFormatException) {
                    return refuse(DestroyReason.PROTOCOL)
                }
            beforeHandshake?.invoke()
            // The ring picks the key by the CREATE's fingerprint (current or previous, never an expired
            // one). An unknown fingerprint and a failed handshake yield the same coarse reason.
            val result =
                try {
                    keys.withKeyFor(body.onionKeyFingerprint, clock.millis() / 1000) { b, k ->
                        NtorHandshake.serverRespond(body, k, b, random)
                    }
                } catch (e: OnionHandshakeException) {
                    return refuse(DestroyReason.AUTH_FAILED)
                } ?: return refuse(DestroyReason.AUTH_FAILED)
            val hop =
                try {
                    RelayHopState(body.hopIndex, result.keys)
                } finally {
                    result.keys.close()
                }
            val circuit =
                RelayCircuit(
                    handleSeq.incrementAndGet(),
                    from,
                    cell.circuitId,
                    hop,
                    clock.millis(),
                    TokenBucket(limits.cellsPerSecondPerCircuit, clock),
                )
            if (table.putIfAbsent(CircuitKey(from.value, cell.circuitId), circuit) != null) {
                hop.close()
                return refuse(DestroyReason.PROTOCOL)
            }
            byHandle[circuit.handle] = circuit
            registered = true
            if (closedFlag.get()) {
                // close() ran while this CREATE was in flight and may have missed the new circuit.
                teardown(circuit, DestroyReason.NONE, Notify.NONE)
                return emptyList()
            }
            val created = result.created.encode(random)
            return listOf(RelayAction.SendCell(from, Cell(cell.circuitId, CellCommand.CREATED, created)))
        } finally {
            if (!registered) {
                total.decrementAndGet()
                linkCounter.decrementAndGet()
            }
        }
    }

    private fun reserve(
        counter: AtomicInteger,
        max: Int,
    ): Boolean {
        while (true) {
            val c = counter.get()
            if (c >= max) return false
            if (counter.compareAndSet(c, c + 1)) return true
        }
    }

    // ---- CREATED ------------------------------------------------------------------------------

    private fun handleCreated(
        from: LinkId,
        cell: Cell,
    ): List<RelayAction> {
        val c = table[CircuitKey(from.value, cell.circuitId)] ?: return emptyList()
        c.lock.withLock {
            if (c.closed || c.extended || c.nextLink != from || c.nextCircuitId != cell.circuitId) return emptyList()
            val created =
                try {
                    CreatedBody.decode(cell.body)
                } catch (e: CellFormatException) {
                    return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
                }
            c.extended = true
            return try {
                val msg = RelayMessage(RelayCommand.EXTENDED, 0, created.toExtendedPayload())
                val body = c.hop.originateBackward(msg, random)
                listOf(RelayAction.SendCell(c.prevLink, Cell(c.prevCircuitId, CellCommand.RELAY, body)))
            } catch (e: OnionResourceLimitException) {
                teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            }
        }
    }

    // ---- RELAY --------------------------------------------------------------------------------

    private fun handleRelay(
        from: LinkId,
        cell: Cell,
    ): List<RelayAction> {
        val c = table[CircuitKey(from.value, cell.circuitId)] ?: return emptyList()
        c.lock.withLock {
            if (c.closed) return emptyList()
            if (!c.cellBucket.tryAcquire()) {
                logger.debug { "circuit closed: cell rate limit" }
                return teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            }
            val forward = c.prevLink == from && c.prevCircuitId == cell.circuitId
            return try {
                if (forward) relayForward(c, cell) else relayBackward(c, cell)
            } catch (e: OnionIntegrityException) {
                logger.debug { "circuit destroyed: integrity failure" }
                teardown(c, DestroyReason.AUTH_FAILED, Notify.BOTH)
            } catch (e: OnionResourceLimitException) {
                teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            }
        }
    }

    private fun relayBackward(
        c: RelayCircuit,
        cell: Cell,
    ): List<RelayAction> {
        if (!c.extended) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        val body = c.hop.wrapBackward(cell.body, random)
        return listOf(RelayAction.SendCell(c.prevLink, Cell(c.prevCircuitId, CellCommand.RELAY, body)))
    }

    private fun relayForward(
        c: RelayCircuit,
        cell: Cell,
    ): List<RelayAction> =
        when (val result = c.hop.unwrapForward(cell.body, random)) {
            is ForwardResult.Forward -> {
                val next = c.nextLink
                if (next == null || !c.extended) {
                    teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
                } else {
                    listOf(RelayAction.SendCell(next, Cell(c.nextCircuitId, CellCommand.RELAY, result.body)))
                }
            }
            is ForwardResult.Local -> handleLocal(c, result.message)
        }

    private fun handleLocal(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> =
        when (msg.command) {
            RelayCommand.DROP -> emptyList()
            RelayCommand.DATA, RelayCommand.END -> listOf(RelayAction.DeliverLocal(c.handle, msg))
            RelayCommand.EXTENDED -> teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            RelayCommand.EXTEND -> handleExtend(c, msg)
        }

    private fun handleExtend(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (c.nextLink != null || c.extendPending) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        val payload =
            try {
                ExtendPayloadCodec.decode(msg.data)
            } catch (e: CellFormatException) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
        if (payload.hopIndex != c.hop.hopIndex + 1 || payload.hopIndex > MAX_HOPS) {
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        // Never extend to ourselves. (A predecessor/duplicate check needs the path, which only the
        // client knows: ClientCircuitBuilder rejects duplicate relays. Chain depth is bounded by MAX_HOPS.)
        if (Arrays.constantTimeAreEqual(payload.targetRelayIdDigest, ownId)) {
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        if (!reserve(pendingCount, limits.maxPendingExtends)) {
            return teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
        }
        val id = pendingSeq.incrementAndGet()
        c.extendPending = true
        c.pendingId = id
        c.pendingExtend = payload
        pending[id] = c
        return listOf(RelayAction.OpenLinkForExtend(id, payload.targetRelayIdDigest, payload.linkSpecifier))
    }

    // ---- DESTROY / teardown -------------------------------------------------------------------

    private fun handleDestroy(
        from: LinkId,
        cell: Cell,
    ): List<RelayAction> {
        val c = table[CircuitKey(from.value, cell.circuitId)] ?: return emptyList()
        val reason = DestroyBody.decode(cell.body)
        val fromPrev = c.prevLink == from && c.prevCircuitId == cell.circuitId
        return teardown(c, reason, if (fromPrev) Notify.NEXT else Notify.PREV)
    }

    private fun destroyCell(
        link: LinkId,
        circuitId: Int,
        reason: DestroyReason,
    ): RelayAction =
        RelayAction.SendCell(link, Cell(circuitId, CellCommand.DESTROY, DestroyBody.encode(reason, random)))

    /** Idempotent: removes the circuit, zeroises its keys and notifies the requested neighbours. */
    private fun teardown(
        c: RelayCircuit,
        reason: DestroyReason,
        notify: Notify,
    ): List<RelayAction> {
        c.lock.withLock {
            if (c.closed) return emptyList()
            c.closed = true
            val out = ArrayList<RelayAction>(3)
            table.remove(CircuitKey(c.prevLink.value, c.prevCircuitId), c)
            val next = c.nextLink
            if (next != null) table.remove(CircuitKey(next.value, c.nextCircuitId), c)
            byHandle.remove(c.handle)
            total.decrementAndGet()
            perLink[c.prevLink.value]?.decrementAndGet()
            if (c.extendPending && pending.remove(c.pendingId) != null) pendingCount.decrementAndGet()
            c.hop.close()
            if (notify == Notify.PREV || notify == Notify.BOTH) {
                out += destroyCell(c.prevLink, c.prevCircuitId, reason)
            }
            if (next != null && (notify == Notify.NEXT || notify == Notify.BOTH)) {
                out += destroyCell(next, c.nextCircuitId, reason)
            }
            out += RelayAction.CircuitClosed(c.handle, reason)
            return out
        }
    }

    private companion object {
        const val ID_ATTEMPTS = 8
    }
}
