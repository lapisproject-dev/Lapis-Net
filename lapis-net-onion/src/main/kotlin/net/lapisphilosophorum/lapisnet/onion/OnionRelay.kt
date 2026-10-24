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

    /**
     * A DIRECTORY_PUBLISH message arrived at this relay (wave V0.10.0-D). The host validates [objectBytes] completely,
     * publishes the verified object on the directory gossip and answers through [OnionRelay.reply] with a
     * DIRECTORY_PUBLISHED message. [objectBytes] is public directory data, but still never logged.
     */
    class DeliverDirectoryPublish(
        val circuitHandle: Long,
        val type: DirectoryObjectType,
        val objectBytes: ByteArray,
    ) : RelayAction {
        override fun toString(): String = "DeliverDirectoryPublish(type=$type)"
    }

    /**
     * A complete sealed mailbox item arrived at this relay (wave V0.10.0-F1). The host announces [itemBytes]
     * on the shared mailbox topic and answers through [OnionRelay.reply] with a MAILBOX_PUBLISHED message.
     * The relay cannot read the item and it is never logged.
     */
    class DeliverMailboxItem(
        val circuitHandle: Long,
        val itemBytes: ByteArray,
    ) : RelayAction {
        override fun toString(): String = "DeliverMailboxItem(length=${itemBytes.size})"
    }

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

/** The hidden-service role of a circuit at THIS relay (last hop only). `NONE -> INTRO | INTRODUCING |
 * RENDEZVOUS_WAITING -> SPLICED -> closed`; a circuit has at most one role for its whole life. */
private enum class CircuitRole {
    NONE,
    INTRO,
    INTRODUCING,
    RENDEZVOUS_WAITING,
    SPLICED,
    DIRECTORY_PUBLISHING,
    MAILBOX_PUBLISHING,
}

private class RelayCircuit(
    val handle: Long,
    val prevLink: LinkId,
    val prevCircuitId: Int,
    val hop: RelayHopState,
    val createdAtMillis: Long,
    val cellBucket: TokenBucket,
) : RelayCircuitRef {
    override val linkKey: Long get() = prevLink.value
    val lock = ReentrantLock()

    @Volatile var role = CircuitRole.NONE

    @Volatile var introduceBucket: TokenBucket? = null
    var partner: RelayCircuit? = null
    var pairOwner = false

    @Volatile var waitingSinceMillis = 0L
    var nextLink: LinkId? = null
    var nextCircuitId = 0
    var extendPending = false
    var extended = false
    var pendingId = 0L
    var pendingExtend: ExtendPayload? = null
    var closed = false
    var directoryPublishes = 0

    // Mailbox item reassembly (wave V0.10.0-F1); guarded by [lock].
    var mailboxItemsDone = 0
    var mailboxBuffer: ByteArray? = null
    var mailboxNextFragment = 0
    var mailboxStartedMillis = 0L
    var mailboxBlocked = false
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
    private val introTable =
        IntroPointTable(limits.maxIntroPointsTotal, limits.maxIntroPointsPerLink, limits.introReplayCacheEntries)
    private val rendezvousTable = RendezvousTable(limits.maxPendingRendezvousTotal, limits.maxPendingRendezvousPerLink)
    private val splicedPairs = AtomicInteger(0)
    private val globalPublishCounter = WindowCounter(limits.directoryPublishGlobalPerMinute, clock)
    private val linkPublishCounters = ConcurrentHashMap<Long, WindowCounter>()
    private val globalMailboxCounter = WindowCounter(limits.mailboxPublishGlobalPerMinute, clock)
    private val linkMailboxCounters = ConcurrentHashMap<Long, WindowCounter>()

    // Work that must run OUTSIDE every circuit lock (never hold two circuit locks at once): collected while a
    // lock is held, executed by the public entry points after all locks are released.
    private sealed interface Deferred

    private class DeferTeardown(
        val circuit: RelayCircuit,
        val reason: DestroyReason,
        val notify: Notify,
    ) : Deferred

    private class DeferSend(
        val circuit: RelayCircuit,
        val message: RelayMessage,
    ) : Deferred

    private class DeferSplice(
        val waiting: RelayCircuit,
        val receiver: RelayCircuit,
        val rendezvous2Payload: ByteArray,
    ) : Deferred

    private val deferred = ThreadLocal.withInitial { ArrayDeque<Deferred>() }

    /** Test hook, invoked immediately before each X25519 handshake is attempted. */
    internal var beforeHandshake: (() -> Unit)? = null

    val circuitCount: Int get() = total.get()

    /** Introduction points currently registered at this relay (leak checks). */
    val introPointCount: Int get() = introTable.size

    /** Rendezvous cookies currently waiting for their second circuit (leak checks). */
    val pendingRendezvousCount: Int get() = rendezvousTable.size

    /** Spliced circuit pairs currently relayed by this relay (leak checks). */
    val splicedPairCount: Int get() = splicedPairs.get()

    /** Test seam: sees every RENDEZVOUS_DATA blob this relay splices (it is end-to-end ciphertext). */
    @ExperimentalOnionApi
    var rendezvousDataObserver: ((ByteArray) -> Unit)? = null

    /** Runs [block], then everything it deferred, after all circuit locks have been released. */
    private fun entry(block: () -> List<RelayAction>): List<RelayAction> {
        val queue = deferred.get()
        val first =
            try {
                block()
            } catch (e: Throwable) {
                queue.clear()
                throw e
            }
        if (queue.isEmpty()) return first
        val out = ArrayList(first)
        try {
            while (queue.isNotEmpty()) out += runDeferred(queue.removeFirst())
        } finally {
            queue.clear()
        }
        return out
    }

    private fun defer(d: Deferred) {
        deferred.get().addLast(d)
    }

    private fun runDeferred(d: Deferred): List<RelayAction> =
        when (d) {
            is DeferTeardown -> teardown(d.circuit, d.reason, d.notify)
            is DeferSend ->
                d.circuit.lock.withLock {
                    if (d.circuit.closed) {
                        emptyList()
                    } else {
                        sendBackward(d.circuit, d.message)
                    }
                }
            is DeferSplice ->
                d.waiting.lock.withLock {
                    if (d.waiting.closed) {
                        teardown(d.receiver, DestroyReason.FINISHED, Notify.PREV)
                    } else {
                        d.waiting.role = CircuitRole.SPLICED
                        d.waiting.partner = d.receiver
                        sendBackward(d.waiting, RelayMessage(RelayCommand.RENDEZVOUS2, 0, d.rendezvous2Payload))
                    }
                }
        }

    /** Caller holds [c]'s lock. */
    private fun sendBackward(
        c: RelayCircuit,
        message: RelayMessage,
    ): List<RelayAction> =
        try {
            val body = c.hop.originateBackward(message, random)
            listOf(RelayAction.SendCell(c.prevLink, Cell(c.prevCircuitId, CellCommand.RELAY, body)))
        } catch (e: OnionResourceLimitException) {
            teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
        }

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
    ): List<RelayAction> = entry { onCellInternal(from, cell) }

    private fun onCellInternal(
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

    fun onLinkClosed(link: LinkId): List<RelayAction> = entry { onLinkClosedInternal(link) }

    /** Number of links with a live mailbox-publish rate counter; for tests of the per-link cleanup. */
    internal fun mailboxCounterLinkCount(): Int = linkMailboxCounters.size

    private fun onLinkClosedInternal(link: LinkId): List<RelayAction> {
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
        linkPublishCounters.remove(link.value)
        linkMailboxCounters.remove(link.value)
        return out
    }

    /** Called by the host with the outcome of an [RelayAction.OpenLinkForExtend]. */
    fun onExtendResult(
        pendingId: Long,
        link: LinkId?,
    ): List<RelayAction> = entry { onExtendResultInternal(pendingId, link) }

    private fun onExtendResultInternal(
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
    ): List<RelayAction> =
        entry {
            val c = byHandle[circuitHandle] ?: return@entry emptyList()
            c.lock.withLock {
                if (c.closed) emptyList() else sendBackward(c, message)
            }
        }

    /** Closes circuits older than the configured lifetime; the host calls this periodically. */
    fun sweepExpired(): List<RelayAction> =
        entry {
            val now = clock.millis()
            val maxAge = limits.circuitMaxLifetime.inWholeMilliseconds
            val maxWait = limits.rendezvousWaitTimeout.inWholeMilliseconds
            val maxAssemble = limits.mailboxAssembleTimeout.inWholeMilliseconds
            val out = ArrayList<RelayAction>()
            for (c in byHandle.values.toList()) {
                if (now - c.createdAtMillis >= maxAge ||
                    (c.role == CircuitRole.RENDEZVOUS_WAITING && now - c.waitingSinceMillis >= maxWait) ||
                    (
                        c.role == CircuitRole.MAILBOX_PUBLISHING &&
                            c.mailboxBuffer != null &&
                            now - c.mailboxStartedMillis > maxAssemble
                    )
                ) {
                    out += teardown(c, DestroyReason.FINISHED, Notify.BOTH)
                }
            }
            out
        }

    override fun close() {
        closedFlag.set(true)
        entry {
            for (c in byHandle.values.toList()) teardown(c, DestroyReason.NONE, Notify.NONE)
            emptyList()
        }
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
            RelayCommand.DATA, RelayCommand.END ->
                if (c.role != CircuitRole.NONE) {
                    teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
                } else {
                    listOf(RelayAction.DeliverLocal(c.handle, msg))
                }
            RelayCommand.EXTENDED -> teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            RelayCommand.EXTEND ->
                if (c.role !=
                    CircuitRole.NONE
                ) {
                    teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
                } else {
                    handleExtend(c, msg)
                }
            RelayCommand.ESTABLISH_INTRO -> handleEstablishIntro(c, msg)
            RelayCommand.INTRODUCE1 -> handleIntroduce1(c, msg)
            RelayCommand.ESTABLISH_RENDEZVOUS -> handleEstablishRendezvous(c, msg)
            RelayCommand.RENDEZVOUS1 -> handleRendezvous1(c, msg)
            RelayCommand.RENDEZVOUS_DATA -> handleRendezvousData(c, msg)
            RelayCommand.DIRECTORY_PUBLISH -> handleDirectoryPublish(c, msg)
            RelayCommand.MAILBOX_PUBLISH -> handleMailboxPublish(c, msg)
            // Replies and forwarded messages never arrive "locally" at a relay.
            RelayCommand.INTRO_ESTABLISHED,
            RelayCommand.INTRODUCE2,
            RelayCommand.INTRODUCE_ACK,
            RelayCommand.RENDEZVOUS_ESTABLISHED,
            RelayCommand.RENDEZVOUS2,
            RelayCommand.DIRECTORY_PUBLISHED,
            RelayCommand.MAILBOX_PUBLISHED,
            -> teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }

    // ---- hidden-service roles (wave V0.10.0-C) --------------------------------------------------

    /** Role messages are only accepted at the last hop of a circuit that has not taken a role yet. */
    private fun canTakeRole(c: RelayCircuit): Boolean =
        c.role == CircuitRole.NONE && c.nextLink == null && !c.extendPending

    private fun handleEstablishIntro(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (!canTakeRole(c)) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        val body =
            try {
                EstablishIntroBody.decode(msg.data)
            } catch (e: CellFormatException) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
        val now = clock.millis() / 1000
        if (body.notValidAfterEpochSecond < now ||
            body.notValidAfterEpochSecond > now + HsConstants.MAX_ESTABLISH_WINDOW_SECONDS ||
            !body.verify(ownId)
        ) {
            logger.debug { "establish-intro refused" }
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        return when (val r = introTable.register(body.authKey.bytes, c, body.establishSeq)) {
            is IntroRegistration.Stale -> teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            is IntroRegistration.LimitReached -> teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            is IntroRegistration.Registered -> {
                c.role = CircuitRole.INTRO
                c.introduceBucket = TokenBucket(limits.introduce1PerSecondPerIntroPoint, clock)
                // make-before-break: the superseded circuit of the same auth key is closed (outside this lock)
                (r.replaced as? RelayCircuit)?.let { defer(DeferTeardown(it, DestroyReason.FINISHED, Notify.BOTH)) }
                sendBackward(c, RelayMessage(RelayCommand.INTRO_ESTABLISHED, 0, StatusBody.encode(0)))
            }
        }
    }

    private fun handleIntroduce1(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (!canTakeRole(c)) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        c.role = CircuitRole.INTRODUCING // at most one INTRODUCE1 per circuit

        fun ack(status: Byte) = sendBackward(c, RelayMessage(RelayCommand.INTRODUCE_ACK, 0, StatusBody.encode(status)))
        val body = msg.data
        val authKey = IntroduceBody.peekAuthKey(body) ?: return ack(IntroduceStatus.MALFORMED)
        val intro = introTable.lookup(authKey) as? RelayCircuit ?: return ack(IntroduceStatus.UNKNOWN)
        // The rate limit comes BEFORE the replay hash and any other work.
        if (intro.introduceBucket?.tryAcquire() != true) return ack(IntroduceStatus.RATE_LIMITED)
        if (introTable.seenBefore(body)) return ack(IntroduceStatus.UNKNOWN)
        defer(DeferSend(intro, RelayMessage(RelayCommand.INTRODUCE2, 0, body)))
        return ack(IntroduceStatus.FORWARDED)
    }

    private fun handleEstablishRendezvous(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (!canTakeRole(c)) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        val cookie =
            try {
                CookieBody.decode(msg.data)
            } catch (e: CellFormatException) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
        return when (rendezvousTable.put(cookie, c)) {
            RendezvousTable.PutResult.DUPLICATE -> teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            RendezvousTable.PutResult.LIMIT -> teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            RendezvousTable.PutResult.OK -> {
                c.role = CircuitRole.RENDEZVOUS_WAITING
                c.waitingSinceMillis = clock.millis()
                sendBackward(c, RelayMessage(RelayCommand.RENDEZVOUS_ESTABLISHED, 0, StatusBody.encode(0)))
            }
        }
    }

    private fun handleRendezvous1(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (!canTakeRole(c)) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        val body =
            try {
                Rendezvous1Body.decode(msg.data)
            } catch (e: CellFormatException) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
        if (!reserve(splicedPairs, limits.maxSplicedPairsTotal)) {
            return teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
        }
        val waiting = rendezvousTable.take(body.cookie) as? RelayCircuit
        if (waiting == null || waiting === c) {
            splicedPairs.decrementAndGet()
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        c.role = CircuitRole.SPLICED
        c.pairOwner = true
        c.partner = waiting
        defer(DeferSplice(waiting, c, body.rendezvous2Payload()))
        return emptyList()
    }

    private fun handleRendezvousData(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        val partner = c.partner
        val data = msg.data
        if (c.role != CircuitRole.SPLICED || partner == null || data.size != HsConstants.E2E_BLOB_SIZE) {
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        @OptIn(ExperimentalOnionApi::class)
        rendezvousDataObserver?.invoke(data)
        defer(DeferSend(partner, RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, data)))
        return emptyList()
    }

    /**
     * Directory publication (wave V0.10.0-D): accepted only at the last hop of a circuit that has no other role, at
     * most `directoryPublishPerCircuit` times per circuit (every attempt counts, also a rate-limited one). The rate
     * limits are checked BEFORE the body is looked at. A body of the wrong length or with an overflowing length
     * field is a protocol violation and destroys the circuit; an unknown object type is answered with a status.
     */
    private fun handleDirectoryPublish(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (c.role == CircuitRole.NONE) {
            if (!canTakeRole(c)) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        } else if (c.role != CircuitRole.DIRECTORY_PUBLISHING) {
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        if (c.directoryPublishes >= limits.directoryPublishPerCircuit) {
            return teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
        }
        c.role = CircuitRole.DIRECTORY_PUBLISHING
        c.directoryPublishes++

        fun ack(status: Byte) =
            sendBackward(c, RelayMessage(RelayCommand.DIRECTORY_PUBLISHED, 0, StatusBody.encode(status)))
        val linkCounter =
            linkPublishCounters.computeIfAbsent(c.prevLink.value) {
                WindowCounter(limits.directoryPublishPerLinkPerMinute, clock)
            }
        if (!linkCounter.tryAcquire() || !globalPublishCounter.tryAcquire()) {
            logger.debug { "directory publish refused: rate limit" }
            return ack(DirectoryPublishStatus.RATE_LIMITED)
        }
        val data = msg.data
        if (data.size != DirectoryPublishBody.BODY_SIZE) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        if (!DirectoryPublishBody.knownType(data)) return ack(DirectoryPublishStatus.UNKNOWN_TYPE)
        val request =
            try {
                DirectoryPublishBody.decode(data)
            } catch (e: CellFormatException) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
        return listOf(RelayAction.DeliverDirectoryPublish(c.handle, request.type, request.objectBytes))
    }

    /**
     * Sealed mailbox item publication (wave V0.10.0-F1): accepted only at the last hop of a circuit with no other
     * role. An item arrives as exactly eight consecutive fragments of 716 bytes; at most `mailboxPublishPerCircuit`
     * items per circuit. The body length is checked first, then the four header bytes; the per-link and global
     * rate limits are applied when an item STARTS, before any payload byte is copied. A wrong length, a broken
     * header, a wrong item or fragment order, a timeout (`mailboxAssembleTimeout`) or any traffic after a refusal
     * destroys the circuit. Only a rate limit is answered with a status, so the answer is no oracle for the item.
     */
    private fun handleMailboxPublish(
        c: RelayCircuit,
        msg: RelayMessage,
    ): List<RelayAction> {
        if (c.role == CircuitRole.NONE) {
            if (!canTakeRole(c)) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        } else if (c.role != CircuitRole.MAILBOX_PUBLISHING) {
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        c.role = CircuitRole.MAILBOX_PUBLISHING
        if (c.mailboxBlocked) return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        val data = msg.data
        val header =
            try {
                MailboxPublishBody.decodeHeader(data)
            } catch (e: CellFormatException) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
        val now = clock.millis()
        if (header.fragIndex == 0) {
            if (c.mailboxBuffer != null || header.itemIndex != c.mailboxItemsDone) {
                return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
            }
            if (c.mailboxItemsDone >= limits.mailboxPublishPerCircuit) {
                return teardown(c, DestroyReason.RESOURCE_LIMIT, Notify.BOTH)
            }
            val linkCounter =
                linkMailboxCounters.computeIfAbsent(c.prevLink.value) {
                    WindowCounter(limits.mailboxPublishPerLinkPerMinute, clock)
                }
            if (!linkCounter.tryAcquire() || !globalMailboxCounter.tryAcquire()) {
                logger.debug { "mailbox publish refused: rate limit" }
                c.mailboxBlocked = true
                return sendBackward(
                    c,
                    RelayMessage(
                        RelayCommand.MAILBOX_PUBLISHED,
                        0,
                        StatusBody.encode(MailboxPublishStatus.RATE_LIMITED),
                    ),
                )
            }
            c.mailboxBuffer = ByteArray(MailboxPublishBody.ITEM_SIZE)
            c.mailboxNextFragment = 0
            c.mailboxStartedMillis = now
        }
        val buffer = c.mailboxBuffer
        if (buffer == null ||
            header.itemIndex != c.mailboxItemsDone ||
            header.fragIndex != c.mailboxNextFragment ||
            now - c.mailboxStartedMillis > limits.mailboxAssembleTimeout.inWholeMilliseconds
        ) {
            return teardown(c, DestroyReason.PROTOCOL, Notify.BOTH)
        }
        MailboxPublishBody
            .fragmentOf(data)
            .copyInto(buffer, header.fragIndex * MailboxPublishBody.FRAGMENT_SIZE)
        c.mailboxNextFragment++
        if (c.mailboxNextFragment < MailboxPublishBody.FRAGMENT_COUNT) return emptyList()
        c.mailboxBuffer = null
        c.mailboxItemsDone++
        return listOf(RelayAction.DeliverMailboxItem(c.handle, buffer))
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
            when (c.role) {
                CircuitRole.INTRO -> introTable.remove(c)
                CircuitRole.RENDEZVOUS_WAITING -> rendezvousTable.remove(c)
                else -> Unit
            }
            if (c.pairOwner) splicedPairs.decrementAndGet()
            c.partner?.let { p ->
                // the other half of a splice cannot outlive this one
                defer(DeferTeardown(p, reason, if (notify == Notify.NONE) Notify.NONE else Notify.PREV))
            }
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
