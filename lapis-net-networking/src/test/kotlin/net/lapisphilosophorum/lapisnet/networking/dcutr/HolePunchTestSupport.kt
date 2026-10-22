package net.lapisphilosophorum.lapisnet.networking.dcutr

import io.libp2p.core.Connection
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.security.SecureChannel
import io.libp2p.crypto.keys.generateEd25519KeyPair
import java.lang.reflect.Proxy
import java.net.InetSocketAddress
import java.util.concurrent.CompletableFuture

/** A clock the test moves by hand; scheduled tasks run, in order, when their time comes. */
internal class ManualClock : HolePunchClock {
    var nowMs = 1_000_000L

    private data class Task(
        val at: Long,
        val order: Int,
        val run: Runnable,
        var cancelled: Boolean = false,
    )

    private val tasks = ArrayList<Task>()
    private var counter = 0
    var closed = false

    override fun nowMillis(): Long = nowMs

    override fun nanoTime(): Long = nowMs * 1_000_000L

    override fun schedule(
        delayNanos: Long,
        task: Runnable,
    ): AutoCloseable {
        val entry = Task(nowMs + delayNanos / 1_000_000L, counter++, task)
        tasks += entry
        return AutoCloseable { entry.cancelled = true }
    }

    override fun close() {
        closed = true
    }

    fun pendingTasks(): Int = tasks.count { !it.cancelled }

    fun advance(ms: Long) {
        val target = nowMs + ms
        while (true) {
            val next =
                tasks.filter { !it.cancelled && it.at <= target }.minWithOrNull(compareBy({ it.at }, { it.order }))
                    ?: break
            tasks.remove(next)
            nowMs = maxOf(nowMs, next.at)
            next.run.run()
        }
        nowMs = target
    }
}

internal fun fakeConnection(
    peer: PeerId,
    relayed: Boolean,
    initiator: Boolean = false,
    address: String? = null,
): FakeConnection = FakeConnection(peer, relayed, initiator, address)

internal class FakeConnection(
    val peer: PeerId,
    val relayed: Boolean,
    private val initiator: Boolean = false,
    addressText: String? = null,
) {
    val closed = CompletableFuture<Unit>()
    private val session = SecureChannel.Session(PeerId.random(), peer, generateEd25519KeyPair().second, null)
    private val address =
        addressText?.let { Multiaddr(it) }
            ?: if (relayed) Multiaddr("/ip4/8.8.4.4/tcp/4001/p2p-circuit") else Multiaddr("/ip4/1.1.1.1/tcp/4001")
    val connection: Connection =
        Proxy.newProxyInstance(
            Connection::class.java.classLoader,
            arrayOf(Connection::class.java),
        ) { proxy, method, args ->
            when (method.name) {
                "secureSession" -> session
                "remoteAddress" -> address
                "isInitiator" -> initiator
                "closeFuture" -> closed
                "close" -> {
                    closed.complete(Unit)
                    closed
                }
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.get(0)
                "toString" -> "FakeConnection($peer, relayed=$relayed)"
                else -> throw UnsupportedOperationException(method.name)
            }
        } as Connection
}

internal class FakeWire : DcutrWire {
    val sent = ArrayList<HolePunchMessage>()
    private val inbox = ArrayDeque<HolePunchMessage>()
    private val waiters = ArrayDeque<CompletableFuture<HolePunchMessage>>()
    var closed = false
    var failure: Throwable? = null

    override fun send(message: HolePunchMessage): CompletableFuture<Unit> {
        sent += message
        return CompletableFuture.completedFuture(Unit)
    }

    override fun receive(): CompletableFuture<HolePunchMessage> {
        val f = CompletableFuture<HolePunchMessage>()
        when {
            inbox.isNotEmpty() -> f.complete(inbox.removeFirst())
            failure != null -> f.completeExceptionally(failure)
            else -> waiters.addLast(f)
        }
        return f
    }

    fun deliver(message: HolePunchMessage) {
        val w = waiters.removeFirstOrNull()
        if (w != null) w.complete(message) else inbox.addLast(message)
    }

    override fun close() {
        closed = true
        failure = IllegalStateException("closed")
        waiters.toList().forEach { it.completeExceptionally(failure) }
        waiters.clear()
    }
}

internal class FakeEnvironment : HolePunchEnvironment {
    /** The wire of the most recent attempt: each [openWire] hands out a fresh one. */
    var wire = FakeWire()
    var direct = false
    var openWireFuture: CompletableFuture<DcutrWire>? = null
    var registryCapacity = 10
    val refusedAddresses = HashSet<InetSocketAddress>()
    val foreignAddresses = HashSet<InetSocketAddress>()
    val registrations = ArrayList<Triple<PeerId, InetSocketAddress, Boolean>>()
    var activeRegistrations = 0
    var expectedPeer: PeerId? = null
    var clock: ManualClock? = null

    class Dial(
        val remote: InetSocketAddress,
        val expected: PeerId,
        val initiatorRole: Boolean,
        val atMs: Long,
        val future: CompletableFuture<Connection>,
    )

    val dials = ArrayList<Dial>()
    var refreshCalls = 0

    override fun openWire(connection: Connection): CompletableFuture<DcutrWire> =
        openWireFuture ?: CompletableFuture.completedFuture(FakeWire().also { wire = it })

    override fun hasDirectConnection(peer: PeerId): Boolean = direct

    override fun isRelayed(connection: Connection): Boolean =
        connection.remoteAddress().toString().contains("p2p-circuit")

    override fun ownAddresses(): Set<InetSocketAddress> = emptySet()

    override fun punchDial(
        remote: InetSocketAddress,
        expected: PeerId,
        initiatorRole: Boolean,
    ): CompletableFuture<Connection> {
        val d = Dial(remote, expected, initiatorRole, clock?.nowMs ?: 0, CompletableFuture())
        dials += d
        return d.future
    }

    override fun registerRole(
        peer: PeerId,
        remote: InetSocketAddress,
        initiatorRole: Boolean,
    ): AutoCloseable? {
        if (activeRegistrations >= registryCapacity || remote in refusedAddresses) return null
        registrations += Triple(peer, remote, initiatorRole)
        activeRegistrations++
        return AutoCloseable { activeRegistrations-- }
    }

    override fun hasForeignRoleEntries(
        peer: PeerId,
        remote: InetSocketAddress,
    ): Boolean = remote in foreignAddresses

    override fun expectedPeerAt(connection: Connection): PeerId? = expectedPeer

    override fun refreshObservedAddresses(): CompletableFuture<Unit> {
        refreshCalls++
        return CompletableFuture.completedFuture(Unit)
    }
}

internal fun publicAddress(
    ip: String,
    port: Int = 4001,
): ByteArray = Multiaddr("/ip4/$ip/tcp/$port").serialize()

internal class Harness(
    config: HolePunchConfig = HolePunchConfig(mode = HolePunchMode.ON),
    observed: List<String> = listOf("/ip4/9.9.9.9/tcp/4001"),
    onRelayReplaced: (Connection) -> Unit = {},
) {
    val clock = ManualClock()
    val env = FakeEnvironment().also { it.clock = clock }
    val filter = HolePunchAddressFilter(allowNonPublic = config.allowNonPublicAddresses)
    val book = ObservedAddressBook(filter)
    val manager = HolePunchManager(env, book, filter, config, clock, onRelayReplaced)
    val relayObserver = PeerId.random()

    init {
        observed.forEach { book.record(relayObserver, Multiaddr(it)) }
    }
}
