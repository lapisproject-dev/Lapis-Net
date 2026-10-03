package net.lapisphilosophorum.lapisnet.storage

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.libp2p.core.Connection
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.BlockRequestAuthoriser
import org.peergos.PeerAddresses
import org.peergos.Want
import org.peergos.blockstore.Blockstore
import org.peergos.blockstore.FileBlockstore
import org.peergos.protocol.bitswap.Bitswap
import org.peergos.protocol.dht.Kademlia
import org.peergos.protocol.dht.pb.Dht
import java.nio.file.Path
import java.time.Duration
import java.util.Collections
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

private val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(10)
private val DEFAULT_CONNECT_TIMEOUT: Duration = Duration.ofSeconds(5)
private const val DEFAULT_RECORD_STORE_CAPACITY = 1024
private const val DEFAULT_DESIRED_PROVIDER_COUNT = 4
private const val RPC_POOL_SIZE = 4

/** How long a (block, peer) pair is not asked again by [NabuStorage.get]; matches Nabu's own want lifetime. */
private val FETCH_REPEAT_WINDOW: Duration = Duration.ofMinutes(5)
private const val RECENT_FETCH_CAPACITY = 4096

/** Thrown when a storage or DHT operation fails or times out. */
class NabuStorageException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Allows every block read - no read-access control in this wave; see docs/architecture.adoc. */
private val allowAllReads =
    BlockRequestAuthoriser { _, _, _ -> CompletableFuture.completedFuture(true) }

private fun daemonThreads(prefix: String): ThreadFactory {
    val counter = AtomicInteger()
    return ThreadFactory { task -> Thread(task, "$prefix-${counter.incrementAndGet()}").apply { isDaemon = true } }
}

/**
 * DHT (Kademlia) + Bitswap content storage, layered on an already-`start()`-ed [LapisNode]'s
 * libp2p [Host] (see [attach]). Domain-agnostic by design: [ByteArray]/[Cid] in and out - no
 * Veritas-specific structure lives here (that lands in a later wave, built on top of this).
 *
 * **The DHT layer is this project's own since V0.9.11** (see [DhtWalker], [LapisKademliaEngine],
 * [BoundedProviderStore], [PeerAddressSanitizer], [InboundDhtRequestPolicy] and [DhtLimits]):
 * Nabu supplies the wire protocol, the routing table and Bitswap, but none of its blocking lookup
 * methods (`findClosestPeers`, `findProviders`, `getCloserPeers`, `provideBlock`,
 * `bootstrapRoutingTable`, `publishValue`, `resolveValue`) is ever called, because they have no
 * deadline, run on a non-daemon pool that wedges permanently, and parse untrusted responses with
 * unbounded parsers. Every operation here has an absolute deadline measured from the start of the
 * call.
 */
class NabuStorage private constructor(
    private val host: Host,
    private val blockstore: Blockstore,
    private val bitswap: Bitswap,
    private val bitswapEngine: RefreshableBitswapEngine,
    private val kademlia: Kademlia,
    private val engine: LapisKademliaEngine,
    private val limits: DhtLimits,
    private val localDht: Boolean,
    /** Nanosecond clock of the repeat window and the want lifetime; tests age both with it. */
    private val clock: () -> Long = System::nanoTime,
) {
    private val stopped = AtomicBoolean(false)

    /** Completed by [stop]; ends every blocking DHT wait early. */
    private val stopSignal = CompletableFuture<Unit>()

    private val operationPermits = Semaphore(limits.maxConcurrentDhtOperations)
    private val addressLock = Any()

    /** Runs the (non-blocking) write continuations of DHT exchanges, never the Netty event loop. */
    private val rpcPool =
        ThreadPoolExecutor(
            RPC_POOL_SIZE,
            RPC_POOL_SIZE,
            30,
            TimeUnit.SECONDS,
            LinkedBlockingQueue(),
            daemonThreads("lapis-dht-rpc"),
        ).apply { allowCoreThreadTimeOut(true) }

    /**
     * A rejected task (after [stop]) is dropped instead of thrown: a [RejectedExecutionException]
     * raised inside a `thenComposeAsync` step surfaces on the thread that completed the previous
     * stage - the Netty event loop - and would leave the dependent future open forever. The
     * exchange's own `orTimeout` cleans up.
     */
    private val rpcExecutor =
        Executor { task ->
            try {
                rpcPool.execute(task)
            } catch (_: RejectedExecutionException) {
                logger.debug { "DHT exchange task dropped: storage is stopped" }
            }
        }

    /**
     * Runs the blocking part of a fetch (connecting to a provider, then Bitswap's `get`, which dials
     * synchronously and starts a `Thread` per call that re-sends the want until it expires). Bounded
     * twice: [DhtLimits.maxConcurrentFetches] run at once and a queue of one call's worth of providers
     * per slot waits; beyond that [get] returns `null` at once ("busy"). Daemon threads - the inner
     * Bitswap thread inherits that - so a stuck dial never pins the JVM.
     */
    private val fetchExecutor =
        ThreadPoolExecutor(
            limits.maxConcurrentFetches,
            limits.maxConcurrentFetches,
            30,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(limits.maxConcurrentFetches * limits.maxProvidersPerKey),
            daemonThreads("lapis-bitswap-fetch"),
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    /** Number of Bitswap requests actually sent by [get]; lets tests observe the repeat window. */
    internal val bitswapRequestsSent = AtomicInteger()

    private val recentFetches: MutableMap<Pair<String, PeerId>, Long> =
        Collections.synchronizedMap(
            object : LinkedHashMap<Pair<String, PeerId>, Long>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Pair<String, PeerId>, Long>): Boolean =
                    size > RECENT_FETCH_CAPACITY
            },
        )

    private val walker =
        DhtWalker(host, kademlia, engine, limits, localDht, rpcExecutor, stopSignal) { peer, addresses ->
            mergeDhtLearned(peer, addresses)
        }

    /** Stores [bytes] in the local blockstore (no network) and returns its [Cid]. */
    fun put(
        bytes: ByteArray,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Cid {
        val cid = awaitOrWrap("put block", timeout) { blockstore.put(bytes, Cid.Codec.Raw) }
        logger.debug { "stored block $cid (${bytes.size} bytes)" }
        return cid
    }

    /**
     * Returns the bytes for [cid] from the LOCAL blockstore only - guaranteed no network I/O and
     * no [findProviders] call, unlike [get]. `null` if [cid] is not held locally.
     *
     * **V0.8.6 addition, for exactly one shape of caller: "is this blob already on my own disk?"**
     * (`lapis-net-dm`'s `DmAttachmentFetcher`). Neither of [get]'s own two forms answers that
     * question correctly: `get(cid, peers = emptySet())` falls through to [findProviders] on a
     * local miss - which costs a full DHT round trip, and, before the V0.9.8 repair described on
     * [provide], never resolved anything at all - and `get(cid, peers =
     * setOf(somePeer))` forces a real Bitswap dial-and-timeout against a peer that may not even be
     * reachable, just to answer a question [get]'s own first line (`blockstore.get(cid)`) already
     * answers for free. This method is exactly that first line, exposed directly.
     */
    fun getLocal(
        cid: Cid,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): ByteArray? {
        val local = awaitOrWrap("check local blockstore", timeout) { blockstore.get(cid) }
        return if (local.isPresent) local.get() else null
    }

    /**
     * Returns the bytes for [cid], or `null` if it can't be found anywhere reachable. Checks
     * the local blockstore first (no network involved). If absent: fetches from [peers] via
     * Bitswap if given, otherwise looks up providers via the DHT first and fetches from whatever
     * it finds. A DHT lookup or Bitswap fetch that fails or times out is treated as "not found"
     * (returns `null`) rather than propagating [NabuStorageException] - an unreachable or
     * non-responding peer is exactly the "can't be found anywhere reachable" case this method
     * documents, not a distinct error condition callers need to handle separately. A failure
     * checking the *local* blockstore still throws, since that signals a real local fault (e.g.
     * disk I/O), not a not-found result. After [stop] only the local blockstore is consulted.
     *
     * **Bounds (V0.9.11).** [timeout] is an absolute deadline from the start of the call: a DHT
     * lookup, if needed, gets the first half of it and the fetch wait whatever remains. At most
     * [DhtLimits.maxProvidersPerKey] peers are tried, each dialled with at most
     * [DhtLimits.maxAddressesPerPeer] addresses. Fetches run on a bounded pool; if every slot is
     * busy this returns `null` immediately instead of queueing.
     *
     * **Known residual risk.** Nabu has no API to cancel a want. A fetch that times out leaves its
     * want registered, and Bitswap's re-send thread for it keeps running - but only against the peer
     * it was asked of, and only until five minutes after the want was last requested FROM THAT PEER
     * ([RefreshableBitswapEngine] tracks wants per peer; activity for other peers or blocks does not
     * keep the thread alive). The dial it makes is bounded only by libp2p's own limits (TCP connect
     * 15 s, Noise read 5 s). The same (block, peer) pair is not requested again within five minutes,
     * so repeated `get` calls do not multiply those threads; once the five minutes are over, the next
     * `get` really sends the request again and renews the want's lifetime for that peer - Nabu alone
     * would never send it again.
     *
     * **Address book.** What a DHT response says about a provider's addresses is unverified. It is
     * used for this one fetch only; an address enters the address book only after a connection over
     * it was made and the peer on the other end proved to be the provider ([connectForFetch]).
     *
     * **Information leak.** With `peers` empty, the block's bare multihash is sent to every peer
     * the lookup queries (at most `walkParallelism x maxWalkRounds` plus the routing-table seeds).
     * The CID is the access token for a block (reads are always authorised) - callers that must not
     * reveal it to the DHT pass explicit `peers`.
     */
    fun get(
        cid: Cid,
        peers: Set<PeerId> = emptySet(),
        timeout: Duration = DEFAULT_TIMEOUT,
    ): ByteArray? {
        val start = System.nanoTime()
        requirePositive(timeout)
        val deadline = start + timeout.toNanos()
        val local = awaitOrWrap("check local blockstore", timeout) { blockstore.get(cid) }
        if (local.isPresent) return local.get()
        if (stopped.get()) return null

        return try {
            // addresses the DHT named for a provider: unverified, they only serve this call's dials
            val hints = HashMap<PeerId, List<Multiaddr>>()
            val targets: List<PeerId> =
                if (peers.isNotEmpty()) {
                    peers.take(limits.maxProvidersPerKey)
                } else {
                    val discovered = lookupProviders(cid, limits.maxProvidersPerKey, start + timeout.toNanos() / 2)
                    discovered.forEach { hints[it.peerId] = it.addresses }
                    discovered.map { it.peerId }
                }
            if (targets.isEmpty()) return null
            fetch(cid, targets, hints, deadline)
        } catch (e: NabuStorageException) {
            logger.debug(e) { "get() could not reach any peer within the timeout - treating as not found" }
            null
        }
    }

    private fun fetch(
        cid: Cid,
        targets: List<PeerId>,
        hints: Map<PeerId, List<Multiaddr>>,
        deadlineNanos: Long,
    ): ByteArray? {
        // The want future is shared by every waiter for this block; it must never be cancelled here.
        val want = bitswapEngine.getWant(Want(cid), true)
        var submitted = 0
        for (peer in targets) {
            if (recentlyRequested(cid, peer)) continue
            try {
                fetchExecutor.execute {
                    // a task that waited in the queue past this call's deadline has nobody left to serve
                    val connected =
                        System.nanoTime() < deadlineNanos && connectForFetch(peer, hints[peer].orEmpty(), deadlineNanos)
                    if (connected && markRequested(cid, peer)) {
                        // Nabu's want expires five minutes after its creation; a request that is really sent
                        // starts a new lifetime, or a block whose first fetch failed could never be fetched again.
                        // The want is registered for THIS peer only, so it is put in no other peer's wantlist.
                        bitswapEngine.refresh(Want(cid), peer)
                        bitswapRequestsSent.incrementAndGet()
                        runCatching { bitswap.get(Want(cid), host, setOf(peer), true) }
                            .onFailure { logger.debug { "bitswap request failed: ${it.javaClass.simpleName}" } }
                    }
                }
                submitted++
            } catch (_: RejectedExecutionException) {
                logger.debug { "all bitswap fetch slots busy" }
                if (submitted == 0) return null
                break
            }
        }
        // every target was asked recently: that request is already running its course, nothing to wait for
        if (submitted == 0) return null
        val remaining = deadlineNanos - System.nanoTime()
        return try {
            want.get(maxOf(remaining, 0), TimeUnit.NANOSECONDS).block
        } catch (_: TimeoutException) {
            null
        } catch (e: ExecutionException) {
            logger.debug { "bitswap want failed: ${e.cause?.javaClass?.simpleName}" }
            null
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }
    }

    /**
     * Makes sure there is a live connection to [peer] BEFORE Bitswap is asked to use it, within
     * [DhtLimits.fetchConnectTimeout]. Bitswap's own dial blocks without a bound of ours; this way a
     * silent or unroutable provider costs one bounded wait and no re-send thread, and the pending
     * dials are cancelled. With a connection in place Bitswap's dial returns immediately.
     *
     * [hints] are addresses a third party (a DHT response) claims for [peer]. They are tried after the
     * addresses already on file and are NOT stored: only the address of a connection that really came
     * up and whose far end authenticated as [peer] is put in the address book (Bitswap resolves
     * addresses from there). So a responder cannot fill the address book with peers that never
     * answered, nor push a victim's real addresses out of its capped entry with made-up ones.
     */
    private fun connectForFetch(
        peer: PeerId,
        hints: List<Multiaddr>,
        deadlineNanos: Long,
    ): Boolean {
        val known =
            host.addressBook
                .getAddrs(peer)
                .join()
                .orEmpty()
        host.network.connections.firstOrNull { it.secureSession().remoteId == peer }?.let { existing ->
            // Bitswap resolves an address from the book before it dials - and then reuses this connection.
            // The connection's own remote address is the one proven to belong to the peer (for an incoming
            // connection it is no address to dial back, but the connection is what will be used).
            if (known.isEmpty()) learnVerifiedAddress(peer, existing, listOf(existing.remoteAddress()))
            return true
        }
        val addresses = (known + hints).distinctBy { it.toString() }.take(limits.maxAddressesPerPeer)
        if (addresses.isEmpty()) return false
        val timeoutNanos = minOf(limits.fetchConnectTimeout.toNanos(), deadlineNanos - System.nanoTime())
        if (timeoutNanos <= 0) return false
        val connecting = host.network.connect(peer, *addresses.toTypedArray())
        return try {
            val connection = connecting.get(timeoutNanos, TimeUnit.NANOSECONDS)
            if (connection.secureSession().remoteId != peer) {
                logger.debug { "a provider's address led to a different peer - not used" }
                runCatching { connection.close() }
                return false
            }
            learnVerifiedAddress(peer, connection, addresses)
            true
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            connecting.cancel(true)
            false
        } catch (e: Exception) {
            logger.debug { "could not connect to a provider: ${e.javaClass.simpleName}" }
            connecting.cancel(true)
            false
        }
    }

    /**
     * Puts into the address book the address [connection] to [peer] actually runs over, if it is one of
     * [candidates] - the single address that is proven to belong to [peer].
     */
    private fun learnVerifiedAddress(
        peer: PeerId,
        connection: Connection,
        candidates: List<Multiaddr>,
    ) {
        val remote = runCatching { connection.remoteAddress().withP2P(peer) }.getOrNull() ?: return
        val match =
            candidates
                .mapNotNull { runCatching { it.withP2P(peer) }.getOrNull() }
                .firstOrNull { it.toString() == remote.toString() } ?: return
        mergeDhtLearned(peer, listOf(match))
    }

    /** Read-only: was a Bitswap request for this (block, peer) pair actually sent within the repeat window? */
    private fun recentlyRequested(
        cid: Cid,
        peer: PeerId,
    ): Boolean {
        val last = synchronized(recentFetches) { recentFetches[cid.toString() to peer] } ?: return false
        return clock() - last < FETCH_REPEAT_WINDOW.toNanos()
    }

    /**
     * Called only when a Bitswap request is about to be sent (a connection exists): records the pair
     * and returns `false` if another call did so within the repeat window. A pair whose connect failed,
     * whose task was rejected or whose deadline passed in the queue is therefore never marked.
     */
    private fun markRequested(
        cid: Cid,
        peer: PeerId,
    ): Boolean {
        val key = cid.toString() to peer
        val now = clock()
        synchronized(recentFetches) {
            val last = recentFetches[key]
            if (last != null && now - last < FETCH_REPEAT_WINDOW.toNanos()) return false
            recentFetches[key] = now
            return true
        }
    }

    /**
     * Announces to the DHT that this node has [cid] available for retrieval: walks Kademlia's
     * keyspace towards [cid]'s key (the bare multihash) and sends an `ADD_PROVIDER` RPC naming this
     * node to each of the [DhtLimits.provideFanout] closest peers it found. A later
     * [findProviders] call for [cid] by any node that can reach one of those peers then resolves
     * back to this node. Peers that can't be dialled, or that time out, are skipped - the
     * announcement is best-effort by nature. Returns how many `ADD_PROVIDER` messages were SENT;
     * **the protocol has no acknowledgement, so this is not a delivery count**. Returns 0 (and
     * logs a warning) if no DHT peer is known.
     *
     * [timeout] is an absolute deadline from the first line of this call: the walk gets the first
     * half, the announcement the rest. Throws [NabuStorageException] if the storage is stopped, if
     * the DHT is busy ([DhtLimits.maxConcurrentDhtOperations]), if the thread is interrupted
     * (the flag is restored) or if the walk itself fails.
     *
     * **Why this does not call Nabu's own `Kademlia.provideBlock` (V0.9.8 repair, Nabu v0.8.0).**
     * `provideBlock` chains the announcement onto the dial as
     * `dialPeer(peer, host).thenCompose { it.provide(...) }`, so `KademliaController.provide`'s
     * `stream.writeAndFlush(...)` executes *inside the `getController()` completion callback*,
     * i.e. on the Netty event-loop thread that just completed that future - and the write is
     * silently dropped there. Nothing surfaces it: `KademliaProtocol.ReplyHandler.send` is
     * fire-and-forget (it returns `completedFuture(true)` without ever observing the write's own
     * future), so `provideBlock` reports success for an RPC that never reached the wire. Verified
     * by a three-way diagnostic spike against real loopback nodes: identical peer, identical
     * addresses, identical message - `thenCompose` (on-loop) delivered nothing, while both
     * `thenComposeAsync` on a separate executor and a plain blocking
     * `dial(...).controller.get()` followed by `provide(...)` delivered the `ADD_PROVIDER`
     * every time. The repair did the dial-then-announce itself, off the event loop.
     *
     * **V0.9.11:** that repair still used Nabu's `findClosestPeers` for the walk, which has no
     * deadline and runs on a non-daemon pool. The walk is now [DhtWalker.closestPeers], also off
     * the event loop and bounded. See docs/architecture.adoc.
     */
    fun provide(
        cid: Cid,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Int {
        val start = System.nanoTime()
        requirePositive(timeout)
        val deadline = start + timeout.toNanos()
        val walkDeadline = start + timeout.toNanos() / 2
        failIfStopped()
        val us = PeerAddresses.fromHost(host)
        return withOperationPermit(deadline) {
            val closest =
                try {
                    walker.closestPeers(dhtKeyFor(cid), limits.provideFanout, walkDeadline)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw NabuStorageException("interrupted while finding DHT peers to announce to", e)
                } catch (e: Exception) {
                    throw NabuStorageException("failed to find DHT peers to announce to", e)
                }
            failIfStopped()
            if (closest.peers.isEmpty()) {
                logger.warn { "provide: no DHT peers known - nothing announced" }
                return@withOperationPermit 0
            }
            val sent =
                try {
                    walker.announce(cid, closest.peers, us, deadline)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw NabuStorageException("interrupted while announcing", e)
                } catch (e: Exception) {
                    throw NabuStorageException("failed to announce", e)
                }
            logger.info {
                "provide: sent ADD_PROVIDER to $sent of ${closest.peers.size} candidate peers " +
                    "(delivery unconfirmed: the protocol has no acknowledgement)"
            }
            logger.debug { "provide: announced $cid" }
            sent
        }
    }

    /**
     * Looks up which known peers have announced [cid] via [provide], by walking Kademlia's
     * keyspace with `GET_PROVIDERS` RPCs (first consulting this node's own provider store). Also
     * resolves peers that never called [provide] but simply hold [cid] in their local blockstore -
     * Nabu's responder side adds itself to any `GET_PROVIDERS` reply for a block it already has.
     * [desiredCount] is clamped to [DhtLimits.maxProvidersPerKey].
     *
     * [timeout] is an absolute deadline from the start of the call; whatever was found when it
     * passes is returned (possibly an empty set). Throws [NabuStorageException] if the storage is
     * stopped, the DHT is busy, the thread is interrupted (the flag is restored) or the walk fails.
     *
     * Returns only peer IDs. [get] resolves the addresses itself and registers them. Note that on a
     * loopback-only deployment those addresses can come back empty for the "responder holds the
     * block itself" case: `KademliaEngine`'s `GET_PROVIDERS` handler filters its own advertised
     * addresses to publicly-routable ones, which loopback addresses are not. Such entries are kept
     * with an empty address list. Provider entries that arrived through a real
     * [provide]/`ADD_PROVIDER` are not filtered and do carry their addresses.
     *
     * Like [get] without `peers`, this reveals the block's bare multihash to the peers it queries.
     */
    fun findProviders(
        cid: Cid,
        desiredCount: Int = DEFAULT_DESIRED_PROVIDER_COUNT,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Set<PeerId> {
        val start = System.nanoTime()
        requirePositive(timeout)
        failIfStopped()
        return lookupProviders(cid, desiredCount, start + timeout.toNanos()).map { it.peerId }.toSet()
    }

    private fun lookupProviders(
        cid: Cid,
        desired: Int,
        deadlineNanos: Long,
    ): List<DhtWalker.WalkPeer> =
        withOperationPermit(deadlineNanos) {
            try {
                walker.findProviders(cid.bareMultihash(), desired, deadlineNanos)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw NabuStorageException("interrupted while finding DHT providers", e)
            } catch (e: Exception) {
                throw NabuStorageException("failed to find DHT providers", e)
            }
        }

    /**
     * Registers [address] (must include a `/p2p/<peerId>` component, e.g. via
     * [Multiaddr.withP2P]) as a peer's dialable address, so a later [get] call can pass that
     * peer explicitly and have Bitswap actually reach it. Bitswap's wire protocol resolves peer
     * addresses from the libp2p [Host]'s address book rather than accepting them inline, and
     * this project's plain `host { }` DSL (see [LapisNode.create]) has no automatic
     * identify-based address-book population on connect, unlike Nabu's own (unused)
     * `org.peergos.HostBuilder`. Not needed when a peer's address is already known some other
     * way (e.g. via [connectToDhtPeer] or DHT-driven discovery inside [get]).
     *
     * The address is put FIRST in the peer's list; the list is capped at
     * [DhtLimits.maxAddressesPerPeer], oldest dropped.
     */
    fun registerPeerAddress(
        address: Multiaddr,
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        val peerId =
            address.getPeerId()
                ?: throw NabuStorageException("address is missing a /p2p/<peerId> component: $address")
        awaitOrWrap("register peer address", timeout) {
            mergeExplicit(peerId, listOf(address))
            CompletableFuture.completedFuture(Unit)
        }
    }

    /**
     * Explicitly connects this node's DHT routing table to the peer listening at [address]
     * (must include a `/p2p/<peerId>` component, e.g. via [Multiaddr.withP2P]). A deterministic,
     * loopback-friendly alternative to a real-network bootstrap - mirrors [LapisNode.connect]'s
     * "explicit local peer" pattern. Returns `true` if the peer was reachable within [timeout] and
     * added, `false` otherwise.
     *
     * Deliberately not Nabu's `bootstrapRoutingTable`: that one resolves DNS, runs on the
     * non-daemon `ioExec` pool and leaves the stream it opens unclosed.
     */
    fun connectToDhtPeer(
        address: Multiaddr,
        timeout: Duration = DEFAULT_CONNECT_TIMEOUT,
    ): Boolean {
        val peerId =
            address.getPeerId()
                ?: throw NabuStorageException("address is missing a /p2p/<peerId> component: $address")
        mergeExplicit(peerId, listOf(address))
        val promise =
            try {
                kademlia.dial(host, peerId, address)
            } catch (e: Exception) {
                logger.debug { "connectToDhtPeer: dial setup failed: ${e.javaClass.simpleName}" }
                return false
            }
        // Close only once the exchange is over (controller done OR failed): the stream future
        // completes when the channel exists, BEFORE protocol negotiation has finished, and
        // resetting it that early would fail the negotiation itself.
        promise.controller.whenComplete { _, _ -> promise.stream.thenAccept { it.close() } }
        return try {
            // Completing the controller is what adds the peer to the routing table (onStartInitiator).
            promise.controller.get(timeout.toNanos(), TimeUnit.NANOSECONDS)
            true
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (e: Exception) {
            logger.debug { "connectToDhtPeer failed: ${e.javaClass.simpleName}" }
            false
        }
    }

    /**
     * Ends every blocking DHT wait early and stops accepting new network work: afterwards [provide]
     * and [findProviders] throw and [get] only consults the local blockstore. The libp2p [Host] is
     * owned by [LapisNode], which stops it on its own. Idempotent.
     */
    fun stop() {
        if (stopped.compareAndSet(false, true)) {
            stopSignal.complete(Unit)
            fetchExecutor.shutdown()
            rpcPool.shutdown()
        }
    }

    /** How many inbound DHT requests [InboundDhtRequestPolicy] rejected (tests). */
    internal fun inboundRejectedCount(): Long = engine.rejectedInboundRequests

    /** How many inbound DHT requests passed validation but made Nabu's responder throw (tests). */
    internal fun inboundFailedCount(): Long = engine.failedInboundRequests

    /** The provider records this node itself holds for [cid] (tests). */
    internal fun localProviderRecords(cid: Cid): List<Dht.Message.Peer> = engine.localProviders(cid.bareMultihash())

    private fun failIfStopped() {
        if (stopped.get()) throw NabuStorageException("storage is stopped")
    }

    private fun requirePositive(timeout: Duration) {
        require(!timeout.isNegative && !timeout.isZero) { "timeout must be positive" }
    }

    private fun <T> withOperationPermit(
        deadlineNanos: Long,
        block: () -> T,
    ): T {
        val acquired =
            try {
                operationPermits.tryAcquire(maxOf(deadlineNanos - System.nanoTime(), 0), TimeUnit.NANOSECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw NabuStorageException("interrupted while waiting for a DHT slot", e)
            }
        if (!acquired) throw NabuStorageException("DHT busy")
        try {
            failIfStopped()
            return block()
        } finally {
            operationPermits.release()
        }
    }

    /** [address]es go first; the list is capped at [DhtLimits.maxAddressesPerPeer]. */
    private fun mergeExplicit(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ) {
        synchronized(addressLock) {
            val existing =
                host.addressBook
                    .getAddrs(peer)
                    .join()
                    .orEmpty()
            setCapped(peer, addresses + existing)
        }
    }

    /**
     * Existing addresses go first, new ones are appended up to the cap: a responder can neither
     * displace the real addresses of an honest peer nor grow an entry past the cap by answering
     * repeatedly. (A plain `setAddrs` with the new list would let a malicious responder replace
     * them, and `addAddrs` grows without bound.)
     */
    private fun mergeDhtLearned(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ) {
        if (addresses.isEmpty()) return
        synchronized(addressLock) {
            val existing =
                host.addressBook
                    .getAddrs(peer)
                    .join()
                    .orEmpty()
            setCapped(peer, existing + addresses)
        }
    }

    private fun setCapped(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ) {
        val capped = addresses.distinctBy { it.toString() }.take(limits.maxAddressesPerPeer)
        host.addressBook.setAddrs(peer, 0, *capped.toTypedArray()).join()
    }

    private fun <T> awaitOrWrap(
        action: String,
        timeout: Duration,
        block: () -> CompletableFuture<T>,
    ): T =
        try {
            block().get(timeout.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw NabuStorageException("timed out waiting to $action", e)
        } catch (e: ExecutionException) {
            throw NabuStorageException("failed to $action", e.cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw NabuStorageException("interrupted while waiting to $action", e)
        } catch (e: NabuStorageException) {
            // Already funneled (e.g. a future refactor of `block` that calls back into another
            // NabuStorage method) - rethrow as-is instead of wrapping a NabuStorageException in
            // another one below.
            throw e
        } catch (e: Exception) {
            // `block()` itself can throw synchronously, before it ever produces a
            // CompletableFuture for `.get()` above to wait on - e.g. Nabu's FileBlockstore.put/
            // get catch a local IOException (disk full, permission denied, read-only filesystem)
            // and rethrow it as a bare RuntimeException on the calling thread, never delivering
            // it via a failed future. The catches above only see failures that *do* make it into
            // a future (or its .get() call); this catches everything else so no exception from a
            // storage/DHT call can escape this class unwrapped.
            throw NabuStorageException("failed to $action", e)
        }

    companion object {
        /**
         * Attaches Nabu's Bitswap + Kademlia DHT protocols to [node]'s already-`start()`-ed
         * libp2p [Host], storing blocks under [blockstoreDir]. Must be called after
         * [LapisNode.start], and at most once per [node] - calling it twice on the same node
         * would register duplicate protocol/connection handlers on the shared [Host]. [localDht]
         * selects Kademlia's LAN vs WAN protocol ID - this project has no real WAN bootstrap
         * infrastructure yet ([LapisNode]'s bootstrap peers are non-functional
         * documentation-range placeholders), so it defaults to `true`; with `false`, addresses
         * learned from the DHT are additionally restricted to public ones. [limits] bounds every
         * DHT operation, see [DhtLimits].
         */
        fun attach(
            node: LapisNode,
            blockstoreDir: Path,
            localDht: Boolean = true,
            limits: DhtLimits = DhtLimits(),
        ): NabuStorage = attachWithClock(node, blockstoreDir, localDht, limits, System::nanoTime)

        /** [attach] with an injectable clock for the repeat window and the want lifetime (tests age both). */
        internal fun attachWithClock(
            node: LapisNode,
            blockstoreDir: Path,
            localDht: Boolean,
            limits: DhtLimits,
            clock: () -> Long,
        ): NabuStorage {
            val host = node.host
            val blockstore = FileBlockstore(blockstoreDir)

            val bitswapEngine = RefreshableBitswapEngine(blockstore, allowAllReads, Bitswap.MAX_MESSAGE_SIZE, clock)
            val bitswap = Bitswap(bitswapEngine)
            // Bitswap implements both ConnectionHandler and AddressBookConsumer - mirroring
            // org.peergos.HostBuilder.build()'s own wiring exactly. addProtocolHandler alone is
            // not enough: without addConnectionHandler the responder side never learns about
            // connected peers, and without setAddressBook, dialPeer() can't resolve addresses -
            // both failures are swallowed silently inside Bitswap.sendWants's try/catch.
            bitswap.setAddressBook(host.addressBook)
            host.addProtocolHandler(bitswap)
            // node.addConnectionHandler, NOT host.addConnectionHandler: a relayed inbound
            // connection is accepted by the circuit-relay stop protocol rather than by a listening
            // transport, so it never reaches jvm-libp2p's own connection-handler broadcast. A
            // Bitswap registered on the Host alone would simply not know that a peer reachable only
            // through a relay exists, and would never answer or send wants to it - the same gap
            // GossipPubSub.attach closes the same way. See LapisNode.addConnectionHandler.
            node.addConnectionHandler(bitswap)

            val ourPeerId = Multihash.deserialize(host.peerId.bytes)
            val engine =
                LapisKademliaEngine(
                    ourPeerId,
                    BoundedProviderStore(limits),
                    BoundedRecordStore(DEFAULT_RECORD_STORE_CAPACITY),
                    blockstore,
                    limits,
                )
            val kademlia = Kademlia(engine, localDht)
            kademlia.setAddressBook(host.addressBook)
            host.addProtocolHandler(kademlia)

            // Register this node's own listen addresses in its own address book. Nabu's
            // KademliaEngine looks its own addresses up there - not from the Host - when it
            // answers a GET_PROVIDERS for a block it holds locally:
            //
            //     addressBook.getAddrs(PeerId.fromBase58(ourPeerId.toBase58())).join()
            //         .stream().filter(a -> isPublic(a)) ...
            //
            // jvm-libp2p's address book returns *null* (not an empty collection) for a peer it
            // has never heard of, and a plain `host { }`-built Host never records its own
            // addresses there - only Nabu's own unused HostBuilder installs a connection handler
            // that populates the address book. So without this line that `.stream()` call throws
            // NPE inside receiveRequest, the responder writes no reply at all, and the asking
            // node's GET_PROVIDERS just times out into an empty provider list. That is the
            // "cross-node DHT provider discovery does not work" defect documented since V0.1.4;
            // see docs/architecture.adoc and MultiNodeDhtProviderDiscoveryTest. setAddrs (not
            // addAddrs) so that attaching twice or re-registering never duplicates entries.
            host.addressBook.setAddrs(host.peerId, 0, *host.listenAddresses().toTypedArray()).join()

            return NabuStorage(host, blockstore, bitswap, bitswapEngine, kademlia, engine, limits, localDht, clock)
        }
    }
}
