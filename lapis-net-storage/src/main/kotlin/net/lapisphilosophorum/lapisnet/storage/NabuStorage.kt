package net.lapisphilosophorum.lapisnet.storage

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.ipfs.multiaddr.MultiAddress
import io.ipfs.multihash.Multihash
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.BlockRequestAuthoriser
import org.peergos.PeerAddresses
import org.peergos.Want
import org.peergos.blockstore.Blockstore
import org.peergos.blockstore.FileBlockstore
import org.peergos.protocol.bitswap.Bitswap
import org.peergos.protocol.bitswap.BitswapEngine
import org.peergos.protocol.dht.Kademlia
import org.peergos.protocol.dht.KademliaEngine
import org.peergos.protocol.dht.RamProviderStore
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

private val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(10)
private const val DEFAULT_PROVIDER_STORE_CAPACITY = 1024
private const val DEFAULT_RECORD_STORE_CAPACITY = 1024
private const val DEFAULT_DESIRED_PROVIDER_COUNT = 4

/**
 * How many of the closest-known peers a [NabuStorage.provide] call announces to. Matches the
 * fan-out Nabu's own `Kademlia.provideBlock` uses, and doubles as the bound that keeps a single
 * `provide` call from fanning out over an arbitrarily large routing table.
 */
private const val DHT_PROVIDE_FANOUT = 20

/** Per-peer cap inside [NabuStorage.provide], so one unresponsive peer can't eat the whole budget. */
private val PER_PEER_ANNOUNCE_TIMEOUT: Duration = Duration.ofSeconds(2)

/** Thrown when a storage or DHT operation fails or times out. */
class NabuStorageException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Allows every block read - no read-access control in this wave; see docs/architecture.adoc. */
private val allowAllReads =
    BlockRequestAuthoriser { _, _, _ -> CompletableFuture.completedFuture(true) }

/**
 * DHT (Kademlia) + Bitswap content storage, layered on an already-`start()`-ed [LapisNode]'s
 * libp2p [Host] (see [attach]). Domain-agnostic by design: [ByteArray]/[Cid] in and out - no
 * Veritas-specific structure lives here (that lands in a later wave, built on top of this).
 */
class NabuStorage private constructor(
    private val host: Host,
    private val blockstore: Blockstore,
    private val bitswap: Bitswap,
    private val kademlia: Kademlia,
) {
    private val stopped = AtomicBoolean(false)

    /** Stores [bytes] in the local blockstore (no network) and returns its [Cid]. */
    fun put(
        bytes: ByteArray,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Cid {
        val cid = awaitOrWrap("put block", timeout) { blockstore.put(bytes, Cid.Codec.Raw) }
        logger.info { "stored block $cid (${bytes.size} bytes)" }
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
     * Bitswap if given, otherwise looks up providers via the DHT ([findProviders]) first and
     * fetches from whatever it finds. A DHT lookup or Bitswap fetch that fails or times out is
     * treated as "not found" (returns `null`) rather than propagating [NabuStorageException] -
     * an unreachable/non-responding peer is exactly the "can't be found anywhere reachable"
     * case this method documents, not a distinct error condition callers need to handle
     * separately. A failure checking the *local* blockstore still throws, since that signals a
     * real local fault (e.g. disk I/O), not a not-found result.
     */
    fun get(
        cid: Cid,
        peers: Set<PeerId> = emptySet(),
        timeout: Duration = DEFAULT_TIMEOUT,
    ): ByteArray? {
        val local = awaitOrWrap("check local blockstore", timeout) { blockstore.get(cid) }
        if (local.isPresent) return local.get()

        return try {
            val targetPeers =
                peers.ifEmpty {
                    // findProvidersRaw's addresses must be registered in the AddressBook before
                    // Bitswap can dial a peer it only just learned about via the DHT - Bitswap's
                    // dialPeer() looks addresses up from the AddressBook, it doesn't accept them
                    // directly (see the wiring note in attach()'s doc comment).
                    val discovered = findProvidersRaw(cid, timeout = timeout)
                    discovered.forEach { peer ->
                        host.addressBook.addAddrs(PeerId(peer.peerId.toBytes()), 0, *peer.addresses.toTypedArray())
                    }
                    discovered.map { PeerId(it.peerId.toBytes()) }.toSet()
                }
            if (targetPeers.isEmpty()) return null

            val fetched =
                awaitOrWrap("fetch block via bitswap", timeout) {
                    bitswap.get(Want(cid), host, targetPeers, true)
                }
            fetched.block
        } catch (e: NabuStorageException) {
            logger.debug(e) { "get($cid) could not reach any peer within the timeout - treating as not found" }
            null
        }
    }

    /**
     * Announces to the DHT that this node has [cid] available for retrieval: sends an
     * `ADD_PROVIDER` RPC naming this node to each of the [DHT_PROVIDE_FANOUT] peers closest to
     * [cid] in the Kademlia keyspace, as found by walking this node's routing table. A later
     * [findProviders] call for [cid] by any node that can reach one of those peers then resolves
     * back to this node. Peers that can't be dialled, or that time out, are skipped - the
     * announcement is best-effort by nature (that is what a DHT publish is), so this only throws
     * if the routing-table walk itself fails.
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
     * every time. This method therefore does the dial-then-announce itself, off the event loop,
     * using only Nabu's public API (no fork, no vendoring). See docs/architecture.adoc.
     */
    fun provide(
        cid: Cid,
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        val us = PeerAddresses.fromHost(host)
        val closest =
            try {
                kademlia.findClosestPeers(cid, DHT_PROVIDE_FANOUT, host)
            } catch (e: Exception) {
                throw NabuStorageException("failed to find DHT peers to announce $cid to", e)
            }
        val deadline = System.nanoTime() + timeout.toNanos()
        var announced = 0
        for (peer in closest) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0) {
                logger.debug { "ran out of time announcing $cid after $announced of ${closest.size} peers" }
                break
            }
            if (announceTo(cid, peer, us, remaining)) announced++
        }
        logger.info { "announced $cid to $announced of ${closest.size} DHT peers" }
    }

    /**
     * Sends one `ADD_PROVIDER` for [cid] to [peer], synchronously on the calling thread (see
     * [provide]'s doc comment for why this must not run on a Netty event-loop thread). Returns
     * `false` - rather than throwing - for every per-peer failure: an unparseable address, an
     * unreachable peer or a timeout is an ordinary outcome of a best-effort DHT publish, not a
     * fault of this node.
     */
    private fun announceTo(
        cid: Cid,
        peer: PeerAddresses,
        us: PeerAddresses,
        remainingNanos: Long,
    ): Boolean {
        // Tolerate addresses this node can't parse or dial rather than failing the whole
        // announcement: `peer` came out of the routing table, i.e. ultimately from a remote
        // peer's FIND_NODE response, so its address list is untrusted input. DNS-form addresses
        // are dropped for the same reason Nabu's own dialPeer drops them - this transport stack
        // does not resolve them.
        val addresses =
            peer.addresses
                .mapNotNull { runCatching { Multiaddr.fromString(it.toString()) }.getOrNull() }
                .filterNot { it.has(Protocol.DNS) || it.has(Protocol.DNS4) || it.has(Protocol.DNS6) }
        if (addresses.isEmpty()) return false
        val peerId = runCatching { PeerId.fromBase58(peer.peerId.toBase58()) }.getOrNull() ?: return false
        val perPeerNanos = minOf(remainingNanos, PER_PEER_ANNOUNCE_TIMEOUT.toNanos())
        return try {
            val controller =
                kademlia
                    .dial(host, peerId, *addresses.toTypedArray())
                    .controller
                    .get(perPeerNanos, TimeUnit.NANOSECONDS)
            controller.provide(cid, us).get(perPeerNanos, TimeUnit.NANOSECONDS)
            true
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (e: Exception) {
            logger.debug(e) { "could not announce $cid to ${peer.peerId} - skipping this peer" }
            false
        }
    }

    /**
     * Looks up which known peers have announced [cid] via [provide], by walking this node's
     * Kademlia routing table and issuing `GET_PROVIDERS` RPCs. Also resolves peers that never
     * called [provide] but simply hold [cid] in their local blockstore - Nabu's responder side
     * adds itself to any `GET_PROVIDERS` reply for a block it already has.
     *
     * Returns only peer IDs. A caller that needs dialable addresses too (i.e. [get]) uses the
     * private raw form, which keeps the [PeerAddresses] and registers them in the address book.
     * Note that on a loopback-only deployment those addresses can come back empty for the
     * "responder holds the block itself" case: `KademliaEngine`'s `GET_PROVIDERS` handler filters
     * its own advertised addresses to publicly-routable ones, which loopback addresses are not.
     * Provider entries that arrived through a real [provide]/`ADD_PROVIDER` are not filtered and
     * do carry their addresses.
     */
    fun findProviders(
        cid: Cid,
        desiredCount: Int = DEFAULT_DESIRED_PROVIDER_COUNT,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Set<PeerId> = findProvidersRaw(cid, desiredCount, timeout).map { PeerId(it.peerId.toBytes()) }.toSet()

    private fun findProvidersRaw(
        cid: Cid,
        desiredCount: Int = DEFAULT_DESIRED_PROVIDER_COUNT,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): List<PeerAddresses> =
        awaitOrWrap("find DHT providers", timeout) { kademlia.findProviders(cid, host, desiredCount) }

    /**
     * Registers [address] (must include a `/p2p/<peerId>` component, e.g. via
     * [Multiaddr.withP2P]) as a peer's dialable address, so a later [get] call can pass that
     * peer explicitly and have Bitswap actually reach it. Bitswap's wire protocol resolves peer
     * addresses from the libp2p [Host]'s address book rather than accepting them inline, and
     * this project's plain `host { }` DSL (see [LapisNode.create]) has no automatic
     * identify-based address-book population on connect, unlike Nabu's own (unused)
     * `org.peergos.HostBuilder`. Not needed when a peer's address is already known some other
     * way (e.g. via [connectToDhtPeer] or DHT-driven discovery inside [get]).
     */
    fun registerPeerAddress(
        address: Multiaddr,
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        val peerId =
            address.getPeerId()
                ?: throw NabuStorageException("address is missing a /p2p/<peerId> component: $address")
        awaitOrWrap("register peer address", timeout) { host.addressBook.addAddrs(peerId, 0, address) }
    }

    /**
     * Explicitly connects this node's DHT routing table to the peer listening at [address]
     * (must include a `/p2p/<peerId>` component, e.g. via [Multiaddr.withP2P]). A deterministic,
     * loopback-friendly alternative to [Kademlia.startBootstrapThread]'s real-network-oriented
     * periodic bootstrap - mirrors [LapisNode.connect]'s "explicit local peer" pattern. Returns
     * `true` if the peer was reachable and added.
     */
    fun connectToDhtPeer(address: Multiaddr): Boolean {
        val connected =
            kademlia.bootstrapRoutingTable(
                host,
                listOf(MultiAddress(address.toString())),
                MATCH_ANY_PROTOCOL,
            )
        return connected > 0
    }

    /**
     * No independent sub-resources to release beyond [host], which [LapisNode] owns and stops
     * on its own - this exists for lifecycle symmetry and forward compatibility with a future
     * wave that starts [Kademlia.startBootstrapThread]. Idempotent: a second call is a no-op.
     */
    fun stop() {
        stopped.compareAndSet(false, true)
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
        private val MATCH_ANY_PROTOCOL: (String) -> Boolean = { true }

        /**
         * Attaches Nabu's Bitswap + Kademlia DHT protocols to [node]'s already-`start()`-ed
         * libp2p [Host], storing blocks under [blockstoreDir]. Must be called after
         * [LapisNode.start], and at most once per [node] - calling it twice on the same node
         * would register duplicate protocol/connection handlers on the shared [Host]. [localDht]
         * selects Kademlia's LAN vs WAN protocol ID - this project has no real WAN bootstrap
         * infrastructure yet ([LapisNode]'s bootstrap peers are non-functional
         * documentation-range placeholders), so it defaults to `true`.
         */
        fun attach(
            node: LapisNode,
            blockstoreDir: Path,
            localDht: Boolean = true,
        ): NabuStorage {
            val host = node.host
            val blockstore = FileBlockstore(blockstoreDir)

            val bitswapEngine = BitswapEngine(blockstore, allowAllReads, Bitswap.MAX_MESSAGE_SIZE, false)
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
            val kademliaEngine =
                KademliaEngine(
                    ourPeerId,
                    RamProviderStore(DEFAULT_PROVIDER_STORE_CAPACITY),
                    BoundedRecordStore(DEFAULT_RECORD_STORE_CAPACITY),
                    blockstore,
                )
            val kademlia = Kademlia(kademliaEngine, localDht)
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
            // see docs/architecture.adoc and MultiNodeDhtProviderDiscoveryTest.
            host.addressBook.addAddrs(host.peerId, 0, *host.listenAddresses().toTypedArray()).join()

            return NabuStorage(host, blockstore, bitswap, kademlia)
        }
    }
}
