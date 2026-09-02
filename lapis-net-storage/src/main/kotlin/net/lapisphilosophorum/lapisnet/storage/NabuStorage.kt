package net.lapisphilosophorum.lapisnet.storage

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.ipfs.multiaddr.MultiAddress
import io.ipfs.multihash.Multihash
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
     * local miss - broken since V0.1.4 (see [provide]'s doc comment) - and `get(cid, peers =
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
     * Announces to the DHT that this node has [cid] available for retrieval.
     *
     * **Known limitation (as of V0.1.4, Nabu v0.8.0):** cross-node provider announcement and
     * discovery via [provide]/[findProviders] has not been verified working end-to-end in this
     * project. A diagnostic spike isolated a GET_PROVIDERS RPC round trip (`Kademlia.dialPeer`
     * → `KademliaController.getProviders`) returning empty even via Nabu's own
     * always-succeeds-if-the-block-is-local auto-provide path in
     * `KademliaEngine.receiveRequest`'s `GET_PROVIDERS` case - i.e. this reproduces without any
     * involvement of [provide]/`ADD_PROVIDER` at all, so the issue is in the RPC/dial mechanism
     * shared by both message types, not specific to provider announcement. See
     * docs/architecture.adoc for the full investigation. What *is* verified working: local
     * put/get ([NabuStorageLocalRoundTripTest]), Bitswap fetch given an explicit peer
     * ([TwoNodeBitswapDirectFetchTest]), and DHT routing-table population via
     * [connectToDhtPeer] ([MultiNodeDhtProviderDiscoveryTest]). Do not rely on this method for
     * discovery-driven [get] calls until this is root-caused.
     */
    fun provide(
        cid: Cid,
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        awaitOrWrap("provide block to DHT", timeout) {
            kademlia.provideBlock(cid, host, PeerAddresses.fromHost(host))
        }
        logger.info { "announced $cid to the DHT" }
    }

    /**
     * Looks up which known peers have announced [cid] via [provide]. See [provide]'s doc comment
     * for a known limitation: this has not been verified to actually find remote providers
     * end-to-end as of V0.1.4.
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
            host.addConnectionHandler(bitswap)

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

            return NabuStorage(host, blockstore, bitswap, kademlia)
        }
    }
}
