package net.lapisphilosophorum.lapisnet.storage

import com.offbynull.kademlia.Id
import com.offbynull.kademlia.Node
import com.offbynull.kademlia.Router
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.multihash.Multihash
import io.libp2p.core.AddressBook
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import org.peergos.Hash
import org.peergos.PeerAddresses
import org.peergos.blockstore.Blockstore
import org.peergos.protocol.dht.KademliaEngine
import org.peergos.protocol.dht.pb.Dht
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * Nabu's [KademliaEngine] with the defects of its RESPONDER side and its routing table closed (V0.9.11, V0.9.16):
 *
 * 1. **Unvalidated key bytes** - `receiveRequest` deserializes request keys with allocate-before-
 *    check parsers; [InboundDhtRequestPolicy] rejects those requests first. Rejected and failed
 *    requests close the stream (a reset) instead of leaving it open, and an exception from the base
 *    class no longer escapes onto the Netty event loop.
 * 2. **`getKClosestPeers` NPE** - Nabu does `new ArrayList<>(addressBook.getAddrs(..).join())`, and
 *    jvm-libp2p's `MemoryAddressBook` returns `null` for an unknown peer. A routing-table entry without
 *    an address-book entry therefore broke every `FIND_NODE` / `GET_PROVIDERS` / `GET_VALUE` answer.
 *    This override skips such entries and caps each peer's address list.
 * 3. **Stream left open after `ADD_PROVIDER`** - the request has no reply, so nothing else would
 *    ever close the responder's end.
 *
 * 4. **Routing table** (V0.9.16) - Nabu builds `Router(id, 2, 2, 2)`: two peers per bucket (its own
 *    `BUCKET_SIZE = 20` is never used), so a third peer of a bucket was admitted but not routable
 *    (`find(.., includeStale = false)` skips the replacement cache). Its own ID is also not hashed the
 *    way every peer ID is, which skews the bucket tree, and `Router.touch` throws when the wall clock
 *    steps backwards, which would break every dial. This engine keeps its own [routingTable]
 *    (k = [DhtLimits.routingBucketSize], hashed own ID, monotonic touch time) and leaves Nabu's empty.
 *
 * Since V0.9.13 `PUT_VALUE` and `GET_VALUE` are not delegated to the base class at all: [IpnsValueResponder]
 * answers them, over [ipnsStore]. The base class gets an [EmptyRecordStore], so it could not store a
 * record even if a code path reached it.
 *
 * The provider store is injected as [BoundedProviderStore]; both are shared with [NabuStorage]'s
 * own (non-Nabu) lookup walk through [localProviders].
 */
internal class LapisKademliaEngine(
    ourPeerId: Multihash,
    private val providerStore: BoundedProviderStore,
    internal val ipnsStore: BoundedIpnsRecordStore,
    blocks: Blockstore,
    private val limits: DhtLimits,
    private val clock: () -> Instant = Instant::now,
) : KademliaEngine(ourPeerId, providerStore, EmptyRecordStore, blocks) {
    /** Answers `PUT_VALUE` / `GET_VALUE`; the base class never sees those two (see [receiveRequest]). */
    internal val ipnsResponder = IpnsValueResponder(ipnsStore, limits, { key, k -> getKClosestPeers(key, k) }, clock)

    @Volatile
    private var book: AddressBook? = null

    /** Guarded by this engine's monitor: [Router] is not thread-safe. */
    private val routingTable =
        Router(
            Id.create(Hash.sha256(ourPeerId.bareMultihash().toBytes()), 256),
            2,
            limits.routingBucketSize,
            limits.routingReplacementCacheSize,
        )

    /** The newest time handed to [Router.touch]; it throws on time going backwards. Guarded by this engine's monitor. */
    private var lastTouch: Instant = Instant.EPOCH

    private val rejected = AtomicLong()
    private val failed = AtomicLong()

    /** How many inbound requests [InboundDhtRequestPolicy] rejected before the base class saw them. */
    val rejectedInboundRequests: Long get() = rejected.get()

    /** How many inbound requests passed the policy but made the base class throw. */
    val failedInboundRequests: Long get() = failed.get()

    override fun setAddressBook(addrs: AddressBook) {
        super.setAddressBook(addrs)
        book = addrs
    }

    /**
     * Admits an authenticated peer into [routingTable] (the base class would use its own k=2 table).
     * Deliberately no `super` call. Never throws: a clock that stepped backwards is clamped.
     */
    @Synchronized
    override fun addOutgoingConnection(peerId: PeerId) {
        val now = clock().let { if (it.isBefore(lastTouch)) lastTouch else it }
        lastTouch = now
        try {
            routingTable.touch(now, Node(Id.create(Hash.sha256(peerId.bytes), 256), peerId.toString()))
        } catch (e: RuntimeException) {
            logger.debug { "routing table refused a peer: ${e.javaClass.simpleName}" }
        }
    }

    /** No-op, as in Nabu: only peers this node dialled and authenticated itself enter the routing table. */
    override fun addIncomingConnection(peerId: PeerId) {
    }

    /** Whether [peerId] is routable, that is in a bucket proper and not only in the replacement cache. */
    @Synchronized
    internal fun isRoutable(peerId: PeerId): Boolean =
        routingTable
            .find(Id.create(Hash.sha256(peerId.bytes), 256), 1, false)
            .firstOrNull()
            ?.link == peerId.toString()

    /** How many peers [getKClosestPeers] could return at most (tests). */
    @Synchronized
    internal fun routingTableSizeForTesting(): Int =
        routingTable.find(Id.create(ByteArray(32), 256), Int.MAX_VALUE, false).size

    override fun receiveRequest(
        msg: Dht.Message,
        source: PeerId,
        stream: Stream,
    ) {
        if (!InboundDhtRequestPolicy.isAcceptable(msg, limits)) {
            rejected.incrementAndGet()
            logger.debug { "rejected an inbound DHT request of type ${msg.type}" }
            stream.close()
            return
        }
        // A reply is written by the base class during receiveRequest; whether one was is learned by
        // watching the writes (PUT_VALUE, for one, answers with an echo only when its record is valid
        // and not older than the stored one).
        val replying = ReplyTrackingStream(stream)
        val handled =
            guarded(msg.type, stream) {
                when (msg.type) {
                    // Never the base class: its record handling cannot serve Ed25519 names (see IpnsValueResponder).
                    Dht.Message.MessageType.PUT_VALUE -> ipnsResponder.handlePut(msg, source, replying)
                    Dht.Message.MessageType.GET_VALUE -> ipnsResponder.handleGet(msg, replying)
                    else -> super.receiveRequest(msg, source, replying)
                }
            }
        if (!handled) return
        // Requests that get no reply must not leave the responder end open until the initiator
        // chooses to close: ADD_PROVIDER and PING never reply, and any other request stays silent when
        // it is invalid (PUT_VALUE: invalid or older than the stored record). Those streams are closed
        // (a reset). An ANSWERED request is only half-closed: Mplex turns close() into a RESET frame,
        // and a non-JVM initiator (go-mplex) can drop an unread reply when the reset overtakes it.
        // The initiator closes its own end after reading the reply; if it does not within
        // streamCloseGrace, the stream is reset after all. Leaving an answered FIND_NODE /
        // GET_PROVIDERS / GET_VALUE stream open instead would let an initiator that never closes keep
        // as many streams open as the muxer allows.
        when (msg.type) {
            Dht.Message.MessageType.ADD_PROVIDER,
            Dht.Message.MessageType.PING,
            -> stream.close()
            else -> if (replying.written) finishAfterReply(stream) else stream.close()
        }
    }

    /**
     * Runs [handle]; returns whether it completed. A failure closes [stream] (a reset) and is counted,
     * so it never reaches the Netty event loop. That includes an [Error] of the base class: Peergos'
     * `CborObject.deserialize` has no depth limit, so a validly signed IPNS record of a few KiB with
     * thousands of nested arrays may overflow the stack - a [StackOverflowError] is the request's
     * failure, not the process's. Other [VirtualMachineError]s (out of memory, internal error) are not
     * recoverable here and are rethrown.
     */
    internal fun guarded(
        type: Dht.Message.MessageType,
        stream: Stream,
        handle: () -> Unit,
    ): Boolean {
        try {
            handle()
            return true
        } catch (e: Throwable) {
            if (e is VirtualMachineError && e !is StackOverflowError) throw e
            failed.incrementAndGet()
            logger.debug { "inbound DHT request of type $type failed: ${e.javaClass.simpleName}" }
            stream.close()
            return false
        }
    }

    private fun finishAfterReply(stream: Stream) {
        stream.closeWrite()
        // copy(): orTimeout must not complete the stream's OWN close future exceptionally.
        stream
            .closeFuture()
            .copy()
            .orTimeout(limits.streamCloseGrace.toNanos(), TimeUnit.NANOSECONDS)
            .whenComplete { _, _ -> stream.close() }
    }

    override fun getKClosestPeers(
        key: ByteArray,
        k: Int,
    ): List<PeerAddresses> {
        val addressBook = book ?: return emptyList()
        val nodes =
            synchronized(this) {
                routingTable.find(Id.create(Hash.sha256(key), 256), k, false)
            }
        return nodes.mapNotNull { node ->
            val peerId = runCatching { PeerId.fromBase58(node.link) }.getOrNull() ?: return@mapNotNull null
            val known = addressBook.getAddrs(peerId).join() ?: return@mapNotNull null
            val addresses =
                known
                    .asSequence()
                    .filterNot { it.hasAny(Protocol.DNS, Protocol.DNS4, Protocol.DNS6, Protocol.DNSADDR) }
                    .distinctBy { it.toString() }
                    .take(limits.maxAddressesPerPeer)
                    .toList()
            if (addresses.isEmpty()) null else PeerAddresses(Multihash.fromBase58(node.link), addresses)
        }
    }

    /** As the base class, but entries whose address bytes cannot be parsed are skipped, not thrown on. */
    override fun getProviders(h: Multihash): Set<PeerAddresses> =
        localProviders(h.bareMultihash())
            .mapNotNull { peer ->
                runCatching {
                    val addrs =
                        peer.addrsList.mapNotNull {
                            runCatching {
                                Multiaddr.deserialize(
                                    it.toByteArray(),
                                )
                            }.getOrNull()
                        }
                    PeerAddresses(Multihash.deserialize(peer.id.toByteArray()), addrs)
                }.getOrNull()
            }.toSet()

    /** Provider records this node has stored itself (from `ADD_PROVIDER`), as a snapshot. */
    fun localProviders(bareKey: Multihash): List<Dht.Message.Peer> = providerStore.getProviders(bareKey).toList()
}

/** A [Stream] that remembers whether anything was written to it; everything else is passed straight through. */
internal class ReplyTrackingStream(
    private val delegate: Stream,
) : Stream by delegate {
    @Volatile
    var written: Boolean = false
        private set

    override fun writeAndFlush(msg: Any) {
        written = true
        delegate.writeAndFlush(msg)
    }
}
