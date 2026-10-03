package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.multihash.Multihash
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.StreamPromise
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import org.peergos.PeerAddresses
import org.peergos.protocol.dht.Kademlia
import org.peergos.protocol.dht.KademliaController
import org.peergos.protocol.dht.pb.Dht
import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

private val logger = KotlinLogging.logger {}

/**
 * This project's own, bounded Kademlia lookup and announce - written instead of calling Nabu's
 * `Kademlia.findClosestPeers` / `findProviders` / `provideBlock`, which have no overall deadline
 * (they `join()` dials and futures without a timeout), run on a fixed 16-thread NON-daemon pool
 * (`ioExec`) that wedges for good once enough calls hang, parse responses with throwing,
 * allocate-before-check parsers, leave every stream they open unclosed, and dial every address a
 * response names.
 *
 * Design rules, each the answer to one of those problems:
 * - **One deadline, passed down.** Every method takes an absolute `System.nanoTime()` deadline and
 *   never blocks past it; each exchange is additionally capped by [DhtLimits.perRpcTimeout].
 * - **No shared mutable walk state.** Exchanges run concurrently, but their results are collected
 *   only on the calling thread, after [CompletableFuture]s that cannot fail (`handle`), so no
 *   callback mutates anything.
 * - **Never on the event loop.** Every continuation that writes to a stream uses
 *   `thenComposeAsync(.., rpcExecutor)`: a plain `thenCompose` would run the write inside the
 *   Netty callback that completed the controller future, where it is silently dropped (the V0.9.8
 *   defect, see [NabuStorage.provide]).
 * - **Streams are always closed**, on success, failure and timeout, including ones that only finish
 *   opening after the exchange gave up.
 * - **Responses are untrusted:** IDs are length- and multihash-checked before anything parses them,
 *   counts are capped, addresses go through [PeerAddressSanitizer].
 *
 * Interruption: the blocking waits throw [InterruptedException] to the caller, which owns the
 * decision what to do with it. [stopSignal] ends every wait early.
 */
internal class DhtWalker(
    private val host: Host,
    private val kademlia: Kademlia,
    private val engine: LapisKademliaEngine,
    private val limits: DhtLimits,
    private val localDht: Boolean,
    private val rpcExecutor: Executor,
    private val stopSignal: CompletableFuture<Unit>,
    private val learnAddresses: (PeerId, List<Multiaddr>) -> Unit,
) {
    data class WalkPeer(
        val peerId: PeerId,
        val addresses: List<Multiaddr>,
    )

    data class ClosestResult(
        val peers: List<WalkPeer>,
        val queried: Int,
        val responded: Int,
    )

    private enum class State { PENDING, RESPONDED, FAILED }

    private class Candidate(
        val peer: WalkPeer,
        val distance: BigInteger,
        var state: State = State.PENDING,
    )

    private class WalkOutcome(
        val candidates: List<Candidate>,
        val queried: Int,
        val responded: Int,
    )

    private val canDial: (Multiaddr) -> Boolean = { addr -> host.network.transports.any { it.handles(addr) } }

    /**
     * The up to [count] peers closest to [key] that this node could find before [deadlineNanos].
     * Peers that failed or timed out are NOT in the result, so a silent peer does not consume a slot
     * of a later announcement; peers that were never queried (lookup ended first) are.
     */
    fun closestPeers(
        key: ByteArray,
        count: Int,
        deadlineNanos: Long,
    ): ClosestResult {
        val outcome =
            walk(key, Dht.Message.MessageType.FIND_NODE, count, deadlineNanos, onReply = {}, satisfied = { false })
        val peers =
            outcome.candidates
                .filter { it.state != State.FAILED }
                .take(count)
                .map { it.peer }
        return ClosestResult(peers, outcome.queried, outcome.responded)
    }

    /**
     * Providers of [bareKey]: first this node's own provider store, then a `GET_PROVIDERS` walk,
     * ending as soon as `min(desired, maxProvidersPerKey)` distinct providers are known. Provider
     * entries with an EMPTY address list are kept on purpose: a responder that holds the block
     * itself names itself without addresses when it only listens on loopback (Nabu filters its own
     * addresses to public ones), and the caller may already know how to reach it.
     */
    fun findProviders(
        bareKey: Multihash,
        desired: Int,
        deadlineNanos: Long,
    ): List<WalkPeer> {
        val wanted = minOf(desired, limits.maxProvidersPerKey).coerceAtLeast(1)
        val found = LinkedHashMap<PeerId, WalkPeer>()

        fun collect(peers: List<WalkPeer>) {
            for (peer in peers) if (found.size < wanted) found.putIfAbsent(peer.peerId, peer)
        }
        collect(engine.localProviders(bareKey).mapNotNull { parsePeer(it) })
        if (found.size >= wanted) return found.values.toList()
        walk(
            bareKey.toBytes(),
            Dht.Message.MessageType.GET_PROVIDERS,
            limits.provideFanout,
            deadlineNanos,
            onReply = { reply -> collect(parsePeerList(reply.providerPeersList)) },
            satisfied = { found.size >= wanted },
        )
        return found.values.toList()
    }

    /**
     * Sends one `ADD_PROVIDER` for [key] naming [us] to each of [targets], at most
     * [DhtLimits.walkParallelism] at a time. Returns how many were SENT - the protocol has no
     * acknowledgement, so this is not "delivered".
     */
    fun announce(
        key: Multihash,
        targets: List<WalkPeer>,
        us: PeerAddresses,
        deadlineNanos: Long,
    ): Int {
        val ourAddresses =
            PeerAddressSanitizer.sanitize(host.peerId, us.addresses.asSequence(), limits, localDht = true) { true }
        val message =
            Dht.Message
                .newBuilder()
                .setType(Dht.Message.MessageType.ADD_PROVIDER)
                .setKey(ByteString.copyFrom(key.bareMultihash().toBytes()))
                .addProviderPeers(
                    Dht.Message.Peer
                        .newBuilder()
                        .setId(ByteString.copyFrom(host.peerId.bytes))
                        .addAllAddrs(ourAddresses.map { ByteString.copyFrom(it.serialize()) })
                        .build(),
                ).build()
        var sent = 0
        for (chunk in targets.chunked(limits.walkParallelism)) {
            if (stopSignal.isDone || System.nanoTime() >= deadlineNanos) break
            val futures = chunk.map { send(it, message, deadlineNanos).handle { ok, t -> t == null && ok == true } }
            await(futures, deadlineNanos)
            sent += futures.count { it.isDone && it.getNow(false) }
        }
        return sent
    }

    private fun walk(
        key: ByteArray,
        type: Dht.Message.MessageType,
        count: Int,
        deadlineNanos: Long,
        onReply: (Dht.Message) -> Unit,
        satisfied: () -> Boolean,
    ): WalkOutcome {
        val alpha = limits.walkParallelism
        val seen = HashSet<PeerId>().apply { add(host.peerId) }
        val candidates = ArrayList<Candidate>()

        fun add(peer: WalkPeer) {
            if (seen.add(peer.peerId)) candidates += Candidate(peer, keyDistance(key, peer.peerId.bytes))
        }
        for (local in engine.getKClosestPeers(key, maxOf(count, alpha))) {
            val id = runCatching { PeerId(local.peerId.toBytes()) }.getOrNull() ?: continue
            add(WalkPeer(id, local.addresses))
        }

        val request =
            Dht.Message
                .newBuilder()
                .setType(type)
                .setKey(ByteString.copyFrom(key))
                .build()
        var queried = 0
        var responded = 0
        var round = 0
        while (round < limits.maxWalkRounds &&
            !satisfied() &&
            !stopSignal.isDone &&
            System.nanoTime() < deadlineNanos
        ) {
            round++
            candidates.sortBy { it.distance }
            // Bounded candidate set: whatever is further away than 2 x count can no longer matter.
            while (candidates.size > 2 * count) candidates.removeAt(candidates.size - 1)
            val batch =
                candidates
                    .asSequence()
                    .filter { it.state != State.FAILED }
                    .take(count)
                    .filter { it.state == State.PENDING }
                    .take(alpha)
                    .toList()
            if (batch.isEmpty()) break
            val futures =
                batch.map {
                    rpc(it.peer, request, deadlineNanos).handle { reply, t ->
                        if (t ==
                            null
                        ) {
                            reply
                        } else {
                            null
                        }
                    }
                }
            await(futures, deadlineNanos)
            queried += batch.size
            // Collected here, on the calling thread only.
            for ((candidate, future) in batch.zip(futures)) {
                val reply = if (future.isDone) future.getNow(null) else null
                if (reply == null) {
                    candidate.state = State.FAILED
                    continue
                }
                candidate.state = State.RESPONDED
                responded++
                learnAddresses(candidate.peer.peerId, verifiedAddresses(candidate.peer))
                onReply(reply)
                parsePeerList(reply.closerPeersList).forEach { add(it) }
            }
        }
        candidates.sortBy { it.distance }
        return WalkOutcome(candidates, queried, responded)
    }

    /**
     * The part of [peer]'s claimed addresses that is PROVEN to belong to it: the address of our own
     * outgoing connection to it, if that is one of the claimed ones. The claim itself came from a third
     * party (a `closerPeers` entry of another responder), and [dialOrNull] reuses an existing connection
     * without looking at the claimed addresses at all - so the claim alone says nothing about [peer].
     * Nothing else is passed on to the address book.
     */
    private fun verifiedAddresses(peer: WalkPeer): List<Multiaddr> {
        val connection =
            host.network.connections.firstOrNull { it.isInitiator && it.secureSession().remoteId == peer.peerId }
                ?: return emptyList()
        val remote = runCatching { connection.remoteAddress().withP2P(peer.peerId).toString() }.getOrNull()
        return peer.addresses.filter { it.toString() == remote }
    }

    /** One dial plus request-response exchange; the stream is closed whatever the outcome. */
    private fun rpc(
        peer: WalkPeer,
        message: Dht.Message,
        deadlineNanos: Long,
    ): CompletableFuture<Dht.Message> {
        val timeoutNanos =
            exchangeTimeout(deadlineNanos)
                ?: return CompletableFuture.failedFuture(TimeoutException("DHT deadline reached"))
        val promise =
            dialOrNull(peer) ?: return CompletableFuture.failedFuture(IllegalStateException("no known address"))
        val result =
            promise.controller
                .thenComposeAsync({ controller -> controller.rpc(message) }, rpcExecutor)
                .orTimeout(timeoutNanos, TimeUnit.NANOSECONDS)
        result.whenComplete { _, _ -> promise.stream.thenAccept { it.close() } }
        return result
    }

    /** One dial plus fire-and-forget write; the stream is closed whatever the outcome. */
    private fun send(
        peer: WalkPeer,
        message: Dht.Message,
        deadlineNanos: Long,
    ): CompletableFuture<Boolean> {
        val timeoutNanos =
            exchangeTimeout(deadlineNanos)
                ?: return CompletableFuture.failedFuture(TimeoutException("DHT deadline reached"))
        val promise =
            dialOrNull(peer) ?: return CompletableFuture.failedFuture(IllegalStateException("no known address"))
        val result =
            promise.controller
                .thenComposeAsync({ controller -> controller.send(message) }, rpcExecutor)
                .orTimeout(timeoutNanos, TimeUnit.NANOSECONDS)
        result.whenComplete { ok, t -> promise.stream.thenAccept { finishSendStream(it, t == null && ok == true) } }
        return result
    }

    /**
     * `closeWrite` is a FIN (the written message is still delivered), `close` is a reset (it may
     * drop unflushed data) - so a delivered write is closed gracefully and only reset if the
     * responder does not close its end within [DhtLimits.streamCloseGrace].
     */
    private fun finishSendStream(
        stream: Stream,
        sent: Boolean,
    ) {
        if (!sent) {
            stream.close()
            return
        }
        stream.closeWrite()
        // copy(): orTimeout must not complete the stream's OWN close future exceptionally.
        stream
            .closeFuture()
            .copy()
            .orTimeout(limits.streamCloseGrace.toNanos(), TimeUnit.NANOSECONDS)
            .whenComplete { _, _ -> stream.close() }
    }

    private fun exchangeTimeout(deadlineNanos: Long): Long? {
        val remaining = deadlineNanos - System.nanoTime()
        return if (remaining <= 0) null else minOf(limits.perRpcTimeout.toNanos(), remaining)
    }

    private fun dialOrNull(peer: WalkPeer): StreamPromise<out KademliaController>? {
        val connected = host.network.connections.any { it.secureSession().remoteId == peer.peerId }
        val addresses = if (connected) peer.addresses else peer.addresses.ifEmpty { knownAddresses(peer.peerId) }
        if (!connected && addresses.isEmpty()) return null
        return try {
            kademlia.dial(host, peer.peerId, *addresses.toTypedArray())
        } catch (e: Exception) {
            logger.debug { "dial setup failed: ${e.javaClass.simpleName}" }
            null
        }
    }

    /** Addresses this node already has on file for [peerId] (explicit or earlier learned, both capped). */
    private fun knownAddresses(peerId: PeerId): List<Multiaddr> {
        val known = host.addressBook.getAddrs(peerId).join() ?: return emptyList()
        return PeerAddressSanitizer.sanitize(peerId, known.asSequence(), limits, localDht, canDial)
    }

    private fun parsePeerList(peers: List<Dht.Message.Peer>): List<WalkPeer> {
        val out = ArrayList<WalkPeer>()
        val ids = HashSet<PeerId>()
        for (peer in peers.asSequence().take(limits.maxCloserPeersPerResponse)) {
            val parsed = parsePeer(peer) ?: continue
            if (ids.add(parsed.peerId)) out += parsed
        }
        return out
    }

    /**
     * Never uses Nabu's `PeerAddresses.fromProtobuf` / `Providers.fromProtobuf`: they call
     * `Multihash.deserialize` on the unchecked ID bytes.
     */
    private fun parsePeer(peer: Dht.Message.Peer): WalkPeer? {
        if (peer.id.size() < MIN_PEER_ID_BYTES || peer.id.size() > MAX_PEER_ID_BYTES) return null
        val idBytes = peer.id.toByteArray()
        if (!CidBytesValidation.isSafeToDeserializeMultihash(idBytes)) return null
        val id = runCatching { PeerId(idBytes) }.getOrNull() ?: return null
        if (id == host.peerId) return null
        return WalkPeer(id, PeerAddressSanitizer.fromRaw(id, peer.addrsList, limits, localDht, canDial))
    }

    /** Blocks until all [futures] are done, [stopSignal] fires, or [deadlineNanos] passes. */
    private fun await(
        futures: List<CompletableFuture<*>>,
        deadlineNanos: Long,
    ) {
        val remaining = deadlineNanos - System.nanoTime()
        if (remaining <= 0 || futures.isEmpty()) return
        try {
            CompletableFuture
                .anyOf(CompletableFuture.allOf(*futures.toTypedArray()), stopSignal)
                .get(remaining, TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            // the deadline - whatever finished has finished
        } catch (_: ExecutionException) {
            // cannot happen: every future passed here is a non-failing `handle` future
        }
    }

    private companion object {
        // io.libp2p.core.PeerId accepts 32..50 bytes
        const val MIN_PEER_ID_BYTES = 32
        const val MAX_PEER_ID_BYTES = 50
    }
}
