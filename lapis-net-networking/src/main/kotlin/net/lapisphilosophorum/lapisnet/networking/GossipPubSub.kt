package net.lapisphilosophorum.lapisnet.networking

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.MessageApi
import io.libp2p.core.pubsub.PubsubPublisherApi
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.Topic
import io.libp2p.core.pubsub.ValidationResult
import io.libp2p.pubsub.NoPeersForOutboundMessageException
import io.libp2p.pubsub.gossip.Gossip
import io.libp2p.pubsub.gossip.GossipParams
import io.libp2p.pubsub.gossip.builders.GossipParamsBuilder
import io.libp2p.pubsub.gossip.builders.GossipRouterBuilder
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong
import java.util.function.Function

private val logger = KotlinLogging.logger {}

private val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(10)

/**
 * Explicit `maxGossipMessageSize` cap (256 KiB), passed to [GossipParamsBuilder] rather than
 * relying on any implicit default. `GossipRouterBuilder()`'s own no-arg-constructed
 * [io.libp2p.pubsub.gossip.GossipParams] is an unset sentinel (all-zero/null fields) - only
 * [GossipParamsBuilder.build] actually fills in real gossipsub defaults
 * (`calculateMissing()`/`checkRequiredFields()`), so [attach] always builds params explicitly
 * through it rather than trusting whatever [GossipRouterBuilder]'s own default `params` happens
 * to be.
 */
private const val MAX_GOSSIP_MESSAGE_SIZE = 262_144

/**
 * Cap on how many distinct "publish" entries a single incoming GossipSub RPC frame may carry
 * (`GossipParams.maxPublishedMessages`, wired through `PubsubRpcLimits`). Round-2 security-audit
 * finding: `GossipParamsBuilder`'s real default for this field is `null`
 * (confirmed by decompiling `GossipParams`/`GossipParamsBuilder` against the real jar), and
 * `PubsubRpcLimits` treats `null` as "no limit" - meaning, without this, a single peer could pack
 * thousands of near-minimum-size messages into one frame, each forcing this project's own
 * decode+verify work (structural decode, then a secp256k1 signature check per
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGrant]), with no per-frame cap at all.
 *
 * 48 is chosen deliberately small, not derived from any protocol requirement: this project's own
 * traffic pattern never legitimately needs to batch many distinct messages into one frame - a
 * single [VeritasGossip][net.lapisphilosophorum.lapisnet.trust.VeritasGossip.announce] call
 * publishes exactly one grant, and GossipSub's own normal relay behavior (forwarding a message it
 * just received to its mesh peers) is also naturally one-message-at-a-time in the common case. 48
 * leaves comfortable headroom for legitimate incidental coalescing (e.g. several independent
 * publishes racing into the same outbound frame under load) without letting a malicious frame
 * force thousands of decode+verify calls in one shot.
 */
private const val MAX_PUBLISHED_MESSAGES_PER_RPC = 48

/**
 * Cap on how many `SUBSCRIBE`/`UNSUBSCRIBE` entries a single incoming RPC frame may carry
 * (`GossipParams.maxSubscriptions`) - same "real default is `null`, i.e. unbounded" finding as
 * [MAX_PUBLISHED_MESSAGES_PER_RPC], for a different RPC-shape dimension. This project's own topic
 * surface is small and fixed at any given time (a handful of well-known topic strings, e.g.
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC]), so a
 * legitimate peer never needs to (un)subscribe from more than a few dozen topics in one frame. 64
 * is generous headroom above that for future topics this project hasn't defined yet, while still
 * bounding the per-frame subscription-processing work to a small constant.
 *
 * `maxIWantMessageIds`, `maxGraftMessages`, and `maxPruneMessages` are deliberately left at their
 * library default (`null`/unbounded) here rather than guessed at: unlike the two fields above,
 * sane bounds for those genuinely depend on this project's mesh-degree (`D`/`DHigh`/`DLow`) and
 * heartbeat-interval tuning, which [attach] does not currently customize (it only sets
 * [MAX_GOSSIP_MESSAGE_SIZE] and the two fields above) - picking a number without that tuning risks
 * rejecting legitimate GRAFT/PRUNE/IWANT churn during normal mesh maintenance. Deferred to a future
 * wave that also tunes `D`/`DHigh`/`DLow`/`heartbeatInterval` together, rather than guessed at in
 * isolation now.
 */
private const val MAX_SUBSCRIPTIONS_PER_RPC = 64

/** Thrown when a GossipSub attach/publish/subscribe operation fails or times out. */
class GossipPubSubException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Domain-agnostic GossipSub pub/sub primitive, layered on an already-`start()`-ed [LapisNode]'s
 * libp2p [io.libp2p.core.Host] (see [attach]) - mirrors `lapis-net-storage`'s `NabuStorage`
 * attach-to-an-existing-`Host` pattern exactly. Deliberately domain-agnostic: raw topic strings
 * and [ByteArray] in/out, no Veritas-specific structure lives here - that lands in
 * `lapis-net-trust`'s `VeritasGossip` (V0.1.7), built on top of this.
 *
 * Unlike `NabuStorage`'s `Bitswap`/`Kademlia` wiring, [io.libp2p.pubsub.gossip.Gossip] does
 * **not** implement `AddressBookConsumer` - no `setAddressBook` call is needed or made here.
 * GossipSub only propagates over connections the [io.libp2p.core.Host] already has; it never
 * dials peers on its own.
 */
class GossipPubSub private constructor(
    private val gossip: Gossip,
    private val publisher: PubsubPublisherApi,
) {
    /**
     * Subscribes to [topic]. [handler] runs once per received message and its returned
     * [ValidationResult] directly gates re-propagation to the rest of the GossipSub mesh -
     * GossipSub has no separate "accept" step distinct from validation, so [handler] must decide
     * both "is this valid" and "should it keep spreading" in one return value.
     *
     * **Does not see this node's own [publish] calls.** GossipSub's local publish path marks the
     * message seen and broadcasts straight to the wire - it never runs the local subscription's
     * validator/delivery pipeline (verified by decompiling `AbstractRouter.publish()`'s lambda
     * against the real jar). A caller that wants to observe its own published messages must do so
     * as an explicit side effect of the code that calls [publish], not by relying on this
     * subscription to see them.
     */
    fun subscribe(
        topic: String,
        handler: (bytes: ByteArray, from: PeerId) -> ValidationResult,
    ): PubsubSubscription {
        val validator =
            Function<MessageApi, CompletableFuture<ValidationResult>> { message ->
                // ByteBufUtil.getBytes is a non-destructive full-readable-bytes copy - unlike a
                // manual readBytes() call, it does not mutate the shared ByteBuf's reader index.
                val bytes = ByteBufUtil.getBytes(message.data)
                // MessageApi.getFrom() is typed nullable in Kotlin (unlike the raw byte[] javap
                // shows) - GossipSub always populates it for a message that reached a validator
                // at all, so a null here would indicate a deeper protocol-level inconsistency,
                // not a routine "no sender" case worth silently tolerating.
                val from = PeerId(checkNotNull(message.from) { "gossip message has no from peer id" })
                CompletableFuture.completedFuture(handler(bytes, from))
            }
        return gossip.subscribe(validator, Topic(topic))
    }

    /**
     * Publishes [bytes] on [topic]. No delivery guarantee - GossipSub propagation is best-effort.
     * See [subscribe]'s doc comment: this node's own [subscribe] handlers never see this call's
     * message.
     *
     * **Silently no-ops if the mesh has no peers for [topic] yet**, rather than throwing -
     * observed in practice immediately after [io.libp2p.core.Host.network].connect() (e.g. a
     * fresh direct dial in a test, or a newly bootstrapped peer): GossipSub's own router throws
     * `NoPeersForOutboundMessageException` synchronously (via a failed future) when it has no
     * mesh/fanout peer to send to at all. That is just an especially immediate case of "no
     * delivery guarantee" - the message never had anywhere to go - so it is logged and swallowed
     * here rather than forcing every caller ([VeritasGossip.announce] included) to separately
     * special-case it. Any other publish failure still throws [GossipPubSubException].
     */
    fun publish(
        topic: String,
        bytes: ByteArray,
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        try {
            awaitOrWrap("publish to gossip topic $topic", timeout) {
                publisher.publish(Unpooled.wrappedBuffer(bytes), Topic(topic))
            }
        } catch (e: GossipPubSubException) {
            if (e.cause is NoPeersForOutboundMessageException) {
                logger.debug { "publish to $topic had no mesh peers yet - not delivered (best-effort, no retry)" }
                return
            }
            throw e
        }
    }

    /**
     * No independent sub-resources to release beyond the shared [io.libp2p.core.Host], which
     * [LapisNode] owns and stops on its own - exists for lifecycle symmetry with
     * `NabuStorage.stop()`. Idempotent (a no-op call is always safe).
     */
    fun stop() {}

    private fun <T> awaitOrWrap(
        action: String,
        timeout: Duration,
        block: () -> CompletableFuture<T>,
    ): T =
        try {
            block().get(timeout.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw GossipPubSubException("timed out waiting to $action", e)
        } catch (e: ExecutionException) {
            throw GossipPubSubException("failed to $action", e.cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw GossipPubSubException("interrupted while waiting to $action", e)
        }

    companion object {
        /**
         * Attaches GossipSub to [node]'s already-`start()`-ed libp2p [io.libp2p.core.Host]. Must
         * be called after [LapisNode.start], and at most once per [node] - same documented-not-
         * enforced precondition as `NabuStorage.attach()`. GossipSub's own message-layer signing
         * (the `from`/`seqno`/signature RPC fields) uses the node's libp2p Ed25519 identity key
         * ([io.libp2p.core.Host.getPrivKey]) - this is a completely different signature layer
         * from a Veritas grant's secp256k1 truster signature, and the two must never be confused.
         *
         * **Must also be called before [LapisNode.connect] for any peer this node wants to gossip
         * with** - unlike `NabuStorage.attach()`, where call order relative to `connect()` doesn't
         * matter (Bitswap dials fresh streams on demand). [io.libp2p.pubsub.gossip.Gossip] is
         * registered as a [io.libp2p.core.ConnectionHandler], which only observes
         * connection-established events for connections made *after* it registers - attaching
         * after an existing connection is already up means GossipSub never opens a mesh stream on
         * it, and messages will silently never be delivered to or from that peer.
         */
        fun attach(node: LapisNode): GossipPubSub {
            val host = node.host
            val params = buildGossipParams()
            val routerBuilder = GossipRouterBuilder()
            routerBuilder.params = params
            val router = routerBuilder.build()
            val gossip = Gossip(router)
            // Gossip implements both ProtocolBinding and ConnectionHandler - mirroring
            // NabuStorage's Bitswap/Kademlia wiring, minus the AddressBookConsumer step (see this
            // class's doc comment: GossipSub never dials on its own).
            host.addProtocolHandler(gossip)
            // node.addConnectionHandler, NOT host.addConnectionHandler: the latter misses relayed
            // inbound connections entirely, which would make a peer reachable only through a
            // circuit-relay invisible to GossipSub. See LapisNode.addConnectionHandler.
            node.addConnectionHandler(gossip)
            val seqNo = AtomicLong(System.currentTimeMillis())
            val publisher = gossip.createPublisher(host.privKey) { seqNo.incrementAndGet() }
            logger.info { "attached GossipSub to host ${host.peerId}" }
            warnIfConnectedBeforeAttach(node)
            return GossipPubSub(gossip, publisher)
        }

        /**
         * Round-2 defensive check for this function's own documented-not-enforced call-order
         * precondition ("must also be called before [LapisNode.connect]"). [LapisNode.connect]
         * counts every call it receives while [LapisNode.gossipAttached] is still `false` -
         * connections GossipSub can never observe, regardless of whether [attach] is called later,
         * because [io.libp2p.pubsub.gossip.Gossip] only sees connection-established events for
         * connections made *after* it registers as a [io.libp2p.core.ConnectionHandler]. This
         * function reads that count once [attach] has finished wiring up, which is the first point
         * at which both facts needed to make the warning meaningful are actually known: that
         * [node] had pre-existing connections, AND that [attach] was eventually called at all.
         *
         * This is a deliberate compromise, not a fully precise check: a node that never calls
         * [attach] never sees this warning (correct - it may legitimately not want GossipSub at
         * all, and must be free to call [LapisNode.connect] without log spam). A node that calls
         * [attach] once, connects some peers, then never attaches again obviously can't be warned
         * about a *future* mistake - there isn't one. What this does NOT catch: a node that calls
         * [attach] correctly, connects some peers fine, and then (nonsensically) tries to attach
         * a *second* [GossipPubSub] instance later - that is already a separately-documented
         * "at most once per node" precondition violation, not this finding's concern.
         */
        private fun warnIfConnectedBeforeAttach(node: LapisNode) {
            node.gossipAttached = true
            val staleConnections = node.connectsBeforeGossipAttach.get()
            if (staleConnections > 0) {
                logger.warn {
                    "GossipPubSub.attach() was called after $staleConnections LapisNode.connect() call(s) " +
                        "already made on this node - GossipSub only observes connections established after " +
                        "it attaches, so pub/sub will not work with the peer(s) connected before this call. " +
                        "Call GossipPubSub.attach() before LapisNode.connect() next time."
                }
            }
        }

        /**
         * Builds the [GossipParams] [attach] passes to [GossipRouterBuilder] - extracted to its own
         * function (rather than inlined in [attach]) purely as a test seam, so the RPC-shape limits
         * below can be asserted against without spinning up a full running node. See
         * [MAX_GOSSIP_MESSAGE_SIZE]'s doc comment for why [attach] always builds params explicitly
         * through [GossipParamsBuilder] rather than trusting any implicit default.
         */
        internal fun buildGossipParams(): GossipParams =
            GossipParamsBuilder()
                .maxGossipMessageSize(MAX_GOSSIP_MESSAGE_SIZE)
                .maxPublishedMessages(MAX_PUBLISHED_MESSAGES_PER_RPC)
                .maxSubscriptions(MAX_SUBSCRIPTIONS_PER_RPC)
                .build()
    }
}
