package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorGossip
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.DestroyBody
import net.lapisphilosophorum.lapisnet.onion.DestroyReason
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishStatus
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishStatus
import net.lapisphilosophorum.lapisnet.onion.OnionKeyRing
import net.lapisphilosophorum.lapisnet.onion.OnionRelay
import net.lapisphilosophorum.lapisnet.onion.RelayAction
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.StatusBody
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Hosts the pure [OnionRelay] state machine on the network: feeds it the cells of the links, executes the
 * [RelayAction]s it returns, keeps the relay's onion keys rotated and persisted, and publishes the relay's
 * [OnionRelayDescriptor] (gossip; the DHT copy is written by the node's single IPNS writer through [currentDescriptor]).
 *
 * Only exists in relay mode (`--onion-relay`). Extends are only ever executed towards relays that have a verified
 * descriptor in the local index and never with a client-supplied link specifier: an extend cannot be abused to make this
 * node connect to an arbitrary host. There is no exit service in this wave; DATA delivered to this relay is answered with
 * END (or handed to the test hook). Thread model: cells of one link arrive on that link's event loop in order; dialing,
 * persistence and gossip run on the pool of the link manager or the supervisor, never on an event loop.
 */
@OptIn(ExperimentalOnionApi::class)
class OnionRelayService private constructor(
    private val node: LapisNode,
    private val identity: DualKeyIdentity,
    private val config: OnionWireConfig,
    private val keyStore: OnionKeyStore,
    private val ring: OnionKeyRing,
    private val relay: OnionRelay,
    private val links: OnionLinkManager,
    private val descriptors: OnionRelayDescriptorIndex,
    private val gossip: OnionRelayDescriptorGossip?,
    private val peerDirectory: PeerDirectoryGossip?,
    val quality: OnionRelayQualityTracker,
    private val clock: Clock,
    private val directorySink: DirectoryPublishSink?,
    private val mailboxSink: MailboxPublishSink?,
) : AutoCloseable {
    private val ownIdentity: Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey
    private val linkTargets = ConcurrentHashMap<Long, Secp256k1PublicKey>()
    private val jobs = ArrayList<NodeServiceSupervisor.PeriodicJob>()

    @Volatile private var latestDescriptor: OnionRelayDescriptor? = null

    @Volatile private var closed = false

    /** Test seam: receives DATA/END addressed to this relay, returns the reply (or null). Never set in production. */
    @ExperimentalOnionApi
    internal var localDeliveryHandler: ((Long, RelayMessage) -> RelayMessage?)? = null

    val relayModeActive: Boolean get() = !closed

    fun circuitCount(): Int = relay.circuitCount

    fun introPointCount(): Int = relay.introPointCount

    fun pendingRendezvousCount(): Int = relay.pendingRendezvousCount

    fun splicedPairCount(): Int = relay.splicedPairCount

    /** Test seam: sees every end-to-end blob this relay splices (it must be unreadable ciphertext). */
    @ExperimentalOnionApi
    internal fun observeRendezvousData(observer: ((ByteArray) -> Unit)?) {
        relay.rendezvousDataObserver = observer
    }

    fun linkCount(): Int = links.linkCount()

    /** The descriptor currently announced, or `null` before the first publication. */
    fun currentDescriptor(): OnionRelayDescriptor? =
        latestDescriptor?.takeIf {
            it.notValidAfterEpochSecond >=
                nowSeconds()
        }

    fun qualityCounts(epochDay: Long): Map<Secp256k1PublicKey, OnionRelayQualityCounts> = quality.counts(epochDay)

    internal fun ringForTest(): OnionKeyRing = ring

    private fun nowSeconds(): Long = clock.millis() / 1000

    // ---- cell handling ---------------------------------------------------------------------------

    private fun onCell(
        link: LinkId,
        cell: Cell,
    ): Boolean {
        if (closed) return true
        val actions = relay.onCell(link, cell)
        when (cell.command) {
            CellCommand.CREATE -> {
                val created = (actions.firstOrNull() as? RelayAction.SendCell)?.cell?.command == CellCommand.CREATED
                if (created) quality.recordCreateAccepted() else quality.recordCreateRejected()
            }
            CellCommand.DESTROY -> {
                val target = linkTargets[link.value]
                if (target != null) {
                    val reason = DestroyBody.decode(cell.body)
                    if (reason == DestroyReason.PROTOCOL || reason == DestroyReason.AUTH_FAILED) {
                        quality.recordDestroyedByTarget(target)
                    }
                }
            }
            else -> Unit
        }
        execute(actions)
        return true
    }

    private fun onLinkClosed(link: LinkId) {
        linkTargets.remove(link.value)
        if (!closed) execute(relay.onLinkClosed(link))
    }

    private fun execute(actions: List<RelayAction>) {
        for (action in actions) {
            when (action) {
                is RelayAction.SendCell -> links.send(action.link, action.cell)
                is RelayAction.OpenLinkForExtend -> extend(action)
                is RelayAction.DeliverLocal -> deliver(action)
                is RelayAction.DeliverDirectoryPublish -> deliverDirectoryPublish(action)
                is RelayAction.DeliverMailboxItem -> deliverMailboxItem(action)
                is RelayAction.CircuitClosed -> Unit
            }
        }
    }

    private fun extend(action: RelayAction.OpenLinkForExtend) {
        val now = nowSeconds()
        val target = descriptors.byRelayIdDigest(action.targetRelayIdDigest, now)
        // No client-chosen link specifier in this wave, only peers with a verified descriptor, never ourselves.
        if (action.linkSpecifier.isNotEmpty() || target == null || target.identity == ownIdentity) {
            execute(relay.onExtendResult(action.pendingId, null))
            return
        }
        quality.recordExtendAttempt(target.identity)
        val addresses = peerDirectory?.lookup(target.identity, now)?.addresses.orEmpty()
        links
            .linkTo(target.peerId, addresses)
            .copy()
            .orTimeout(config.extendTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .whenComplete { linkId, error ->
                if (error != null || linkId == null || closed) {
                    execute(relay.onExtendResult(action.pendingId, null))
                } else {
                    quality.recordExtendLinkSuccess(target.identity)
                    linkTargets[linkId.value] = target.identity
                    execute(relay.onExtendResult(action.pendingId, linkId))
                }
            }
    }

    private fun deliver(action: RelayAction.DeliverLocal) {
        val handler = localDeliveryHandler
        val reply =
            when {
                handler != null -> handler(action.circuitHandle, action.message)
                action.message.command == RelayCommand.DATA ->
                    RelayMessage(RelayCommand.END, action.message.streamId, ByteArray(0))
                else -> null
            }
        if (reply != null) execute(relay.reply(action.circuitHandle, reply))
    }

    /**
     * Directory publication through a circuit (wave V0.10.0-D): validation and gossip publication run on the bounded
     * pool of the link manager (signature checks and a blocking publish must not stall an event loop); the status goes
     * back through the circuit. A saturated pool is answered with the rate-limited status.
     */
    private fun deliverDirectoryPublish(action: RelayAction.DeliverDirectoryPublish) {
        val sink = directorySink
        val accepted =
            sink != null &&
                links.submit {
                    val status =
                        try {
                            sink.publish(action.type, action.objectBytes)
                        } catch (e: RuntimeException) {
                            DirectoryPublishStatus.RATE_LIMITED
                        }
                    replyPublished(action.circuitHandle, status)
                }
        if (!accepted) {
            replyPublished(
                action.circuitHandle,
                if (sink == null) DirectoryPublishStatus.UNKNOWN_TYPE else DirectoryPublishStatus.RATE_LIMITED,
            )
        }
    }

    private fun deliverMailboxItem(action: RelayAction.DeliverMailboxItem) {
        val sink = mailboxSink
        val accepted =
            sink != null &&
                links.submit {
                    val status =
                        try {
                            sink.publish(action.itemBytes)
                        } catch (e: RuntimeException) {
                            MailboxPublishStatus.RATE_LIMITED
                        }
                    replyMailbox(action.circuitHandle, status)
                }
        if (!accepted) replyMailbox(action.circuitHandle, MailboxPublishStatus.RATE_LIMITED)
    }

    private fun replyMailbox(
        handle: Long,
        status: Byte,
    ) {
        if (closed) return
        execute(relay.reply(handle, RelayMessage(RelayCommand.MAILBOX_PUBLISHED, 0, StatusBody.encode(status))))
    }

    private fun replyPublished(
        handle: Long,
        status: Byte,
    ) {
        if (closed) return
        execute(relay.reply(handle, RelayMessage(RelayCommand.DIRECTORY_PUBLISHED, 0, StatusBody.encode(status))))
    }

    // ---- keys and descriptor ---------------------------------------------------------------------

    /** Signs and announces a fresh descriptor for the current onion key. */
    @Synchronized
    internal fun publishDescriptor() {
        val binding = ring.current() ?: return
        val now = nowSeconds()
        val sequence = maxOf(keyStore.lastDescriptorSequence + 1, now)
        val expiry = minOf(now + config.descriptorTtl.inWholeSeconds, binding.notValidAfterEpochSecond)
        val descriptor = OnionRelayDescriptor.create(identity, binding, sequence, expiry, now)
        keyStore.lastDescriptorSequence = sequence
        try {
            keyStore.persist(ring)
        } catch (e: OnionKeyStoreException) {
            logger.warn { "could not persist the onion key file (${e.javaClass.simpleName})" }
        }
        latestDescriptor = descriptor
        descriptors.add(descriptor, now)
        try {
            gossip?.announce(descriptor)
        } catch (e: RuntimeException) {
            logger.debug { "descriptor announcement failed: ${e.javaClass.simpleName}" }
        }
    }

    /** Rotates now (test seam and the body of the periodic check): new key, persisted, re-announced. */
    @Synchronized
    internal fun rotateNow() {
        keyStore.rotate(ring, config.onionKeyLifetime)
        publishDescriptor()
    }

    /** Rotation check: retire expired keys, rotate a key older than `onionKeyRotateAfter`, re-announce on rotation. */
    @Synchronized
    internal fun maintenance() {
        if (closed) return
        val now = nowSeconds()
        val retired = ring.retireExpired(now)
        val current = ring.current()
        val createdAt = current?.let { it.notValidAfterEpochSecond - config.onionKeyLifetime.inWholeSeconds }
        if (current == null || now - createdAt!! >= config.onionKeyRotateAfter.inWholeSeconds) {
            rotateNow()
            // the previous key now expires on its own schedule; nothing more to retire immediately
        } else if (retired > 0) {
            try {
                keyStore.persist(ring)
            } catch (e: OnionKeyStoreException) {
                logger.warn { "could not persist the onion key file (${e.javaClass.simpleName})" }
            }
        }
    }

    internal fun sweep() {
        if (closed) return
        execute(relay.sweepExpired())
        descriptors.evictExpired(nowSeconds())
    }

    override fun close() {
        if (closed) return
        closed = true
        jobs.forEach { it.cancel() }
        links.acceptInbound = false
        relay.close()
        ring.close()
        keyStore.close()
    }

    companion object {
        /**
         * Starts relay mode: loads or creates the onion keys, registers the protocol handler on the host, starts the sweep,
         * rotation and republish jobs on [supervisor] and announces the first descriptor. Everything is undone if a step throws.
         */
        internal fun attach(
            node: LapisNode,
            identity: DualKeyIdentity,
            config: OnionWireConfig,
            keyStore: OnionKeyStore,
            descriptors: OnionRelayDescriptorIndex,
            descriptorGossip: OnionRelayDescriptorGossip?,
            peerDirectory: PeerDirectoryGossip?,
            supervisor: NodeServiceSupervisor,
            links: OnionLinkManager,
            directorySink: DirectoryPublishSink? = null,
            mailboxSink: MailboxPublishSink? = null,
            quality: OnionRelayQualityTracker = OnionRelayQualityTracker(),
            clock: Clock = Clock.systemUTC(),
            random: SecureRandom = SecureRandom(),
        ): OnionRelayService {
            require(config.relayMode) { "relay mode is not enabled" }
            val ring = OnionKeyRing(identity.secp256k1KeyPair.publicKey)
            var service: OnionRelayService? = null
            try {
                val mode = keyStore.loadOrCreate(ring, config.onionKeyLifetime)
                if (mode == OnionKeyStore.LoadResult.EPHEMERAL) {
                    logger.warn { "onion relay keys are kept in memory only (no keystore passphrase): lost on restart" }
                }
                val relay = OnionRelay(ring, config.relayLimits, clock, random)
                val svc =
                    OnionRelayService(
                        node,
                        identity,
                        config,
                        keyStore,
                        ring,
                        relay,
                        links,
                        descriptors,
                        descriptorGossip,
                        peerDirectory,
                        quality,
                        clock,
                        directorySink,
                        mailboxSink,
                    )
                service = svc
                links.addClosedSink { svc.onLinkClosed(it) }
                links.hasCircuits = { relay.hasCircuitsOn(it) }
                links.circuitKnown = { l, id -> relay.knowsCircuit(l, id) }
                links.addSink(CellSink { link, cell -> svc.onCell(link, cell) })
                links.acceptInbound = true
                node.host.addProtocolHandler(links.binding)
                svc.jobs +=
                    supervisor.launchPeriodic(
                        "onion-sweep",
                        interval = config.sweepInterval,
                        jitter = 1.seconds,
                        initialDelay = config.sweepInterval,
                    ) { svc.sweep() }
                svc.jobs +=
                    supervisor.launchPeriodic(
                        "onion-key-rotation",
                        interval = 1.hours,
                        jitter = 1.seconds,
                        initialDelay = 1.hours,
                    ) { svc.maintenance() }
                svc.jobs +=
                    supervisor.launchPeriodic(
                        "onion-descriptor-republish",
                        interval = config.descriptorRepublishInterval,
                        jitter = 1.seconds,
                        initialDelay = config.descriptorInitialRepublishDelay,
                    ) { svc.publishDescriptor() }
                svc.publishDescriptor()
                logger.info { "onion relay mode on" }
                return svc
            } catch (e: Exception) {
                links.acceptInbound = false
                service?.close() ?: ring.close()
                throw e
            }
        }
    }
}
