package net.lapisphilosophorum.lapisnet.dm

import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant

/** `correct horse battery staple`, as a fresh [CharArray] every call - mirrors
 * `lapis-net-ratchet`'s own `testPassphrase()` (not reusable across modules, `internal`). Moved
 * here from `DmTestFixtures.kt` (V0.8.7 two-node-call-integration-test wave): `DmTestFixtures.kt`
 * stays in `src/test`, which this `testFixtures` file cannot see (only the reverse - `src/test` can
 * see `testFixtures`), so [buildDmTestNode]'s own default parameter needs this function local to
 * this file now. */
internal fun dmTestPassphrase(): CharArray = "correct horse battery staple".toCharArray()

/** A single, fully-wired node for DM integration/adversarial tests - real [LapisNode], real
 * GossipSub/directory/prekey-bundle/mailbox machinery, and a real [DmSessionManager]. Mirrors
 * `TwoNodePrekeyBundleGossipIntegrationTest`'s own real-two-node setup, extended one layer up.
 *
 * V0.8.7 (two-node-call-integration-test wave): moved from `src/test` to this module's `testFixtures`
 * source set and made public (was `internal`) - now also consumed cross-module by
 * `lapis-net-call`'s `TwoNodeCallIntegrationTest` via `testFixtures(project(":lapis-net-dm"))`, not
 * only by this module's own `src/test`. A future editor changing this class's shape should check
 * that consumer too, not just this module's own tests. */
class DmTestNode(
    val identity: DualKeyIdentity,
    val node: LapisNode,
    val prekeyStore: PrekeyStore,
    val peerDirectory: PeerDirectoryGossip,
    val prekeyBundleGossip: PrekeyBundleGossip,
    val storage: NabuStorage,
    val pubsub: GossipPubSub,
    val mailboxGossip: MailboxGossip,
    val dmSessionManager: DmSessionManager,
) {
    fun publishSelf(notValidAfterEpochSecond: Long = Instant.now().epochSecond + 3600) {
        val record =
            PeerRecord.create(
                identity = identity,
                addresses = node.listenAddresses(),
                capabilities = setOf(PeerCapability.DM),
                sequenceNumber = System.nanoTime(),
                notValidAfterEpochSecond = notValidAfterEpochSecond,
            )
        peerDirectory.announce(record)
        val bundle = prekeyStore.publishBundle(identity, notValidAfterEpochSecond)
        prekeyBundleGossip.announce(bundle)
    }

    fun stop() {
        runCatching { dmSessionManager.stop() }
        runCatching { mailboxGossip.stop() }
        runCatching { peerDirectory.stop() }
        runCatching { prekeyBundleGossip.stop() }
        runCatching { node.stop() }
    }
}

fun buildDmTestNode(
    identity: DualKeyIdentity = DualKeyIdentity.generate(),
    sessionStoreDirectory: Path = Files.createTempDirectory("dm-test-sessions"),
    passphrase: CharArray = dmTestPassphrase(),
    // Deliberately SMALL by default - most adversarial tests in this suite (DmStreamAbuseTest cases
    // (h)/(h2)) want a pool that is cheap to exhaust. Tests asserting an EXACT
    // availableOneTimePrekeyCount() after one or two legitimate consumptions (DmSessionManagerTest)
    // must pass a count comfortably above DmSessionManager.PREKEY_REPLENISH_LOW_WATERMARK so the
    // security-audit-round-1 self-healing fix (DmSessionManager.replenishOneTimePrekeysIfLow) does
    // not asynchronously top the pool back up mid-test and invalidate their exact-count assertion -
    // see those tests' own call sites for why.
    oneTimePrekeyCount: Int = 5,
    // V0.8.5 - test-overridable to a small value for tests that need a fast mailbox re-announce/
    // poll cadence without waiting a full 5-minute/60-second default cycle.
    mailboxRedeliverIntervalSeconds: Long = MailboxRedeliveryScheduler.DEFAULT_REDELIVER_INTERVAL_SECONDS,
    mailboxPollIntervalSeconds: Long = MailboxPoller.DEFAULT_POLL_INTERVAL_SECONDS,
    // V0.8.6 - null (the default) preserves every prior test's "no filters configured" behavior
    // exactly. Wired into BOTH MailboxGossip's offline pre-check AND DmSessionManager's post-AEAD
    // classification - a real caller is intended to wire the SAME DmAcceptanceCheck into both.
    acceptance: DmAcceptanceCheck? = null,
    // V0.8.6 - null (the default) preserves every prior test's "sends never auto-accept" behavior
    // exactly. A test that wants to exercise the send-marks-accepted escape path passes the SAME
    // instance here and into `acceptance`'s own `isAcceptedContact` lambda - see
    // DmSessionManager.attach's own `acceptedContacts` parameter doc comment.
    acceptedContacts: DmAcceptedContacts? = null,
    // V0.9.14 - null (the default) preserves every prior test's gossip-only behavior exactly.
    dhtOutbox: DhtOutbox? = null,
    // V0.10.0-F1 - anonymity-mode manager (no DmProtocol, no poller); default keeps every prior test unchanged.
    anonymous: Boolean = false,
): DmTestNode {
    val node = LapisNode.create(identity)
    node.start(bootstrapPeers = emptyList())
    val storage = NabuStorage.attach(node, Files.createTempDirectory("dm-test-storage"))
    // GossipPubSub must be attached BEFORE any connect() call - mirrors every sibling two-node test.
    val pubsub = GossipPubSub.attach(node)
    val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
    val prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
    val mailboxGossip = MailboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey, acceptance)
    // Fresh PrekeyStore every call, even for a "restarted" identity - fine for this test harness
    // because the node using buildDmTestNode() a SECOND time with the same identity is always the
    // X3DH INITIATOR side in these tests, never the responder, so it never needs its own
    // already-consumed one-time-prekey tombstones to survive a restart.
    val prekeyStore =
        PrekeyStore.create(
            Files.createTempDirectory("dm-test-prekeystore"),
            identity,
            oneTimePrekeyCount = oneTimePrekeyCount,
        )
    val dmSessionManager =
        DmSessionManager.attach(
            identity,
            prekeyStore,
            node,
            peerDirectory,
            prekeyBundleGossip,
            mailboxGossip,
            storage,
            pubsub,
            sessionStoreDirectory,
            passphrase,
            mailboxRedeliverIntervalSeconds = mailboxRedeliverIntervalSeconds,
            mailboxPollIntervalSeconds = mailboxPollIntervalSeconds,
            acceptance = acceptance,
            acceptedContacts = acceptedContacts,
            dhtOutbox = dhtOutbox,
            anonymous = anonymous,
        )
    return DmTestNode(
        identity,
        node,
        prekeyStore,
        peerDirectory,
        prekeyBundleGossip,
        storage,
        pubsub,
        mailboxGossip,
        dmSessionManager,
    )
}

/**
 * Polls [condition] every [pollMs] until it holds or [timeout] (default 30 s) has passed; returns the last result.
 * The shared wait of this module's tests (replaces the private copies that some test files had).
 */
fun awaitTrue(
    timeout: Duration = Duration.ofSeconds(30),
    pollMs: Long = 50,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(pollMs)
    }
    return condition()
}

/** The two topics every [DmTestNode] publishes on in [DmTestNode.publishSelf]. */
val DM_TEST_NODE_TOPICS: List<String> =
    listOf(PeerDirectoryGossip.PEER_RECORD_GOSSIP_TOPIC, PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC)

/**
 * Waits until [publisher] can publish on every one of [topics] towards [receiver] without the router failing the
 * publish: [publisher] has seen [receiver]'s SUBSCRIBE for each topic, and [receiver] has seen at least one SUBSCRIBE
 * of [publisher] (that arrived over [publisher]'s outbound pubsub stream, so that stream is open).
 *
 * Without this wait a publish right after `connect` failed under CPU load with `SemiDuplexNoOutboundStreamException`
 * ("No active outbound stream", wrapped in [net.lapisphilosophorum.lapisnet.networking.GossipPubSubException]): the
 * peer was already known to the router, but the outbound stream to it was not open yet. A pure state wait, no retry.
 */
fun awaitGossipReady(
    publisher: GossipPubSub,
    publisherPeer: io.libp2p.core.PeerId,
    receiver: GossipPubSub,
    receiverPeer: io.libp2p.core.PeerId,
    topics: Collection<String>,
    timeout: Duration = Duration.ofSeconds(30),
): Boolean {
    fun ready(): Boolean {
        val seenByPublisher = publisher.remotePeerTopics()[receiverPeer].orEmpty()
        return seenByPublisher.containsAll(topics) && receiver.remotePeerTopics().containsKey(publisherPeer)
    }
    return awaitTrue(timeout) { ready() }
}

/** Connects [a] to [b] and republishes both nodes' directory records/prekey bundles until each side
 * can see the other's - GossipSub mesh formation (GRAFT) is asynchronous, so retrying the whole
 * publish, not just the assertion, mirrors `TwoNodePrekeyBundleGossipIntegrationTest`'s established
 * retry-the-whole-announce-call pattern. Bounded-polling-against-one-deadline, no fixed
 * `Thread.sleep` wait for the OUTCOME (only a short sleep between retries). Before the first publish it
 * waits (state-based, see [awaitGossipReady]) until both pubsub streams are open in both directions. */
fun connectAndConverge(
    a: DmTestNode,
    b: DmTestNode,
    timeout: Duration = Duration.ofSeconds(30),
) {
    a.node.connect(PeerInfo(b.node.peerId, b.node.listenAddresses()))
    check(
        awaitGossipReady(a.pubsub, a.node.peerId, b.pubsub, b.node.peerId, DM_TEST_NODE_TOPICS, timeout) &&
            awaitGossipReady(b.pubsub, b.node.peerId, a.pubsub, a.node.peerId, DM_TEST_NODE_TOPICS, timeout),
    ) {
        "pubsub streams between ${a.identity.secp256k1KeyPair.publicKey.fingerprint()} and " +
            "${b.identity.secp256k1KeyPair.publicKey.fingerprint()} were not open within $timeout"
    }
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        a.publishSelf()
        b.publishSelf()
        val aSeesB = a.peerDirectory.lookup(b.identity.secp256k1KeyPair.publicKey) != null
        val bSeesA = b.peerDirectory.lookup(a.identity.secp256k1KeyPair.publicKey) != null
        val aSeesBBundle = a.prekeyBundleGossip.lookup(b.identity.secp256k1KeyPair.publicKey) != null
        val bSeesABundle = b.prekeyBundleGossip.lookup(a.identity.secp256k1KeyPair.publicKey) != null
        if (aSeesB && bSeesA && aSeesBBundle && bSeesABundle) return
        Thread.sleep(500)
    }
    error(
        "directory/prekey-bundle records for ${a.identity.secp256k1KeyPair.publicKey.fingerprint()} <-> " +
            "${b.identity.secp256k1KeyPair.publicKey.fingerprint()} did not converge within $timeout",
    )
}

/**
 * V0.8.5: publishes [pointer] via [publisherPubsub] on its own recipient-scoped mailbox topic and
 * retries (republishing the WHOLE call, mirroring [connectAndConverge]'s established
 * bounded-polling-against-one-deadline discipline) until it appears in [recipientMailboxGossip]'s
 * [MailboxGossip.pending] list - GossipSub mesh formation (GRAFT) is asynchronous, exactly like
 * every sibling two-node test's directory/prekey-bundle convergence. [publisherPubsub] need not be
 * subscribed to the topic itself - mirrors how [DmSessionManager.sendOffline]/
 * [MailboxRedeliveryScheduler] publish on a RECIPIENT's topic without ever subscribing to it.
 */
internal fun publishAndConvergeMailboxPointer(
    publisherPubsub: GossipPubSub,
    recipientMailboxGossip: MailboxGossip,
    pointer: MailboxPointer,
    timeout: Duration = Duration.ofSeconds(30),
) {
    val bytes = MailboxPointerCodec.encode(pointer)
    val topic = MailboxTopics.forRecipient(pointer.recipientIdentity)
    val targetContentId = pointer.contentId()
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        publisherPubsub.publish(topic, bytes)
        if (recipientMailboxGossip.pending().any { it.contentId().contentEquals(targetContentId) }) return
        Thread.sleep(500)
    }
    error("mailbox pointer for CID ${pointer.blobCid} did not converge on topic $topic within $timeout")
}

/** A TCP listener that accepts connections and never sends or reads a byte: a dial to it hangs until the dialler's
 * own timeout. Close it in a `finally` block. */
class BlackHoleListener internal constructor(
    private val server: java.net.ServerSocket,
) : AutoCloseable {
    private val accepted = java.util.Collections.synchronizedList(mutableListOf<java.net.Socket>())
    private val acceptor =
        Thread({
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                accepted.add(socket)
            }
        }, "black-hole-listener").apply {
            isDaemon = true
            start()
        }

    fun multiaddr(): io.libp2p.core.multiformats.Multiaddr =
        io.libp2p.core.multiformats
            .Multiaddr("/ip4/127.0.0.1/tcp/${server.localPort}")

    override fun close() {
        runCatching { server.close() }
        synchronized(accepted) { accepted.forEach { runCatching { it.close() } } }
        acceptor.join(5_000)
    }
}

fun blackHoleListener(): BlackHoleListener =
    BlackHoleListener(java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress()))
