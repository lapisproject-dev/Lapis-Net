package net.lapisphilosophorum.lapisnet.dm

import io.libp2p.core.PeerInfo
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

/** A single, fully-wired node for DM integration/adversarial tests - real [LapisNode], real
 * GossipSub/directory/prekey-bundle/mailbox machinery, and a real [DmSessionManager]. Mirrors
 * `TwoNodePrekeyBundleGossipIntegrationTest`'s own real-two-node setup, extended one layer up. */
internal class DmTestNode(
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

internal fun buildDmTestNode(
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
): DmTestNode {
    val node = LapisNode.create(identity)
    node.start(bootstrapPeers = emptyList())
    val storage = NabuStorage.attach(node, Files.createTempDirectory("dm-test-storage"))
    // GossipPubSub must be attached BEFORE any connect() call - mirrors every sibling two-node test.
    val pubsub = GossipPubSub.attach(node)
    val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
    val prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
    val mailboxGossip = MailboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
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

/** Connects [a] to [b] and republishes both nodes' directory records/prekey bundles until each side
 * can see the other's - GossipSub mesh formation (GRAFT) is asynchronous, so retrying the whole
 * publish, not just the assertion, mirrors `TwoNodePrekeyBundleGossipIntegrationTest`'s established
 * retry-the-whole-announce-call pattern. Bounded-polling-against-one-deadline, no fixed
 * `Thread.sleep` wait for the OUTCOME (only a short sleep between retries). */
internal fun connectAndConverge(
    a: DmTestNode,
    b: DmTestNode,
    timeout: Duration = Duration.ofSeconds(30),
) {
    a.node.connect(PeerInfo(b.node.peerId, b.node.listenAddresses()))
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
