package net.lapisphilosophorum.lapisnet.onionwire

import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.lifecycle.NodeServiceSupervisor
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

/** Short intervals so that descriptors converge within a test. */
fun fastWireConfig(
    relay: Boolean,
    base: OnionWireConfig = OnionWireConfig(),
): OnionWireConfig =
    base.copy(
        relayMode = relay,
        descriptorInitialRepublishDelay = 1.seconds,
        descriptorRepublishInterval = 3.seconds,
        linkHandshakeTimeout = 2.seconds,
        extendTimeout = 5.seconds,
    )

fun awaitTrue(
    timeout: Duration = Duration.ofSeconds(20),
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(25)
    }
    return condition()
}

/** A real node (loopback TCP) with the full onion wire stack attached. */
class WireTestNode(
    relay: Boolean,
    config: OnionWireConfig = fastWireConfig(relay),
    val dir: Path = Files.createTempDirectory("onion-wire-node"),
    passphrase: CharArray? = null,
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    clock: Clock = Clock.systemUTC(),
    directoryMode: DirectoryAnonymityMode = DirectoryAnonymityMode.OFF,
    directorySink: DirectoryPublishSink? = null,
    mailboxSink: MailboxPublishSink? = null,
) : AutoCloseable {
    val node: LapisNode = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
    val storage: NabuStorage =
        NabuStorage.attach(
            node,
            dir.resolve("storage").also { Files.createDirectories(it) },
        )
    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val peerDirectory: PeerDirectoryGossip = PeerDirectoryGossip.attach(pubsub, storage)
    val supervisor = NodeServiceSupervisor("onion-wire-test")
    val keyFile: Path = dir.resolve("relay.onionkeys")
    val wire: OnionWire =
        OnionWire.attach(
            node,
            identity,
            config,
            pubsub,
            peerDirectory,
            supervisor,
            keyFile,
            passphrase,
            clock,
            directoryMode,
            directorySink,
            mailboxSinkOverride = mailboxSink,
        )

    fun connectTo(other: WireTestNode) {
        node.connect(PeerInfo(other.node.peerId, other.node.listenAddresses()))
    }

    override fun close() {
        runCatching { supervisor.stopAll() }
        runCatching { wire.close() }
        runCatching { peerDirectory.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

val WireTestNode.peerId get() = node.peerId
val WireTestNode.key get() = identity.secp256k1KeyPair.publicKey
