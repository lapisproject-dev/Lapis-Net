package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - `LapisNode` + `NabuStorage` +
 * [GossipPubSub] + [PeerDirectoryGossip] fully attached on both, mirroring
 * `net.lapisphilosophorum.lapisnet.trust.TwoNodeVeritasGossipIntegrationTest`'s connectivity and
 * bounded-polling-against-one-deadline pattern exactly. Node A announces its own record; node B's
 * [PeerDirectoryGossip.lookup] is polled with a bounded timeout until it converges with A's.
 */
class TwoNodePeerDirectoryGossipIntegrationTest :
    FunSpec({
        test("a record announced on node A propagates to node B, round-trips addresses/peerId, and persists") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("directory-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("directory-gossip-b"))

                // GossipPubSub (and therefore PeerDirectoryGossip, which subscribes through it)
                // must be attached BEFORE the nodes connect - Gossip is a ConnectionHandler and
                // only sees connection-established events for connections made after it registers.
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val directoryA = PeerDirectoryGossip.attach(pubsubA, storageA)
                val directoryB = PeerDirectoryGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val record =
                    PeerRecord.create(
                        identityA,
                        addresses = nodeA.listenAddresses(),
                        capabilities = setOf(PeerCapability.DM, PeerCapability.MAILBOX),
                        sequenceNumber = 0,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )

                // GossipSub mesh formation (GRAFT) is asynchronous, so retry announce(), not just
                // the assertion below - retrying the whole announce() call is safe (see
                // PeerDirectoryGossip.announce's doc comment: storage.put is idempotent and
                // index.add is a harmless no-op on a duplicate).
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var lookedUp = directoryB.lookup(identityA.secp256k1KeyPair.publicKey)
                while (lookedUp == null && Instant.now().isBefore(deadline)) {
                    directoryA.announce(record)
                    Thread.sleep(500)
                    lookedUp = directoryB.lookup(identityA.secp256k1KeyPair.publicKey)
                }

                lookedUp.shouldNotBeNull()
                lookedUp shouldBe record
                lookedUp.addresses shouldBe nodeA.listenAddresses()
                lookedUp.peerId shouldBe nodeA.peerId
                lookedUp.peerId shouldBe identityA.deriveLibp2pPeerId()

                // Durable persistence, not just the in-memory index.
                val recordBytes = PeerRecordCodec.encode(record)
                val cid = storageA.put(recordBytes)
                storageB.get(cid) shouldBe recordBytes

                // Node B's own self-announced record for identityB and node A's received record
                // for identityA are both independently correct and don't clobber each other in
                // PeerRecordIndex (keyed by identity, not by which node announced it).
                val recordB =
                    PeerRecord.create(
                        identityB,
                        addresses = nodeB.listenAddresses(),
                        capabilities = setOf(PeerCapability.DM),
                        sequenceNumber = 0,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                directoryB.announce(recordB)
                directoryB.lookup(identityB.secp256k1KeyPair.publicKey) shouldBe recordB
                directoryB.lookup(identityA.secp256k1KeyPair.publicKey) shouldBe record

                directoryA.stop()
                directoryB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
