package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.OneTimePrekey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - mirrors
 * [TwoNodePeerDirectoryGossipIntegrationTest]'s connectivity and bounded-polling-against-one-
 * deadline pattern exactly. Node A announces its own prekey bundle; node B's
 * [PrekeyBundleGossip.lookup] is polled with a bounded timeout until it converges with A's.
 */
class TwoNodePrekeyBundleGossipIntegrationTest :
    FunSpec({
        test("a prekey bundle announced on node A propagates to node B and round-trips byte-for-byte") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("prekeybundle-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("prekeybundle-gossip-b"))

                // GossipPubSub must be attached BEFORE the nodes connect - see
                // TwoNodePeerDirectoryGossipIntegrationTest's identical comment.
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val prekeysA = PrekeyBundleGossip.attach(pubsubA, storageA)
                val prekeysB = PrekeyBundleGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val x25519IdentityA = X25519KeyPair.generate()
                val bindingA = EncryptionKeyBinding.create(identityA.secp256k1KeyPair, x25519IdentityA.publicKey)
                val bundle =
                    PrekeyBundle.create(
                        identity = identityA,
                        encryptionBinding = bindingA,
                        signedPrekeyId = 0,
                        signedPrekey = X25519KeyPair.generate().publicKey,
                        oneTimePrekeys = listOf(OneTimePrekey(0, X25519KeyPair.generate().publicKey)),
                        sequenceNumber = 0,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )

                // GossipSub mesh formation (GRAFT) is asynchronous, so retry announce(), not just
                // the assertion below - retrying the whole announce() call is safe, mirroring
                // PrekeyBundleGossip.announce's doc comment.
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var lookedUp = prekeysB.lookup(identityA.secp256k1KeyPair.publicKey)
                while (lookedUp == null && Instant.now().isBefore(deadline)) {
                    prekeysA.announce(bundle)
                    Thread.sleep(500)
                    lookedUp = prekeysB.lookup(identityA.secp256k1KeyPair.publicKey)
                }

                lookedUp.shouldNotBeNull()
                lookedUp shouldBe bundle
                lookedUp.verifyEncryptionBinding() shouldBe true
                lookedUp.verifySignedPrekey() shouldBe true

                // Durable persistence, not just the in-memory index.
                val bundleBytes = PrekeyBundleCodec.encode(bundle)
                val cid = storageA.put(bundleBytes)
                storageB.get(cid) shouldBe bundleBytes

                // Node B's own self-announced bundle for identityB and node A's received bundle for
                // identityA are both independently correct and don't clobber each other.
                val x25519IdentityB = X25519KeyPair.generate()
                val bindingB = EncryptionKeyBinding.create(identityB.secp256k1KeyPair, x25519IdentityB.publicKey)
                val bundleB =
                    PrekeyBundle.create(
                        identity = identityB,
                        encryptionBinding = bindingB,
                        signedPrekeyId = 0,
                        signedPrekey = X25519KeyPair.generate().publicKey,
                        oneTimePrekeys = emptyList(),
                        sequenceNumber = 0,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                prekeysB.announce(bundleB)
                prekeysB.lookup(identityB.secp256k1KeyPair.publicKey) shouldBe bundleB
                prekeysB.lookup(identityA.secp256k1KeyPair.publicKey) shouldBe bundle

                prekeysA.stop()
                prekeysB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
