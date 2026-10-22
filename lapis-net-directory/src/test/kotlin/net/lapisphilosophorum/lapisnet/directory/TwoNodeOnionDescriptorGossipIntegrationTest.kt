package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.time.Clock
import java.time.Duration
import java.time.Instant

/** Two real nodes on loopback: relay A announces its descriptor, B finds it in its own index. */
class TwoNodeOnionDescriptorGossipIntegrationTest :
    FunSpec({
        test("a descriptor announced on node A reaches the index of node B") {
            val identityA = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val indexA = OnionRelayDescriptorIndex()
                val indexB = OnionRelayDescriptorIndex()
                val gossipA = OnionRelayDescriptorGossip.attach(pubsubA, indexA)
                val gossipB = OnionRelayDescriptorGossip.attach(pubsubB, indexB)
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val relay = OnionRelayPublisher(DirectoryPublisher(identityA))
                val descriptor = relay.descriptor()
                val key = identityA.secp256k1KeyPair.publicKey
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var found = indexB.current(key, Clock.systemUTC().millis() / 1000)
                while (found == null && Instant.now().isBefore(deadline)) {
                    gossipA.announce(descriptor)
                    Thread.sleep(500)
                    found = indexB.current(key, Clock.systemUTC().millis() / 1000)
                }
                found.shouldNotBeNull()
                found shouldBe descriptor
                indexB.byRelayIdDigest(descriptor.relayIdDigest(), Clock.systemUTC().millis() / 1000) shouldBe
                    descriptor

                gossipA.stop()
                gossipB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
