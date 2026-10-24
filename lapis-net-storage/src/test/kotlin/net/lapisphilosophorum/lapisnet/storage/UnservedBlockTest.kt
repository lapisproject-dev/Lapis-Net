package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import java.time.Duration

/** Blocks stored with [NabuStorage.putUnserved] are readable locally but invisible to remote Bitswap probes. */
class UnservedBlockTest :
    FunSpec({
        test("an unserved block is readable locally but a remote peer cannot fetch or detect it via Bitswap") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))
                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-unserved-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("nabu-unserved-b"))
                storageB.registerPeerAddress(nodeA.listenAddresses().first().withP2P(nodeA.peerId))

                val secret = "mail accepted over a circuit".toByteArray()
                val served = "public block".toByteArray()
                val secretCid = storageA.putUnserved(secret)
                val servedCid = storageA.put(served)

                storageA.getLocal(secretCid) shouldBe secret
                storageA.get(secretCid) shouldBe secret

                // control: the public block is fetchable, so a miss below is not a broken connection
                storageB.get(servedCid, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(10)) shouldBe served
                storageB.get(secretCid, peers = setOf(nodeA.peerId), timeout = Duration.ofSeconds(3)) shouldBe null
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
