package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files

/**
 * Three local nodes (A, B, C) in a chain - A and C are each explicitly connected to B's DHT
 * routing table via [NabuStorage.connectToDhtPeer] (not mDNS, not real bootstrap infra, same
 * "explicit local peer" reasoning as [TwoNodeBitswapDirectFetchTest]). Neither A nor C ever
 * learns about the other by any means other than the DHT: they are never connected to each
 * other and never given each other's address.
 *
 * **This suite used to pin a known-broken behaviour.** From V0.1.4 until V0.9.8 the second test
 * here asserted that `findProviders(...)` came back *empty*, because cross-node provider
 * discovery did not work at all. Both underlying defects are fixed in V0.9.8 (see
 * [NabuStorage.attach]'s self-address registration and [NabuStorage.provide]'s off-event-loop
 * announcement, plus docs/architecture.adoc), so these are now real assertions on real
 * behaviour: the discovery round trip has to actually resolve C -> B -> A, and the block has to
 * actually arrive.
 */
class MultiNodeDhtProviderDiscoveryTest :
    FunSpec({
        test("connectToDhtPeer populates both A's and C's routing tables with B, in a 3-node chain") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-storage-a"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("nabu-storage-c"))
                NabuStorage.attach(nodeB, Files.createTempDirectory("nabu-storage-b"))

                val bAddress = nodeB.listenAddresses().first().withP2P(nodeB.peerId)
                storageA.connectToDhtPeer(bAddress) shouldBe true
                storageC.connectToDhtPeer(bAddress) shouldBe true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
            }
        }

        test(
            "findProviders discovers, via B, the provider A announced with provide() - " +
                "and get() then fetches the block with no explicit peer hint",
        ) {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-storage-a"))
                NabuStorage.attach(nodeB, Files.createTempDirectory("nabu-storage-b"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("nabu-storage-c"))

                val bAddress = nodeB.listenAddresses().first().withP2P(nodeB.peerId)
                storageA.connectToDhtPeer(bAddress) shouldBe true
                storageC.connectToDhtPeer(bAddress) shouldBe true

                val payload = "cross-node DHT provider discovery payload".toByteArray()
                val cid = storageA.put(payload)
                // C holds no copy of its own, and has no idea A exists, before the DHT lookup.
                storageC.getLocal(cid) shouldBe null

                storageA.provide(cid)

                // The announcement travelled A -> B (ADD_PROVIDER); the lookup travels
                // C -> B (GET_PROVIDERS) and must name A.
                storageC.findProviders(cid) shouldBe setOf(nodeA.peerId)

                // And the addresses that came back with it are good enough to actually fetch the
                // block over Bitswap, without the caller passing any peer.
                val fetched = storageC.get(cid)
                fetched shouldNotBe null
                fetched!!.toList() shouldBe payload.toList()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
            }
        }
    })
