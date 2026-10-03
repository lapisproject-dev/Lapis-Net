package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.protocol.dht.pb.Dht
import java.nio.file.Files
import java.time.Duration

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
 *
 * **What each test proves (corrected in V0.9.11).** The 3-node test proves only repair 2, the
 * announcement: B answers `GET_PROVIDERS` from the record A sent it, and B never holds the block
 * itself, so B's own address entry is never read. Repair 1, [NabuStorage.attach]'s registration of the
 * node's own addresses, is exercised only when a node answers `GET_PROVIDERS` for a block it holds
 * - which is what the 2-node test below does. Before V0.9.11 that case had no test; mutating the
 * registration away left the whole suite green.
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
        test("a node that holds the block itself answers GET_PROVIDERS for it, with no provide() at all") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-storage-a"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("nabu-storage-c"))
                storageC.connectToDhtPeer(nodeA.listenAddresses().first().withP2P(nodeA.peerId)) shouldBe true

                val cid = storageA.put("held by A, never announced".toByteArray())

                // A's responder adds ITSELF to the reply because the block is in its blockstore; for that it
                // reads its own entry in its own address book (see attach()).
                storageC.findProviders(cid) shouldBe setOf(nodeA.peerId)
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeC.stop() }
            }
        }

        test("the address book entry for the node itself is exactly its listen addresses, without duplicates") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            try {
                node.start(bootstrapPeers = emptyList())
                NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-self"))
                val registered =
                    node.host.addressBook
                        .getAddrs(node.peerId)
                        .join()
                        .orEmpty()
                        .map { it.toString() }
                registered.size shouldBe registered.toSet().size
                registered.toSet() shouldBe node.listenAddresses().map { it.toString() }.toSet()
            } finally {
                runCatching { node.stop() }
            }
        }

        test("provide and findProviders search the keyspace under the bare multihash, not under the CID bytes") {
            val victim = LapisNode.create(DualKeyIdentity.generate())
            val recorder = ScriptedDhtPeer.start()
            try {
                victim.start(bootstrapPeers = emptyList())
                val storage = NabuStorage.attach(victim, Files.createTempDirectory("nabu-storage-keys"))
                // answer FIND_NODE (with no closer peers) so the recorder counts as responsive and is announced to
                recorder.answer(Dht.Message.MessageType.FIND_NODE) { it }
                storage.connectToDhtPeer(recorder.address) shouldBe true
                val cid = storage.put("a CIDv1 whose bytes differ from its multihash".toByteArray())
                val bare = cid.bareMultihash().toBytes().toList()
                cid.toBytes().toList() shouldNotBe bare

                storage.provide(cid, Duration.ofSeconds(3))
                storage.findProviders(cid, timeout = Duration.ofSeconds(3))

                val findNodeKeys = recorder.engine.received.filter { it.type == Dht.Message.MessageType.FIND_NODE }
                val getProvidersKeys =
                    recorder.engine.received.filter {
                        it.type ==
                            Dht.Message.MessageType.GET_PROVIDERS
                    }
                val addProviderKeys =
                    recorder.engine.received.filter {
                        it.type == Dht.Message.MessageType.ADD_PROVIDER
                    }
                (findNodeKeys.isNotEmpty() && getProvidersKeys.isNotEmpty() && addProviderKeys.isNotEmpty()) shouldBe
                    true
                (findNodeKeys + getProvidersKeys + addProviderKeys).forEach {
                    it.key.toByteArray().toList() shouldBe
                        bare
                }
            } finally {
                recorder.stop()
                runCatching { victim.stop() }
            }
        }
    })
