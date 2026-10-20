package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.host.MemoryAddressBook
import org.peergos.blockstore.RamBlockstore
import java.time.Instant

/**
 * Nabu v0.8.0 builds its routing table as `Router(id, 2, 2, 2)`: at most TWO peers per bucket, the
 * rest only in a replacement cache that `find(.., includeStale = false)` never returns. A third peer
 * in the same bucket was therefore added but not routable (about one in seven random three-peer
 * networks), which made `MultiNodeIpnsValueTest` flaky. [LapisKademliaEngine] keeps its own table.
 */
class LapisKademliaEngineRoutingTableTest :
    FunSpec({
        class Fixture(
            val limits: DhtLimits,
            clock: () -> Instant = Instant::now,
        ) {
            val me: PeerId = realPeerId()
            val book = MemoryAddressBook()
            val engine =
                LapisKademliaEngine(
                    Multihash.deserialize(me.bytes),
                    BoundedProviderStore(limits),
                    BoundedIpnsRecordStore(8),
                    RamBlockstore(),
                    limits,
                    clock,
                ).also { it.setAddressBook(book) }
            private var port = 1

            /** [n] fresh peers that all fall into the half of the key space opposite to [me] (one bucket). */
            fun peersInOneBucket(n: Int): List<PeerId> {
                val found = mutableListOf<PeerId>()
                while (found.size < n) {
                    val p = realPeerId()
                    if (topBit(p) != topBit(me)) found += p
                }
                return found
            }

            fun know(peer: PeerId) {
                book.setAddrs(peer, 0, Multiaddr("/ip4/10.0.0.1/tcp/${port++}")).join()
            }
        }

        val probe = ByteArray(32) { 7 }

        test("three peers in one bucket are all returned by getKClosestPeers") {
            val f = Fixture(DhtLimits(maxAddressesPerPeer = 4, maxAddressesPerIp = 4))
            val peers = f.peersInOneBucket(3)
            peers.forEach {
                f.know(it)
                f.engine.addOutgoingConnection(it)
            }

            f.engine
                .getKClosestPeers(probe, 20)
                .map { it.peerId.toBase58() }
                .toSet() shouldBe
                peers.map { it.toBase58() }.toSet()
        }

        test("a bucket is capped at routingBucketSize, the rest waits in the replacement cache") {
            val f = Fixture(DhtLimits(routingBucketSize = 4, routingReplacementCacheSize = 2))
            val peers = f.peersInOneBucket(12)
            peers.forEach {
                f.know(it)
                f.engine.addOutgoingConnection(it)
            }

            f.engine.routingTableSizeForTesting() shouldBe 4
            peers.count { f.engine.isRoutable(it) } shouldBe 4
        }

        test("isRoutable is false for a peer that only reached the replacement cache, true for the others") {
            val f = Fixture(DhtLimits(routingBucketSize = 2, routingReplacementCacheSize = 2))
            val (first, second, third) = f.peersInOneBucket(3)
            listOf(first, second, third).forEach { f.engine.addOutgoingConnection(it) }

            f.engine.isRoutable(first) shouldBe true
            f.engine.isRoutable(second) shouldBe true
            f.engine.isRoutable(third) shouldBe false
            f.engine.isRoutable(realPeerId()) shouldBe false
        }

        test("a clock stepping backwards does not throw and the peer is still routable") {
            var now = Instant.parse("2026-01-01T00:00:00Z")
            val f = Fixture(DhtLimits(), clock = { now })
            val (early, late) = f.peersInOneBucket(2)
            f.engine.addOutgoingConnection(early)
            now = now.minusSeconds(3600)
            f.engine.addOutgoingConnection(late)

            f.engine.isRoutable(early) shouldBe true
            f.engine.isRoutable(late) shouldBe true
        }

        test("addIncomingConnection never admits a peer") {
            val f = Fixture(DhtLimits())
            val peer = f.peersInOneBucket(1).single()
            f.engine.addIncomingConnection(peer)

            f.engine.isRoutable(peer) shouldBe false
            f.engine.routingTableSizeForTesting() shouldBe 0
        }

        test("the table's own ID is the same SHA-256 key space as every peer's") {
            val f = Fixture(DhtLimits())
            // Identity multihash of an Ed25519 key: bareMultihash bytes equal the PeerId bytes.
            Multihash
                .deserialize(f.me.bytes)
                .bareMultihash()
                .toBytes()
                .toList() shouldBe f.me.bytes.toList()
        }
    })
