package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import org.peergos.protocol.dht.pb.Dht

class BoundedProviderStoreTest :
    FunSpec({
        fun key(n: Int) = Multihash(Multihash.Type.sha2_256, ByteArray(32) { n.toByte() })

        fun provider(
            id: PeerId = realPeerId(),
            addrs: List<Multiaddr> = emptyList(),
        ): Dht.Message.Peer =
            Dht.Message.Peer
                .newBuilder()
                .setId(ByteString.copyFrom(id.bytes))
                .addAllAddrs(addrs.map { ByteString.copyFrom(it.serialize()) })
                .build()

        test("stores and returns a provider") {
            val store = BoundedProviderStore(DhtLimits())
            val p = provider()
            store.addProvider(key(1), p)
            store.getProviders(key(1)).map { it.id } shouldBe listOf(p.id)
            store.getProviders(key(2)) shouldHaveSize 0
        }

        test("at most maxProvidersPerKey per key, oldest evicted first") {
            val store = BoundedProviderStore(DhtLimits(maxProvidersPerKey = 3))
            val ps = (1..6).map { provider() }
            ps.forEach { store.addProvider(key(1), it) }
            store.getProviders(key(1)).map { it.id }.toSet() shouldBe ps.takeLast(3).map { it.id }.toSet()
        }

        test("one record per provider ID - the newest wins") {
            val store = BoundedProviderStore(DhtLimits())
            val id = realPeerId()
            store.addProvider(key(1), provider(id, listOf(Multiaddr("/ip4/1.1.1.1/tcp/1"))))
            store.addProvider(key(1), provider(id, listOf(Multiaddr("/ip4/2.2.2.2/tcp/2"))))
            val stored = store.getProviders(key(1))
            stored shouldHaveSize 1
            Multiaddr
                .deserialize(
                    stored
                        .single()
                        .addrsList
                        .single()
                        .toByteArray(),
                ).toString() shouldBe
                "/ip4/2.2.2.2/tcp/2"
        }

        test("a provider ID cannot be duplicated by adding it many times") {
            val store = BoundedProviderStore(DhtLimits())
            val p = provider()
            repeat(500) { store.addProvider(key(1), p) }
            store.getProviders(key(1)) shouldHaveSize 1
        }

        test("keys are evicted least-recently-used beyond providerStoreKeyCapacity") {
            val store = BoundedProviderStore(DhtLimits(providerStoreKeyCapacity = 3))
            store.addProvider(key(1), provider())
            store.addProvider(key(2), provider())
            store.addProvider(key(3), provider())
            store.getProviders(key(1)) shouldHaveSize 1 // touch: key 1 becomes the most recent
            store.addProvider(key(4), provider())
            store.getProviders(key(2)) shouldHaveSize 0
            store.getProviders(key(1)) shouldHaveSize 1
            store.getProviders(key(3)) shouldHaveSize 1
            store.getProviders(key(4)) shouldHaveSize 1
        }

        test("addresses are capped when stored, and junk addresses are dropped") {
            val store = BoundedProviderStore(DhtLimits(maxAddressesPerPeer = 4, maxAddressesPerIp = 4))
            val many = (1..1000).map { Multiaddr("/ip4/1.2.3.4/tcp/$it") }
            val raw =
                Dht.Message.Peer
                    .newBuilder()
                    .setId(ByteString.copyFrom(realPeerId().bytes))
                    .addAllAddrs(many.map { ByteString.copyFrom(it.serialize()) })
                    .build()
            store.addProvider(key(1), raw)
            store.getProviders(key(1)).single().addrsCount shouldBe 4
        }

        test("a provider ID that is the wrong size or declares an oversized multihash is rejected") {
            val store = BoundedProviderStore(DhtLimits())
            val tooShort =
                Dht.Message.Peer
                    .newBuilder()
                    .setId(ByteString.copyFrom(ByteArray(10) { 1 }))
                    .build()
            val oversized =
                Dht.Message.Peer
                    .newBuilder()
                    .setId(
                        ByteString.copyFrom(
                            byteArrayOf(0x12, 0xF0.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x07) +
                                ByteArray(30),
                        ),
                    ).build()
            store.addProvider(key(1), tooShort)
            store.addProvider(key(1), oversized)
            store.getProviders(key(1)) shouldHaveSize 0
        }

        test("getProviders returns a snapshot that later additions do not change") {
            val store = BoundedProviderStore(DhtLimits())
            store.addProvider(key(1), provider())
            val snapshot = store.getProviders(key(1))
            repeat(5) { store.addProvider(key(1), provider()) }
            snapshot shouldHaveSize 1
        }

        test("reading while another thread adds does not throw") {
            val store = BoundedProviderStore(DhtLimits())
            store.addProvider(key(1), provider())
            val writer =
                Thread {
                    repeat(2000) { store.addProvider(key(1), provider()) }
                }
            writer.start()
            repeat(2000) { store.getProviders(key(1)).forEach { it.id } }
            writer.join()
        }

        test("a CID key and its bare multihash address the same record") {
            val store = BoundedProviderStore(DhtLimits())
            val cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 5 })
            store.addProvider(cid, provider())
            store.getProviders(cid.bareMultihash()) shouldHaveSize 1
        }
    })
