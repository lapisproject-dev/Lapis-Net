package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * What a DHT response says about a peer's addresses is unverified. It may be used for one dial, but
 * the address book - which is capped per peer and never expires - only receives an address over which
 * the peer on the far end really proved to be that peer. Otherwise a responder could fill the address
 * book with peers that never answered, and fill an honest peer's capped entry with made-up addresses so
 * that the real ones could never be learned afterwards.
 */
class DhtFetchAddressVerificationTest :
    FunSpec({
        val limits = DhtLimits(fetchConnectTimeout = Duration.ofSeconds(1), perRpcTimeout = Duration.ofSeconds(1))

        fun LapisNode.addressesOf(peer: PeerId): List<String> =
            host.addressBook
                .getAddrs(peer)
                .join()
                .orEmpty()
                .map { it.toString() }

        fun providerReply(
            hostile: ScriptedDhtPeer,
            vararg providers: Dht.Message.Peer,
        ) = hostile.answer(Dht.Message.MessageType.GET_PROVIDERS) {
            it.toBuilder().addAllProviderPeers(providers.toList()).build()
        }

        fun loopback(port: Int) = Multiaddr("/ip4/127.0.0.1/tcp/$port").serialize()

        val cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 11 })

        test("providers that never answered are not remembered, however often they are named").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            val hostile = ScriptedDhtPeer.start()
            CountingListener().use { silent ->
                try {
                    val storage = storageOn(victim, limits)
                    val fakes = List(8) { realPeerId() }
                    providerReply(hostile, *fakes.map { peerProto(it, listOf(loopback(silent.port))) }.toTypedArray())
                    storage.connectToDhtPeer(hostile.address) shouldBe true

                    repeat(3) { storage.get(cid, timeout = Duration.ofSeconds(4)) shouldBe null }

                    silent.acceptedCount shouldBeGreaterThanOrEqual 1 // the dials were really made
                    fakes.forEach { victim.addressesOf(it) shouldHaveSize 0 }
                } finally {
                    hostile.stop()
                    victim.stop()
                }
            }
        }

        test("made-up addresses for an honest provider are not stored, so its real address is still learned").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            val honest = newNode()
            val hostile = ScriptedDhtPeer.start()
            CountingListener().use { silent ->
                try {
                    val storage = storageOn(victim, limits)
                    val honestStorage = storageOn(honest)
                    val payload = "block of the honest provider".toByteArray()
                    val realCid = honestStorage.put(payload)
                    storage.connectToDhtPeer(hostile.address) shouldBe true

                    // first the hostile responder names the honest provider with addresses that lead nowhere
                    providerReply(hostile, peerProto(honest.peerId, listOf(loopback(silent.port))))
                    storage.get(realCid, timeout = Duration.ofSeconds(4)) shouldBe null
                    victim.addressesOf(honest.peerId) shouldHaveSize 0

                    // then it names the real address: the fetch works and exactly that address is remembered
                    providerReply(hostile, peerProto(honest.peerId, listOf(addressOf(honest).serialize())))
                    storage.get(realCid, timeout = Duration.ofSeconds(10)) shouldBe payload
                    victim.addressesOf(honest.peerId) shouldBe listOf(addressOf(honest).toString())
                } finally {
                    hostile.stop()
                    honest.stop()
                    victim.stop()
                }
            }
        }

        test("an address that leads to a different peer than the one named is neither used nor stored").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            val honest = newNode()
            val hostile = ScriptedDhtPeer.start()
            try {
                val storage = storageOn(victim, limits)
                val honestStorage = storageOn(honest)
                val realCid = honestStorage.put("not for the impostor".toByteArray())
                storage.connectToDhtPeer(hostile.address) shouldBe true
                val impostor = realPeerId()
                // the honest node's address, claimed for another peer ID
                val withoutPeerId = honest.listenAddresses().first().serialize()
                providerReply(hostile, peerProto(impostor, listOf(withoutPeerId)))

                storage.get(realCid, timeout = Duration.ofSeconds(4)) shouldBe null

                victim.addressesOf(impostor) shouldHaveSize 0
                victim.addressesOf(honest.peerId) shouldHaveSize 0
            } finally {
                hostile.stop()
                honest.stop()
                victim.stop()
            }
        }

        test("a responder cannot make this node store made-up addresses for a peer it is already connected to").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            val honest = newNode()
            val hostile = ScriptedDhtPeer.start()
            CountingListener().use { silent ->
                try {
                    val storage = storageOn(victim, limits)
                    storageOn(honest)
                    // connected, but not in the routing table and not in the address book
                    victim.connect(PeerInfo(honest.peerId, honest.listenAddresses()))
                    storage.connectToDhtPeer(hostile.address) shouldBe true
                    val fake = loopback(silent.port)
                    hostile.answer(Dht.Message.MessageType.FIND_NODE) {
                        it.toBuilder().addCloserPeers(peerProto(honest.peerId, listOf(fake))).build()
                    }

                    storage.provide(cid, Duration.ofSeconds(4))

                    victim.addressesOf(honest.peerId).none { it.contains("/tcp/${silent.port}") } shouldBe true
                } finally {
                    hostile.stop()
                    honest.stop()
                    victim.stop()
                }
            }
        }
    })
