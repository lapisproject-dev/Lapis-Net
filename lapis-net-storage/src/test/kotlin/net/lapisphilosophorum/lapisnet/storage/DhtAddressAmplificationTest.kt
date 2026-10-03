package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * V0.9.11 / finding C (address amplification): a peer entry in a DHT response may name any number of
 * addresses, and Nabu dials ALL of them in parallel - one response entry is a request to open
 * hundreds of connections to hosts of the responder's choosing. Here a hostile responder names
 * addresses that all point at counting TCP listeners; the victim must open no more connections than
 * its limits allow, over both the FIND_NODE path (walk / announce) and the GET_PROVIDERS path
 * (lookup + Bitswap fetch).
 */
class DhtAddressAmplificationTest :
    FunSpec({
        /** 400 addresses, the first 32 (the whole parse window) valid and pointing at the listeners. */
        fun hostileAddresses(
            listeners: List<CountingListener>,
            hosts: List<String>,
        ): List<ByteArray> {
            val valid =
                (0 until 32).map {
                    val i = it % listeners.size
                    Multiaddr("/ip4/${hosts[i]}/tcp/${listeners[i].port}").serialize()
                }
            val junk = (0 until 368).map { byteArrayOf(it.toByte(), 1, 2, 3) }
            return valid + junk
        }

        fun runScenario(
            limits: DhtLimits,
            maxAccepts: Int,
            viaProviders: Boolean,
            distinctHosts: Boolean = false,
        ) {
            // distinct 127.0.0.k addresses exist only on Linux; elsewhere every listener shares 127.0.0.1
            val hosts = List(64) { if (distinctHosts) "127.0.0.${it + 1}" else "127.0.0.1" }
            val listeners = hosts.map { CountingListener(it) }
            val hostile = ScriptedDhtPeer.start()
            val victim = newNode()
            try {
                val storage = storageOn(victim, limits)
                val x = realPeerId()
                val entry = peerProto(x, hostileAddresses(listeners, hosts))
                if (viaProviders) {
                    hostile.answer(
                        Dht.Message.MessageType.GET_PROVIDERS,
                    ) { it.toBuilder().addProviderPeers(entry).build() }
                } else {
                    hostile.answer(Dht.Message.MessageType.FIND_NODE) { it.toBuilder().addCloserPeers(entry).build() }
                }
                storage.connectToDhtPeer(hostile.address) shouldBe true

                if (viaProviders) {
                    val cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 3 })
                    storage.get(cid, timeout = Duration.ofSeconds(2))
                    val stored =
                        victim.host.addressBook
                            .getAddrs(x)
                            .join()
                            .orEmpty()
                    stored.size shouldBeLessThanOrEqual limits.maxAddressesPerPeer
                } else {
                    storage.provide(
                        Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 4 }),
                        Duration.ofSeconds(3),
                    )
                }
                Thread.sleep(1_500) // let every connection attempt that is going to be made, be made

                val accepted = listeners.sumOf { it.acceptedCount }
                accepted shouldBeGreaterThanOrEqual 1 // the scenario really reached the dial
                accepted shouldBeLessThanOrEqual maxAccepts
            } finally {
                hostile.stop()
                victim.stop()
                listeners.forEach { it.close() }
            }
        }

        val perPeer8 = DhtLimits(maxAddressesPerPeer = 8, maxAddressesPerIp = 8, perRpcTimeout = Duration.ofMillis(500))
        val perIp2 = DhtLimits(perRpcTimeout = Duration.ofMillis(500))

        test(
            "FIND_NODE response: a 400-address peer entry costs at most maxAddressesPerPeer connection attempts",
        ).config(
            timeout = 60.seconds,
        ) { runScenario(perPeer8, maxAccepts = 8, viaProviders = false) }

        test("FIND_NODE response: at most maxAddressesPerIp attempts per host with the default limits").config(
            timeout = 60.seconds,
        ) { runScenario(perIp2, maxAccepts = 2, viaProviders = false) }

        test(
            "GET_PROVIDERS response: a 400-address provider costs at most maxAddressesPerPeer attempts in get()",
        ).config(
            timeout = 60.seconds,
        ) { runScenario(perPeer8, maxAccepts = 8, viaProviders = true) }

        test("GET_PROVIDERS response: at most maxAddressesPerIp attempts per host with the default limits").config(
            timeout = 60.seconds,
        ) { runScenario(perIp2, maxAccepts = 2, viaProviders = true) }

        val onLinux = System.getProperty("os.name").lowercase().contains("linux")

        test(
            "FIND_NODE response: 32 valid addresses on 32 different hosts still cost at most maxAddressesPerPeer attempts",
        ).config(
            timeout = 60.seconds,
            enabled = onLinux,
        ) { runScenario(perIp2, maxAccepts = 8, viaProviders = false, distinctHosts = true) }

        test(
            "GET_PROVIDERS response: 32 valid addresses on 32 different hosts still cost at most maxAddressesPerPeer attempts",
        ).config(
            timeout = 60.seconds,
            enabled = onLinux,
        ) { runScenario(perIp2, maxAccepts = 8, viaProviders = true, distinctHosts = true) }

        test("a hostile response naming our own ID or an unparseable ID changes nothing and breaks nothing").config(
            timeout = 60.seconds,
        ) {
            val hostile = ScriptedDhtPeer.start()
            val victim = newNode()
            try {
                val storage = storageOn(victim, DhtLimits(perRpcTimeout = Duration.ofMillis(500)))
                val selfEntry = peerProto(victim.peerId, listOf(Multiaddr("/ip4/127.0.0.1/tcp/9").serialize()))
                val shortId = peerProto(PeerId.random(), listOf(Multiaddr("/ip4/127.0.0.1/tcp/9").serialize()))
                hostile.answer(Dht.Message.MessageType.FIND_NODE) {
                    it
                        .toBuilder()
                        .addCloserPeers(selfEntry)
                        .addCloserPeers(shortId)
                        .build()
                }
                storage.connectToDhtPeer(hostile.address) shouldBe true
                storage.provide(
                    Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 5 }),
                    Duration.ofSeconds(3),
                )
                // our own entry in the address book is still exactly our listen addresses
                victim.host.addressBook
                    .getAddrs(victim.peerId)
                    .join()
                    .orEmpty()
                    .map { it.toString() }
                    .toSet() shouldBe victim.listenAddresses().map { it.toString() }.toSet()
            } finally {
                hostile.stop()
                victim.stop()
            }
        }
    })
