package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.libp2p.core.PeerInfo
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

/** A [RemoteContentSource] that answers from maps and counts the calls. */
private class MapSource(
    val blocks: Map<String, ByteArray> = emptyMap(),
    val records: Map<String, ByteArray> = emptyMap(),
) : RemoteContentSource {
    var cachedAsks = 0

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray? = blocks[cid.toString()]

    override fun resolveIpnsRecord(
        name: ByteArray,
        timeout: Duration,
    ): ByteArray? = records[name.toHexString()]

    override fun blockIfCached(cid: Cid): ByteArray? {
        cachedAsks++
        return blocks[cid.toString()]
    }
}

/** Wave V0.10.0-J1a: [StorageNetworkMode.LOCAL_ONLY] serves nothing and reaches nobody directly. */
class NabuStorageLocalOnlyTest :
    FunSpec({
        test("every network operation is refused; local reads work; without a source a miss is null") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            node.start()
            try {
                val storage =
                    NabuStorage.attach(
                        node,
                        Files.createTempDirectory("local-only"),
                        networkMode = StorageNetworkMode.LOCAL_ONLY,
                    )
                val cid = storage.put("held locally".toByteArray())
                storage.get(cid) shouldBe "held locally".toByteArray()
                storage.getLocal(cid) shouldBe "held locally".toByteArray()
                // a CID of a block this node does not hold (computed by a second, local-only store elsewhere)
                val missing =
                    Cid.buildCidV1(
                        Cid.Codec.Raw,
                        io.ipfs.multihash.Multihash.Type.sha2_256,
                        sha256("not here"),
                    )
                storage.get(missing).shouldBeNull()
                val refusals =
                    listOf<() -> Unit>(
                        { storage.provide(cid) },
                        { storage.findProviders(cid) },
                        { storage.get(missing, peers = setOf(node.peerId)) },
                        {
                            storage.publishIpnsValue(
                                generateKeyPair(KeyType.ED25519).first,
                                byteArrayOf(1),
                                1,
                                Instant.now().plusSeconds(600),
                            )
                        },
                        { storage.registerPeerAddress(node.listenAddresses().first().withP2P(node.peerId)) },
                        { storage.connectToDhtPeer(node.listenAddresses().first().withP2P(node.peerId)) },
                    )
                for (call in refusals) {
                    val e = shouldThrow<AnonymousStorageRefusedException> { call() }
                    e.message!! shouldNotContain cid.toString()
                }
                storage.refusedNetworkOperations shouldBe refusals.size.toLong()
                // nothing registered on the host: neither Bitswap nor Kademlia
                node.host.getProtocols().flatMap { it.protocolDescriptor.announceProtocols }.none {
                    it.contains("bitswap") || it.contains("kad")
                } shouldBe true
            } finally {
                node.stop()
            }
        }

        test("a foreign node can neither fetch a block from nor enter the DHT of a local-only node").config(
            timeout = 60.seconds,
        ) {
            val anonymous = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            val other = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                anonymous.start()
                other.start()
                val local =
                    NabuStorage.attach(
                        anonymous,
                        Files.createTempDirectory("local-only-a"),
                        networkMode = StorageNetworkMode.LOCAL_ONLY,
                    )
                val network = NabuStorage.attach(other, Files.createTempDirectory("network-b"))
                val cid = local.put("a block only the anonymous node holds".toByteArray())
                other.connect(PeerInfo(anonymous.peerId, anonymous.listenAddresses()))
                val address = anonymous.listenAddresses().first().withP2P(anonymous.peerId)
                network.registerPeerAddress(address)
                network.get(cid, peers = setOf(anonymous.peerId), timeout = Duration.ofSeconds(5)).shouldBeNull()
                network.connectToDhtPeer(address, Duration.ofSeconds(5)) shouldBe false
            } finally {
                runCatching { anonymous.stop() }
                runCatching { other.stop() }
            }
        }

        test("the remote source: a matching block is used and stored unserved, a forged one is dropped") {
            val helper = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also { it.start() }
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            node.start()
            try {
                val scratch = NabuStorage.attach(helper, Files.createTempDirectory("scratch"))
                val good = "fetched over a circuit".toByteArray()
                val goodCid = scratch.put(good)
                val forgedCid = scratch.put("what the CID names".toByteArray())
                val source =
                    MapSource(
                        blocks =
                            mapOf(
                                goodCid.toString() to good,
                                forgedCid.toString() to "something else".toByteArray(),
                            ),
                    )
                val storage =
                    NabuStorage.attach(
                        node,
                        Files.createTempDirectory("local-only-remote"),
                        networkMode = StorageNetworkMode.LOCAL_ONLY,
                        remote = source,
                    )
                storage.get(goodCid) shouldBe good
                storage.getLocal(goodCid) shouldBe good
                storage.get(forgedCid).shouldBeNull()
                storage.getLocal(forgedCid).shouldBeNull()
            } finally {
                runCatching { node.stop() }
                runCatching { helper.stop() }
            }
        }

        test("the remote source: an IPNS record is validated here; a record of another name or tampered is dropped") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            node.start()
            try {
                val publisher = IpnsIdentity.generate()
                val stranger = IpnsIdentity.generate()
                val record = publisher.record(value = "value".toByteArray(), sequence = 7)
                val source =
                    MapSource(
                        records =
                            mapOf(
                                publisher.key.toHexString() to record,
                                // a valid record, but of another name
                                stranger.key.toHexString() to publisher.record(),
                            ),
                    )
                val storage =
                    NabuStorage.attach(
                        node,
                        Files.createTempDirectory("local-only-ipns"),
                        networkMode = StorageNetworkMode.LOCAL_ONLY,
                        remote = source,
                    )
                val value = storage.resolveIpnsValue(publisher.peerId).shouldNotBeNull()
                value.value shouldBe "value".toByteArray()
                value.sequence shouldBe 7
                storage.resolveIpnsValue(stranger.peerId).shouldBeNull()
                val tampered =
                    MapSource(records = mapOf(publisher.key.toHexString() to tamper(record) { it.setSequence(99) }))
                val node2 = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also { it.start() }
                try {
                    NabuStorage
                        .attach(
                            node2,
                            Files.createTempDirectory("local-only-ipns-2"),
                            networkMode = StorageNetworkMode.LOCAL_ONLY,
                            remote = tampered,
                        ).resolveIpnsValue(publisher.peerId)
                        .shouldBeNull()
                } finally {
                    node2.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("mode NETWORK is unchanged: Bitswap and Kademlia are registered") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            node.start()
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("network"))
                storage.networkMode shouldBe StorageNetworkMode.NETWORK
                val ids = node.host.getProtocols().flatMap { it.protocolDescriptor.announceProtocols }
                ids.any { it.contains("bitswap") } shouldBe true
                ids.any { it.contains("kad") } shouldBe true
            } finally {
                node.stop()
            }
        }
    })

private fun sha256(text: String): ByteArray =
    java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(text.toByteArray())

private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
