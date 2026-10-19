package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.X3dh
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

/** One node with everything attached: storage, pubsub, both gossip classes and the DHT fallback. */
private class DirectoryNode(
    val who: DirectoryPublisher = DirectoryPublisher(),
    limits: DirectoryDhtLimits = DirectoryDhtLimits(),
) {
    val node: LapisNode = LapisNode.create(who.identity).also { it.start(bootstrapPeers = emptyList()) }
    val storage: NabuStorage = NabuStorage.attach(node, Files.createTempDirectory("directory-dht-it"))
    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val gossip: PeerDirectoryGossip = PeerDirectoryGossip.attach(pubsub, storage)
    val prekeys: PrekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
    val dht: DirectoryDht = DirectoryDht.attach(storage, gossip, prekeys, limits)

    val dhtAddress get() = node.listenAddresses().first().withP2P(node.peerId)

    fun connectGossip(other: DirectoryNode) {
        node.connect(PeerInfo(other.node.peerId, other.node.listenAddresses()))
    }

    fun stop() {
        runCatching { gossip.stop() }
        runCatching { prekeys.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

private fun until(
    seconds: Long,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plusSeconds(seconds)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(250)
    }
    return condition()
}

class ThreeNodeDirectoryDhtIntegrationTest :
    FunSpec({
        test(
            "a node that missed the gossip window catches up through the DHT, X3DH works against the bundle, and nothing is gossiped on",
        ).config(
            timeout = 180.seconds,
        ) {
            val a = DirectoryNode(limits = DirectoryDhtLimits(minRepublishInterval = Duration.ZERO))
            val b = DirectoryNode()
            val c = DirectoryNode()
            val d = DirectoryNode()
            try {
                // A and B are in the gossip mesh and in each other's DHT routing table
                a.connectGossip(b)
                a.storage.connectToDhtPeer(b.dhtAddress) shouldBe true

                val record = a.who.peerRecord(sequence = 1)
                val bundle = a.who.bundle(sequence = 1)
                var seenByB = b.gossip.lookup(a.who.key)
                val gossipDeadline = Instant.now().plusSeconds(25)
                while (seenByB == null && Instant.now().isBefore(gossipDeadline)) {
                    a.gossip.announce(record)
                    Thread.sleep(500)
                    seenByB = b.gossip.lookup(a.who.key)
                }
                seenByB.shouldNotBeNull()
                a.dht.publishOwn(a.who.identity, record, bundle).acknowledged shouldBe 1

                // C is not part of any of this; wait until GossipSub's message history is gone for sure
                Thread.sleep(7_000)
                c.gossip.lookup(a.who.key).shouldBeNull()

                // D joins C's gossip mesh first, proven by a canary that goes C -> D
                d.connectGossip(c)
                val canary = c.who.peerRecord(sequence = 0)
                until(25) {
                    c.gossip.announce(canary)
                    d.gossip.lookup(c.who.key) != null
                } shouldBe true

                // now C reaches the DHT (via B) and resolves A with the peer ID hint
                c.storage.connectToDhtPeer(b.dhtAddress) shouldBe true
                c.dht.resolve(a.who.key, a.who.peerId, Duration.ofSeconds(10)) shouldBe
                    DirectoryDhtResolution.Found(peerRecordAccepted = true, prekeyBundleAccepted = true)
                c.gossip.lookup(a.who.key) shouldBe record
                c.prekeys.lookup(a.who.key) shouldBe bundle

                // X3DH end to end against the resolved bundle
                val x25519 = X25519KeyPair.generate()
                val resolvedBundle = c.dht.lookupPrekeyBundle(a.who.key, a.who.peerId)!!
                val initiation =
                    X3dh.initiate(
                        initiatorIdentity = c.who.key,
                        initiatorEncryptionBinding =
                            EncryptionKeyBinding.create(
                                c.who.identity.secp256k1KeyPair,
                                x25519.publicKey,
                            ),
                        initiatorX25519IdentityPrivateKey = x25519.privateKey,
                        bundle = resolvedBundle,
                    )
                initiation.shouldNotBeNull()

                // what came from the DHT is not gossiped on: D, in C's mesh, never gets A's record
                Thread.sleep(4_000)
                d.gossip.lookup(a.who.key).shouldBeNull()
                d.prekeys.lookup(a.who.key).shouldBeNull()
            } finally {
                listOf(a, b, c, d).forEach { it.stop() }
            }
        }

        test(
            "catchUp finds an identity through the peer ID of an old record, and refreshStale renews an expired record",
        ).config(
            timeout = 180.seconds,
        ) {
            val fast =
                DirectoryDhtLimits(
                    minRepublishInterval = Duration.ZERO,
                    minResolveInterval = Duration.ZERO,
                    negativeCacheTtl = Duration.ZERO,
                )
            val a = DirectoryNode(limits = fast)
            val b = DirectoryNode()
            val c = DirectoryNode(limits = fast)
            try {
                a.storage.connectToDhtPeer(b.dhtAddress) shouldBe true
                c.storage.connectToDhtPeer(b.dhtAddress) shouldBe true

                val shortLived = a.who.peerRecord(sequence = 1, expiresInSeconds = 3)
                a.dht.publishOwn(a.who.identity, shortLived, null).acknowledged shouldBe 1
                // no peer ID known yet: skipped without a network call
                c.dht.catchUp(listOf(a.who.key), Duration.ofSeconds(5)) shouldBe CatchUpReport(0, 0, 1)
                c.dht.resolve(a.who.key, a.who.peerId, Duration.ofSeconds(10)) shouldBe
                    DirectoryDhtResolution.Found(peerRecordAccepted = true, prekeyBundleAccepted = false)

                // the record expires; A renews it
                Thread.sleep(4_500)
                c.gossip.lookup(a.who.key).shouldBeNull()
                val renewed = a.who.peerRecord(sequence = 2, expiresInSeconds = 3600)
                a.dht.publishOwn(a.who.identity, renewed, null).acknowledged shouldBe 1

                // the old record still tells C where to ask: catchUp needs no hint now
                c.dht.refreshStale() shouldBe CatchUpReport(attempted = 1, found = 1, skipped = 0)
                c.gossip.lookup(a.who.key) shouldBe renewed
            } finally {
                listOf(a, b, c).forEach { it.stop() }
            }
        }
    })
