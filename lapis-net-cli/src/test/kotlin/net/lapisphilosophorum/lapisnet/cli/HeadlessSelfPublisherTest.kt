package net.lapisphilosophorum.lapisnet.cli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class HeadlessSelfPublisherTest :
    FunSpec({
        test("a DHT publication nobody acknowledged is not done: it is retried after the attempt interval") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
            val storage = NabuStorage.attach(node, Files.createTempDirectory("headless-publisher-test"))
            val pubsub = GossipPubSub.attach(node)
            val directory = PeerDirectoryGossip.attach(pubsub, storage)
            val bundles = PrekeyBundleGossip.attach(pubsub, storage)
            val dht = DirectoryDht.attach(storage, directory, bundles, DirectoryDhtLimits())
            var now = System.currentTimeMillis()
            val publisher =
                HeadlessSelfPublisher(
                    identity = identity,
                    addresses = { listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001")) },
                    peerDirectory = directory,
                    directoryDht = dht,
                    minDhtAttemptInterval = 300.seconds,
                    maxInterval = 6.hours,
                    clockMillis = { now },
                )
            try {
                // a lone node has no DHT peers: the value is held locally only (0 acknowledged)
                publisher.tick()
                publisher.dhtAttempts shouldBe 1
                publisher.dhtPublications shouldBe 0
                now += 60_000
                publisher.tick()
                publisher.dhtAttempts shouldBe 1 // still inside the attempt window
                now += 300_000
                publisher.tick() // nothing changed, yet it must try again (not marked done)
                publisher.dhtAttempts shouldBe 2
                publisher.dhtPublications shouldBe 0
            } finally {
                runCatching { directory.stop() }
                runCatching { bundles.stop() }
                runCatching { pubsub.stop() }
                runCatching { storage.stop() }
                runCatching { node.stop() }
            }
        }
    })
