package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class SelfRecordRepublisherTest :
    FunSpec({
        class Fixture(
            withDht: Boolean = false,
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
            val storage = NabuStorage.attach(node, Files.createTempDirectory("republisher-test"))
            val pubsub = GossipPubSub.attach(node)
            val directory = PeerDirectoryGossip.attach(pubsub, storage)
            val bundles = PrekeyBundleGossip.attach(pubsub, storage)
            val prekeys =
                PrekeyStore.create(
                    Files.createTempDirectory("republisher-prekeys"),
                    identity,
                    passphraseProvider = { null },
                )
            val dht = if (withDht) DirectoryDht.attach(storage, directory, bundles, DirectoryDhtLimits()) else null
            var addresses: List<Multiaddr> = listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001"))
            var now = System.currentTimeMillis()
            val republisher =
                SelfRecordRepublisher(
                    identity = identity,
                    addresses = { addresses },
                    peerDirectory = directory,
                    prekeyBundleGossip = bundles,
                    prekeyStore = prekeys,
                    directoryDht = dht,
                    outbox = null,
                    maxGossipInterval = 6.hours,
                    minDhtAttemptInterval = 300.seconds,
                    clockMillis = { now },
                )

            fun stop() {
                runCatching { directory.stop() }
                runCatching { bundles.stop() }
                runCatching { pubsub.stop() }
                runCatching { storage.stop() }
                runCatching { node.stop() }
            }
        }

        test("the first tick publishes; further ticks without a change do nothing") {
            val f = Fixture()
            try {
                f.republisher.tick()
                f.republisher.gossipPublications shouldBe 1
                f.now += 60_000
                f.republisher.tick()
                f.republisher.tick()
                f.republisher.gossipPublications shouldBe 1
            } finally {
                f.stop()
            }
        }

        test(
            "changed addresses (a relay reservation arrived) are re-published and become the tracked record",
        ) {
            val f = Fixture()
            try {
                f.republisher.tick()
                val first = f.directory.lookup(f.identity.secp256k1KeyPair.publicKey).shouldNotBeNull()
                val changed = Multiaddr("/ip4/127.0.0.1/tcp/4002")
                f.addresses = f.addresses + changed
                f.now += 1_000
                f.republisher.tick()
                f.republisher.gossipPublications shouldBe 2
                val second = f.directory.lookup(f.identity.secp256k1KeyPair.publicKey).shouldNotBeNull()
                second.addresses shouldContain changed
                (second.sequenceNumber > first.sequenceNumber) shouldBe true
            } finally {
                f.stop()
            }
        }

        test("a refresh happens at the latest after maxGossipInterval even if nothing changed") {
            val f = Fixture()
            try {
                f.republisher.tick()
                f.now += 6.hours.inWholeMilliseconds - 1
                f.republisher.tick()
                f.republisher.gossipPublications shouldBe 1
                f.now += 2
                f.republisher.tick()
                f.republisher.gossipPublications shouldBe 2
            } finally {
                f.stop()
            }
        }

        test("the capability set stays {DM} - never RELAY") {
            val f = Fixture()
            try {
                f.republisher.tick()
                f.directory
                    .lookup(f.identity.secp256k1KeyPair.publicKey)
                    .shouldNotBeNull()
                    .capabilities shouldBe
                    setOf(PeerCapability.DM)
            } finally {
                f.stop()
            }
        }

        test("the very first DHT attempt is not blocked, later ones are throttled to one per interval") {
            val f = Fixture(withDht = true)
            try {
                f.republisher.dhtAttempts shouldBe 0
                f.republisher.tick()
                // regression: a clock overflow once made the first attempt "never due"
                f.republisher.dhtAttempts shouldBe 1
                f.addresses = listOf(Multiaddr("/ip4/127.0.0.1/tcp/4004"))
                f.now += 10_000
                f.republisher.tick()
                f.republisher.dhtAttempts shouldBe 1 // changed again, but inside the 300 s attempt window
                f.now += 300_000
                f.republisher.tick()
                f.republisher.dhtAttempts shouldBe 2
            } finally {
                f.stop()
            }
        }

        test("includeDht=false never touches the DHT; an unreachable DHT never breaks the gossip republication") {
            val f = Fixture(withDht = true)
            try {
                f.republisher.tick(includeDht = false)
                f.republisher.dhtPublications shouldBe 0
                f.republisher.gossipPublications shouldBe 1
                f.addresses = listOf(Multiaddr("/ip4/127.0.0.1/tcp/4003"))
                shouldNotThrowAny { f.republisher.tick() } // a lone node has no DHT peers: the attempt may fail
                f.republisher.gossipPublications shouldBe 2
            } finally {
                f.stop()
            }
        }

        test("a DHT publication nobody acknowledged is not done: it is retried after the attempt interval") {
            val f = Fixture(withDht = true)
            try {
                // a lone node has no DHT peers: the value is held locally only (0 acknowledged)
                f.republisher.tick()
                f.republisher.dhtAttempts shouldBe 1
                f.republisher.dhtPublications shouldBe 0
                f.now += 60_000
                f.republisher.tick()
                f.republisher.dhtAttempts shouldBe 1 // still inside the attempt window
                f.now += 300_000
                f.republisher.tick() // nothing changed, yet it must try again (not marked done)
                f.republisher.dhtAttempts shouldBe 2
                f.republisher.dhtPublications shouldBe 0
            } finally {
                f.stop()
            }
        }
    })
