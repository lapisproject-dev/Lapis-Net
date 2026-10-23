package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/**
 * Two real nodes on loopback, coexistence: an anonymous record travels on its own topic, while the ordinary
 * address-bearing record flow between the same nodes is unchanged, and a node that never subscribed to the anonymous
 * topic (a v0.12.0 node) is not disturbed by it.
 */
class TwoNodeAnonymousPeerRecordGossipIntegrationTest :
    FunSpec({
        test("anonymous and ordinary records coexist, and a node without the anonymous topic keeps working") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate()) // "v0.12.0": no anonymous topic at all
            try {
                listOf(nodeA, nodeB, nodeC).forEach { it.start(bootstrapPeers = emptyList()) }
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val pubsubC = GossipPubSub.attach(nodeC)
                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("anon-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("anon-b"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("anon-c"))
                val dirA = PeerDirectoryGossip.attach(pubsubA, storageA)
                val dirB = PeerDirectoryGossip.attach(pubsubB, storageB)
                val dirC = PeerDirectoryGossip.attach(pubsubC, storageC)
                val anonA = AnonymousPeerRecordGossip.attach(pubsubA, dirA.anonymousRecords)
                val anonB = AnonymousPeerRecordGossip.attach(pubsubB, dirB.anonymousRecords)
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))
                nodeA.connect(PeerInfo(nodeC.peerId, nodeC.listenAddresses()))

                val hidden = AnonymousPublisher()
                val plain = AnonymousPublisher()
                val anonymousRecord = hidden.record(System.currentTimeMillis())
                val plainRecord = plain.peerRecord(sequence = System.currentTimeMillis())
                val now = { Instant.now().epochSecond }

                val deadline = Instant.now().plus(Duration.ofSeconds(25))
                while (Instant.now().isBefore(deadline) &&
                    (
                        dirB.anonymousRecords.current(hidden.key, now()) == null ||
                            dirB.lookup(plain.key) == null ||
                            dirC.lookup(plain.key) == null
                    )
                ) {
                    anonA.announce(anonymousRecord)
                    dirA.announce(plainRecord)
                    Thread.sleep(500)
                }
                dirB.anonymousRecords.current(hidden.key, now()).shouldNotBeNull() shouldBe anonymousRecord
                dirB.lookup(plain.key) shouldBe plainRecord // the ordinary flow is untouched
                dirC.lookup(plain.key).shouldNotBeNull() // the old node still receives ordinary records
                dirC.anonymousRecords.current(hidden.key, now()).shouldBeNull() // and never sees the anonymous topic

                // a node in anonymity mode superseding its address record: B drops the old address entry
                val migrating = AnonymousPublisher()
                val oldAddress = migrating.peerRecord(sequence = System.currentTimeMillis())
                while (Instant.now().isBefore(deadline) && dirB.lookup(migrating.key) == null) {
                    dirA.announce(oldAddress)
                    Thread.sleep(500)
                }
                dirB.lookup(migrating.key).shouldNotBeNull()
                val newer = migrating.record(oldAddress.sequenceNumber + 1)
                while (Instant.now().isBefore(deadline) &&
                    dirB.anonymousRecords.current(migrating.key, now()) == null
                ) {
                    anonA.announce(newer)
                    Thread.sleep(500)
                }
                dirB.anonymousRecords.current(migrating.key, now()).shouldNotBeNull()
                dirB.lookup(migrating.key).shouldBeNull() // the old address entry is gone on B

                anonA.stop()
                anonB.stop()
                listOf(dirA, dirB, dirC).forEach { it.stop() }
                listOf(pubsubA, pubsubB, pubsubC).forEach { it.stop() }
            } finally {
                listOf(nodeA, nodeB, nodeC).forEach { runCatching { it.stop() } }
            }
        }
    })
