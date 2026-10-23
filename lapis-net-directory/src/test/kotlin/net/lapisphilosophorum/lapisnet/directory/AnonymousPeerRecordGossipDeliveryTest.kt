package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration

/** The real [GossipPubSub] without any peer: a record is "sent" into the void and must not count as delivered. */
class AnonymousPeerRecordGossipDeliveryTest :
    FunSpec({
        test("without a mesh peer a record is not reported as delivered") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            try {
                node.start(bootstrapPeers = emptyList())
                val pubsub = GossipPubSub.attach(node)
                val storage = NabuStorage.attach(node, Files.createTempDirectory("anon-delivery"))
                val dir = PeerDirectoryGossip.attach(pubsub, storage)
                val gossip = AnonymousPeerRecordGossip.attach(pubsub, dir.anonymousRecords)
                val record = AnonymousPublisher().record(System.currentTimeMillis())

                pubsub.publishReporting(ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC, byteArrayOf(1, 2, 3)) shouldBe false
                shouldThrow<IllegalStateException> {
                    gossip.announceDelivered(record, Duration.ofMillis(300), Duration.ofMillis(50))
                }
                gossip.stop()
            } finally {
                runCatching { node.stop() }
            }
        }
    })
