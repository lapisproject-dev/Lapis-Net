package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordCodec
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordGossip
import net.lapisphilosophorum.lapisnet.directory.ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorGossip
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.onion.DirectoryObjectType
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishStatus
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Clock
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The relay-side validation of [GossipDirectoryPublishSink]: rejection paths and the "no oracle" property (a valid but
 * known or superseded object is answered like a new one, but is not published again).
 */
class GossipDirectoryPublishSinkTest :
    FunSpec({
        val clock = Clock.systemUTC()
        val identity = DualKeyIdentity.generate()
        val node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
        val storage =
            NabuStorage.attach(
                node,
                Files.createTempDirectory("sink-test").resolve("storage").also { Files.createDirectories(it) },
            )
        val pubsub = GossipPubSub.attach(node)
        val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
        val serviceIndex = OnionServiceDescriptorIndex()
        val published = CopyOnWriteArrayList<Pair<String, ByteArray>>()
        pubsub.outboundTap = { topic, bytes -> published += topic to bytes }
        val sink =
            GossipDirectoryPublishSink(
                AnonymousPeerRecordGossip.attach(pubsub, peerDirectory.anonymousRecords, clock),
                OnionServiceDescriptorGossip.attach(pubsub, serviceIndex, clock),
                serviceIndex,
                pubsub,
                clock,
            )
        afterSpec {
            runCatching { peerDirectory.stop() }
            runCatching { pubsub.stop() }
            runCatching { storage.stop() }
            runCatching { node.stop() }
        }

        fun now() = clock.millis() / 1000

        fun count(topic: String) = published.count { it.first == topic }

        fun anonymousRecord(
            seq: Long,
            notValidAfter: Long = now() + 600,
            at: Long = now(),
        ) = AnonymousPeerRecord.create(
            identity,
            Ed25519KeyPair.generate(),
            setOf(AnonymousCapability.DM),
            null,
            seq,
            notValidAfter,
            at,
        )

        test("garbage of every type is MALFORMED") {
            for (type in DirectoryObjectType.entries) {
                sink.publish(type, ByteArray(5) { 3 }) shouldBe DirectoryPublishStatus.MALFORMED
            }
        }

        test("anonymous record: new is published, duplicate re-announced, stale not republished, invalid rejected") {
            val topic = ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC
            val newer = AnonymousPeerRecordCodec.encode(anonymousRecord(2_000))
            sink.publish(DirectoryObjectType.ANONYMOUS_PEER_RECORD, newer) shouldBe DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 1
            // known: same answer, announced again on purpose (the first publication may have found no mesh peer)
            sink.publish(DirectoryObjectType.ANONYMOUS_PEER_RECORD, newer) shouldBe DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 2
            // superseded: same answer (no oracle), nothing published
            val older = AnonymousPeerRecordCodec.encode(anonymousRecord(1_000))
            sink.publish(DirectoryObjectType.ANONYMOUS_PEER_RECORD, older) shouldBe DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 2
            // expired
            val expired = AnonymousPeerRecordCodec.encode(anonymousRecord(3_000, now() - 10, now() - 1_000))
            sink.publish(DirectoryObjectType.ANONYMOUS_PEER_RECORD, expired) shouldBe DirectoryPublishStatus.INVALID
            // tampered signature
            val tampered = AnonymousPeerRecordCodec.encode(anonymousRecord(4_000))
            tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x55).toByte()
            sink.publish(DirectoryObjectType.ANONYMOUS_PEER_RECORD, tampered) shouldBe DirectoryPublishStatus.INVALID
            count(topic) shouldBe 2
        }

        test("service descriptor: new and duplicate are published, expired and tampered are INVALID") {
            val topic = ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC

            fun descriptor(
                seq: Long,
                at: Long = now(),
            ): OnionServiceDescriptor {
                val relay = Secp256k1KeyPair.generate()
                val binding = OnionKeyBinding.create(relay, X25519KeyPair.generate().publicKey, at + 3_600)
                return OnionServiceDescriptor.create(
                    Ed25519KeyPair.generate(),
                    X25519KeyPair.generate().publicKey,
                    listOf(IntroPointEntry(binding, Ed25519KeyPair.generate().publicKey)),
                    seq,
                    at + 600,
                    at,
                )
            }

            val bytes = OnionServiceDescriptorCodec.encode(descriptor(1))
            sink.publish(DirectoryObjectType.ONION_SERVICE_DESCRIPTOR, bytes) shouldBe DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 1
            // a retry through the same relay (first publish found no mesh peer) must have an effect
            sink.publish(DirectoryObjectType.ONION_SERVICE_DESCRIPTOR, bytes) shouldBe DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 2
            val tampered = OnionServiceDescriptorCodec.encode(descriptor(2))
            tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x55).toByte()
            sink.publish(DirectoryObjectType.ONION_SERVICE_DESCRIPTOR, tampered) shouldBe
                DirectoryPublishStatus.INVALID
            val expired = OnionServiceDescriptorCodec.encode(descriptor(3, now() - 5_000))
            sink.publish(DirectoryObjectType.ONION_SERVICE_DESCRIPTOR, expired) shouldBe
                DirectoryPublishStatus.INVALID
            count(topic) shouldBe 2
        }

        test("prekey bundle: new is published once, duplicate and stale are ACCEPTED without republication") {
            val topic = PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC
            val prekeys = PrekeyStore.create(Files.createTempDirectory("sink-prekeys"), identity)
            val first = prekeys.publishBundle(identity, now() + 600)
            val second = prekeys.publishBundle(identity, now() + 600)
            val (older, newer) =
                if (first.sequenceNumber <= second.sequenceNumber) first to second else second to first
            val newerBytes = PrekeyBundleCodec.encode(newer)
            sink.publish(DirectoryObjectType.PREKEY_BUNDLE, newerBytes) shouldBe DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 1
            // duplicate and stale: same answer (no oracle), but nothing goes onto the topic again
            sink.publish(DirectoryObjectType.PREKEY_BUNDLE, newerBytes) shouldBe DirectoryPublishStatus.ACCEPTED
            sink.publish(DirectoryObjectType.PREKEY_BUNDLE, PrekeyBundleCodec.encode(older)) shouldBe
                DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe 1
        }

        test("prekey bundle already known to the node's own index is ACCEPTED but not republished") {
            val topic = PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC
            val nodeBundles = PrekeyBundleGossip.attach(pubsub, storage)
            val knownSink =
                GossipDirectoryPublishSink(
                    AnonymousPeerRecordGossip.attach(pubsub, peerDirectory.anonymousRecords, clock),
                    OnionServiceDescriptorGossip.attach(pubsub, serviceIndex, clock),
                    serviceIndex,
                    pubsub,
                    clock,
                    nodeBundles,
                )
            val prekeys = PrekeyStore.create(Files.createTempDirectory("sink-prekeys3"), identity)
            val bundle = prekeys.publishBundle(identity, now() + 600)
            nodeBundles.announce(bundle)
            val before = count(topic)
            knownSink.publish(DirectoryObjectType.PREKEY_BUNDLE, PrekeyBundleCodec.encode(bundle)) shouldBe
                DirectoryPublishStatus.ACCEPTED
            count(topic) shouldBe before
            runCatching { nodeBundles.stop() }
        }

        test("prekey bundle outside the TTL window or with a broken signature is rejected and never published") {
            val topic = PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC
            val before = count(topic)
            val other = DualKeyIdentity.generate()
            val prekeys = PrekeyStore.create(Files.createTempDirectory("sink-prekeys2"), other)
            val expired = prekeys.publishBundle(other, now() - 10, nowEpochSecond = now() - 1_000)
            sink.publish(DirectoryObjectType.PREKEY_BUNDLE, PrekeyBundleCodec.encode(expired)) shouldBe
                DirectoryPublishStatus.INVALID
            val tooFar =
                prekeys.publishBundle(other, now() + 8 * 24 * 3600L, nowEpochSecond = now() + 8 * 24 * 3600L - 60)
            sink.publish(DirectoryObjectType.PREKEY_BUNDLE, PrekeyBundleCodec.encode(tooFar)) shouldBe
                DirectoryPublishStatus.INVALID
            val tampered = PrekeyBundleCodec.encode(prekeys.publishBundle(other, now() + 600))
            tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x55).toByte()
            val status = sink.publish(DirectoryObjectType.PREKEY_BUNDLE, tampered)
            (status == DirectoryPublishStatus.INVALID || status == DirectoryPublishStatus.MALFORMED) shouldBe true
            count(topic) shouldBe before
        }
    })
