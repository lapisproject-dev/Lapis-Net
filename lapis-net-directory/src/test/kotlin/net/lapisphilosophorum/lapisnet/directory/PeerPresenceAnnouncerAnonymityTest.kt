package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Instant
import java.util.concurrent.CompletableFuture

private class RecordingChannel(
    override val exposesOrigin: Boolean = false,
    val succeed: Boolean = true,
) : DirectoryPublicationChannel {
    val records = mutableListOf<AnonymousPeerRecord>()

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> {
        records += record
        return CompletableFuture.completedFuture(succeed)
    }

    override fun publishPrekeyBundle(bundle: PrekeyBundle) = CompletableFuture.completedFuture(succeed)

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor) =
        CompletableFuture.completedFuture(succeed)
}

/** [PeerPresenceAnnouncer] in anonymity mode: fail closed for address-bearing records, floors for anonymous ones. */
class PeerPresenceAnnouncerAnonymityTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-anonymity-test"))
        val pubsub = GossipPubSub.attach(node)
        val published = mutableListOf<ByteArray>()
        pubsub.outboundTap = { _, bytes -> published += bytes }
        val gossip = PeerDirectoryGossip.attach(pubsub, storage)

        afterSpec {
            gossip.stop()
            pubsub.stop()
            runCatching { node.stop() }
        }

        val identity = DualKeyIdentity.generate()

        fun record(
            addresses: List<io.libp2p.core.multiformats.Multiaddr>,
            seq: Long,
        ) = PeerRecord.create(identity, addresses, emptySet(), seq, Instant.now().epochSecond + 600)

        test("in mode ON a record with addresses is refused fail-closed and nothing is published") {
            val announcer = PeerPresenceAnnouncer(gossip, anonymityMode = DirectoryAnonymityMode.ON)
            val before = published.size
            announcer.announceIfDue(
                record(
                    listOf(
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/127.0.0.1/tcp/4001"),
                    ),
                    1,
                ),
            ) shouldBe false
            published.size shouldBe before
            gossip.lookup(identity.secp256k1KeyPair.publicKey) shouldBe null
        }

        test("in mode ON an address-free tombstone is allowed (the OFF-to-ON transition)") {
            val announcer = PeerPresenceAnnouncer(gossip, anonymityMode = DirectoryAnonymityMode.ON)
            announcer.announceIfDue(record(emptyList(), 2)) shouldBe true
        }

        test("in mode OFF behaviour is unchanged: address-bearing records are announced") {
            val other = DualKeyIdentity.generate()
            val announcer = PeerPresenceAnnouncer(gossip)
            val r =
                PeerRecord.create(
                    other,
                    listOf(
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/127.0.0.1/tcp/4002"),
                    ),
                    emptySet(),
                    1,
                    Instant.now().epochSecond + 600,
                )
            announcer.announceIfDue(r) shouldBe true
            announcer.announceIfDue(r) shouldBe false // the monotonic floor still applies
        }

        test("anonymous records obey the monotonic floor, and a failed publication does not consume it") {
            val p = AnonymousPublisher()
            val announcer = PeerPresenceAnnouncer(gossip, minRepublishIntervalSeconds = 300)
            val channel = RecordingChannel()
            announcer.announceAnonymousIfDue(p.record(1), channel, nowNanos = 1_000).get() shouldBe true
            announcer.announceAnonymousIfDue(p.record(2), channel, nowNanos = 2_000).get() shouldBe false
            channel.records.size shouldBe 1
            announcer.announceAnonymousIfDue(p.record(3), channel, nowNanos = 301_000_000_000L).get() shouldBe true

            val failing = RecordingChannel(succeed = false)
            val second = PeerPresenceAnnouncer(gossip, minRepublishIntervalSeconds = 300)
            second.announceAnonymousIfDue(p.record(4), failing, nowNanos = 1_000).get() shouldBe false
            second.announceAnonymousIfDue(p.record(5), channel, nowNanos = 2_000).get() shouldBe true
        }

        test("in mode ON a channel that exposes the origin is refused") {
            val p = AnonymousPublisher()
            val announcer = PeerPresenceAnnouncer(gossip, anonymityMode = DirectoryAnonymityMode.ON)
            val direct = RecordingChannel(exposesOrigin = true)
            announcer.announceAnonymousIfDue(p.record(1), direct).get() shouldBe false
            direct.records.size shouldBe 0
        }
    })
