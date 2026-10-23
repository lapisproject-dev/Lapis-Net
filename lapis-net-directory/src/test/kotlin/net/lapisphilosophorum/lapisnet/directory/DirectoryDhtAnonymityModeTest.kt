package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/**
 * [DirectoryDht] in anonymity mode ON: the fakes for the IPNS store and the rendezvous store must not receive a single
 * write, except the one address-free tombstone.
 */
class DirectoryDhtAnonymityModeTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("dht-anonymity-test"))
        val pubsub = GossipPubSub.attach(node)

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        class Rig(
            mode: DirectoryAnonymityMode,
        ) {
            val fake = FakeIpnsValueStore()
            val rendezvous = FakeRendezvousStore()
            val outbox = DhtOutbox()
            val gossip = PeerDirectoryGossip.attach(pubsub, storage)
            val prekeys = PrekeyBundleGossip.attach(pubsub, storage)
            val dht =
                DirectoryDht(
                    fake,
                    gossip,
                    prekeys,
                    DirectoryDhtLimits(minRepublishInterval = Duration.ZERO),
                    rendezvous = rendezvous,
                    outbox = outbox,
                    anonymityMode = mode,
                )

            fun stop() {
                gossip.stop()
                prekeys.stop()
            }
        }

        fun withRig(
            mode: DirectoryAnonymityMode = DirectoryAnonymityMode.ON,
            body: (Rig) -> Unit,
        ) {
            val rig = Rig(mode)
            try {
                body(rig)
            } finally {
                rig.stop()
            }
        }

        val publisher = DirectoryPublisher()

        test("in mode ON publishOwn refuses a record with addresses and writes nothing") {
            withRig { rig ->
                shouldThrow<IllegalStateException> {
                    rig.dht.publishOwn(
                        publisher.identity,
                        publisher.peerRecord(),
                        null,
                    )
                }
                rig.fake.published.size shouldBe 0
                rig.rendezvous.provided.size shouldBe 0
            }
        }

        test("in mode ON publishOwn refuses a prekey bundle alone, a relay descriptor and an outbox-only value") {
            withRig { rig ->
                rig.outbox.offer(outboxEntry())
                shouldThrow<IllegalStateException> { rig.dht.publishOwn(publisher.identity, null, publisher.bundle()) }
                val relay = OnionRelayPublisher(publisher)
                shouldThrow<IllegalStateException> {
                    rig.dht.publishOwn(publisher.identity, null, null, onionRelayDescriptor = relay.descriptor())
                }
                shouldThrow<IllegalStateException> { rig.dht.publishOwn(publisher.identity, null, null) }
                rig.fake.published.size shouldBe 0
                rig.rendezvous.provided.size shouldBe 0
                rig.outbox.size() shouldBe 1 // entries stay queued
            }
        }

        test("in mode ON no rendezvous provider record is ever sent") {
            withRig { rig ->
                rig.outbox.offer(outboxEntry())
                runCatching { rig.dht.publishOwn(publisher.identity, publisher.peerRecord(), null) }
                rig.rendezvous.provided.size shouldBe 0
            }
        }

        test("in mode OFF the same call still publishes (behaviour unchanged)") {
            withRig(DirectoryAnonymityMode.OFF) { rig ->
                rig.dht.publishOwn(publisher.identity, publisher.peerRecord(), null).acknowledged shouldBe 1
                rig.fake.published.size shouldBe 1
            }
        }

        test("publishTombstone writes exactly one value without addresses, bundle, outbox or relay descriptor") {
            withRig { rig ->
                rig.outbox.offer(outboxEntry())
                val tombstone =
                    PeerRecord.create(publisher.identity, emptyList(), emptySet(), 7, Instant.now().epochSecond + 3600)
                rig.dht.publishTombstone(publisher.identity, tombstone).acknowledged shouldBe 1
                rig.fake.published.size shouldBe 1
                rig.rendezvous.provided.size shouldBe 0
                val value =
                    DirectoryDhtValueCodec.decode(
                        rig.fake.published
                            .single()
                            .value,
                    )
                value.outboxEntries.size shouldBe 0
                value.onionRelayDescriptorBytes shouldBe null
                value.prekeyBundleBytes shouldBe null
                PeerRecordCodec.decode(value.peerRecordBytes!!).addresses.size shouldBe 0
            }
        }

        test("publishTombstone refuses records with addresses, foreign records and expired records") {
            withRig { rig ->
                shouldThrow<IllegalArgumentException> {
                    rig.dht.publishTombstone(publisher.identity, publisher.peerRecord())
                }
                val foreign = DirectoryPublisher()
                shouldThrow<IllegalArgumentException> {
                    rig.dht.publishTombstone(
                        publisher.identity,
                        PeerRecord.create(
                            foreign.identity,
                            emptyList(),
                            emptySet(),
                            1,
                            Instant.now().epochSecond + 100,
                        ),
                    )
                }
                shouldThrow<IllegalArgumentException> {
                    rig.dht.publishTombstone(
                        publisher.identity,
                        PeerRecord.create(
                            publisher.identity,
                            emptyList(),
                            emptySet(),
                            1,
                            Instant.now().epochSecond - 100,
                        ),
                    )
                }
                rig.fake.published.size shouldBe 0
                Multiaddr("/ip4/127.0.0.1/tcp/1").toString().isNotEmpty() shouldBe true
            }
        }
    })
