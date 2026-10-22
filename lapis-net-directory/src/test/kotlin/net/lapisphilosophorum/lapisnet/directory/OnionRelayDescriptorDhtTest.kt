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
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

class OnionRelayDescriptorDhtTest :
    FunSpec({
        val now = Instant.now().epochSecond
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("onion-descriptor-dht-test"))
        val pubsub = GossipPubSub.attach(node)

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        class Rig {
            val fake = FakeIpnsValueStore()
            val rendezvous = FakeRendezvousStore()
            val index = OnionRelayDescriptorIndex()
            val nanos = AtomicLong(1_000_000_000_000L)
            val gossip = PeerDirectoryGossip.attach(pubsub, storage)
            val prekeys = PrekeyBundleGossip.attach(pubsub, storage)
            val dht =
                DirectoryDht(
                    fake,
                    gossip,
                    prekeys,
                    DirectoryDhtLimits(minRepublishInterval = Duration.ZERO, minDiscoveryInterval = Duration.ZERO),
                    { nanos.get() },
                    Instant::now,
                    rendezvous,
                    null,
                    null,
                    index,
                )

            fun stop() {
                gossip.stop()
                prekeys.stop()
            }
        }

        fun withRig(body: (Rig) -> Unit) {
            val rig = Rig()
            try {
                body(rig)
            } finally {
                rig.stop()
            }
        }

        fun validate(
            publisher: DirectoryPublisher,
            value: DirectoryDhtValue,
        ) = DirectoryDhtValidator.validate(
            ipnsValueOf(publisher.peerId, DirectoryDhtValueCodec.encode(value)),
            publisher.key,
            now,
        )

        test("flag 0x08 round-trips and a value without it is byte-identical to the previous format") {
            val a = DirectoryPublisher()
            val r = OnionRelayPublisher(a)
            val d = r.descriptor()
            val without = a.value()
            val withDescriptor =
                DirectoryDhtValue(
                    a.key,
                    a.identity.binding,
                    without.peerRecordBytes,
                    without.prekeyBundleBytes,
                    onionRelayDescriptorBytes = OnionRelayDescriptorCodec.encode(d),
                )
            val encoded = DirectoryDhtValueCodec.encode(withDescriptor)
            DirectoryDhtValueCodec.decode(encoded) shouldBe withDescriptor
            val plain = DirectoryDhtValueCodec.encode(without)
            // the new part is appended; flags differ only by the 0x08 bit
            encoded.size shouldBe plain.size + 2 + OnionRelayDescriptorCodec.ENCODED_SIZE
            (encoded[5].toInt() and 0x08) shouldBe 0x08
            (plain[5].toInt() and 0x08) shouldBe 0
            DirectoryDhtValueCodec.decode(plain).onionRelayDescriptorBytes shouldBe null
        }

        test("a descriptor-only value is allowed; an empty or oversize descriptor part is refused") {
            val a = DirectoryPublisher()
            val d = OnionRelayPublisher(a).descriptor()
            val only =
                DirectoryDhtValue(
                    a.key,
                    a.identity.binding,
                    null,
                    null,
                    onionRelayDescriptorBytes = OnionRelayDescriptorCodec.encode(d),
                )
            DirectoryDhtValueCodec.decode(DirectoryDhtValueCodec.encode(only)) shouldBe only
            shouldThrow<IllegalArgumentException> {
                DirectoryDhtValue(a.key, a.identity.binding, null, null, onionRelayDescriptorBytes = ByteArray(0))
            }
            val big =
                DirectoryDhtValue(
                    a.key,
                    a.identity.binding,
                    null,
                    null,
                    onionRelayDescriptorBytes = ByteArray(600) { 1 },
                )
            shouldThrow<IllegalArgumentException> { DirectoryDhtValueCodec.encode(big) }
        }

        test("a valid descriptor passes the validator; one of a foreign identity is rejected") {
            val a = DirectoryPublisher()
            val own = OnionRelayPublisher(a).descriptor()

            fun valueWith(d: OnionRelayDescriptor) =
                DirectoryDhtValue(
                    a.key,
                    a.identity.binding,
                    null,
                    null,
                    onionRelayDescriptorBytes = OnionRelayDescriptorCodec.encode(d),
                )
            validate(a, valueWith(own))!!.onionDescriptor shouldBe own
            val foreign = OnionRelayPublisher().descriptor()
            validate(a, valueWith(foreign)) shouldBe null
        }

        test("a descriptor with a broken signature rejects the whole value; an expired one is just dropped") {
            val a = DirectoryPublisher()
            val r = OnionRelayPublisher(a)
            val bytes = OnionRelayDescriptorCodec.encode(r.descriptor())
            bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
            val broken =
                DirectoryDhtValue(
                    a.key,
                    a.identity.binding,
                    a.value().peerRecordBytes,
                    null,
                    onionRelayDescriptorBytes = bytes,
                )
            validate(a, broken) shouldBe null
            val expiring = r.descriptor(expiresInSeconds = 100)
            val value =
                DirectoryDhtValue(
                    a.key,
                    a.identity.binding,
                    a.value().peerRecordBytes,
                    null,
                    onionRelayDescriptorBytes = OnionRelayDescriptorCodec.encode(expiring),
                )
            val entry =
                DirectoryDhtValidator.validate(
                    ipnsValueOf(a.peerId, DirectoryDhtValueCodec.encode(value)),
                    a.key,
                    now + 200,
                )
            entry!!.onionDescriptor shouldBe null
        }

        test("publishOwn embeds the descriptor, announces the relay rendezvous and a resolver ingests it") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val d = OnionRelayPublisher(a).descriptor()
                val result = rig.dht.publishOwn(a.identity, a.peerRecord(), null, onionRelayDescriptor = d)
                result.skippedByRateLimit shouldBe false
                (OnionRelayRendezvous.cid() in rig.rendezvous.provided) shouldBe true
                DirectoryDhtValueCodec
                    .decode(
                        rig.fake.published
                            .single()
                            .value,
                    ).onionRelayDescriptorBytes
                    ?.contentEquals(OnionRelayDescriptorCodec.encode(d)) shouldBe true

                val resolved = rig.dht.resolve(a.key, a.peerId)
                (resolved as DirectoryDhtResolution.Found).onionRelayDescriptorAccepted shouldBe true
                rig.index.current(a.key, now) shouldBe d
            }
        }

        test("publishOwn refuses a descriptor of another identity") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val foreign = OnionRelayPublisher().descriptor()
                shouldThrow<IllegalArgumentException> {
                    rig.dht.publishOwn(a.identity, a.peerRecord(), null, onionRelayDescriptor = foreign)
                }
            }
        }

        test("a relay is found through the rendezvous fallback with gossip disabled") {
            withRig { rig ->
                val relay = DirectoryPublisher()
                val d = OnionRelayPublisher(relay).descriptor()
                // the relay publishes through its own DHT view into the shared fake stores
                val relayRig = Rig()
                try {
                    val own =
                        DirectoryDht(
                            rig.fake,
                            relayRig.gossip,
                            relayRig.prekeys,
                            DirectoryDhtLimits(minRepublishInterval = Duration.ZERO),
                            rendezvous = rig.rendezvous,
                        )
                    own.publishOwn(relay.identity, relay.peerRecord(), null, onionRelayDescriptor = d)
                } finally {
                    relayRig.stop()
                }
                rig.rendezvous.providers
                    .getOrPut(OnionRelayRendezvous.cid()) { HashSet() }
                    .add(relay.peerId)
                rig.index.current(relay.key, now) shouldBe null
                val report = rig.dht.discoverOnionRelays()
                report.providersFound shouldBe 1
                report.descriptorsAccepted shouldBe 1
                rig.index.current(relay.key, now) shouldBe d
            }
        }

        test("discoverOnionRelays is rate limited by minDiscoveryInterval") {
            val rig = Rig()
            try {
                val limited =
                    DirectoryDht(
                        rig.fake,
                        rig.gossip,
                        rig.prekeys,
                        DirectoryDhtLimits(minDiscoveryInterval = Duration.ofMinutes(5)),
                        { rig.nanos.get() },
                        Instant::now,
                        rig.rendezvous,
                        null,
                        null,
                        rig.index,
                    )
                limited.discoverOnionRelays().throttled shouldBe false
                limited.discoverOnionRelays().throttled shouldBe true
            } finally {
                rig.stop()
            }
        }
    })
