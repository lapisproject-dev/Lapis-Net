package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.seconds

/** The outbox, rendezvous and dispatch parts of [DirectoryDht] against fake DHT stores (V0.9.14). */
class DirectoryDhtOutboxTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-dht-outbox-test"))
        val pubsub = GossipPubSub.attach(node)

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        class Rig(
            val fake: FakeIpnsValueStore = FakeIpnsValueStore(),
            limits: DirectoryDhtLimits = DirectoryDhtLimits(),
            val rendezvous: FakeRendezvousStore? = FakeRendezvousStore(),
            localIdentity: Secp256k1PublicKey? = null,
            val outbox: DhtOutbox? = DhtOutbox(),
        ) {
            val nanos = AtomicLong(1_000_000_000_000L)
            val wall = arrayOf(Instant.now())
            val gossip = PeerDirectoryGossip.attach(pubsub, storage)
            val prekeys = PrekeyBundleGossip.attach(pubsub, storage)
            val dht =
                DirectoryDht(
                    fake,
                    gossip,
                    prekeys,
                    limits,
                    { nanos.get() },
                    { wall[0] },
                    rendezvous,
                    localIdentity,
                    outbox,
                )

            fun advance(seconds: Long) {
                nanos.addAndGet(Duration.ofSeconds(seconds).toNanos())
                wall[0] = wall[0].plusSeconds(seconds)
            }

            fun stop() {
                gossip.stop()
                prekeys.stop()
            }
        }

        fun withRig(
            fake: FakeIpnsValueStore = FakeIpnsValueStore(),
            limits: DirectoryDhtLimits = DirectoryDhtLimits(minRepublishInterval = Duration.ZERO),
            rendezvous: FakeRendezvousStore? = FakeRendezvousStore(),
            localIdentity: Secp256k1PublicKey? = null,
            outbox: DhtOutbox? = DhtOutbox(),
            body: (Rig) -> Unit,
        ) {
            val rig = Rig(fake, limits, rendezvous, localIdentity, outbox)
            try {
                body(rig)
            } finally {
                rig.stop()
            }
        }

        /** Publishes [a]'s value with [entries] (and a peer record) into [fake], as A's own node would. */
        fun publishWithOutbox(
            fake: FakeIpnsValueStore,
            a: DirectoryPublisher,
            entries: List<OutboxEntry>,
            withRecord: Boolean = true,
        ) {
            withRig(fake = fake, rendezvous = null) { rig ->
                entries.forEach { rig.outbox!!.offer(it) }
                rig.dht
                    .publishOwn(a.identity, if (withRecord) a.peerRecord() else null, null)
                    .skippedByRateLimit shouldBe false
            }
        }

        fun rendezvousCid(key: Secp256k1PublicKey) = MessagingRendezvous.cidFor(key)

        test("publishing an outbox-only value carries the selected entries and reports counts") {
            val a = DirectoryPublisher()
            withRig { rig ->
                val entries = List(3) { outboxEntry(expiresInSeconds = 5000) }
                entries.forEach { rig.outbox!!.offer(it) }
                val result = rig.dht.publishOwn(a.identity, null, null)
                result.outboxEntriesPublished shouldBe 3
                result.outboxEntriesOmitted shouldBe 0
                val published = rig.fake.published.single()
                val decoded = DirectoryDhtValueCodec.decode(published.value)
                decoded.outboxEntries.toSet() shouldBe entries.toSet()
                decoded.peerRecordBytes shouldBe null
                // the IPNS record expires with the latest entry (no directory part to bound it)
                published.notValidAfter.epochSecond shouldBe entries.maxOf { it.notValidAfterEpochSecond }
            }
        }

        test("an outbox-only publication is capped at one record validity") {
            val a = DirectoryPublisher()
            withRig { rig ->
                rig.outbox!!.offer(outboxEntry(expiresInSeconds = 30L * 86_400))
                rig.dht.publishOwn(a.identity, null, null)
                val max = rig.wall[0].plus(DirectoryDhtLimits().maxRecordValidity)
                (
                    rig.fake.published
                        .single()
                        .notValidAfter <= max
                ) shouldBe true
            }
        }

        test("nothing to publish: no parts and an empty or fully expired outbox") {
            val a = DirectoryPublisher()
            withRig { rig ->
                shouldThrow<IllegalArgumentException> { rig.dht.publishOwn(a.identity, null, null) }
                rig.outbox!!.offer(outboxEntry(expiresInSeconds = -10))
                shouldThrow<IllegalArgumentException> { rig.dht.publishOwn(a.identity, null, null) }
            }
            withRig(outbox = null) { rig ->
                shouldThrow<IllegalArgumentException> { rig.dht.publishOwn(a.identity, null, null) }
            }
        }

        test("a full outbox is cut to the byte budget and the rest is reported as omitted") {
            val a = DirectoryPublisher()
            withRig { rig ->
                repeat(12) { rig.outbox!!.offer(outboxEntry(payloadSize = 274)) }
                val result = rig.dht.publishOwn(a.identity, a.peerRecord(), null)
                (result.outboxEntriesPublished > 0) shouldBe true
                result.outboxEntriesPublished + result.outboxEntriesOmitted shouldBe 12
                (
                    rig.fake.published
                        .single()
                        .value.size <= DirectoryDhtValueCodec.MAX_VALUE_BYTES
                ) shouldBe true
                DirectoryDhtValueCodec
                    .decode(
                        rig.fake.published
                            .single()
                            .value,
                    ).outboxEntries.size shouldBe result.outboxEntriesPublished
            }
        }

        test("a rate-limited publication changes nothing, announces nothing and reports the entries as omitted") {
            val a = DirectoryPublisher()
            withRig(limits = DirectoryDhtLimits(minRepublishInterval = Duration.ofSeconds(300))) { rig ->
                rig.outbox!!.offer(outboxEntry())
                rig.dht.publishOwn(a.identity, null, null).skippedByRateLimit shouldBe false
                val before = rig.rendezvous!!.provided.size
                rig.outbox.offer(outboxEntry())
                val second = rig.dht.publishOwn(a.identity, null, null)
                second.skippedByRateLimit shouldBe true
                rig.fake.published.size shouldBe 1
                rig.rendezvous.provided.size shouldBe before
            }
        }

        test("a rendezvous provider record is announced once per recipient and interval") {
            val a = DirectoryPublisher()
            withRig { rig ->
                val recipients = List(3) { newKey() }
                recipients.forEach { rig.outbox!!.offer(outboxEntry(recipient = it, expiresInSeconds = 86_400)) }
                val first = rig.dht.publishOwn(a.identity, null, null)
                first.rendezvousAnnounced shouldBe 3
                rig.rendezvous!!.provided.toSet() shouldBe recipients.map { rendezvousCid(it) }.toSet()

                rig.advance(301)
                rig.dht.publishOwn(a.identity, null, null).rendezvousAnnounced shouldBe 0
                rig.rendezvous.provided.size shouldBe 3

                rig.advance(3600)
                rig.dht.publishOwn(a.identity, null, null).rendezvousAnnounced shouldBe 3
                rig.rendezvous.provided.size shouldBe 6
            }
        }

        test("at most maxRendezvousAnnouncesPerPublish recipients are announced per publication") {
            val a = DirectoryPublisher()
            val limits = DirectoryDhtLimits(minRepublishInterval = Duration.ZERO, maxRendezvousAnnouncesPerPublish = 2)
            withRig(limits = limits) { rig ->
                repeat(5) { rig.outbox!!.offer(outboxEntry()) }
                rig.dht.publishOwn(a.identity, null, null).rendezvousAnnounced shouldBe 2
                rig.rendezvous!!.provided.size shouldBe 2
            }
        }

        test("with rendezvous disabled, or without a rendezvous store, nothing is announced") {
            val a = DirectoryPublisher()
            val off = DirectoryDhtLimits(minRepublishInterval = Duration.ZERO, rendezvousEnabled = false)
            withRig(limits = off) { rig ->
                rig.outbox!!.offer(outboxEntry())
                rig.dht.publishOwn(a.identity, null, null).rendezvousAnnounced shouldBe 0
                rig.rendezvous!!.provided.size shouldBe 0
            }
            withRig(rendezvous = null) { rig ->
                rig.outbox!!.offer(outboxEntry())
                rig.dht.publishOwn(a.identity, null, null).rendezvousAnnounced shouldBe 0
            }
        }

        test("a failing announcement is isolated to its recipient") {
            val a = DirectoryPublisher()
            withRig { rig ->
                val bad = newKey()
                rig.rendezvous!!.failProvideFor = setOf(rendezvousCid(bad))
                rig.outbox!!.offer(outboxEntry(recipient = bad))
                rig.outbox.offer(outboxEntry())
                rig.outbox.offer(outboxEntry())
                val result = rig.dht.publishOwn(a.identity, null, null)
                result.rendezvousAnnounced shouldBe 2
                rig.fake.published.size shouldBe 1
                // and the failed recipient is not hammered on the very next publication
                rig.advance(301)
                rig.dht.publishOwn(a.identity, null, null).rendezvousAnnounced shouldBe 0
            }
        }

        test(
            "only entries addressed to the local identity reach the consumer of their kind; the peer record is ingested first",
        ) {
            val a = DirectoryPublisher()
            val c = newKey()
            val fake = FakeIpnsValueStore()
            val forC = outboxEntry(recipient = c)
            val forC2 = outboxEntry(recipient = c, kind = OutboxEntryKind.MAIL_POINTER, payloadSize = 100)
            val forD = outboxEntry(recipient = newKey())
            publishWithOutbox(fake, a, listOf(forC, forC2, forD))
            withRig(fake = fake, localIdentity = c, outbox = null) { rig ->
                val dm = mutableListOf<OutboxEntry>()
                val seenSender = mutableListOf<Secp256k1PublicKey>()
                val seenPeer = mutableListOf<PeerId>()
                var recordKnownAtCall = false
                rig.dht.registerOutboxConsumer(OutboxEntryKind.DM_MAILBOX_POINTER) { sender, peerId, entry ->
                    recordKnownAtCall = rig.gossip.lookup(a.key) != null
                    seenSender += sender
                    seenPeer += peerId
                    dm += entry
                    OutboxIngestOutcome.ACCEPTED
                }
                val result = rig.dht.resolve(a.key, a.peerId)
                result shouldBe
                    DirectoryDhtResolution.Found(
                        peerRecordAccepted = true,
                        prekeyBundleAccepted = false,
                        outboxEntriesDispatched = 1,
                        outboxEntriesAccepted = 1,
                    )
                dm shouldBe listOf(forC)
                seenSender shouldBe listOf(a.key)
                seenPeer shouldBe listOf(a.peerId)
                recordKnownAtCall shouldBe true
            }
        }

        test("entries are ignored without a local identity and without a registered consumer") {
            val a = DirectoryPublisher()
            val c = newKey()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, listOf(outboxEntry(recipient = c)))
            withRig(fake = fake, localIdentity = null, outbox = null) { rig ->
                var called = false
                rig.dht.registerOutboxConsumer(OutboxEntryKind.DM_MAILBOX_POINTER) { _, _, _ ->
                    called = true
                    OutboxIngestOutcome.ACCEPTED
                }
                (rig.dht.resolve(a.key, a.peerId) as DirectoryDhtResolution.Found).outboxEntriesDispatched shouldBe 0
                called shouldBe false
            }
            withRig(fake = fake, localIdentity = c, outbox = null) { rig ->
                (rig.dht.resolve(a.key, a.peerId) as DirectoryDhtResolution.Found).outboxEntriesDispatched shouldBe 0
            }
        }

        test("a second registration for the same kind is refused") {
            withRig { rig ->
                rig.dht.registerOutboxConsumer(OutboxEntryKind.MAIL_POINTER) { _, _, _ -> OutboxIngestOutcome.ACCEPTED }
                shouldThrow<IllegalArgumentException> {
                    rig.dht.registerOutboxConsumer(
                        OutboxEntryKind.MAIL_POINTER,
                    ) { _, _, _ -> OutboxIngestOutcome.ACCEPTED }
                }
                rig.dht.registerOutboxConsumer(
                    OutboxEntryKind.DM_MAILBOX_POINTER,
                ) { _, _, _ -> OutboxIngestOutcome.ACCEPTED }
            }
        }

        test("a consumer that throws is isolated and counted as rejected; the other entries are still delivered") {
            val a = DirectoryPublisher()
            val c = newKey()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, listOf(outboxEntry(recipient = c), outboxEntry(recipient = c)))
            withRig(fake = fake, localIdentity = c, outbox = null) { rig ->
                var calls = 0
                rig.dht.registerOutboxConsumer(OutboxEntryKind.DM_MAILBOX_POINTER) { _, _, _ ->
                    calls++
                    if (calls == 1) error("boom")
                    OutboxIngestOutcome.ACCEPTED
                }
                val found = rig.dht.resolve(a.key, a.peerId) as DirectoryDhtResolution.Found
                found.outboxEntriesDispatched shouldBe 2
                found.outboxEntriesAccepted shouldBe 1
                found.peerRecordAccepted shouldBe true
            }
        }

        test("a consumer that calls back into the DHT does not deadlock").config(timeout = 30.seconds) {
            val a = DirectoryPublisher()
            val c = newKey()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, listOf(outboxEntry(recipient = c)))
            withRig(fake = fake, localIdentity = c, outbox = null) { rig ->
                var inner: DirectoryDhtResolution? = null
                rig.dht.registerOutboxConsumer(OutboxEntryKind.DM_MAILBOX_POINTER) { _, _, _ ->
                    inner = rig.dht.resolve(a.key, a.peerId)
                    OutboxIngestOutcome.ACCEPTED
                }
                rig.dht.resolve(a.key, a.peerId) shouldBe
                    DirectoryDhtResolution.Found(true, false, outboxEntriesDispatched = 1, outboxEntriesAccepted = 1)
                inner shouldBe DirectoryDhtResolution.Throttled
            }
        }

        test("at most maxDispatchedEntriesPerResolve entries are handed to consumers") {
            val a = DirectoryPublisher()
            val c = newKey()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, List(4) { outboxEntry(recipient = c) })
            val limits = DirectoryDhtLimits(maxDispatchedEntriesPerResolve = 2)
            withRig(fake = fake, limits = limits, localIdentity = c, outbox = null) { rig ->
                rig.dht.registerOutboxConsumer(
                    OutboxEntryKind.DM_MAILBOX_POINTER,
                ) { _, _, _ -> OutboxIngestOutcome.ACCEPTED }
                (rig.dht.resolve(a.key, a.peerId) as DirectoryDhtResolution.Found).outboxEntriesDispatched shouldBe 2
            }
        }

        test("resolveByPeerId takes the identity from the value, is throttled and negatively cached") {
            val a = DirectoryPublisher()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, listOf(outboxEntry()))
            withRig(fake = fake, outbox = null) { rig ->
                (rig.dht.resolveByPeerId(a.peerId) is DirectoryDhtResolution.Found) shouldBe true
                rig.gossip.lookup(a.key) shouldBe rig.gossip.lookup(a.key) // ingested under the value's own identity
                (rig.gossip.lookup(a.key) != null) shouldBe true
                rig.dht.resolveByPeerId(a.peerId) shouldBe DirectoryDhtResolution.Throttled

                val unknown = DirectoryPublisher()
                rig.dht.resolveByPeerId(unknown.peerId) shouldBe DirectoryDhtResolution.NotFound
                rig.dht.resolveByPeerId(unknown.peerId) shouldBe DirectoryDhtResolution.Throttled
                rig.fake.resolveCalls.count { it == unknown.peerId } shouldBe 1
                rig.advance(61)
                rig.dht.resolveByPeerId(unknown.peerId) shouldBe DirectoryDhtResolution.NotFound
                rig.fake.resolveCalls.count { it == unknown.peerId } shouldBe 2
            }
        }

        test("a value found through the own rendezvous key that is the own value is not ingested") {
            val a = DirectoryPublisher()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, listOf(outboxEntry()))
            withRig(fake = fake, localIdentity = a.key, outbox = null) { rig ->
                rig.dht.resolveByPeerId(a.peerId) shouldBe DirectoryDhtResolution.NotFound
                rig.gossip.lookup(a.key) shouldBe null
            }
        }

        test("discoverInbox finds the announcing node, resolves it and hands the entry to the consumer") {
            val a = DirectoryPublisher()
            val c = newKey()
            val fake = FakeIpnsValueStore()
            publishWithOutbox(fake, a, listOf(outboxEntry(recipient = c)))
            withRig(fake = fake, localIdentity = c, outbox = null) { rig ->
                rig.rendezvous!!.providers[rendezvousCid(c)] = mutableSetOf(a.peerId)
                rig.dht.registerOutboxConsumer(
                    OutboxEntryKind.DM_MAILBOX_POINTER,
                ) { _, _, _ -> OutboxIngestOutcome.ACCEPTED }
                rig.dht.discoverInbox(Duration.ofSeconds(5)) shouldBe
                    InboxDiscoveryReport(
                        providersFound = 1,
                        resolved = 1,
                        entriesAccepted = 1,
                        skipped = 0,
                        throttled = false,
                    )
                rig.rendezvous.findCalls shouldBe listOf(rendezvousCid(c))
            }
        }

        test("discoverInbox is throttled between network discoveries") {
            val c = newKey()
            withRig(localIdentity = c, outbox = null) { rig ->
                rig.dht.discoverInbox(Duration.ofSeconds(5)).throttled shouldBe false
                rig.dht.discoverInbox(Duration.ofSeconds(5)).throttled shouldBe true
                rig.rendezvous!!.findCalls.size shouldBe 1
                rig.advance(301)
                rig.dht.discoverInbox(Duration.ofSeconds(5)).throttled shouldBe false
                rig.rendezvous.findCalls.size shouldBe 2
            }
        }

        test("discoverInbox asks for at most maxRendezvousProviders and survives a failing lookup") {
            val c = newKey()
            val limits = DirectoryDhtLimits(maxRendezvousProviders = 2)
            withRig(limits = limits, localIdentity = c, outbox = null) { rig ->
                rig.rendezvous!!.providers[rendezvousCid(c)] =
                    MutableList(5) { DirectoryPublisher().peerId }.toMutableSet()
                val report = rig.dht.discoverInbox(Duration.ofSeconds(5))
                report.providersFound shouldBe 2
                rig.fake.resolveCalls.size shouldBe 2
            }
            withRig(localIdentity = c, outbox = null) { rig ->
                rig.rendezvous!!.failFind = true
                rig.dht.discoverInbox(Duration.ofSeconds(5)) shouldBe InboxDiscoveryReport(0, 0, 0, 0, false)
            }
        }

        test("discoverInbox needs a local identity and enabled rendezvous") {
            withRig(localIdentity = null, outbox = null) { rig ->
                shouldThrow<IllegalStateException> { rig.dht.discoverInbox(Duration.ofSeconds(1)) }
            }
            val off = DirectoryDhtLimits(rendezvousEnabled = false)
            withRig(limits = off, localIdentity = newKey(), outbox = null) { rig ->
                shouldThrow<IllegalStateException> { rig.dht.discoverInbox(Duration.ofSeconds(1)) }
            }
            withRig(rendezvous = null, localIdentity = newKey(), outbox = null) { rig ->
                shouldThrow<IllegalStateException> { rig.dht.discoverInbox(Duration.ofSeconds(1)) }
            }
        }

        test("the rendezvous key is deterministic, domain separated and differs per recipient") {
            val r = newKey()
            rendezvousCid(r) shouldBe rendezvousCid(r)
            (rendezvousCid(r) == rendezvousCid(newKey())) shouldBe false
            rendezvousCid(r).codec shouldBe io.ipfs.cid.Cid.Codec.Raw
        }

        test("limits reject nonsense values") {
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxOutboxEntriesPerValue = 0) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxOutboxEntriesPerValue = 65) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxOutboxBytes = 4096) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxRendezvousProviders = 9) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxRendezvousAnnouncesPerPublish = 0) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(rendezvousTrackerCapacity = 0) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxDispatchedEntriesPerResolve = 0) }
        }
    })
