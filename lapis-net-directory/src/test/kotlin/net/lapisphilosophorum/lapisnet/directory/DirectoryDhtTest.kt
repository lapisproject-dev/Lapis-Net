package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageBusyException
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * [DirectoryDht] against a fake DHT ([FakeIpnsValueStore]): everything but the network. One real node
 * only provides the storage and pubsub that the gossip classes need.
 */
class DirectoryDhtTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("directory-dht-test"))
        val pubsub = GossipPubSub.attach(node)

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        class Rig(
            val fake: FakeIpnsValueStore = FakeIpnsValueStore(),
            limits: DirectoryDhtLimits = DirectoryDhtLimits(),
        ) {
            val nanos = AtomicLong(1_000_000_000_000L)
            val wall = arrayOf(Instant.now())
            val gossip = PeerDirectoryGossip.attach(pubsub, storage)
            val prekeys = PrekeyBundleGossip.attach(pubsub, storage)
            val dht = DirectoryDht(fake, gossip, prekeys, limits, { nanos.get() }, { wall[0] })

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
            limits: DirectoryDhtLimits = DirectoryDhtLimits(),
            body: (Rig) -> Unit,
        ) {
            val rig = Rig(limits = limits)
            try {
                body(rig)
            } finally {
                rig.stop()
            }
        }

        /** Puts [a]'s value into the fake DHT the way A's own node would. */
        fun publishInto(
            fake: FakeIpnsValueStore,
            a: DirectoryPublisher,
            record: PeerRecord? = a.peerRecord(),
            bundle: net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle? = a.bundle(),
        ) {
            withRig { publisherRig ->
                val own =
                    DirectoryDht(
                        fake,
                        publisherRig.gossip,
                        publisherRig.prekeys,
                        DirectoryDhtLimits(minRepublishInterval = Duration.ZERO),
                    )
                own.publishOwn(a.identity, record, bundle).skippedByRateLimit shouldBe false
            }
        }

        test("a record already in the gossip index is answered without any DHT call") {
            withRig { rig ->
                val a = DirectoryPublisher()
                rig.gossip.announce(a.peerRecord())
                rig.dht.lookupPeerRecord(a.key, a.peerId) shouldBe rig.gossip.lookup(a.key)
                rig.fake.resolveCalls.size shouldBe 0
            }
        }

        test("a missing record is fetched from the DHT and is then visible through the gossip index") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val record = a.peerRecord(sequence = 3)
                val bundle = a.bundle(sequence = 4)
                publishInto(rig.fake, a, record, bundle)

                rig.dht.lookupPeerRecord(a.key, a.peerId) shouldBe record
                rig.gossip.lookup(a.key) shouldBe record
                rig.prekeys.lookup(a.key) shouldBe bundle
                rig.fake.resolveCalls.size shouldBe 1
            }
        }

        test("an expired record in the index triggers the DHT and is replaced by the newer one") {
            withRig { rig ->
                val a = DirectoryPublisher()
                rig.gossip.announce(a.peerRecord(sequence = 0, expiresInSeconds = -30))
                rig.gossip.lookup(a.key) shouldBe null
                val fresh = a.peerRecord(sequence = 1)
                publishInto(rig.fake, a, fresh, null)

                // the peer ID hint is not needed: the expired record still names it
                rig.dht.lookupPeerRecord(a.key) shouldBe fresh
            }
        }

        test("a bundle is fetched the same way") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val bundle = a.bundle(sequence = 2)
                publishInto(rig.fake, a, a.peerRecord(), bundle)
                rig.dht.lookupPrekeyBundle(a.key, a.peerId) shouldBe bundle
            }
        }

        test("without a peer ID hint and without any record nothing is asked") {
            withRig { rig ->
                val a = DirectoryPublisher()
                rig.dht.resolve(a.key) shouldBe DirectoryDhtResolution.NoPeerIdKnown
                rig.dht.lookupPeerRecord(a.key) shouldBe null
                rig.fake.resolveCalls.size shouldBe 0
            }
        }

        test("a not-found result is cached negatively for negativeCacheTtl, then asked again") {
            withRig { rig ->
                val a = DirectoryPublisher()
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.NotFound
                rig.advance(40) // past minResolveInterval, inside negativeCacheTtl
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.Throttled
                rig.fake.resolveCalls.size shouldBe 1
                rig.advance(30) // 70 s: past the 60 s negative TTL
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.NotFound
                rig.fake.resolveCalls.size shouldBe 2
            }
        }

        test("a wrong peer ID hint does not poison the negative cache of the correct peer ID") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val other = DirectoryPublisher()
                publishInto(rig.fake, a)
                rig.dht.resolve(a.key, other.peerId) shouldBe DirectoryDhtResolution.NotFound
                (rig.dht.resolve(a.key, a.peerId) is DirectoryDhtResolution.Found) shouldBe true
            }
        }

        test("a found result is throttled for minResolveInterval") {
            withRig { rig ->
                val a = DirectoryPublisher()
                publishInto(rig.fake, a)
                (rig.dht.resolve(a.key, a.peerId) is DirectoryDhtResolution.Found) shouldBe true
                rig.advance(10)
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.Throttled
                rig.advance(25)
                (rig.dht.resolve(a.key, a.peerId) is DirectoryDhtResolution.Found) shouldBe true
                rig.fake.resolveCalls.size shouldBe 2
            }
        }

        test("the resolve tracker is bounded: an identity pushed out of it can be asked again at once") {
            withRig(DirectoryDhtLimits(resolveTrackerCapacity = 2)) { rig ->
                val ids = List(3) { DirectoryPublisher() }
                ids.forEach { rig.dht.resolve(it.key, it.peerId) shouldBe DirectoryDhtResolution.NotFound }
                rig.fake.resolveCalls.size shouldBe 3
                rig.dht.resolve(ids[2].key, ids[2].peerId) shouldBe DirectoryDhtResolution.Throttled
                rig.dht.resolve(ids[0].key, ids[0].peerId) shouldBe DirectoryDhtResolution.NotFound // forgotten
                rig.fake.resolveCalls.size shouldBe 4
            }
        }

        test("a busy DHT is reported as Busy and does not count as a lookup") {
            withRig { rig ->
                val a = DirectoryPublisher()
                rig.fake.busy()
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.Busy
                rig.fake.resolveFailure = null
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.NotFound
            }
        }

        test("another storage failure is NotFound, a peer ID without an IPNS name is NoPeerIdKnown") {
            withRig { rig ->
                val a = DirectoryPublisher()
                rig.fake.resolveFailure = NabuStorageException("failed to resolve")
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.NotFound
                rig.fake.resolveFailure = IllegalArgumentException("only Ed25519 peer IDs have an IPNS name")
                val b = DirectoryPublisher()
                rig.dht.resolve(b.key, b.peerId) shouldBe DirectoryDhtResolution.NoPeerIdKnown
            }
        }

        test("a value that does not validate is Rejected and nothing of it enters the index") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val b = DirectoryPublisher()
                // B's perfectly valid value, served under A's name and asked for as A
                rig.fake.resolveOverride = ipnsValueOf(a.peerId, DirectoryDhtValueCodec.encode(b.value()))
                rig.dht.resolve(a.key, a.peerId) shouldBe DirectoryDhtResolution.Rejected
                rig.gossip.lookup(a.key) shouldBe null
                rig.gossip.lookup(b.key) shouldBe null
                rig.prekeys.lookup(b.key) shouldBe null
            }
        }

        test("a DHT record older than what the index holds is not taken over") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val current = a.peerRecord(sequence = 5)
                rig.gossip.announce(current)
                publishInto(rig.fake, a, a.peerRecord(sequence = 3), null)

                rig.dht.resolve(a.key, a.peerId) shouldBe
                    DirectoryDhtResolution.Found(
                        peerRecordAccepted = false,
                        prekeyBundleAccepted = false,
                    )
                rig.gossip.lookup(a.key) shouldBe current
            }
        }

        test("catchUp looks at no more than the cap, one overall report") {
            withRig(DirectoryDhtLimits(maxIdentitiesPerCatchUp = 3)) { rig ->
                val ids = List(7) { DirectoryPublisher() }
                ids.forEach { rig.gossip.announce(it.peerRecord(expiresInSeconds = -30)) }
                publishInto(rig.fake, ids[0], ids[0].peerRecord(sequence = 1), null)
                publishInto(rig.fake, ids[1], ids[1].peerRecord(sequence = 1), null)

                val report = rig.dht.catchUp(ids.map { it.key } + ids.map { it.key }, Duration.ofSeconds(5))

                report shouldBe CatchUpReport(attempted = 3, found = 2, skipped = 4)
                rig.fake.resolveCalls.size shouldBe 3
            }
        }

        test("catchUp does not spend its cap on throttled identities and rotates through the rest") {
            withRig(DirectoryDhtLimits(maxIdentitiesPerCatchUp = 2)) { rig ->
                val ids = List(5) { DirectoryPublisher() }
                ids.forEach { rig.gossip.announce(it.peerRecord(expiresInSeconds = -30)) }

                rig.dht.catchUp(ids.map { it.key }, Duration.ofSeconds(5))
                rig.dht.catchUp(ids.map { it.key }, Duration.ofSeconds(5))
                rig.dht.catchUp(ids.map { it.key }, Duration.ofSeconds(5))

                // every identity asked exactly once: earlier ones are throttled, so later ones get the slots
                rig.fake.resolveCalls.toSet() shouldBe ids.map { it.peerId }.toSet()
                rig.fake.resolveCalls.size shouldBe 5
            }
        }

        test("catchUp rotates through more identities than the cap once nobody is throttled any more") {
            val limits =
                DirectoryDhtLimits(
                    maxIdentitiesPerCatchUp = 2,
                    minResolveInterval = Duration.ofSeconds(5),
                    negativeCacheTtl = Duration.ofSeconds(10),
                )
            withRig(limits) { rig ->
                val ids = List(5) { DirectoryPublisher() }
                ids.forEach { rig.gossip.announce(it.peerRecord(expiresInSeconds = -30)) }
                val keys = ids.map { it.key }

                repeat(3) {
                    rig.dht.catchUp(keys, Duration.ofSeconds(5))
                    rig.advance(20) // the negative cache has run out: all five are candidates again
                }

                // without the cursor this would be {0,1} three times
                val peers = ids.map { it.peerId }
                rig.fake.resolveCalls shouldBe listOf(peers[0], peers[1], peers[2], peers[3], peers[4], peers[0])
            }
        }

        test("catchUp moves its start on only past the identities it actually asked before the deadline") {
            val limits =
                DirectoryDhtLimits(
                    maxIdentitiesPerCatchUp = 4,
                    minResolveInterval = Duration.ofSeconds(1),
                    negativeCacheTtl = Duration.ofSeconds(1),
                )
            withRig(limits) { rig ->
                val ids = List(4) { DirectoryPublisher() }
                ids.forEach { rig.gossip.announce(it.peerRecord(expiresInSeconds = -30)) }
                val keys = ids.map { it.key }
                // every lookup takes 2 s of the injected clock, so only one fits into 3 s
                rig.fake.onResolve = { rig.nanos.addAndGet(Duration.ofSeconds(2).toNanos()) }

                val seen = mutableListOf<io.libp2p.core.PeerId>()
                repeat(4) {
                    rig.fake.resolveCalls.clear()
                    rig.dht.catchUp(keys, Duration.ofSeconds(3))
                    seen += rig.fake.resolveCalls
                    rig.advance(20)
                }

                // two fit per run (the second starts at 2 s < 3 s); every identity gets asked, none is jumped over
                seen.toSet() shouldBe ids.map { it.peerId }.toSet()
            }
        }

        test("catchUp asks every identity within bounded runs even when calls fall inside the negative cache TTL") {
            val limits =
                DirectoryDhtLimits(
                    maxIdentitiesPerCatchUp = 32,
                    minResolveInterval = Duration.ofSeconds(1),
                    negativeCacheTtl = Duration.ofSeconds(60),
                )
            withRig(limits) { rig ->
                val ids = List(40) { DirectoryPublisher() }
                ids.forEach { rig.gossip.announce(it.peerRecord(expiresInSeconds = -30)) }
                val keys = ids.map { it.key }
                // each lookup takes 2 s of the clock, so 5 fit into the 10 s deadline
                rig.fake.onResolve = { rig.nanos.addAndGet(Duration.ofSeconds(2).toNanos()) }

                val seen = mutableSetOf<io.libp2p.core.PeerId>()
                repeat(8) {
                    rig.fake.resolveCalls.clear()
                    rig.dht.catchUp(keys, Duration.ofSeconds(10))
                    seen += rig.fake.resolveCalls
                    rig.advance(5) // well inside negativeCacheTtl: earlier ones stay throttled
                }

                seen shouldBe ids.map { it.peerId }.toSet()
            }
        }

        test("publishOwn clamps the IPNS validity to a smaller maxRecordValidity reported by the store") {
            withRig(DirectoryDhtLimits(minRepublishInterval = Duration.ZERO)) { rig ->
                rig.fake.maxRecordValidityOverride = Duration.ofSeconds(100)
                val a = DirectoryPublisher()
                rig.dht.publishOwn(a.identity, a.peerRecord(expiresInSeconds = 5000), null)
                val published = rig.fake.published.single()
                (published.notValidAfter <= rig.wall[0].plusSeconds(100)) shouldBe true
            }
        }

        test("catchUp skips identities with no known peer ID without a network call") {
            withRig { rig ->
                val unknown = List(3) { DirectoryPublisher() }
                val report = rig.dht.catchUp(unknown.map { it.key }, Duration.ofSeconds(5))
                report shouldBe CatchUpReport(attempted = 0, found = 0, skipped = 3)
                rig.fake.resolveCalls.size shouldBe 0
            }
        }

        test("refreshStale asks only for identities whose record or bundle is expired or about to expire") {
            withRig { rig ->
                val expired = DirectoryPublisher()
                val expiring = DirectoryPublisher()
                val healthy = DirectoryPublisher()
                rig.gossip.announce(expired.peerRecord(expiresInSeconds = -30))
                rig.gossip.announce(expiring.peerRecord(expiresInSeconds = 100))
                rig.gossip.announce(healthy.peerRecord(expiresInSeconds = 3000))
                publishInto(rig.fake, expired, expired.peerRecord(sequence = 1), null)

                val report = rig.dht.refreshStale()

                rig.fake.resolveCalls.toSet() shouldBe setOf(expired.peerId, expiring.peerId)
                report.attempted shouldBe 2
                report.found shouldBe 1
                rig.gossip.lookup(expired.key)!!.sequenceNumber shouldBe 1
            }
        }

        test("publishOwn publishes one value under the node's own name with a rising sequence and the earlier expiry") {
            withRig(DirectoryDhtLimits(minRepublishInterval = Duration.ofSeconds(300))) { rig ->
                val a = DirectoryPublisher()
                val record = a.peerRecord(expiresInSeconds = 1000)
                val bundle = a.bundle(expiresInSeconds = 5000)

                val first = rig.dht.publishOwn(a.identity, record, bundle)
                first shouldBe DirectoryDhtPublishResult(1, 1, skippedByRateLimit = false)
                val published = rig.fake.published.single()
                published.publisher shouldBe a.peerId
                published.notValidAfter shouldBe Instant.ofEpochSecond(record.notValidAfterEpochSecond)
                (published.sequence >= rig.wall[0].toEpochMilli()) shouldBe true
                DirectoryDhtValueCodec.decode(published.value) shouldBe
                    a.value(record, bundle).let {
                        DirectoryDhtValue(it.identity, it.binding, it.peerRecordBytes, it.prekeyBundleBytes)
                    }

                // inside the floor nothing is published
                rig.advance(100)
                rig.dht.publishOwn(a.identity, record, bundle) shouldBe
                    DirectoryDhtPublishResult(0, 0, skippedByRateLimit = true)
                rig.fake.published.size shouldBe 1

                rig.advance(250)
                rig.dht.publishOwn(a.identity, a.peerRecord(), bundle).skippedByRateLimit shouldBe false
                rig.fake.published.size shouldBe 2
                (rig.fake.published[1].sequence > rig.fake.published[0].sequence) shouldBe true
            }
        }

        test("the sequence still rises when the wall clock stands still or goes back") {
            withRig(DirectoryDhtLimits(minRepublishInterval = Duration.ZERO)) { rig ->
                val a = DirectoryPublisher()
                repeat(3) { rig.dht.publishOwn(a.identity, a.peerRecord(), null) }
                rig.wall[0] = rig.wall[0].minusSeconds(3600)
                rig.dht.publishOwn(a.identity, a.peerRecord(), null)
                val sequences = rig.fake.published.map { it.sequence }
                sequences shouldBe sequences.sorted().distinct()
                sequences.size shouldBe 4
            }
        }

        test("the IPNS expiry is capped at maxRecordValidity") {
            withRig(DirectoryDhtLimits(maxRecordValidity = Duration.ofSeconds(600))) { rig ->
                val a = DirectoryPublisher()
                rig.dht.publishOwn(a.identity, null, a.bundle(expiresInSeconds = 5000))
                val expiry =
                    rig.fake.published
                        .single()
                        .notValidAfter
                (expiry <= rig.wall[0].plusSeconds(600)) shouldBe true
            }
        }

        test("publishOwn refuses foreign, invalid, oversized, expired and empty input") {
            withRig { rig ->
                val a = DirectoryPublisher()
                val b = DirectoryPublisher()
                shouldThrow<IllegalArgumentException> { rig.dht.publishOwn(a.identity, null, null) }
                shouldThrow<IllegalArgumentException> { rig.dht.publishOwn(a.identity, b.peerRecord(), null) }
                shouldThrow<IllegalArgumentException> { rig.dht.publishOwn(a.identity, null, b.bundle()) }
                shouldThrow<IllegalArgumentException> {
                    rig.dht.publishOwn(a.identity, a.peerRecord(expiresInSeconds = -5), null)
                }
                // a record with 16 relayed-style addresses plus a full bundle are over the envelope limit
                val wide =
                    PeerRecord.create(
                        a.identity,
                        List(PeerRecordCodec.MAX_ADDRESSES) {
                            Multiaddr("/ip6/2001:db8::${it + 1}/tcp/4001/p2p/${b.peerId.toBase58()}")
                        },
                        setOf(PeerCapability.DM),
                        0,
                        Instant.now().epochSecond + 3600,
                    )
                shouldThrow<IllegalArgumentException> {
                    rig.dht.publishOwn(a.identity, wide, a.bundle(oneTimePrekeys = 100))
                }
                // each alone fits
                rig.dht.publishOwn(a.identity, wide, null).skippedByRateLimit shouldBe false
                rig.fake.published.clear()
                rig.fake.published.size shouldBe 0
            }
        }

        test("a failed publication does not start the republish floor and is not retried with the same sequence") {
            val failing =
                object : IpnsValueStore {
                    var calls = 0
                    val sequences = mutableListOf<Long>()

                    override fun publish(
                        signingKey: io.libp2p.core.crypto.PrivKey,
                        value: ByteArray,
                        sequence: Long,
                        notValidAfter: Instant,
                        ttl: Duration,
                        timeout: Duration,
                    ): net.lapisphilosophorum.lapisnet.storage.IpnsPublishResult {
                        sequences += sequence
                        if (calls++ == 0) throw NabuStorageBusyException()
                        return net.lapisphilosophorum.lapisnet.storage
                            .IpnsPublishResult(1, 1)
                    }

                    override fun resolve(
                        publisher: io.libp2p.core.PeerId,
                        timeout: Duration,
                    ): net.lapisphilosophorum.lapisnet.storage.IpnsValue? = null
                }
            val gossip = PeerDirectoryGossip.attach(pubsub, storage)
            val prekeys = PrekeyBundleGossip.attach(pubsub, storage)
            try {
                val dht = DirectoryDht(failing, gossip, prekeys, DirectoryDhtLimits())
                val a = DirectoryPublisher()
                shouldThrow<NabuStorageException> { dht.publishOwn(a.identity, a.peerRecord(), null) }
                dht.publishOwn(a.identity, a.peerRecord(), null).skippedByRateLimit shouldBe false
                (failing.sequences[1] > failing.sequences[0]) shouldBe true
            } finally {
                gossip.stop()
                prekeys.stop()
            }
        }

        test("limits are validated") {
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxIdentitiesPerCatchUp = 0) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(minResolveInterval = Duration.ofSeconds(-1)) }
            shouldThrow<IllegalArgumentException> {
                DirectoryDhtLimits(
                    minResolveInterval = Duration.ofSeconds(90),
                    negativeCacheTtl = Duration.ofSeconds(60),
                )
            }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(resolveTrackerCapacity = 0) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(defaultTimeout = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(maxRecordValidity = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { DirectoryDhtLimits(minRepublishInterval = Duration.ofSeconds(-1)) }
        }
    })
