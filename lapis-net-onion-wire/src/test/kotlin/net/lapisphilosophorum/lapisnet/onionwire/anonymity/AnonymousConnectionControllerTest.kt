@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDirectoryCodec
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec
import net.lapisphilosophorum.lapisnet.directory.RelayDirectoryFetchResult
import net.lapisphilosophorum.lapisnet.directory.RelayDirectorySnapshotIngest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.confinement.ConnectionConfinement
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardChoiceGate
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardManager
import net.lapisphilosophorum.lapisnet.onionwire.path.InMemoryGuardStateStore
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.OnionPathSelector
import net.lapisphilosophorum.lapisnet.onionwire.path.seededRandom
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicReference

/** A relay identity with a signed descriptor and a matching peer record (no network). */
internal class TestRelay(
    now: Long = System.currentTimeMillis() / 1000,
    validitySeconds: Long = 3600,
) {
    val identity: DualKeyIdentity = DualKeyIdentity.generate()
    val descriptor: OnionRelayDescriptor =
        OnionRelayDescriptor.create(
            identity,
            OnionKeyBinding.create(identity.secp256k1KeyPair, X25519KeyPair.generate().publicKey, now + 7 * 86_400),
            1,
            now + validitySeconds,
            now,
        )
    val record: PeerRecord =
        PeerRecord.create(
            identity,
            listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001")),
            emptySet(),
            1,
            now + validitySeconds,
            now,
        )
    val peerId: PeerId get() = descriptor.peerId
    val key: Secp256k1PublicKey get() = descriptor.identity
}

/** In-memory network: who is connected, which dials succeed, what each source answers. */
private class FakeNetwork : ConfinedNetwork {
    val connected = ConcurrentHashMap.newKeySet<PeerId>()
    val failingDials = ConcurrentHashMap.newKeySet<PeerId>()
    val dials = ArrayList<PeerId>()
    val fetches = ArrayList<PeerId>()
    val answers = ConcurrentHashMap<PeerId, RelayDirectoryFetchResult>()

    /** Sources whose fetch never completes (stays in flight). */
    val hanging = ConcurrentHashMap.newKeySet<PeerId>()
    val closedOutside = ArrayList<Set<PeerId>>()

    override fun isConnected(peer: PeerId): Boolean = peer in connected

    override fun dial(
        peer: PeerId,
        addresses: List<Multiaddr>,
    ) {
        dials += peer
        if (peer in failingDials) throw IllegalStateException("refused")
        connected += peer
    }

    override fun fetch(peer: PeerId): CompletableFuture<RelayDirectoryFetchResult> {
        fetches += peer
        if (peer in hanging) return CompletableFuture()
        return CompletableFuture.completedFuture(answers[peer] ?: RelayDirectoryFetchResult.Failed)
    }

    override fun closeOutside(allowed: Set<PeerId>) {
        closedOutside += allowed
        connected.retainAll(allowed)
    }
}

private class Fixture(
    bootstrapCount: Int = 1,
    relayCount: Int = 6,
    relayValiditySeconds: Long = 3600,
) {
    val clock = WireTestClock()
    val random = seededRandom(7)
    val relays = List(relayCount) { TestRelay(validitySeconds = relayValiditySeconds) }
    val bootstrap = List(bootstrapCount) { PeerId.random() }
    val index = OnionRelayDescriptorIndex()
    val records = relays.associate { it.key to it.record }
    val ingest = RelayDirectorySnapshotIngest(index, { _, _ -> true }, clock)
    val locator = MapLocator().also { l -> relays.forEachIndexed { i, r -> l.put(r.descriptor, v4(10 + i, i)) } }
    val guards = GuardManager(InMemoryGuardStateStore(), random, clock)
    val controllerRef = AtomicReference<AnonymousConnectionController?>()
    val gate =
        object : GuardChoiceGate {
            override fun mayChooseNewGuard(): Boolean = controllerRef.get()?.relayViewReady() == true

            override fun confirmations(identity: Secp256k1PublicKey): Int = ingest.sourcesFor(identity)
        }
    val selector =
        OnionPathSelector(
            { index.snapshot(clock.millis() / 1000) },
            DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
            locator,
            { null },
            guards = guards,
            random = random,
            clock = clock,
            guardGate = gate,
        )
    val confinement = ConnectionConfinement()
    val network = FakeNetwork()
    var viewChanges = 0
    val controller =
        AnonymousConnectionController(
            confinement,
            bootstrap.map { Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/$it") },
            guards,
            selector,
            index,
            { id, _ -> records[id] },
            network,
            ingest,
            clock,
            random,
            Executor { it.run() },
            onRelayViewChanged = { viewChanges++ },
        ).also { controllerRef.set(it) }

    fun snapshot(): RelayDirectoryFetchResult =
        RelayDirectoryFetchResult.Ok(
            OnionRelayDirectoryCodec.decodeResponse(
                OnionRelayDirectoryCodec.encodeResponse(
                    relays.map { it.descriptor to PeerRecordCodec.encode(it.record) },
                ),
            ),
        )

    /** The relay descriptors as gossip would have delivered them: in the index, without any snapshot provenance. */
    fun gossipAllRelays() {
        val now = clock.millis() / 1000
        relays.forEach { index.add(it.descriptor, now) }
    }

    fun guardPeers(): Set<PeerId> {
        val s = guards.snapshot()
        return listOfNotNull(s.primary, s.backup).map { g -> relays.first { it.key == g.identity }.peerId }.toSet()
    }
}

class AnonymousConnectionControllerTest :
    FunSpec({
        test(
            "bootstrapping -> guards only: snapshot from the bootstrap peer, guards chosen and connected, bootstrap closed",
        ) {
            val f = Fixture()
            f.network.answers[f.bootstrap[0]] = f.snapshot()
            f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
            f.confinement.isAllowed(f.bootstrap[0]) shouldBe true
            f.controller.tick()
            f.network.dials.first() shouldBe f.bootstrap[0]
            f.network.fetches.first() shouldBe f.bootstrap[0]
            f.viewChanges shouldBe 1
            f.guards.guardCount() shouldBe 2
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
            f.confinement.isAllowed(f.bootstrap[0]) shouldBe false
            f.confinement.allowedSnapshot() shouldBe f.guardPeers()
            f.network.connected shouldContainExactlyInAnyOrder f.guardPeers()
            f.controller.guardConnections() shouldBe 2
            // a single configured source: the first guard choice trusted it (Q14), visible in the status
            f.controller.singleDirectorySource() shouldBe true
            // each guard was asked for its snapshot once after connecting
            f.network.fetches.count { it in f.guardPeers() } shouldBe 2
        }

        test("guard loss: bootstrap peers are allowed again only after two unhealthy ticks (hysteresis)") {
            val f = Fixture()
            f.network.answers[f.bootstrap[0]] = f.snapshot()
            f.controller.tick()
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
            f.network.failingDials += f.guardPeers()
            f.network.connected.clear()
            f.controller.tick()
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
            f.confinement.isAllowed(f.bootstrap[0]) shouldBe false
            f.controller.tick()
            f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
            f.confinement.isAllowed(f.bootstrap[0]) shouldBe true
            // guards are back: guards only again, no close-and-reconnect loop in between
            f.network.failingDials.clear()
            f.controller.tick()
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
        }

        test("bootstrap dials back off 5 s, 15 s, 45 s, then 60 s") {
            val f = Fixture()
            f.network.failingDials += f.bootstrap[0]
            f.controller.tick()
            f.network.dials.size shouldBe 1
            f.clock.advanceSeconds(4)
            f.controller.tick()
            f.network.dials.size shouldBe 1
            f.clock.advanceSeconds(2)
            f.controller.tick()
            f.network.dials.size shouldBe 2
            f.clock.advanceSeconds(14)
            f.controller.tick()
            f.network.dials.size shouldBe 2
            f.clock.advanceSeconds(2)
            f.controller.tick()
            f.network.dials.size shouldBe 3
            f.clock.advanceSeconds(46)
            f.controller.tick()
            f.network.dials.size shouldBe 4
            f.clock.advanceSeconds(59)
            f.controller.tick()
            f.network.dials.size shouldBe 4
            f.clock.advanceSeconds(2)
            f.controller.tick()
            f.network.dials.size shouldBe 5
            f.guards.guardCount() shouldBe 0
        }

        test(
            "gate: with two configured sources and one unreachable, one answer is not enough until 120 s have passed",
        ) {
            val f = Fixture(bootstrapCount = 2)
            f.network.answers[f.bootstrap[0]] = f.snapshot()
            f.network.failingDials += f.bootstrap[1]
            f.controller.tick()
            f.controller.relayViewReady() shouldBe false
            f.guards.guardCount() shouldBe 0
            f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
            // four failed dials in a row (backoff 5 s, 15 s, 45 s): the second source counts as unreachable
            for (s in listOf(6L, 16L, 46L)) {
                f.clock.advanceSeconds(s)
                f.controller.tick()
            }
            val unreachableAfter = AnonymousConnectionController.UNREACHABLE_AFTER_DIAL_FAILURES
            f.network.dials.count { it == f.bootstrap[1] } shouldBe unreachableAfter
            // 68 s after the first answer: the settle window has not passed yet
            f.controller.relayViewReady() shouldBe false
            f.guards.guardCount() shouldBe 0
            f.clock.advanceSeconds(53)
            f.controller.relayViewReady() shouldBe true
            f.controller.tick()
            f.guards.guardCount() shouldBe 2
            f.controller.singleDirectorySource() shouldBe false
        }

        for (failure in listOf(
            RelayDirectoryFetchResult.Failed,
            RelayDirectoryFetchResult.Malformed,
            RelayDirectoryFetchResult.Timeout,
        )) {
            test(
                "gate: a reachable source that answers $failure keeps it closed past 120 s and is retried soon " +
                    "(one hostile source alone never decides the guard choice)",
            ) {
                val f = Fixture(bootstrapCount = 2)
                // source 0 answers at once (it may be the hostile one); source 1's server refuses the stream
                f.network.answers[f.bootstrap[0]] = f.snapshot()
                f.network.answers[f.bootstrap[1]] = failure
                f.controller.tick()
                f.network.fetches.count { it == f.bootstrap[1] } shouldBe 1
                f.clock.advanceSeconds(130)
                f.controller.tick()
                f.controller.relayViewReady() shouldBe false
                f.guards.guardCount() shouldBe 0
                f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
                // retried inside the window (backoff), not only after 10 minutes
                f.network.fetches.count { it == f.bootstrap[1] } shouldBe 2
                f.clock.advanceSeconds(600)
                f.controller.tick()
                f.guards.guardCount() shouldBe 0
                // the second source answers: two sources, the gate opens and every relay is confirmed twice
                f.network.answers[f.bootstrap[1]] = f.snapshot()
                f.clock.advanceSeconds(61)
                f.controller.tick()
                f.controller.relayViewReady() shouldBe true
                f.relays.all { f.ingest.sourcesFor(it.key) >= 2 } shouldBe true
                f.guards.guardCount() shouldBe 2
            }
        }

        test("a source that fails before its first snapshot is retried after 5 s, 15 s, 45 s, then 60 s") {
            val f = Fixture()
            f.network.answers[f.bootstrap[0]] = RelayDirectoryFetchResult.Failed
            f.controller.tick()
            f.network.fetches.size shouldBe 1
            val steps = listOf(4L to 1, 2L to 2, 14L to 2, 2L to 3, 44L to 3, 2L to 4, 58L to 4, 2L to 5)
            for ((advance, expected) in steps) {
                f.clock.advanceSeconds(advance)
                f.controller.tick()
                f.network.fetches.size shouldBe expected
            }
            f.guards.guardCount() shouldBe 0
            f.controller.relayViewReady() shouldBe false
        }

        test("gate: two answering sources open it at once and confirm every relay twice") {
            val f = Fixture(bootstrapCount = 2)
            f.network.answers[f.bootstrap[0]] = f.snapshot()
            f.network.answers[f.bootstrap[1]] = f.snapshot()
            f.controller.tick()
            f.controller.relayViewReady() shouldBe true
            f.relays.all { f.ingest.sourcesFor(it.key) >= 2 } shouldBe true
            f.guards.guardCount() shouldBe 2
        }

        test("a source that does not speak the protocol is skipped and the next one is used") {
            val f = Fixture(bootstrapCount = 2)
            f.network.answers[f.bootstrap[0]] = RelayDirectoryFetchResult.Unsupported
            f.network.answers[f.bootstrap[1]] = f.snapshot()
            f.controller.tick()
            f.network.fetches.count { it == f.bootstrap[0] } shouldBe 1
            f.network.fetches.count { it == f.bootstrap[1] } shouldBe 1
            // only one source answered: the gate waits for the settle time
            f.controller.relayViewReady() shouldBe false
            f.clock.advanceSeconds(700)
            f.controller.tick()
            // the unsupported source is never asked again
            f.network.fetches.count { it == f.bootstrap[0] } shouldBe 1
            f.guards.guardCount() shouldBe 2
        }

        test("no answer at all: no guard is chosen, the node stays bootstrapping (fail-closed)") {
            val f = Fixture()
            f.network.answers[f.bootstrap[0]] = RelayDirectoryFetchResult.Malformed
            f.controller.tick()
            f.clock.advanceSeconds(300)
            f.controller.tick()
            f.guards.guardCount() shouldBe 0
            f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
            f.controller.relayViewReady() shouldBe false
        }

        test("the preference picks only confirmed candidates when at least three exist") {
            // exactly three confirmed: after the primary is taken only two remain for the backup, which must still
            // come from them (regression of the J1b load series, where an unconfirmed Sybil became the backup)
            val f = Fixture(bootstrapCount = 2, relayCount = 12)
            val confirmed = f.relays.take(3)
            val onlyOne = f.relays.drop(3)

            fun snap(rs: List<TestRelay>) =
                RelayDirectoryFetchResult.Ok(
                    OnionRelayDirectoryCodec.decodeResponse(
                        OnionRelayDirectoryCodec.encodeResponse(
                            rs.map {
                                it.descriptor to
                                    PeerRecordCodec.encode(it.record)
                            },
                        ),
                    ),
                )
            f.network.answers[f.bootstrap[0]] = snap(f.relays)
            f.network.answers[f.bootstrap[1]] = snap(confirmed)
            f.controller.tick()
            val s = f.guards.snapshot()
            val chosen = listOfNotNull(s.primary, s.backup).map { it.identity }
            chosen.size shouldBe 2
            chosen.all { id -> confirmed.any { it.key == id } } shouldBe true
            chosen.none { id -> onlyOne.any { it.key == id } } shouldBe true
        }
        test("gossip fallback: every bootstrap peer is old (no snapshots), the gossip view is used after 120 s") {
            val f = Fixture(bootstrapCount = 2)
            f.bootstrap.forEach { f.network.answers[it] = RelayDirectoryFetchResult.Unsupported }
            f.gossipAllRelays()
            f.controller.tick()
            f.network.fetches.size shouldBe 2
            f.controller.gossipOnlyRelayView() shouldBe true
            f.controller.relayViewReady() shouldBe false
            f.guards.guardCount() shouldBe 0
            f.clock.advanceSeconds(119)
            f.controller.tick()
            f.controller.relayViewReady() shouldBe false
            f.guards.guardCount() shouldBe 0
            f.clock.advanceSeconds(2)
            f.controller.relayViewReady() shouldBe true
            f.controller.tick()
            f.guards.guardCount() shouldBe 2
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
            f.network.connected shouldContainExactlyInAnyOrder f.guardPeers()
            // the old sources are never asked again
            f.network.fetches.count { it in f.bootstrap } shouldBe 2
        }

        test("gossip fallback: a guard that later answers Ok does not close the gate that had already opened") {
            val f = Fixture(bootstrapCount = 2, relayValiditySeconds = 24 * 3600)
            f.bootstrap.forEach { f.network.answers[it] = RelayDirectoryFetchResult.Unsupported }
            f.gossipAllRelays()
            f.controller.tick()
            f.clock.advanceSeconds(121)
            f.controller.tick()
            f.controller.relayViewReady() shouldBe true
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
            val guards = f.guardPeers().toList()
            guards.size shouldBe 2
            // a newer guard answers its next (refresh) fetch with a snapshot: one responder, fewer than required
            f.network.answers[guards[0]] = f.snapshot()
            f.clock.advanceSeconds(4 * 3600)
            f.controller.tick()
            f.network.fetches.count { it == guards[0] } shouldBe 2
            f.controller.gossipOnlyRelayView() shouldBe false
            // the settle window started with the gossip fallback, not with this first snapshot
            f.controller.relayViewReady() shouldBe true
        }

        test("no gossip fallback while one bootstrap peer was never reached (fail-closed)") {
            val f = Fixture(bootstrapCount = 2)
            f.network.answers[f.bootstrap[0]] = RelayDirectoryFetchResult.Unsupported
            f.network.failingDials += f.bootstrap[1]
            f.gossipAllRelays()
            f.controller.tick()
            f.clock.advanceSeconds(700)
            f.controller.tick()
            f.controller.gossipOnlyRelayView() shouldBe false
            f.controller.relayViewReady() shouldBe false
            f.guards.guardCount() shouldBe 0
            f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
        }

        test("no bootstrap peer configured: flagged, nothing is dialled or fetched, stays bootstrapping") {
            val f = Fixture(bootstrapCount = 0)
            f.controller.noBootstrapPeers() shouldBe true
            f.controller.tick()
            f.clock.advanceSeconds(700)
            f.controller.tick()
            f.network.dials.size shouldBe 0
            f.network.fetches.size shouldBe 0
            f.controller.state() shouldBe ConfinementState.BOOTSTRAPPING
            val withOne = Fixture(bootstrapCount = 1)
            withOne.controller.noBootstrapPeers() shouldBe false
        }

        test("one fetch per source per 10 minutes once it has delivered a snapshot") {
            // no relay: the snapshot is valid but empty, so no path is ready and the node keeps asking its source
            val f = Fixture(relayCount = 0)
            f.network.answers[f.bootstrap[0]] = f.snapshot()
            f.controller.tick()
            f.network.fetches.size shouldBe 1
            f.clock.advanceSeconds(9 * 60)
            f.controller.tick()
            f.network.fetches.size shouldBe 1
            f.clock.advanceSeconds(61)
            f.controller.tick()
            f.network.fetches.size shouldBe 2
        }

        test("at most 6 fetches per hour in total, over all sources") {
            val f = Fixture(bootstrapCount = 8)
            f.controller.tick()
            f.network.fetches.size shouldBe AnonymousConnectionController.MAX_FETCHES_PER_HOUR
            f.controller.snapshotFetches() shouldBe AnonymousConnectionController.MAX_FETCHES_PER_HOUR.toLong()
            // every source is due again after 10 minutes, but the hourly budget is spent
            f.clock.advanceSeconds(11 * 60)
            f.controller.tick()
            f.network.fetches.size shouldBe AnonymousConnectionController.MAX_FETCHES_PER_HOUR
            f.clock.advanceSeconds(50 * 60)
            f.controller.tick()
            f.network.fetches.size shouldBe 2 * AnonymousConnectionController.MAX_FETCHES_PER_HOUR
        }

        test("at most 4 bootstrap sources are asked at the same time") {
            val f = Fixture(bootstrapCount = 8)
            f.network.hanging += f.bootstrap
            f.controller.tick()
            f.network.fetches.size shouldBe AnonymousConnectionController.MAX_BOOTSTRAP_FETCH_SOURCES
            val distinct = f.network.fetches.toSet()
            distinct.size shouldBe AnonymousConnectionController.MAX_BOOTSTRAP_FETCH_SOURCES
            // still in flight: no further source is asked, even when the interval has passed
            f.clock.advanceSeconds(11 * 60)
            f.controller.tick()
            f.network.fetches.size shouldBe AnonymousConnectionController.MAX_BOOTSTRAP_FETCH_SOURCES
        }

        test(
            "guard fetch: postponed while the hourly budget is spent, then asked, then refreshed every 3 h +/- 20 %",
        ) {
            val f = Fixture(bootstrapCount = 6, relayValiditySeconds = 23 * 3600L)
            // six old sources spend the whole budget; the guards come from the gossip view
            f.bootstrap.forEach { f.network.answers[it] = RelayDirectoryFetchResult.Unsupported }
            f.gossipAllRelays()
            f.controller.tick()
            f.network.fetches.size shouldBe 6
            f.clock.advanceSeconds(121)
            f.controller.tick()
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
            val guards = f.guardPeers()
            // the guards are connected, but the budget allows no fetch: postponed, not dropped
            f.network.fetches.count { it in guards } shouldBe 0
            f.clock.advanceSeconds(30 * 60)
            f.controller.tick()
            f.network.fetches.count { it in guards } shouldBe 0
            // the first fetches leave the hour window: each guard is asked once
            f.clock.advanceSeconds(30 * 60)
            f.controller.tick()
            guards.forEach { g -> f.network.fetches.count { it == g } shouldBe 1 }
            // the refresh is due between 2.4 h and 3.6 h later
            f.clock.advanceSeconds((2.4 * 3600).toLong() - 60)
            f.controller.tick()
            guards.forEach { g -> f.network.fetches.count { it == g } shouldBe 1 }
            f.clock.advanceSeconds((1.2 * 3600).toLong() + 120)
            f.controller.tick()
            guards.forEach { g -> f.network.fetches.count { it == g } shouldBe 2 }
            f.controller.state() shouldBe ConfinementState.GUARDS_ONLY
        }
    })
