@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.confinement.ConnectionConfinement
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.syntheticDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

private fun now() = Clock.systemUTC().millis() / 1000

/** The bootstrap multiaddr of [n] as an operator would configure it (`.../p2p/<id>`). */
private fun bootstrapAddress(n: WireTestNode): Multiaddr =
    n.node
        .listenAddresses()
        .first()
        .withP2P(n.peerId)

private fun announceRecord(n: WireTestNode) {
    n.peerDirectory.announce(PeerRecord.create(n.identity, n.node.listenAddresses(), emptySet(), 1, now() + 3600))
}

/**
 * Wave V0.10.0-J1b on real loopback nodes: a node in anonymity mode with connection confinement learns relays ONLY from
 * the relay directory snapshot of its bootstrap peer (it starts after the relays gossiped their descriptors and gets no
 * replay), chooses guards, closes the bootstrap connection, holds connections to its guards only and builds 3-hop
 * circuits. All relays sit on 127.0.0.1, so the locator is injected with synthetic, distinct /16 networks (as in
 * [MultiNodeAnonymityModeTest]); network diversity is NOT verified over real networks here.
 */
class MultiNodeRelayDirectorySnapshotTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        val runtimes = ArrayList<AnonymityRuntime>()
        afterSpec {
            runtimes.forEach { runCatching { it.close() } }
            all.forEach { it.close() }
        }

        val relays = List(6) { WireTestNode(relay = true).also { all += it } }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = MapLocator()

        fun startClient(
            bootstrap: List<WireTestNode>,
            confinement: ConnectionConfinement,
            client: WireTestNode,
        ): AnonymityRuntime {
            val modeStore =
                InMemoryDirectoryModeStore(
                    DirectoryModeState(
                        DirectoryAnonymityMode.OFF,
                        System.currentTimeMillis() - 5000,
                    ),
                )
            return AnonymityRuntime
                .start(
                    client.wire,
                    client.identity,
                    client.dir,
                    { null },
                    locator,
                    modeStore,
                    PrekeyStore.create(
                        Files.createTempDirectory("snapshot-prekeys").resolve("prekeys"),
                        client.identity,
                    ),
                    Ed25519KeyPair.generate(),
                    supervisor = client.supervisor,
                    governor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
                    confinement = confinement,
                    bootstrapPeers = bootstrap.map { bootstrapAddress(it) },
                ).also { runtimes += it }
        }

        fun guardPeerIds(
            client: WireTestNode,
            runtime: AnonymityRuntime,
        ): Set<PeerId> {
            val ids = runtime.guardIdentitiesForTest()
            return ids
                .mapNotNull {
                    client.wire.descriptors
                        .current(it, now())
                        ?.peerId
                }.toSet()
        }

        test("the relays gossip descriptors and peer records; the bootstrap relay holds all of them") {
            relays.forEach { announceRecord(it) }
            val descriptors =
                relays.map {
                    awaitTrue { it.wire.currentDescriptor() != null }.let { _ ->
                        it.wire.currentDescriptor()!!
                    }
                }
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(10 + i, i)) }
            awaitTrue(Duration.ofSeconds(90)) {
                descriptors.all { d ->
                    relays[0].wire.descriptors.current(d.identity, now()) != null &&
                        relays[0].peerDirectory.lookup(d.identity) != null
                }
            } shouldBe true
        }

        test(
            "a confined client learns relays from the snapshot, keeps only guard connections and builds circuits",
        ).config(
            timeout = 180.seconds,
        ) {
            val confinement = ConnectionConfinement()
            val client =
                WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON, confinement = confinement).also {
                    all +=
                        it
                }
            // nothing gossiped reaches it before it starts: it knows no relay and no peer record
            client.wire.descriptors.size() shouldBe 0
            client.node.listenAddresses().shouldBeEmpty()
            val started = System.nanoTime()
            val runtime = startClient(listOf(relays[0]), confinement, client)
            awaitTrue(Duration.ofSeconds(60)) {
                runtime.status().connectionState == "guards-only" && runtime.status().guards == 2
            } shouldBe true
            val confinedAfterMillis = (System.nanoTime() - started) / 1_000_000
            val status = runtime.status()
            (status.snapshotFetches >= 1) shouldBe true
            status.singleDirectorySource shouldBe true
            // the relays came from the snapshot, together with the guards' peer records
            (client.wire.descriptors.size() >= 6) shouldBe true
            val guardPeers = guardPeerIds(client, runtime)
            guardPeers.size shouldBe 2

            // 3-hop circuits: the directory publication goes through them
            awaitTrue(Duration.ofSeconds(60)) {
                runtime.maintainNow()
                runtime.publications() >= 1
            } shouldBe true
            val publishedAfterMillis = (System.nanoTime() - started) / 1_000_000
            println(
                "J1b measurement: guards-only after $confinedAfterMillis ms, first publication after $publishedAfterMillis ms",
            )
            (publishedAfterMillis < 60_000 + confinedAfterMillis) shouldBe true

            // every connection of the client goes to {primary, backup}; the bootstrap connection is closed unless it is a guard
            val remotes =
                client.node.host.network.connections
                    .filter { !it.closeFuture().isDone }
                    .map { it.secureSession().remoteId }
                    .toSet()
            (remotes - guardPeers).shouldBeEmpty()
            if (relays[0].peerId !in guardPeers) (relays[0].peerId in remotes) shouldBe false
            confinement.allowedSnapshot() shouldBe guardPeers

            // a relay that is not a guard can not reach the client: it has no address, and the client refuses to dial it
            val outsider = relays.first { it.peerId !in guardPeers }
            client.node.listenAddresses().shouldBeEmpty()
            runCatching {
                client.node.connect(
                    PeerInfo(outsider.peerId, outsider.node.listenAddresses()),
                )
            }.isFailure shouldBe
                true
            runtime.close()
        }

        test("a malicious bootstrap with a Sybil flood and an honest bootstrap: the guard is never a Sybil").config(
            timeout = 180.seconds,
        ) {
            // the malicious bootstrap meshes with the relays (it serves the honest descriptors it saw too) and adds 200
            // validly signed Sybil descriptors in diverse synthetic networks to its own index, without gossiping them
            val malicious = WireTestNode(relay = false).also { all += it }
            relays.forEach { malicious.connectTo(it) }
            // both sources must hold the whole honest view first: the preference for confirmed candidates needs at least
            // three relays confirmed by both (a thin honest view is the documented limit of the defence, not tested here)
            val honest = relays.map { it.wire.currentDescriptor()!!.identity }
            awaitTrue(Duration.ofSeconds(90)) {
                honest.all { id ->
                    malicious.wire.descriptors.current(id, now()) != null &&
                        relays[1].wire.descriptors.current(id, now()) != null
                }
            } shouldBe true
            val sybils = ArrayList<OnionRelayDescriptor>()
            repeat(200) { i ->
                val d = syntheticDescriptor()
                locator.put(d, v4(100 + i / 200, i % 200))
                malicious.wire.descriptors.add(d, now())
                sybils += d
            }
            val sybilIds: Set<Secp256k1PublicKey> = sybils.map { it.identity }.toSet()
            val confinement = ConnectionConfinement()
            val client =
                WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON, confinement = confinement).also {
                    all +=
                        it
                }
            val runtime = startClient(listOf(malicious, relays[1]), confinement, client)
            awaitTrue(Duration.ofSeconds(90)) { runtime.status().guards == 2 } shouldBe true
            val guards = runtime.guardIdentitiesForTest()
            guards.none { it in sybilIds } shouldBe true
            // the snapshot budget held: at most 64 new identities from the flooding source
            (client.wire.descriptors.size() <= 6 + 64) shouldBe true
            runtime.close()
        }
    })
