package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.core.test.TestScope
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

private val FAST_DHT =
    DirectoryDhtLimits(
        minRepublishInterval = Duration.ZERO,
        minResolveInterval = Duration.ZERO,
        negativeCacheTtl = Duration.ZERO,
        minDiscoveryInterval = Duration.ZERO,
    )

/** The relay and DHT bootstrap node: a LapisNode with the relay SERVER role, Nabu storage and a RELAY peer record. */
private class RelayNode {
    val identity = DualKeyIdentity.generate()
    val node =
        LapisNode.create(identity, relayConfig = RelayConfig.relayServer()).also {
            it.start(bootstrapPeers = emptyList())
        }
    val storage = NabuStorage.attach(node, Files.createTempDirectory("wired-relay"))
    val pubsub = GossipPubSub.attach(node)
    val directory = PeerDirectoryGossip.attach(pubsub, storage)
    val address get() = node.listenAddresses().first().withP2P(node.peerId)

    fun announceRelayRecord() {
        directory.announce(
            PeerRecord.create(
                identity,
                node.listenAddresses(),
                setOf(PeerCapability.RELAY),
                System.currentTimeMillis(),
                Instant.now().epochSecond + 3600,
            ),
        )
    }

    fun stop() {
        runCatching { directory.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

private data class Scenario(
    val delivered: Boolean,
    val entriesAccepted: Int,
    val pendingAfterDiscovery: Int,
    val providersFound: Int,
    val resolved: Int,
)

private fun postJson(
    port: Int,
    path: String,
    body: String,
): HttpResponse<String> {
    val base = "http://127.0.0.1:$port"
    return HttpClient.newHttpClient().send(
        HttpRequest
            .newBuilder(URI("$base$path"))
            .header("Content-Type", "application/json")
            .header("Origin", base)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(),
        HttpResponse.BodyHandlers.ofString(),
    )
}

private fun connect(
    from: BrowserServer,
    to: BrowserServer,
) {
    from.nodeForTesting.connect(PeerInfo(to.nodeForTesting.peerId, to.nodeForTesting.listenAddresses()))
}

/**
 * The V0.9.15 end-to-end proof, over real libp2p/Nabu: a private node A behind a relay R (A holds a reservation, found
 * and ranked through the directory, and its record is re-published WITH the circuit address), and an offline DM from A
 * to B that reaches B only through the DHT outbox - or, for a B that gates strangers, is declined at the DHT entrance
 * (T1) and never reaches the store.
 */
class MultiNodeWiredBrowserTest :
    FunSpec({
        suspend fun TestScope.scenario(
            bGated: Boolean,
            tag: String,
        ): Scenario {
            val relay = RelayNode()
            val dirA: Path = Files.createTempDirectory("wired-a-$tag")
            val dirB: Path = Files.createTempDirectory("wired-b-$tag")
            val idA = DualKeyIdentity.generate()
            val idB = DualKeyIdentity.generate()
            val aKey = idA.secp256k1KeyPair.publicKey
            val bKey = idB.secp256k1KeyPair.publicKey
            val configA =
                BrowserConfig(NodeWiringOptions.resolve(mapOf("reachability" to "private")))
            val configB =
                BrowserConfig(
                    acceptance = if (bGated) DmAcceptanceSettings(veritasGate = true) else DmAcceptanceSettings(),
                )

            fun startB() =
                startWiredTestServer(
                    identity = idB,
                    config = configB,
                    dataDirectory = dirB,
                    directoryDhtLimits = FAST_DHT,
                    mailboxPollIntervalSeconds = 2,
                    mailboxRedeliverIntervalSeconds = 3600,
                )

            var running: BrowserServer? = null
            val a =
                startWiredTestServer(
                    identity = idA,
                    config = configA,
                    dataDirectory = dirA,
                    directoryDhtLimits = FAST_DHT,
                    selfRecordCheckInterval = 300.milliseconds,
                    mailboxRedeliverIntervalSeconds = 3600,
                    autoRelayConfig =
                        AutoRelayConfig(
                            allowNonPublicCandidateAddresses = true,
                            reselectInterval = Duration.ofSeconds(1),
                        ),
                )
            try {
                val b = startB()
                running = b
                // gossip mesh A-B first (the republisher only announces on a CHANGE), then both know the relay
                connect(a, b)
                awaitCondition(60, "directory convergence A <-> B") {
                    a.republishSelfForDmTesting()
                    b.republishSelfForDmTesting()
                    a.peerDirectoryForDmTesting.lookup(bKey) != null &&
                        a.prekeyBundleGossipForDmTesting.lookup(bKey) != null &&
                        b.peerDirectoryForDmTesting.lookup(aKey) != null
                }
                connect(a, b)
                a.nodeForTesting.connect(PeerInfo(relay.node.peerId, relay.node.listenAddresses()))

                // 1. relay: A finds R in the directory, reserves, and re-publishes its record WITH the circuit address
                awaitCondition(60, "A learns the relay record") {
                    relay.announceRelayRecord()
                    a.peerDirectoryForDmTesting.lookup(relay.identity.secp256k1KeyPair.publicKey) != null
                }
                awaitCondition(60, "A holds a relay reservation") {
                    a.nodeForTesting.relayClient
                        .reservations()
                        .isNotEmpty()
                }
                awaitCondition(60, "B sees A's record with the circuit address") {
                    b.peerDirectoryForDmTesting
                        .lookup(aKey)
                        ?.addresses
                        ?.any { it.toString().contains("p2p-circuit") } == true
                }
                b.peerDirectoryForDmTesting.lookup(aKey)!!.capabilities shouldBe setOf(PeerCapability.DM)

                // 2. B goes offline; A deposits a DM for it
                b.stop()
                running = null
                var queued = false
                val sendDeadline = Instant.now().plusSeconds(60)
                var lastBody = ""
                while (!queued && Instant.now().isBefore(sendDeadline)) {
                    val response =
                        postJson(
                            a.boundPort,
                            "/api/dm/${hexOfKey(bKey)}",
                            json.encodeToString(NewDmRequest(body = "offline hello via the DHT")),
                        )
                    lastBody = response.body()
                    queued = response.statusCode() == 200
                    if (!queued) Thread.sleep(500)
                }
                check(queued) { "A could not deposit the offline DM: $lastBody" }
                a.dhtOutboxForTesting!!.size() shouldBe 1

                // 3. A publishes its outbox to the DHT (R is the only DHT node)
                check(a.storageForTesting.connectToDhtPeer(relay.address)) { "A cannot reach the DHT node" }
                awaitCondition(60, "A publishes its outbox") { a.selfRecordRepublisherForTesting.dhtPublications >= 1 }

                // 4. B comes back, reaches only the DHT, and discovers the inbox
                val b2 = startB()
                running = b2
                check(b2.storageForTesting.connectToDhtPeer(relay.address)) { "B cannot reach the DHT node" }
                var accepted = 0
                val discoverDeadline = Instant.now().plusSeconds(60)
                var providers = 0
                var resolved = 0
                while (accepted == 0 && resolved == 0 && Instant.now().isBefore(discoverDeadline)) {
                    val report = b2.directoryDhtForTesting!!.discoverInbox(Duration.ofSeconds(10))
                    accepted += report.entriesAccepted
                    providers += report.providersFound
                    resolved += report.resolved
                    if (accepted == 0 && resolved == 0) Thread.sleep(500)
                }
                val pendingAfterDiscovery = b2.mailboxGossipForTesting.pending().size
                if (!bGated) {
                    awaitCondition(90, "B receives the DM") {
                        b2.dmStoreForTesting.peers().contains(aKey)
                    }
                    val history = b2.dmStoreForTesting.historyFor(aKey)
                    history.size shouldBe 1
                } else {
                    Thread.sleep(8_000)
                    b2.dmStoreForTesting.peers().contains(aKey) shouldBe false
                }
                return Scenario(
                    b2.dmStoreForTesting.peers().contains(aKey),
                    accepted,
                    pendingAfterDiscovery,
                    providers,
                    resolved,
                )
            } finally {
                runCatching { running?.stop() }
                runCatching { a.stop() }
                relay.stop()
            }
        }

        test(
            "relay + DHT: a private node reserves a relay, re-publishes its circuit address, and its offline DM reaches B through the DHT",
        ).config(timeout = 600.seconds) {
            val result = scenario(bGated = false, tag = "open")
            result.delivered shouldBe true
            // the DHT was the route: B discovered the entry itself (no gossip redelivery: interval 3600 s)
            (result.providersFound >= 1) shouldBe true
            (result.resolved >= 1) shouldBe true
            (result.entriesAccepted >= 1) shouldBe true
        }

        test("T1: a stranger's validly signed pointer is declined at the DHT entrance of a gated node")
            .config(timeout = 600.seconds) {
                val result = scenario(bGated = true, tag = "gated")
                // the stranger's entry WAS found and resolved - and declined at the entrance
                (result.providersFound >= 1) shouldBe true
                (result.resolved >= 1) shouldBe true
                result.entriesAccepted shouldBe 0
                result.pendingAfterDiscovery shouldBe 0
                result.delivered shouldBe false
            }
    })
