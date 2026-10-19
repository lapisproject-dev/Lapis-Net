package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private val fastLimits =
    DirectoryDhtLimits(
        minRepublishInterval = Duration.ZERO,
        minResolveInterval = Duration.ZERO,
        negativeCacheTtl = Duration.ZERO,
        minDiscoveryInterval = Duration.ZERO,
    )

private class MailNode(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val node: LapisNode = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
    val storage: NabuStorage = NabuStorage.attach(node, Files.createTempDirectory("mail-dht-it"))
    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val directory: PeerDirectoryGossip = PeerDirectoryGossip.attach(pubsub, storage)
    val bundles: PrekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
    val key = identity.secp256k1KeyPair.publicKey
    val dhtAddress get() = node.listenAddresses().first().withP2P(node.peerId)

    fun stop() {
        runCatching { directory.stop() }
        runCatching { bundles.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

/**
 * V0.9.14, the defining mail test: A mails C, who is not subscribed to anything and does not know A (first
 * contact). A publishes its outbox and announces a rendezvous record; B is only a DHT node; C asks the
 * rendezvous key, resolves A's value, fetches envelope and body from A and finds the mail in its inbox.
 */
class ThreeNodeMailDhtIntegrationTest :
    FunSpec({
        fun scenario(gated: Boolean): Triple<Int, Int, Long> {
            val outbox = DhtOutbox()
            val a = MailNode()
            val b = MailNode()
            val c = MailNode()
            var fetcher: InboxDhtFetcher? = null
            var inbox: InboxGossip? = null
            try {
                MailSender(
                    a.pubsub,
                    a.storage,
                    outbox,
                ).send(
                    a.identity.secp256k1KeyPair,
                    listOf(c.key),
                    "hello",
                    "from a",
                    encryption = EncryptionMode.HYBRID_ECIES,
                )
                outbox.size() shouldBe 1

                inbox =
                    InboxGossip.attach(
                        c.pubsub,
                        c.storage,
                        c.key,
                        if (gated) {
                            MailAcceptanceCheck(
                                gates = listOf(MailAcceptanceGate.VeritasPath),
                                trustGraph = TrustGraph.fromEdges(emptyList()),
                                karmaScoreOf = KarmaScoreLookup { 0.0 },
                            )
                        } else {
                            null
                        },
                    )
                a.storage.connectToDhtPeer(b.dhtAddress) shouldBe true
                c.storage.connectToDhtPeer(b.dhtAddress) shouldBe true
                val aDht = DirectoryDht.attach(a.storage, a.directory, a.bundles, fastLimits, a.key, outbox)
                val cDht = DirectoryDht.attach(c.storage, c.directory, c.bundles, fastLimits, c.key)
                fetcher = InboxDhtFetcher.attach(inbox, c.storage, c.directory, cDht, c.key, pollIntervalSeconds = 2)

                val record =
                    PeerRecord.create(
                        a.identity,
                        a.node.listenAddresses(),
                        setOf(PeerCapability.DM),
                        System.nanoTime(),
                        Instant.now().epochSecond + 3600,
                    )
                val published = aDht.publishOwn(a.identity, record, null)
                published.acknowledged shouldBe 1
                published.outboxEntriesPublished shouldBe 1
                (published.rendezvousAnnounced >= 1) shouldBe true

                val deadline = Instant.now().plusSeconds(if (gated) 45 else 75)
                while (Instant.now().isBefore(deadline)) {
                    cDht.discoverInbox(Duration.ofSeconds(10))
                    val done =
                        if (gated) {
                            fetcher.fetchAttempts >= 1 && fetcher.pendingCount() == 0
                        } else {
                            inbox
                                .messages()
                                .isNotEmpty()
                        }
                    if (done) break
                    Thread.sleep(1000)
                }
                Thread.sleep(3000)
                return Triple(inbox.messages().size, fetcher.pendingCount(), fetcher.fetchAttempts)
            } finally {
                fetcher?.stop()
                inbox?.stop()
                listOf(a, b, c).forEach { it.stop() }
            }
        }

        test("a first-contact mail reaches an offline recipient through rendezvous, the DHT outbox and a direct fetch")
            .config(timeout = 240.seconds) {
                val (messages, pending, _) = scenario(gated = false)
                messages shouldBe 1
                pending shouldBe 0
            }

        test(
            "the recipient's acceptance policy applies to the DHT path: the envelope is declined and the body never fetched",
        ).config(timeout = 240.seconds) {
            val (messages, pending, attempts) = scenario(gated = true)
            messages shouldBe 0
            pending shouldBe 0
            attempts shouldBe 1L
        }
    })
