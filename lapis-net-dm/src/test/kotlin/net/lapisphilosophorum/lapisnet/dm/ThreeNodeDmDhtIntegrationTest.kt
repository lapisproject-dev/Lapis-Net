package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtResolution
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections
import kotlin.time.Duration.Companion.seconds

private val fastLimits =
    DirectoryDhtLimits(
        minRepublishInterval = Duration.ZERO,
        minResolveInterval = Duration.ZERO,
        negativeCacheTtl = Duration.ZERO,
    )

/**
 * V0.9.14, the defining DM test: A deposits an offline message for C while C is not listening to its mailbox
 * topic; the pointer reaches C only through the DHT - A publishes its outbox, B is merely a DHT node, C
 * catches up and the unchanged [MailboxPoller] fetches the blob from A and delivers the message.
 */
class ThreeNodeDmDhtIntegrationTest :
    FunSpec({
        /** Runs the scenario; returns (received messages, pending pointers right after the catch-up). */
        fun scenario(
            gated: Boolean,
            waitSeconds: Long,
        ): Pair<List<DmInboundMessage>, Int> {
            val outbox = DhtOutbox()
            val a = buildDmTestNode(dhtOutbox = outbox)
            val bNode = LapisNode.create(DualKeyIdentity.generate())
            bNode.start(bootstrapPeers = emptyList())
            val bStorage = NabuStorage.attach(bNode, Files.createTempDirectory("dm-dht-b"))

            val cIdentity = DualKeyIdentity.generate()
            val cNode = LapisNode.create(cIdentity)
            cNode.start(bootstrapPeers = emptyList())
            val cStorage = NabuStorage.attach(cNode, Files.createTempDirectory("dm-dht-c"))
            val cPubsub = GossipPubSub.attach(cNode)
            val cDirectory = PeerDirectoryGossip.attach(cPubsub, cStorage)
            val cBundles = PrekeyBundleGossip.attach(cPubsub, cStorage)
            val cPrekeys =
                PrekeyStore.create(
                    Files.createTempDirectory("dm-dht-c-pk"),
                    cIdentity,
                    oneTimePrekeyCount = 5,
                )
            var cManager: DmSessionManager? = null
            try {
                val cKey = cIdentity.secp256k1KeyPair.publicKey
                val aKey = a.identity.secp256k1KeyPair.publicKey
                cNode.connect(PeerInfo(a.node.peerId, a.node.listenAddresses()))

                // A learns C's record and bundle (needed for the X3DH first contact), C learns A's record
                val converge = Instant.now().plusSeconds(30)
                while (Instant.now().isBefore(converge)) {
                    a.publishSelf()
                    val nva = Instant.now().epochSecond + 3600
                    cDirectory.announce(
                        PeerRecord.create(
                            cIdentity,
                            cNode.listenAddresses(),
                            setOf(PeerCapability.DM),
                            System.nanoTime(),
                            nva,
                        ),
                    )
                    cBundles.announce(cPrekeys.publishBundle(cIdentity, nva))
                    if (a.peerDirectory.lookup(cKey) != null &&
                        a.prekeyBundleGossip.lookup(cKey) != null &&
                        cDirectory.lookup(aKey) != null
                    ) {
                        break
                    }
                    Thread.sleep(500)
                }

                // C is not listening to its mailbox topic yet: the deposit's gossip never reaches it
                val body = "dht-delivered-" + "x".repeat(300)
                var deposited = false
                val depositDeadline = Instant.now().plusSeconds(30)
                while (!deposited && Instant.now().isBefore(depositDeadline)) {
                    deposited = runCatching { a.dmSessionManager.sendOffline(cKey, DmContent(body = body)) }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true
                outbox.size() shouldBe 1

                val acceptance =
                    if (gated) {
                        DmAcceptanceCheck(
                            gates = listOf(AcceptanceGate.VeritasPath),
                            trustGraph = TrustGraph.fromEdges(emptyList()),
                            karmaScoreOf = KarmaScoreLookup { 0.0 },
                        )
                    } else {
                        null
                    }
                val cMailbox = MailboxGossip.attach(cPubsub, cStorage, cKey, acceptance)
                cManager =
                    DmSessionManager.attach(
                        cIdentity,
                        cPrekeys,
                        cNode,
                        cDirectory,
                        cBundles,
                        cMailbox,
                        cStorage,
                        cPubsub,
                        Files.createTempDirectory("dm-dht-c-sessions"),
                        dmTestPassphrase(),
                        mailboxPollIntervalSeconds = 2L,
                        acceptance = acceptance,
                    )
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                cManager.addInboundListener { received.add(it) }
                cMailbox.pending().size shouldBe 0

                // the DHT: A and C know B only
                val bAddress = bNode.listenAddresses().first().withP2P(bNode.peerId)
                a.storage.connectToDhtPeer(bAddress) shouldBe true
                cStorage.connectToDhtPeer(bAddress) shouldBe true
                val aDht =
                    DirectoryDht.attach(
                        a.storage,
                        a.peerDirectory,
                        a.prekeyBundleGossip,
                        fastLimits,
                        aKey,
                        outbox,
                    )
                val cDht = DirectoryDht.attach(cStorage, cDirectory, cBundles, fastLimits, cKey)
                cDht.registerOutboxConsumer(OutboxEntryKind.DM_MAILBOX_POINTER, cMailbox.dhtConsumer())

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

                var accepted = 0
                val catchUpDeadline = Instant.now().plusSeconds(30)
                while (accepted == 0 && Instant.now().isBefore(catchUpDeadline)) {
                    val r = cDht.resolve(aKey, a.node.peerId, Duration.ofSeconds(10))
                    if (r is DirectoryDhtResolution.Found) accepted = r.outboxEntriesAccepted
                    if (gated && r is DirectoryDhtResolution.Found) break
                    if (accepted == 0) Thread.sleep(500)
                }
                val pendingAfterCatchUp = cMailbox.pending().size
                if (gated) {
                    accepted shouldBe 0
                    Thread.sleep(waitSeconds * 1000)
                } else {
                    accepted shouldBe 1
                    val receiveDeadline = Instant.now().plusSeconds(waitSeconds)
                    while (received.isEmpty() && Instant.now().isBefore(receiveDeadline)) Thread.sleep(500)
                    Thread.sleep(3000) // a second delivery, if any, would show up now
                }
                return received.toList() to pendingAfterCatchUp
            } finally {
                runCatching { cManager?.stop() }
                runCatching { cDirectory.stop() }
                runCatching { cBundles.stop() }
                runCatching { cPubsub.stop() }
                runCatching { cNode.stop() }
                runCatching { bNode.stop() }
                a.stop()
            }
        }

        test("an offline DM reaches a recipient that missed the gossip, through the DHT outbox, exactly once")
            .config(timeout = 240.seconds) {
                val (received, _) = scenario(gated = false, waitSeconds = 60)
                received.size shouldBe 1
                received[0].content.body.startsWith("dht-delivered-") shouldBe true
            }

        test("the acceptance policy of the recipient applies to the DHT path: a gated sender is not delivered")
            .config(timeout = 240.seconds) {
                val (received, pending) = scenario(gated = true, waitSeconds = 12)
                received.size shouldBe 0
                pending shouldBe 0
            }
    })
