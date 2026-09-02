package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections

class DmSendAutoTest :
    FunSpec({
        test("online and reachable: sendAuto dials successfully and returns SENT_ONLINE") {
            val sender = buildDmTestNode()
            val recipient = buildDmTestNode()
            try {
                connectAndConverge(sender, recipient)
                val recipientPub = recipient.identity.secp256k1KeyPair.publicKey

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                var outcome: DmSendOutcome? = null
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(deadline)) {
                    outcome =
                        runCatching {
                            sender.dmSessionManager.sendAuto(recipientPub, DmContent(body = "hello online"))
                        }.getOrNull()
                    if (received.isEmpty()) Thread.sleep(1000)
                }

                outcome shouldBe DmSendOutcome.SENT_ONLINE
                received.size shouldBe 1
                received[0].content.body shouldBe "hello online"
            } finally {
                sender.stop()
                recipient.stop()
            }
        }

        test("no directory record for the recipient at all: sendAuto falls straight to QUEUED_FOR_PICKUP") {
            val sender = buildDmTestNode()
            val recipientIdentity = DualKeyIdentity.generate()
            val recipientPrekeyStore =
                PrekeyStore.create(
                    Files.createTempDirectory("send-auto-no-record-prekeystore"),
                    recipientIdentity,
                    oneTimePrekeyCount = 5,
                )
            val recipientNode = LapisNode.create(recipientIdentity)
            recipientNode.start(bootstrapPeers = emptyList())
            val recipientStorage =
                NabuStorage.attach(
                    recipientNode,
                    Files.createTempDirectory("send-auto-no-record-storage"),
                )
            val recipientPubsub = GossipPubSub.attach(recipientNode)
            val recipientPrekeyBundleGossip = PrekeyBundleGossip.attach(recipientPubsub, recipientStorage)
            try {
                recipientNode.connect(PeerInfo(sender.node.peerId, sender.node.listenAddresses()))
                val recipientPub = recipientIdentity.secp256k1KeyPair.publicKey

                // Only the BUNDLE converges (needed for X3DH first contact) - the directory record
                // never does, since it is never announced here at all.
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (Instant.now().isBefore(deadline)) {
                    recipientPrekeyBundleGossip.announce(
                        recipientPrekeyStore.publishBundle(recipientIdentity, Instant.now().epochSecond + 3600),
                    )
                    if (sender.prekeyBundleGossip.lookup(recipientPub) != null) break
                    Thread.sleep(500)
                }
                sender.prekeyBundleGossip.lookup(recipientPub) shouldNotBe null
                sender.peerDirectory.lookup(recipientPub) shouldBe null

                val outcome = sender.dmSessionManager.sendAuto(recipientPub, DmContent(body = "no record, offline"))
                outcome shouldBe DmSendOutcome.QUEUED_FOR_PICKUP
            } finally {
                runCatching { recipientPrekeyBundleGossip.stop() }
                runCatching { recipientNode.stop() }
                sender.stop()
            }
        }

        test(
            "a directory record that has gone unreachable (dial fails) falls back to an offline " +
                "deposit that is a real X3DH_INITIAL - proven end-to-end: the recipient later comes " +
                "back online with NO prior session and still successfully establishes one and " +
                "receives the message, which is only possible if a genuine X3DH_INITIAL (never a " +
                "TEXT envelope on a nonexistent session) was deposited",
        ) {
            val sender = buildDmTestNode(mailboxRedeliverIntervalSeconds = 2L)
            val recipientIdentity = DualKeyIdentity.generate()
            val recipientSessionDir = Files.createTempDirectory("send-auto-dial-fail-recipient-sessions")
            val recipientPrekeyStore =
                PrekeyStore.create(
                    Files.createTempDirectory("send-auto-dial-fail-prekeystore"),
                    recipientIdentity,
                    oneTimePrekeyCount = 5,
                )

            var recipientNode = LapisNode.create(recipientIdentity)
            recipientNode.start(bootstrapPeers = emptyList())
            var recipientStorage =
                NabuStorage.attach(
                    recipientNode,
                    Files.createTempDirectory("send-auto-dial-fail-storage"),
                )
            var recipientPubsub = GossipPubSub.attach(recipientNode)
            var recipientPeerDirectory = PeerDirectoryGossip.attach(recipientPubsub, recipientStorage)
            var recipientPrekeyBundleGossip = PrekeyBundleGossip.attach(recipientPubsub, recipientStorage)

            try {
                recipientNode.connect(PeerInfo(sender.node.peerId, sender.node.listenAddresses()))
                val recipientPub = recipientIdentity.secp256k1KeyPair.publicKey

                val convergeDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (Instant.now().isBefore(convergeDeadline)) {
                    sender.publishSelf()
                    val notValidAfter = Instant.now().epochSecond + 3600
                    recipientPeerDirectory.announce(
                        PeerRecord.create(
                            recipientIdentity,
                            recipientNode.listenAddresses(),
                            setOf(PeerCapability.DM),
                            System.nanoTime(),
                            notValidAfter,
                        ),
                    )
                    recipientPrekeyBundleGossip.announce(
                        recipientPrekeyStore.publishBundle(recipientIdentity, notValidAfter),
                    )
                    if (sender.peerDirectory.lookup(recipientPub) != null &&
                        sender.prekeyBundleGossip.lookup(recipientPub) != null
                    ) {
                        break
                    }
                    Thread.sleep(500)
                }
                sender.peerDirectory.lookup(recipientPub) shouldNotBe null

                // "Goes offline": stop ONLY the recipient's node (the address sender has cached is
                // now genuinely unreachable), without stopping peerDirectory/prekeyBundleGossip -
                // sender's own already-converged copy is what matters, not the recipient's.
                recipientNode.stop()

                // sendAuto must fall back cleanly, never throw, never hang.
                val outcome =
                    sender.dmSessionManager.sendAuto(
                        recipientPub,
                        DmContent(body = "first contact while offline"),
                    )
                outcome shouldBe DmSendOutcome.QUEUED_FOR_PICKUP

                // Recipient "comes back online": fresh LapisNode/storage/pubsub/directory/bundle -
                // and ONLY NOW MailboxGossip/DmSessionManager, against the SAME identity/prekeyStore/
                // sessionDirectory, exactly mirroring TwoNodeOfflineMailboxIntegrationTest's two-phase
                // construction.
                recipientNode = LapisNode.create(recipientIdentity)
                recipientNode.start(bootstrapPeers = emptyList())
                recipientStorage =
                    NabuStorage.attach(recipientNode, Files.createTempDirectory("send-auto-dial-fail-storage-2"))
                recipientPubsub = GossipPubSub.attach(recipientNode)
                recipientPeerDirectory = PeerDirectoryGossip.attach(recipientPubsub, recipientStorage)
                recipientPrekeyBundleGossip = PrekeyBundleGossip.attach(recipientPubsub, recipientStorage)
                val recipientMailboxGossip = MailboxGossip.attach(recipientPubsub, recipientStorage, recipientPub)
                val recipientDmSessionManager =
                    DmSessionManager.attach(
                        recipientIdentity,
                        recipientPrekeyStore,
                        recipientNode,
                        recipientPeerDirectory,
                        recipientPrekeyBundleGossip,
                        recipientMailboxGossip,
                        recipientStorage,
                        recipientPubsub,
                        recipientSessionDir,
                        dmTestPassphrase(),
                        mailboxPollIntervalSeconds = 2L,
                    )
                try {
                    recipientNode.connect(PeerInfo(sender.node.peerId, sender.node.listenAddresses()))
                    val reconvergeDeadline = Instant.now().plus(Duration.ofSeconds(30))
                    while (Instant.now().isBefore(reconvergeDeadline)) {
                        val notValidAfter = Instant.now().epochSecond + 3600
                        recipientPeerDirectory.announce(
                            PeerRecord.create(
                                recipientIdentity,
                                recipientNode.listenAddresses(),
                                setOf(PeerCapability.DM),
                                System.nanoTime(),
                                notValidAfter,
                            ),
                        )
                        if (recipientPeerDirectory.lookup(sender.identity.secp256k1KeyPair.publicKey) != null) break
                        sender.publishSelf()
                        Thread.sleep(500)
                    }

                    val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                    recipientDmSessionManager.addInboundListener { received.add(it) }

                    val receiveDeadline = Instant.now().plus(Duration.ofSeconds(45))
                    while (received.isEmpty() && Instant.now().isBefore(receiveDeadline)) Thread.sleep(500)

                    received.size shouldBe 1
                    received[0].content.body shouldBe "first contact while offline"
                    received[0].sender shouldBe sender.identity.secp256k1KeyPair.publicKey
                } finally {
                    recipientDmSessionManager.stop()
                    runCatching { recipientMailboxGossip.stop() }
                    runCatching { recipientPrekeyBundleGossip.stop() }
                    runCatching { recipientPeerDirectory.stop() }
                    runCatching { recipientNode.stop() }
                }
            } finally {
                runCatching { recipientPrekeyBundleGossip.stop() }
                runCatching { recipientPeerDirectory.stop() }
                runCatching { recipientNode.stop() }
                sender.stop()
            }
        }

        test(
            "a directory record advertising an unsupported transport (dial throws SYNCHRONOUSLY, " +
                "not via a failed future) still falls back to QUEUED_FOR_PICKUP with a genuine " +
                "X3DH_INITIAL - regression test for the finding that dispatchOnlineLocked's " +
                "dmProtocol.dial(...) call can throw outside await(...)'s ExecutionException/" +
                "TimeoutException translation (e.g. jvm-libp2p's TransportNotSupportedException), " +
                "which previously escaped sendAuto's catch (e: DmSessionException) entirely",
        ) {
            val sender = buildDmTestNode(mailboxRedeliverIntervalSeconds = 2L)
            val recipientIdentity = DualKeyIdentity.generate()
            val recipientPrekeyStore =
                PrekeyStore.create(
                    Files.createTempDirectory("send-auto-unsupported-transport-prekeystore"),
                    recipientIdentity,
                    oneTimePrekeyCount = 5,
                )
            val recipientNode = LapisNode.create(recipientIdentity)
            recipientNode.start(bootstrapPeers = emptyList())
            val recipientStorage =
                NabuStorage.attach(
                    recipientNode,
                    Files.createTempDirectory("send-auto-unsupported-transport-storage"),
                )
            val recipientPubsub = GossipPubSub.attach(recipientNode)
            val recipientPrekeyBundleGossip = PrekeyBundleGossip.attach(recipientPubsub, recipientStorage)
            val recipientPeerDirectory = PeerDirectoryGossip.attach(recipientPubsub, recipientStorage)
            try {
                recipientNode.connect(PeerInfo(sender.node.peerId, sender.node.listenAddresses()))
                val recipientPub = recipientIdentity.secp256k1KeyPair.publicKey

                // Bundle converges normally (needed for X3DH first contact), but the directory
                // record sender caches for this peer advertises ONLY a /quic-v1 address - a
                // transport sender's (TCP-only, see LapisNode's transports { add(::TcpTransport) })
                // host never bound. binding.dial(...) -> Host.newStream(...) ->
                // NetworkImpl.connect(...) throws TransportNotSupportedException SYNCHRONOUSLY,
                // before any CompletableFuture is even created - unlike a reachability failure on a
                // supported transport, which fails asynchronously through the returned future.
                val unsupportedTransportAddress = Multiaddr("/ip4/203.0.113.1/udp/4001/quic-v1")
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (Instant.now().isBefore(deadline)) {
                    recipientPeerDirectory.announce(
                        PeerRecord.create(
                            recipientIdentity,
                            listOf(unsupportedTransportAddress),
                            setOf(PeerCapability.DM),
                            System.nanoTime(),
                            Instant.now().epochSecond + 3600,
                        ),
                    )
                    recipientPrekeyBundleGossip.announce(
                        recipientPrekeyStore.publishBundle(recipientIdentity, Instant.now().epochSecond + 3600),
                    )
                    if (sender.peerDirectory.lookup(recipientPub) != null &&
                        sender.prekeyBundleGossip.lookup(recipientPub) != null
                    ) {
                        break
                    }
                    Thread.sleep(500)
                }
                sender.peerDirectory.lookup(recipientPub) shouldNotBe null
                sender.peerDirectory.lookup(recipientPub)?.addresses shouldBe listOf(unsupportedTransportAddress)

                // Must fall back cleanly (never throw the synchronous TransportNotSupportedException
                // straight out of sendAuto) AND must be the genuine X3DH_INITIAL built by THIS single
                // call's prepareEnvelopeLocked - not a second, wrong-typed re-encrypt.
                val outcome =
                    sender.dmSessionManager.sendAuto(
                        recipientPub,
                        DmContent(body = "unsupported transport, offline fallback"),
                    )
                outcome shouldBe DmSendOutcome.QUEUED_FOR_PICKUP

                // A second call must reuse the now-cached session and emit a plain TEXT envelope
                // rather than re-running X3DH - proving the FIRST call's envelope really was the
                // X3DH_INITIAL (if it had wrongly been a TEXT envelope on a nonexistent session, this
                // would still "succeed" at the API level but the recipient could never decrypt it).
                val secondOutcome =
                    sender.dmSessionManager.sendAuto(
                        recipientPub,
                        DmContent(body = "second message, same unreachable transport"),
                    )
                secondOutcome shouldBe DmSendOutcome.QUEUED_FOR_PICKUP
            } finally {
                runCatching { recipientPeerDirectory.stop() }
                runCatching { recipientPrekeyBundleGossip.stop() }
                runCatching { recipientNode.stop() }
                sender.stop()
            }
        }
    })
