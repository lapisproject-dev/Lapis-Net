package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
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

/**
 * The mandatory, defining V0.8.5 integration test: the RECIPIENT node starts AFTER the sender has
 * already deposited a mailbox pointer + blob - the genuinely offline scenario - and offline
 * delivery still completes. Mirrors `TwoNodeDmIntegrationTest`'s/
 * `net.lapisphilosophorum.lapisnet.trust.TwoNodeVeritasGossipIntegrationTest`'s bounded-polling-
 * against-one-deadline discipline throughout: no fixed `Thread.sleep` wait for the OUTCOME, only a
 * short sleep between retries.
 *
 * **Two-phase recipient construction is the load-bearing setup detail, inlined directly in this one
 * test rather than added as a reusable harness helper** (judgment call, per this wave's own plan):
 * the recipient's `LapisNode`/`NabuStorage`/`GossipPubSub`/`PeerDirectoryGossip`/`PrekeyBundleGossip`/
 * `PrekeyStore` are constructed and CONNECTED early enough to publish a directory record and prekey
 * bundle and converge with the sender (`sendOffline`'s X3DH first-contact bootstrap needs the
 * recipient's bundle to already be resolvable) - but [MailboxGossip]/[DmSessionManager] are deferred
 * until AFTER `sendOffline` has already run and its `MailboxRedeliveryScheduler` has fired at least
 * once. Only THEN are they constructed - the "recipient comes online" moment this test's name
 * promises. Without this two-phase split, "recipient starts after sender deposits" would only mean
 * "recipient wasn't subscribed to the mailbox topic yet", not a genuinely offline recipient.
 */
class TwoNodeOfflineMailboxIntegrationTest :
    FunSpec({
        test("recipient node starts AFTER the sender has already deposited a mailbox pointer + blob") {
            // Short redeliver interval - see MailboxRedeliveryScheduler's own doc comment for why
            // periodic re-announcement, not the original publish, is what the recipient's later
            // subscription actually catches (GossipSub has no message replay).
            val sender = buildDmTestNode(mailboxRedeliverIntervalSeconds = 2L)

            val recipientIdentity = DualKeyIdentity.generate()
            val recipientNode = LapisNode.create(recipientIdentity)
            recipientNode.start(bootstrapPeers = emptyList())
            val recipientStorage =
                NabuStorage.attach(
                    recipientNode,
                    Files.createTempDirectory("offline-mailbox-recipient-storage"),
                )
            val recipientPubsub = GossipPubSub.attach(recipientNode)
            val recipientPeerDirectory = PeerDirectoryGossip.attach(recipientPubsub, recipientStorage)
            val recipientPrekeyBundleGossip = PrekeyBundleGossip.attach(recipientPubsub, recipientStorage)
            val recipientPrekeyStore =
                PrekeyStore.create(
                    Files.createTempDirectory("offline-mailbox-recipient-prekeystore"),
                    recipientIdentity,
                    oneTimePrekeyCount = 5,
                )
            var recipientDmSessionManager: DmSessionManager? = null

            try {
                recipientNode.connect(PeerInfo(sender.node.peerId, sender.node.listenAddresses()))

                val recipientPublicKey = recipientIdentity.secp256k1KeyPair.publicKey
                val senderPublicKey = sender.identity.secp256k1KeyPair.publicKey
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

                    val senderSeesRecipient = sender.peerDirectory.lookup(recipientPublicKey) != null
                    val senderSeesRecipientBundle = sender.prekeyBundleGossip.lookup(recipientPublicKey) != null
                    val recipientSeesSender = recipientPeerDirectory.lookup(senderPublicKey) != null
                    if (senderSeesRecipient && senderSeesRecipientBundle && recipientSeesSender) break
                    Thread.sleep(500)
                }
                (sender.prekeyBundleGossip.lookup(recipientPublicKey) != null) shouldBe true

                // THE DEFINING MOMENT: the sender deposits while the recipient's MailboxGossip/
                // DmSessionManager do not exist yet - genuinely offline, not merely "not subscribed".
                val bodyText = "a".repeat(2048)
                var deposited = false
                val depositDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (!deposited && Instant.now().isBefore(depositDeadline)) {
                    deposited =
                        runCatching {
                            sender.dmSessionManager.sendOffline(recipientPublicKey, DmContent(body = bodyText))
                        }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true

                // "The recipient comes online": construct MailboxGossip + DmSessionManager now, with
                // a short poll interval so this test does not need to wait a full minute.
                val recipientMailboxGossip = MailboxGossip.attach(recipientPubsub, recipientStorage, recipientPublicKey)
                recipientDmSessionManager =
                    DmSessionManager.attach(
                        recipientIdentity,
                        recipientPrekeyStore,
                        recipientNode,
                        recipientPeerDirectory,
                        recipientPrekeyBundleGossip,
                        recipientMailboxGossip,
                        recipientStorage,
                        recipientPubsub,
                        Files.createTempDirectory("offline-mailbox-recipient-sessions"),
                        dmTestPassphrase(),
                        mailboxPollIntervalSeconds = 2L,
                    )
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipientDmSessionManager.addInboundListener { received.add(it) }

                val receiveDeadline = Instant.now().plus(Duration.ofSeconds(45))
                while (received.isEmpty() && Instant.now().isBefore(receiveDeadline)) Thread.sleep(500)

                // Deliberately not just "isEmpty() shouldBe false": this test runs with a 2s
                // redeliver interval and a 2s poll interval for the whole 45s receive window - i.e.
                // the SAME pointer keeps getting re-announced and re-attempted throughout, exactly
                // the configuration under which a double delivery (including the security-audit
                // round 1 X3DH_INITIAL-replay-after-restart class of bug - see
                // DmSessionManager.recordAcceptedX3dhInitialEphemeralKey) would show up. Sleep a bit
                // past the deadline the receive loop already exited at, so a slow-arriving SECOND
                // delivery (if this ever regresses) has time to show up before asserting the count.
                Thread.sleep(4000)
                received.size shouldBe 1
                received[0].content.body shouldBe bodyText
                received[0].sender shouldBe senderPublicKey
            } finally {
                recipientDmSessionManager?.stop()
                runCatching { recipientPrekeyBundleGossip.stop() }
                runCatching { recipientPeerDirectory.stop() }
                runCatching { recipientNode.stop() }
                sender.stop()
            }
        }
    })
