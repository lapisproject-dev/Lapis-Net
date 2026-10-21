package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryConsumer
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.OutboxIngestOutcome
import net.lapisphilosophorum.lapisnet.networking.config.DeclaredReachability
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import kotlin.time.Duration.Companion.seconds

private val NOOP_CONSUMER = OutboxEntryConsumer { _, _, _ -> OutboxIngestOutcome.REJECTED }

private fun configOf(
    wiring: NodeWiringOptions = NodeWiringOptions(),
    acceptance: DmAcceptanceSettings = DmAcceptanceSettings(),
    mailAcceptance: MailAcceptanceSettings = MailAcceptanceSettings(),
) = BrowserConfig(wiring, acceptance, mailAcceptance)

/** What `BrowserServer.start` switches on, for every combination of the operator's options. */
class BrowserServerWiringTest :
    FunSpec({
        test("dhtFallback=false: no DHT, no fetcher, no outbox anywhere").config(timeout = 90.seconds) {
            val server = startWiredTestServer(config = configOf(NodeWiringOptions(dhtFallback = false)))
            try {
                server.directoryDhtForTesting.shouldBeNull()
                server.dhtOutboxForTesting.shouldBeNull()
                server.inboxDhtFetcherForTesting.shouldBeNull()
                server.madliGossipForTesting.shouldBeNull()
                server.autoRelaySelectorForTesting.shouldBeNull()
                server.relayReliabilityJobForTesting.shouldBeNull()
            } finally {
                server.stop()
            }
        }

        test(
            "dhtFallback=true: DHT, fetcher and outbox exist and BOTH outbox consumers are registered exactly once",
        ).config(
            timeout = 90.seconds,
        ) {
            val server = startWiredTestServer()
            try {
                val dht = server.directoryDhtForTesting.shouldNotBeNull()
                server.dhtOutboxForTesting.shouldNotBeNull()
                server.inboxDhtFetcherForTesting.shouldNotBeNull()
                // registerOutboxConsumer refuses a second consumer per kind: proves both are taken, so the DM pointer
                // entrance of the DHT path is mailboxGossip.dhtConsumer() and nobody can add a second, unchecked one.
                shouldThrow<IllegalArgumentException> {
                    dht.registerOutboxConsumer(OutboxEntryKind.DM_MAILBOX_POINTER, NOOP_CONSUMER)
                }
                shouldThrow<IllegalArgumentException> {
                    dht.registerOutboxConsumer(OutboxEntryKind.MAIL_POINTER, NOOP_CONSUMER)
                }
            } finally {
                server.stop()
            }
        }

        test(
            "publishRelayReliability is off by default and then no publisher and no Madli exist",
        ).config(timeout = 90.seconds) {
            val server = startWiredTestServer()
            try {
                server.relayReliabilityJobForTesting.shouldBeNull()
                server.madliGossipForTesting.shouldBeNull()
            } finally {
                server.stop()
            }
        }

        test(
            "publishRelayReliability=true starts the publisher job and Madli, without auto-relay",
        ).config(timeout = 90.seconds) {
            val server = startWiredTestServer(config = configOf(NodeWiringOptions(publishRelayReliability = true)))
            try {
                server.relayReliabilityJobForTesting.shouldNotBeNull().name shouldBe "madli-relay-publisher"
                server.madliGossipForTesting.shouldNotBeNull()
                server.autoRelaySelectorForTesting.shouldBeNull()
            } finally {
                server.stop()
            }
        }

        test("reachability=public: the selector does not run (and does not exist)").config(timeout = 90.seconds) {
            val server =
                startWiredTestServer(config = configOf(NodeWiringOptions(reachability = DeclaredReachability.PUBLIC)))
            try {
                server.autoRelaySelectorForTesting.shouldBeNull()
                server.nodeForTesting.relayClient.reservations() shouldBe emptyList()
            } finally {
                server.stop()
            }
        }

        test(
            "reachability=private with auto-relay=false declares but does not run the selector",
        ).config(timeout = 90.seconds) {
            val options = NodeWiringOptions.resolve(mapOf("reachability" to "private", "auto-relay" to "false"))
            val server = startWiredTestServer(config = configOf(options))
            try {
                server.autoRelaySelectorForTesting.shouldBeNull()
                server.madliGossipForTesting.shouldBeNull()
                server.configForTesting.wiring.reachability shouldBe DeclaredReachability.PRIVATE
            } finally {
                server.stop()
            }
        }

        test("reachability=private starts the Madli-ranked selector, which is running").config(timeout = 90.seconds) {
            val options = NodeWiringOptions.resolve(mapOf("reachability" to "private"))
            val server =
                startWiredTestServer(
                    config = configOf(options),
                    autoRelayConfig = AutoRelayConfig(allowNonPublicCandidateAddresses = true),
                )
            try {
                server.madliGossipForTesting.shouldNotBeNull()
                server.autoRelaySelectorForTesting.shouldNotBeNull().isRunning() shouldBe true
                server.relayReliabilityJobForTesting.shouldBeNull() // the publisher stays off
            } finally {
                server.stop()
            }
        }

        test(
            "one acceptance instance serves MailboxGossip (gossip and DHT) and DmSessionManager",
        ).config(timeout = 90.seconds) {
            val server =
                startWiredTestServer(config = configOf(acceptance = DmAcceptanceSettings(veritasGate = true)))
            try {
                val inMailbox = server.mailboxGossipForTesting.currentAcceptanceCheck().shouldNotBeNull()
                val inDm = server.dmSessionManagerForTesting.currentAcceptanceCheck().shouldNotBeNull()
                (inMailbox === inDm) shouldBe true
                (inMailbox === server.acceptanceForTesting.currentForTesting()) shouldBe true
            } finally {
                server.stop()
            }
        }

        test("with no gate configured neither consumer has a check (accept-all)").config(timeout = 90.seconds) {
            val server = startWiredTestServer()
            try {
                server.mailboxGossipForTesting.currentAcceptanceCheck().shouldBeNull()
                server.dmSessionManagerForTesting.currentAcceptanceCheck().shouldBeNull()
            } finally {
                server.stop()
            }
        }

        test("the acceptance refresh job hands the SAME new instance to both consumers").config(timeout = 90.seconds) {
            val server =
                startWiredTestServer(
                    config = configOf(acceptance = DmAcceptanceSettings(veritasGate = true)),
                    acceptanceRefreshInterval = 1.seconds,
                )
            try {
                val before = server.mailboxGossipForTesting.currentAcceptanceCheck().shouldNotBeNull()
                val grant =
                    net.lapisphilosophorum.lapisnet.trust.VeritasGrant.create(
                        truster = server.identityForTesting().secp256k1KeyPair,
                        target = randomPeer(),
                        trustMicros = 800_000,
                        comment = "refresh",
                    )
                server.veritasForTesting().announce(grant)
                awaitCondition(30, "acceptance check was not rebuilt") {
                    server.mailboxGossipForTesting.currentAcceptanceCheck() !== before
                }
                awaitCondition(10, "both consumers must converge on the same instance") {
                    server.mailboxGossipForTesting.currentAcceptanceCheck() ===
                        server.dmSessionManagerForTesting.currentAcceptanceCheck()
                }
            } finally {
                server.stop()
            }
        }

        test(
            "the mail check is installed in InboxGossip right after start (no unfiltered window), shared by DM's graph",
        ).config(timeout = 90.seconds) {
            val server =
                startWiredTestServer(
                    config =
                        configOf(
                            acceptance = DmAcceptanceSettings(veritasGate = true),
                            mailAcceptance = MailAcceptanceSettings(veritasGate = true),
                        ),
                )
            try {
                val mail = server.mailInboxForTesting.currentAcceptanceCheck().shouldNotBeNull()
                (mail === server.acceptanceForTesting.currentMailForTesting()) shouldBe true
                val dm = server.mailboxGossipForTesting.currentAcceptanceCheck().shouldNotBeNull()
                (dm.trustGraph === mail.trustGraph) shouldBe true
            } finally {
                server.stop()
            }
        }

        test("no mail gate: InboxGossip has no check; mail-only leaves the DM consumers without one").config(
            timeout = 90.seconds,
        ) {
            val off = startWiredTestServer()
            val mailOnly =
                startWiredTestServer(config = configOf(mailAcceptance = MailAcceptanceSettings(karmaMinScore = 1.0)))
            try {
                off.mailInboxForTesting.currentAcceptanceCheck().shouldBeNull()
                mailOnly.mailInboxForTesting.currentAcceptanceCheck().shouldNotBeNull()
                mailOnly.mailboxGossipForTesting.currentAcceptanceCheck().shouldBeNull()
                mailOnly.dmSessionManagerForTesting.currentAcceptanceCheck().shouldBeNull()
            } finally {
                off.stop()
                mailOnly.stop()
            }
        }

        test("the refresh job also runs for a mail-only setup and installs a new mail check").config(
            timeout = 90.seconds,
        ) {
            val server =
                startWiredTestServer(
                    config = configOf(mailAcceptance = MailAcceptanceSettings(veritasGate = true)),
                    acceptanceRefreshInterval = 1.seconds,
                )
            try {
                val before = server.mailInboxForTesting.currentAcceptanceCheck().shouldNotBeNull()
                server.veritasForTesting().announce(
                    net.lapisphilosophorum.lapisnet.trust.VeritasGrant.create(
                        truster = server.identityForTesting().secp256k1KeyPair,
                        target = randomPeer(),
                        trustMicros = 800_000,
                        comment = "refresh",
                    ),
                )
                awaitCondition(30, "mail check was not rebuilt") {
                    server.mailInboxForTesting.currentAcceptanceCheck() !== before
                }
                server.mailboxGossipForTesting.currentAcceptanceCheck().shouldBeNull()
            } finally {
                server.stop()
            }
        }
    })
