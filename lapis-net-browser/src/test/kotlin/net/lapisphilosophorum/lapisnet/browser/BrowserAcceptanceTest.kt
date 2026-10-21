package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import java.nio.file.Files
import kotlin.time.Duration.Companion.seconds

class BrowserAcceptanceTest :
    FunSpec({
        class Fixture(
            val settings: DmAcceptanceSettings,
            val mailSettings: MailAcceptanceSettings = MailAcceptanceSettings(),
            karma: (net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey) -> Double = { 0.0 },
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
            val storage = NabuStorage.attach(node, Files.createTempDirectory("browser-acceptance-test"))
            val pubsub = GossipPubSub.attach(node)
            val veritas = VeritasGossip.attach(pubsub, storage)
            val contacts = DmAcceptedContacts()
            val acceptance =
                BrowserAcceptance(
                    settings,
                    mailSettings,
                    identity.secp256k1KeyPair.publicKey,
                    veritas,
                    { _ -> KarmaScoreLookup(karma) },
                    contacts,
                )

            fun stop() {
                runCatching { veritas.stop() }
                runCatching { pubsub.stop() }
                runCatching { storage.stop() }
                runCatching { node.stop() }
            }
        }

        val stranger = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

        test("no gate configured: no check at all (accept-all), and a block reason falls back to POLICY") {
            val f = Fixture(DmAcceptanceSettings())
            try {
                f.acceptance.buildCheck().shouldBeNull()
                f.acceptance.blockReasonOf(stranger) shouldBe CallBlockReason.POLICY
                f.acceptance.refresh({ error("nothing to refresh") }, { error("nothing to refresh") }) shouldBe false
                f.acceptance.gateNames() shouldBe emptyList()
            } finally {
                f.stop()
            }
        }

        test("the reason of a block names exactly the one gate that failed") {
            val veritasOnly = Fixture(DmAcceptanceSettings(veritasGate = true))
            val karmaOnly = Fixture(DmAcceptanceSettings(karmaMinScore = 5.0))
            val both = Fixture(DmAcceptanceSettings(veritasGate = true, karmaMinScore = 5.0))
            try {
                veritasOnly.acceptance.buildCheck().shouldNotBeNull()
                veritasOnly.acceptance.blockReasonOf(stranger) shouldBe CallBlockReason.VERITAS_BELOW_THRESHOLD
                karmaOnly.acceptance.buildCheck().shouldNotBeNull()
                karmaOnly.acceptance.blockReasonOf(stranger) shouldBe CallBlockReason.KARMA_BELOW_THRESHOLD
                both.acceptance.buildCheck().shouldNotBeNull()
                // two failed gates: no single cause
                both.acceptance.blockReasonOf(stranger) shouldBe CallBlockReason.POLICY
                veritasOnly.acceptance.gateNames() shouldBe listOf("veritas-path")
                both.acceptance.gateNames() shouldBe listOf("veritas-path", "karma>=5.0")
            } finally {
                listOf(veritasOnly, karmaOnly, both).forEach { it.stop() }
            }
        }

        test("a failing Karma lookup degrades to POLICY instead of throwing") {
            val f = Fixture(DmAcceptanceSettings(karmaMinScore = 1.0), karma = { error("lookup broke") })
            try {
                f.acceptance.buildCheck().shouldNotBeNull()
                f.acceptance.blockReasonOf(stranger) shouldBe CallBlockReason.POLICY
            } finally {
                f.stop()
            }
        }

        test("the check consults the accepted contacts live, and honors the deposit floor") {
            val f = Fixture(DmAcceptanceSettings(veritasGate = true, minDepositMsat = 777))
            try {
                val check = f.acceptance.buildCheck().shouldNotBeNull()
                check.isAcceptedContact(stranger) shouldBe false
                f.contacts.accept(stranger)
                check.isAcceptedContact(stranger) shouldBe true
                check.minDepositMsat shouldBe 777
                check.gates.size shouldBe 1
            } finally {
                f.stop()
            }
        }

        test("refresh rebuilds only after the trust graph changed, and hands out ONE new instance").config(
            timeout = 60.seconds,
        ) {
            val f = Fixture(DmAcceptanceSettings(veritasGate = true))
            try {
                val first = f.acceptance.buildCheck().shouldNotBeNull()
                f.acceptance.refresh(
                    { error("graph unchanged - must not rebuild") },
                    { error("no mail gate") },
                ) shouldBe
                    false

                val grant =
                    VeritasGrant.create(
                        truster = f.identity.secp256k1KeyPair,
                        target = stranger,
                        trustMicros = 900_000,
                        comment = "test",
                    )
                f.veritas.announce(grant)
                val received = mutableListOf<net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck?>()
                f.acceptance.refresh(
                    applyDm = { check ->
                        // exactly what BrowserServer does: this one value goes to MailboxGossip AND DmSessionManager
                        received += check
                        received += check
                    },
                    applyMail = { error("no mail gate") },
                ) shouldBe true
                received.size shouldBe 2
                (received[0] === received[1]) shouldBe true
                received[0] shouldNotBe first
                (received[0] === f.acceptance.currentForTesting()) shouldBe true
                // the new graph now trusts the stranger: no block reason is a veritas block any more
                f.acceptance.refresh({ error("unchanged again") }, { error("no mail gate") }) shouldBe false
            } finally {
                f.stop()
            }
        }

        test("refresh rebuilds when a grant is revoked (same pair, newer grant, unchanged count)").config(
            timeout = 60.seconds,
        ) {
            val f = Fixture(DmAcceptanceSettings(veritasGate = true))
            try {
                val grant =
                    VeritasGrant.create(
                        truster = f.identity.secp256k1KeyPair,
                        target = stranger,
                        trustMicros = 900_000,
                        comment = "trust",
                    )
                f.veritas.announce(grant)
                f.acceptance.buildCheck().shouldNotBeNull()
                f.acceptance.refresh({ error("unchanged") }, { error("no mail gate") }) shouldBe false

                val revocation =
                    VeritasGrant.create(
                        truster = f.identity.secp256k1KeyPair,
                        target = stranger,
                        trustMicros = 0,
                        comment = "revoked",
                        previous = grant,
                    )
                f.veritas.announce(revocation)
                f.veritas.currentGrants().size shouldBe 1
                var rebuilt = false
                f.acceptance.refresh({ rebuilt = true }, { error("no mail gate") }) shouldBe true
                rebuilt shouldBe true
                f.acceptance.refresh({ error("unchanged again") }, { error("no mail gate") }) shouldBe false
            } finally {
                f.stop()
            }
        }

        test("DM and mail checks come from ONE trust graph; each is null while its own gates are off") {
            val both =
                Fixture(DmAcceptanceSettings(veritasGate = true), MailAcceptanceSettings(karmaMinScore = 2.0))
            val dmOnly = Fixture(DmAcceptanceSettings(veritasGate = true))
            val mailOnly = Fixture(DmAcceptanceSettings(), MailAcceptanceSettings(veritasGate = true))
            try {
                val checks = both.acceptance.buildChecks()
                checks.dm.shouldNotBeNull()
                checks.mail.shouldNotBeNull()
                (checks.dm.trustGraph === checks.mail.trustGraph) shouldBe true
                both.acceptance.mailGateNames() shouldBe listOf("karma>=2.0")
                (both.acceptance.currentMailForTesting() === checks.mail) shouldBe true
                dmOnly.acceptance
                    .buildChecks()
                    .mail
                    .shouldBeNull()
                mailOnly.acceptance
                    .buildChecks()
                    .dm
                    .shouldBeNull()
                mailOnly.acceptance
                    .buildChecks()
                    .mail
                    .shouldNotBeNull()
                mailOnly.acceptance.gateNames() shouldBe emptyList()
            } finally {
                listOf(both, dmOnly, mailOnly).forEach { it.stop() }
            }
        }

        test("the mail check passes accepted contacts, and a mail-only setup never calls applyDm on refresh").config(
            timeout = 60.seconds,
        ) {
            val f = Fixture(DmAcceptanceSettings(), MailAcceptanceSettings(veritasGate = true))
            try {
                val mail =
                    f.acceptance
                        .buildChecks()
                        .mail
                        .shouldNotBeNull()
                mail.isAcceptedContact(stranger) shouldBe false
                f.contacts.accept(stranger)
                mail.isAcceptedContact(stranger) shouldBe true

                f.veritas.announce(
                    VeritasGrant.create(
                        truster = f.identity.secp256k1KeyPair,
                        target = stranger,
                        trustMicros = 900_000,
                        comment = "test",
                    ),
                )
                val applied = mutableListOf<net.lapisphilosophorum.lapisnet.mail.MailAcceptanceCheck?>()
                f.acceptance.refresh(applyDm = { error("DM gates are off") }, applyMail = { applied += it }) shouldBe
                    true
                applied.size shouldBe 1
                applied[0].shouldNotBeNull() shouldNotBe mail
                f.acceptance.refresh({ error("unchanged") }, { error("unchanged") }) shouldBe false
            } finally {
                f.stop()
            }
        }

        test("failed mail gates map to the four block reasons, and the counters survive a refresh") {
            val veritas = net.lapisphilosophorum.lapisnet.mail.MailAcceptanceGate.VeritasPath
            val karma =
                net.lapisphilosophorum.lapisnet.mail.MailAcceptanceGate
                    .KarmaThreshold(1.0)
            BrowserAcceptance.mailBlockReasonOf(listOf(veritas)) shouldBe MailBlockReason.VERITAS_BELOW_THRESHOLD
            BrowserAcceptance.mailBlockReasonOf(listOf(karma)) shouldBe MailBlockReason.KARMA_BELOW_THRESHOLD
            BrowserAcceptance.mailBlockReasonOf(listOf(veritas, karma)) shouldBe MailBlockReason.ALL_ACTIVE_GATES_FAILED
            BrowserAcceptance.mailBlockReasonOf(emptyList()) shouldBe MailBlockReason.POLICY

            val f = Fixture(DmAcceptanceSettings(), MailAcceptanceSettings(veritasGate = true))
            try {
                f.acceptance.mailBlocks.record(MailBlockReason.VERITAS_BELOW_THRESHOLD, 1234L)
                f.acceptance.buildChecks()
                f.acceptance.buildChecks()
                f.acceptance.mailBlocks.total() shouldBe 1
                f.acceptance.mailBlocks
                    .toStatus()
                    .byReason shouldBe mapOf("veritas-below-threshold" to 1L)
                f.acceptance.mailBlocks.lastBlockedEpochSecond shouldBe 1234L
            } finally {
                f.stop()
            }
        }
    })
