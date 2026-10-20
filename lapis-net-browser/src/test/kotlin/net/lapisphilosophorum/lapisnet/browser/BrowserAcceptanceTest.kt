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
                f.acceptance.refresh { error("nothing to refresh") } shouldBe false
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
                f.acceptance.refresh { error("graph unchanged - must not rebuild") } shouldBe false

                val grant =
                    VeritasGrant.create(
                        truster = f.identity.secp256k1KeyPair,
                        target = stranger,
                        trustMicros = 900_000,
                        comment = "test",
                    )
                f.veritas.announce(grant)
                val received = mutableListOf<net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck?>()
                f.acceptance.refresh { check ->
                    // exactly what BrowserServer does: this one value goes to MailboxGossip AND DmSessionManager
                    received += check
                    received += check
                } shouldBe true
                received.size shouldBe 2
                (received[0] === received[1]) shouldBe true
                received[0] shouldNotBe first
                (received[0] === f.acceptance.currentForTesting()) shouldBe true
                // the new graph now trusts the stranger: no block reason is a veritas block any more
                f.acceptance.refresh { error("unchanged again") } shouldBe false
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
                f.acceptance.refresh { error("unchanged") } shouldBe false

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
                f.acceptance.refresh { rebuilt = true } shouldBe true
                rebuilt shouldBe true
                f.acceptance.refresh { error("unchanged again") } shouldBe false
            } finally {
                f.stop()
            }
        }
    })
