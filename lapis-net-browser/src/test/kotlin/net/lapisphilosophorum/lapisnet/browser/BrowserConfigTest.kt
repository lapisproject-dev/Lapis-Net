package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.DeclaredReachability
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import java.nio.file.Files
import java.nio.file.Path

private fun homeWith(content: String?): Path {
    val home = Files.createTempDirectory("browser-config-test")
    if (content != null) Files.writeString(home.resolve(BrowserConfig.FILE_NAME), content)
    return home
}

class BrowserConfigTest :
    FunSpec({
        test("no arguments, environment or file: the defaults - gates OFF, DHT fallback on, nothing else") {
            val config = BrowserConfig.load(emptyList(), emptyMap(), homeWith(null))
            config shouldBe BrowserConfig.DEFAULT
            config.acceptance.enabled shouldBe false
            config.acceptance.gates() shouldBe emptyList()
            config.wiring.dhtFallback shouldBe true
            config.wiring.autoRelay shouldBe false
            config.wiring.publishRelayReliability shouldBe false
        }

        test("the file is read with its camelCase keys") {
            val home =
                homeWith(
                    """
                    reachability=private
                    autoRelay=true
                    dhtFallback=false
                    publishRelayReliability=true
                    holePunching=off
                    dmAcceptance.veritasGate=true
                    dmAcceptance.karmaMinScore=2.5
                    dmAcceptance.minDepositMsat=5000
                    """.trimIndent(),
                )
            val config = BrowserConfig.load(emptyList(), emptyMap(), home)
            config.wiring.reachability shouldBe DeclaredReachability.PRIVATE
            config.wiring.autoRelay shouldBe true
            config.wiring.dhtFallback shouldBe false
            config.wiring.publishRelayReliability shouldBe true
            config.wiring.holePunching shouldBe net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode.OFF
            config.acceptance.gates() shouldBe listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(2.5))
            config.acceptance.minDepositMsat shouldBe 5000
        }

        test("precedence: arguments over environment over file over defaults") {
            val home = homeWith("dhtFallback=false\nreachability=public\n")
            val env = mapOf("LAPISNET_DHT_FALLBACK" to "true", "LAPISNET_REACHABILITY" to "private")
            val fromEnv = BrowserConfig.load(emptyList(), env, home)
            fromEnv.wiring.dhtFallback shouldBe true // env beats file
            fromEnv.wiring.reachability shouldBe DeclaredReachability.PRIVATE
            val fromArgs = BrowserConfig.load(listOf("--dht-fallback=false", "--reachability=undeclared"), env, home)
            fromArgs.wiring.dhtFallback shouldBe false // args beat env
            fromArgs.wiring.reachability shouldBe DeclaredReachability.UNDECLARED
        }

        test("acceptance settings come from environment and arguments as well") {
            val env = mapOf("LAPISNET_DM_VERITAS_GATE" to "true")
            BrowserConfig.load(emptyList(), env, homeWith(null)).acceptance.veritasGate shouldBe true
            BrowserConfig.load(listOf("--dm-karma-min-score=1"), env, homeWith(null)).acceptance.gates() shouldBe
                listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(1.0))
        }

        test("an invalid value in the FILE aborts, even when a higher-priority source overrides it") {
            val home = homeWith("dhtFallback=maybe\n")
            shouldThrow<InvalidWiringOptionException> { BrowserConfig.load(emptyList(), emptyMap(), home) }
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(listOf("--dht-fallback=true"), emptyMap(), home)
            }
        }

        test("an invalid environment value aborts") {
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), mapOf("LAPISNET_AUTO_RELAY" to "yes"), homeWith(null))
            }
        }

        test("a cross-source inconsistency is detected on the merged result") {
            val home = homeWith("autoRelay=true\n")
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(
                    emptyList(),
                    emptyMap(),
                    home,
                )
            }.message shouldBe
                "--auto-relay requires --reachability=private"
            BrowserConfig.load(listOf("--reachability=private"), emptyMap(), home).wiring.autoRelay shouldBe true
        }

        test("an unknown key in the file is an error (typo protection)") {
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), emptyMap(), homeWith("dhtFalback=true\n"))
            }.message shouldContain "unknown key"
        }

        test("a file larger than 64 KiB is refused") {
            val big = "# " + "x".repeat((BrowserConfig.MAX_FILE_BYTES + 10).toInt()) + "\n"
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), emptyMap(), homeWith(big))
            }.message shouldContain "larger than"
        }

        test("an unreadable file (a directory in its place) aborts the start") {
            val home = Files.createTempDirectory("browser-config-test-dir")
            Files.createDirectory(home.resolve(BrowserConfig.FILE_NAME))
            shouldThrow<InvalidWiringOptionException> { BrowserConfig.load(emptyList(), emptyMap(), home) }
        }

        test("karmaMinScore must be a finite number >= 0; minDepositMsat an integer >= 1") {
            listOf("NaN", "Infinity", "-Infinity", "-1", "abc", "").forEach {
                shouldThrow<InvalidWiringOptionException> {
                    BrowserConfig.load(listOf("--dm-karma-min-score=$it"), emptyMap(), homeWith(null))
                }
            }
            listOf("0", "-5", "1.5", "abc", "").forEach {
                shouldThrow<InvalidWiringOptionException> {
                    BrowserConfig.load(listOf("--dm-min-deposit-msat=$it"), emptyMap(), homeWith(null))
                }
            }
            BrowserConfig
                .load(
                    listOf("--dm-karma-min-score=0"),
                    emptyMap(),
                    homeWith(null),
                ).acceptance.karmaMinScore shouldBe
                0.0
            BrowserConfig
                .load(
                    listOf("--dm-min-deposit-msat=1"),
                    emptyMap(),
                    homeWith(null),
                ).acceptance.minDepositMsat shouldBe
                1
        }

        test("DmAcceptanceSettings validates its own invariants") {
            shouldThrow<IllegalArgumentException> { DmAcceptanceSettings(karmaMinScore = Double.NaN) }
            shouldThrow<IllegalArgumentException> { DmAcceptanceSettings(karmaMinScore = -0.1) }
            shouldThrow<IllegalArgumentException> { DmAcceptanceSettings(minDepositMsat = 0) }
        }

        test("mail acceptance: defaults off, file keys, environment, arguments, and precedence") {
            BrowserConfig.DEFAULT.mailAcceptance.enabled shouldBe false
            val home =
                homeWith(
                    """
                    mailAcceptance.veritasGate=true
                    mailAcceptance.karmaMinScore=2.5
                    mailAcceptance.minDepositMsat=5000
                    """.trimIndent(),
                )
            val fromFile = BrowserConfig.load(emptyList(), emptyMap(), home)
            fromFile.mailAcceptance shouldBe MailAcceptanceSettings(true, 2.5, 5000)
            // DM and mail are independent
            fromFile.acceptance shouldBe DmAcceptanceSettings()
            val env = mapOf("LAPISNET_MAIL_KARMA_MIN_SCORE" to "7")
            BrowserConfig.load(emptyList(), env, home).mailAcceptance.karmaMinScore shouldBe 7.0
            BrowserConfig.load(listOf("--mail-karma-min-score=9"), env, home).mailAcceptance.karmaMinScore shouldBe 9.0
            BrowserConfig
                .load(listOf("--mail-veritas-gate=true"), emptyMap(), homeWith(null))
                .mailAcceptance
                .gates() shouldBe
                listOf(net.lapisphilosophorum.lapisnet.mail.MailAcceptanceGate.VeritasPath)
        }

        test("invalid mail values abort in every layer, and the message names the mail option") {
            listOf("NaN", "-1", "abc", "").forEach {
                val e =
                    shouldThrow<InvalidWiringOptionException> {
                        BrowserConfig.load(listOf("--mail-karma-min-score=$it"), emptyMap(), homeWith(null))
                    }
                e.message!! shouldContain "mail-karma-min-score"
            }
            listOf("0", "x", "1.5").forEach {
                val e =
                    shouldThrow<InvalidWiringOptionException> {
                        BrowserConfig.load(listOf("--mail-min-deposit-msat=$it"), emptyMap(), homeWith(null))
                    }
                e.message!! shouldContain "mail-min-deposit-msat"
            }
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(listOf("--mail-veritas-gate=yes"), emptyMap(), homeWith(null))
            }
            // invalid in the file, overridden by an argument: still aborts
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(
                    listOf("--mail-karma-min-score=1"),
                    emptyMap(),
                    homeWith("mailAcceptance.karmaMinScore=-3"),
                )
            }
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), mapOf("LAPISNET_MAIL_MIN_DEPOSIT_MSAT" to "0"), homeWith(null))
            }
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), emptyMap(), homeWith("mailAcceptance.foo=1"))
            }
            // the DM option error still names the DM option
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(listOf("--dm-karma-min-score=-1"), emptyMap(), homeWith(null))
            }.message!! shouldContain "dm-karma-min-score"
            BrowserConfig.HELP_TEXT shouldContain "--mail-veritas-gate"
            BrowserConfig.HELP_TEXT shouldContain "--mail-karma-min-score"
            BrowserConfig.HELP_TEXT shouldContain "--mail-min-deposit-msat"
        }

        test("MailAcceptanceSettings validates its own invariants") {
            shouldThrow<IllegalArgumentException> { MailAcceptanceSettings(karmaMinScore = Double.NaN) }
            shouldThrow<IllegalArgumentException> { MailAcceptanceSettings(karmaMinScore = -0.1) }
            shouldThrow<IllegalArgumentException> { MailAcceptanceSettings(minDepositMsat = 0) }
        }

        test("anonymity: default off, the file key, environment over file, arguments over environment") {
            BrowserConfig.load(emptyList(), emptyMap(), homeWith(null)).wiring.anonymity shouldBe AnonymityMode.OFF
            val home = homeWith("anonymity=on\n")
            BrowserConfig.load(emptyList(), emptyMap(), home).wiring.anonymity shouldBe AnonymityMode.ON
            val env = mapOf("LAPISNET_ANONYMITY" to "off")
            BrowserConfig.load(emptyList(), env, home).wiring.anonymity shouldBe AnonymityMode.OFF
            BrowserConfig.load(listOf("--anonymity=on"), env, homeWith(null)).wiring.anonymity shouldBe AnonymityMode.ON
            BrowserConfig
                .load(
                    listOf("--anonymity=off"),
                    mapOf("LAPISNET_ANONYMITY" to "on"),
                    home,
                ).wiring.anonymity shouldBe
                AnonymityMode.OFF
        }

        test("anonymity: an invalid value in ANY source aborts, even where a higher-priority source overrides it") {
            val bad = homeWith("anonymity=maybe\n")
            shouldThrow<InvalidWiringOptionException> { BrowserConfig.load(emptyList(), emptyMap(), bad) }
            shouldThrow<InvalidWiringOptionException> { BrowserConfig.load(listOf("--anonymity=off"), emptyMap(), bad) }
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), mapOf("LAPISNET_ANONYMITY" to "ON"), homeWith(null))
            }
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(listOf("--anonymity=yes"), emptyMap(), homeWith(null))
            }.message shouldBe "--anonymity must be on|off"
            // the environment layer is checked even when the arguments override it
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(listOf("--anonymity=off"), mapOf("LAPISNET_ANONYMITY" to "1"), homeWith(null))
            }
        }

        test("anonymity on: hole punching resolves to off; an explicit auto or on from any source is a conflict") {
            BrowserConfig.load(listOf("--anonymity=on"), emptyMap(), homeWith(null)).wiring.holePunching shouldBe
                net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode.OFF
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(emptyList(), emptyMap(), homeWith("anonymity=on\nholePunching=auto\n"))
            }.message shouldContain "hole-punching cannot be enabled while anonymity=on"
            shouldThrow<InvalidWiringOptionException> {
                BrowserConfig.load(listOf("--anonymity=on"), mapOf("LAPISNET_HOLE_PUNCHING" to "on"), homeWith(null))
            }
            BrowserConfig
                .load(
                    emptyList(),
                    emptyMap(),
                    homeWith("anonymity=on\nholePunching=off\n"),
                ).wiring.anonymity shouldBe
                AnonymityMode.ON
        }
    })
