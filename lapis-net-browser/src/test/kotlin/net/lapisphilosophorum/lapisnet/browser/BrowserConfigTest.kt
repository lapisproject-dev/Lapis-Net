package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
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
    })
