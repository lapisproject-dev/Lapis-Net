package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files

private class Captured {
    private val outBytes = ByteArrayOutputStream()
    private val errBytes = ByteArrayOutputStream()
    val out = PrintStream(outBytes, true)
    val err = PrintStream(errBytes, true)
    val outText: String get() = outBytes.toString()
    val errText: String get() = errBytes.toString()
}

class BrowserMainExitCodeTest :
    FunSpec({
        val home = Files.createTempDirectory("browser-main-test").toString()
        val env = mapOf("LAPISNET_HOME" to home)

        test("--auto-relay=true without a private reachability exits with 2, one line on stderr, nothing started") {
            val captured = Captured()
            var started = false
            val code = runBrowserMain(listOf("--auto-relay=true"), env, captured.out, captured.err) { started = true }
            code shouldBe 2
            started shouldBe false
            captured.errText.trim() shouldBe "lapisnet-browser: --auto-relay requires --reachability=private"
            captured.errText shouldNotContain "Exception"
            captured.errText shouldNotContain "\tat "
        }

        test("an unknown option and an invalid value both exit with 2") {
            for (args in listOf(listOf("--frobnicate=1"), listOf("--reachability=nope"), listOf("stray"))) {
                val captured = Captured()
                runBrowserMain(args, env, captured.out, captured.err) { error("must not start") } shouldBe 2
            }
        }

        test("--help lists the shared options and the browser settings and exits with 0") {
            val captured = Captured()
            runBrowserMain(listOf("--help"), env, captured.out, captured.err) { error("must not start") } shouldBe 0
            captured.outText shouldContain "--reachability"
            captured.outText shouldContain "--dht-fallback"
            captured.outText shouldContain "--publish-relay-reliability"
            captured.outText shouldContain "dmAcceptance.veritasGate"
            captured.errText shouldBe ""
        }

        test("a valid configuration is handed to the server start") {
            val captured = Captured()
            var seen: BrowserConfig? = null
            val code =
                runBrowserMain(listOf("--dht-fallback=false"), env, captured.out, captured.err) { seen = it }
            code shouldBe 0
            seen?.wiring?.dhtFallback shouldBe false
        }
    })
