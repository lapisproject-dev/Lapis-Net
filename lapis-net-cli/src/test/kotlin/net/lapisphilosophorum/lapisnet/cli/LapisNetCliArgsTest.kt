package net.lapisphilosophorum.lapisnet.cli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import java.io.ByteArrayOutputStream
import java.io.PrintStream

private class Streams {
    private val o = ByteArrayOutputStream()
    private val e = ByteArrayOutputStream()
    val out = PrintStream(o, true)
    val err = PrintStream(e, true)
    val outText get() = o.toString()
    val errText get() = e.toString()
}

private fun neverStart(options: NodeWiringOptions): HeadlessNode = error("must not start a node: $options")

class LapisNetCliArgsTest :
    FunSpec({
        test("without arguments the demo path runs, exactly as before (through a seam: no network run here)") {
            val s = Streams()
            var demoRuns = 0
            runCli(
                emptyList(),
                s.out,
                s.err,
                awaitShutdown = {},
                startNode = ::neverStart,
                demo = { demoRuns++ },
            ) shouldBe
                0
            demoRuns shouldBe 1
            s.outText shouldBe ""
        }

        test("node with an invalid option exits with 2, one line, no stack trace, no node started") {
            val bad =
                listOf(
                    listOf("node", "--reachability=bogus"),
                    listOf("node", "--auto-relay=true"),
                    listOf("node", "--dht-fallback=yes"),
                    listOf("node", "--frobnicate=1"),
                    listOf("node", "positional"),
                    listOf("node", "--dht-fallback=true", "--dht-fallback=false"),
                )
            for (args in bad) {
                val s = Streams()
                runCli(
                    args,
                    s.out,
                    s.err,
                    awaitShutdown = {},
                    startNode = ::neverStart,
                    demo = { error("no demo") },
                ) shouldBe
                    2
                s.errText
                    .trim()
                    .lines()
                    .size shouldBe 1
                s.errText shouldContain "lapisnet node:"
                s.errText shouldNotContain "Exception"
            }
        }

        test("an unknown subcommand exits with 2 and prints the usage") {
            val s = Streams()
            runCli(listOf("frobnicate"), s.out, s.err, awaitShutdown = {}, startNode = ::neverStart, demo = {}) shouldBe
                2
            s.errText shouldContain "unknown command 'frobnicate'"
            s.errText shouldContain "Usage:"
        }

        test("--help and node --help exit with 0 and document the options and the metadata warning") {
            for (args in listOf(listOf("--help"), listOf("node", "--help"), listOf("node", "-h"))) {
                val s = Streams()
                runCli(
                    args,
                    s.out,
                    s.err,
                    awaitShutdown = {},
                    startNode = ::neverStart,
                    demo = { error("no demo") },
                ) shouldBe
                    0
                s.outText shouldContain "--reachability"
                s.outText shouldContain "--publish-relay-reliability"
                s.outText shouldContain "older nodes reject v2 vectors as invalid"
                s.outText shouldContain "--dht-fallback=false"
                s.errText shouldBe ""
            }
        }
    })
