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
                    listOf("node", "--hole-punching=maybe"),
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

        test("--hole-punching=off is accepted and reaches the node options; the help lists it") {
            val s = Streams()
            var seen: NodeWiringOptions? = null
            runCatching {
                runCli(
                    listOf("node", "--hole-punching=off"),
                    s.out,
                    s.err,
                    awaitShutdown = {},
                    startNode = {
                        seen = it
                        error("stop here")
                    },
                    demo = { error("no demo") },
                )
            }
            seen!!.holePunching shouldBe net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode.OFF
            val help = Streams()
            runCli(
                listOf("node", "--help"),
                help.out,
                help.err,
                awaitShutdown = {},
                startNode = ::neverStart,
                demo = {},
            ) shouldBe
                0
            help.outText shouldContain "--hole-punching=auto|on|off"
        }

        test("--onion-relay=true reaches the node options and is announced as infrastructure only") {
            val s = Streams()
            var seen: NodeWiringOptions? = null
            runCatching {
                runCli(
                    listOf("node", "--onion-relay=true"),
                    s.out,
                    s.err,
                    awaitShutdown = {},
                    startNode = {
                        seen = it
                        error("stop here")
                    },
                    demo = { error("no demo") },
                )
            }
            seen!!.onionRelay shouldBe true
            val bad = Streams()
            runCli(
                listOf("node", "--onion-relay=maybe"),
                bad.out,
                bad.err,
                startNode = ::neverStart,
                demo = {},
            ) shouldBe
                2
            bad.errText shouldContain "onion-relay"
        }

        test("--anonymity=on reaches the node options; conflicts and bad values exit with 2") {
            val s = Streams()
            var seen: NodeWiringOptions? = null
            runCatching {
                runCli(
                    listOf("node", "--anonymity=on"),
                    s.out,
                    s.err,
                    awaitShutdown = {},
                    startNode = {
                        seen = it
                        error("stop here")
                    },
                    demo = { error("no demo") },
                )
            }
            seen!!.anonymity shouldBe net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode.ON
            for (
            (args, text) in
            listOf(
                listOf("node", "--anonymity=ON") to "--anonymity must be on|off",
                listOf("node", "--anonymity=yes") to "--anonymity must be on|off",
                listOf("node", "--anonymity=on", "--hole-punching=auto") to "hole-punching cannot be enabled",
                listOf("node", "--anonymity=on", "--hole-punching=on") to "hole-punching cannot be enabled",
                listOf("node", "--anonymity=on", "--onion-relay=true") to "onion-relay cannot be combined",
            )
            ) {
                val bad = Streams()
                runCli(args, bad.out, bad.err, startNode = ::neverStart, demo = {}) shouldBe 2
                bad.errText shouldContain text
                bad.errText
                    .trim()
                    .lines()
                    .size shouldBe 1
            }
        }

        test("the help documents --anonymity as experimental and incomplete") {
            val help = Streams()
            runCli(
                listOf("node", "--help"),
                help.out,
                help.err,
                awaitShutdown = {},
                startNode = ::neverStart,
                demo = {},
            ) shouldBe
                0
            help.outText shouldContain "--anonymity=on|off"
            help.outText shouldContain "experimental"
            help.outText shouldContain "call media is direct"
            help.outText shouldContain "--anonymity-allow-call-media=true|false"
        }
    })
