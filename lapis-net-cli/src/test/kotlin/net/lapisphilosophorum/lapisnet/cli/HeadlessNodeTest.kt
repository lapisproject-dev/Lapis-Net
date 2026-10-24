@file:OptIn(net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.cli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import java.nio.file.Files
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private val OWN_THREADS =
    listOf("lapis-cli-node-worker", "lapis-cli-node-stop", "lapis-relay-autoselect", "lapis-net-onion")

private fun ownThreads(): List<String> =
    Thread
        .getAllStackTraces()
        .keys
        .filter { t ->
            t.isAlive && OWN_THREADS.any { t.name.startsWith(it) }
        }.map { it.name }

private fun start(
    options: NodeWiringOptions,
    dataDirectory: java.nio.file.Path = Files.createTempDirectory("headless-node-test"),
    passphrase: () -> CharArray? = { null },
): HeadlessNode =
    HeadlessNode.start(
        options = options,
        identity = DualKeyIdentity.generate(),
        bootstrapPeers = emptyList(),
        listenAddress = Multiaddr("/ip4/127.0.0.1/tcp/0"),
        dataDirectory = dataDirectory,
        onionKeyPassphrase = passphrase,
        autoRelayConfig = AutoRelayConfig(allowNonPublicCandidateAddresses = true),
        directoryDhtLimits = DirectoryDhtLimits(),
        maintenanceInterval = 200.milliseconds,
        maintenanceInitialDelay = 100.milliseconds,
        selfRecordCheckInterval = 200.milliseconds,
    )

class HeadlessNodeTest :
    FunSpec({
        test(
            "reachability=private runs the Madli-ranked selector; the publisher stays off by default",
        ).config(timeout = 90.seconds) {
            val node = start(NodeWiringOptions.resolve(mapOf("reachability" to "private")))
            try {
                node.autoRelaySelector.shouldNotBeNull().isRunning() shouldBe true
                node.madliGossip.shouldNotBeNull()
                node.directoryDht.shouldNotBeNull()
                node.relayReliabilityJob.shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("publish-relay-reliability=true starts the publisher job, false never does").config(timeout = 90.seconds) {
            val on = start(NodeWiringOptions.resolve(mapOf("publish-relay-reliability" to "true")))
            val off = start(NodeWiringOptions.resolve(emptyMap()))
            try {
                on.relayReliabilityJob.shouldNotBeNull().name shouldBe "madli-relay-publisher"
                on.autoRelaySelector.shouldBeNull() // no auto-relay without reachability=private
                off.relayReliabilityJob.shouldBeNull()
                off.madliGossip.shouldBeNull()
            } finally {
                on.stop()
                off.stop()
            }
        }

        test("dht-fallback=false attaches no DHT").config(timeout = 90.seconds) {
            val node = start(NodeWiringOptions.resolve(mapOf("dht-fallback" to "false")))
            try {
                node.directoryDht.shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("reachability=public does not run a selector").config(timeout = 90.seconds) {
            val node = start(NodeWiringOptions.resolve(mapOf("reachability" to "public")))
            try {
                node.autoRelaySelector.shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test(
            "starting and stopping twice with everything on leaves no supervised thread behind",
        ).config(timeout = 120.seconds) {
            val baseline = ownThreads().size
            repeat(2) {
                val node =
                    start(
                        NodeWiringOptions.resolve(
                            mapOf("reachability" to "private", "publish-relay-reliability" to "true"),
                        ),
                    )
                Thread.sleep(600) // every periodic job runs at least once
                val supervisor = node.supervisor
                node.stop()
                node.stop() // idempotent
                supervisor.isTerminated() shouldBe true
                val deadline = System.nanoTime() + 15_000_000_000L
                while (System.nanoTime() < deadline && ownThreads().size > baseline) Thread.sleep(100)
                ownThreads().size shouldBe baseline
            }
        }

        test(
            "onion relay off: the descriptor index exists, but no relay service, key file, descriptor or onion thread",
        ).config(
            timeout = 90.seconds,
        ) {
            val dir = Files.createTempDirectory("headless-onion-off")
            val node = start(NodeWiringOptions.resolve(emptyMap()), dir)
            try {
                val wire = node.onionWire
                wire.relayService.shouldBeNull()
                wire.currentDescriptor().shouldBeNull()
                Files.exists(dir.resolve("onion-relay.onionkeys")) shouldBe false
                ownThreads().none { it.startsWith("lapis-net-onion") } shouldBe true
            } finally {
                node.stop()
            }
        }

        test("onion relay on with a passphrase: encrypted key file, announced descriptor, clean stop").config(
            timeout = 120.seconds,
        ) {
            val dir = Files.createTempDirectory("headless-onion-on")
            val node = start(NodeWiringOptions.resolve(mapOf("onion-relay" to "true")), dir) { "pw".toCharArray() }
            try {
                val wire = node.onionWire
                wire.relayService.shouldNotBeNull().relayModeActive shouldBe true
                val d = wire.currentDescriptor().shouldNotBeNull()
                wire.descriptors.current(d.identity, System.currentTimeMillis() / 1000) shouldBe d
                Files.exists(dir.resolve("onion-relay.onionkeys")) shouldBe true
            } finally {
                node.stop()
            }
            node.onionWire.relayService!!.relayModeActive shouldBe false
        }

        test(
            "onion relay on without a passphrase runs with in-memory keys and writes no file",
        ).config(timeout = 90.seconds) {
            val dir = Files.createTempDirectory("headless-onion-ephemeral")
            val node = start(NodeWiringOptions.resolve(mapOf("onion-relay" to "true")), dir)
            try {
                node.onionWire.currentDescriptor().shouldNotBeNull()
                Files.exists(dir.resolve("onion-relay.onionkeys")) shouldBe false
            } finally {
                node.stop()
            }
        }

        test("anonymity off: the start line says so, OFF is persisted, no anonymity runtime, status off").config(
            timeout = 90.seconds,
        ) {
            val dir = Files.createTempDirectory("headless-anon-off")
            val node = start(NodeWiringOptions.resolve(emptyMap()), dir)
            try {
                node.anonymity.shouldBeNull()
                node.anonymityStatus().mode shouldBe "off"
                val out = java.io.ByteArrayOutputStream()
                val err = java.io.ByteArrayOutputStream()
                runCli(
                    listOf("node"),
                    java.io.PrintStream(out, true),
                    java.io.PrintStream(err, true),
                    awaitShutdown = {},
                    startNode = { node },
                    demo = {},
                ) shouldBe 0
                out.toString() shouldContain "anonymity=off"
                err.toString() shouldBe ""
                // the first tick persisted the normal-mode state (needed so that a later switch to ON sends a tombstone)
                val state =
                    net.lapisphilosophorum.lapisnet.directory
                        .FileDirectoryModeStore(
                            dir.resolve("directory-mode.state"),
                        ).load()
                state.shouldNotBeNull().mode shouldBe
                    net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode.OFF
            } finally {
                node.stop()
            }
        }

        test(
            "anonymity on on loopback: warning on stderr, no diverse path, no direct publication and no fallback",
        ).config(timeout = 120.seconds) {
            val dir = Files.createTempDirectory("headless-anon-on")
            val baseline = ownThreads().size
            val node = start(NodeWiringOptions.resolve(mapOf("anonymity" to "on")), dir)
            try {
                node.anonymity.shouldNotBeNull()
                node.options.holePunching shouldBe net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode.OFF
                node.node.holePunching.shouldBeNull()
                // the real locator sees no diverse path (no relays at all): a status code, never a direct publication
                var status = node.anonymityStatus()
                val deadline = System.nanoTime() + 20_000_000_000L
                while (status.lastError.wire != "insufficient-relays" && System.nanoTime() < deadline) {
                    Thread.sleep(100)
                    status = node.anonymityStatus()
                }
                status.mode shouldBe "on"
                status.incomplete shouldBe true
                status.lastError.wire shouldBe "insufficient-relays"
                status.guards shouldBe 0
                // nothing was published from this node itself: the normal-mode state file was never written
                Files.exists(dir.resolve("directory-mode.state")) shouldBe false
                val out = java.io.ByteArrayOutputStream()
                val err = java.io.ByteArrayOutputStream()
                runCli(
                    listOf("node", "--anonymity=on"),
                    java.io.PrintStream(out, true),
                    java.io.PrintStream(err, true),
                    awaitShutdown = {},
                    startNode = { node },
                    demo = {},
                ) shouldBe 0
                out.toString() shouldContain "anonymity=on"
                err.toString() shouldContain "Anonymity mode is incomplete"
                err.toString() shouldContain "would reveal your IP address"
            } finally {
                node.stop()
            }
            val deadline = System.nanoTime() + 15_000_000_000L
            while (System.nanoTime() < deadline && ownThreads().size > baseline) Thread.sleep(100)
            ownThreads().size shouldBe baseline
        }
    })
