package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.networking.config.DeclaredReachability
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import net.lapisphilosophorum.lapisnet.networking.relay.NodeReachability

class NodeWiringOptionsTest :
    FunSpec({
        fun resolve(vararg args: String) = NodeWiringOptions.resolve(NodeWiringOptions.parseCliArgs(args.toList()))

        test("defaults: undeclared, nothing switched on except the DHT fallback") {
            val o = resolve()
            o.reachability shouldBe DeclaredReachability.UNDECLARED
            o.autoRelay shouldBe false
            o.dhtFallback shouldBe true
            o.publishRelayReliability shouldBe false
            o.relayConfig().reachability shouldBe NodeReachability.UNSPECIFIED
        }

        // reachability x auto-relay -> (effective autoRelay, RelayConfig.reachability)
        data class Row(
            val args: List<String>,
            val autoRelay: Boolean,
            val relayReachability: NodeReachability,
        )
        listOf(
            Row(listOf("--reachability=undeclared"), false, NodeReachability.UNSPECIFIED),
            Row(listOf("--reachability=undeclared", "--auto-relay=false"), false, NodeReachability.UNSPECIFIED),
            Row(listOf("--reachability=public"), false, NodeReachability.PUBLIC),
            Row(listOf("--reachability=public", "--auto-relay=false"), false, NodeReachability.PUBLIC),
            Row(listOf("--reachability=private"), true, NodeReachability.PRIVATE),
            Row(listOf("--reachability=private", "--auto-relay=true"), true, NodeReachability.PRIVATE),
            // declared private, selector deliberately off: the library config must NOT be PRIVATE (S4)
            Row(listOf("--reachability=private", "--auto-relay=false"), false, NodeReachability.UNSPECIFIED),
        ).forEach { row ->
            test("combination ${row.args}") {
                val o = NodeWiringOptions.resolve(NodeWiringOptions.parseCliArgs(row.args))
                o.autoRelay shouldBe row.autoRelay
                o.relayConfig().reachability shouldBe row.relayReachability
            }
        }

        test("private without auto-relay keeps the declared value for the status panel") {
            val o = resolve("--reachability=private", "--auto-relay=false")
            o.reachability shouldBe DeclaredReachability.PRIVATE
            o.declaredPrivateWithoutAutoRelay shouldBe true
        }

        test("auto-relay=true without reachability=private is an error with the exact text") {
            listOf(
                listOf("--auto-relay=true"),
                listOf("--auto-relay=true", "--reachability=public"),
                listOf("--auto-relay=true", "--reachability=undeclared"),
            ).forEach { args ->
                shouldThrow<InvalidWiringOptionException> {
                    NodeWiringOptions.resolve(NodeWiringOptions.parseCliArgs(args))
                }.message shouldBe "--auto-relay requires --reachability=private"
            }
        }

        test("an invalid reachability value is an error, never a silent default") {
            shouldThrow<InvalidWiringOptionException> { resolve("--reachability=bogus") }.message shouldBe
                "--reachability must be public|private|undeclared"
            shouldThrow<InvalidWiringOptionException> { resolve("--reachability=") }
        }

        test("reachability tolerates case and surrounding whitespace") {
            resolve("--reachability= Private ").reachability shouldBe DeclaredReachability.PRIVATE
            resolve("--reachability=PUBLIC").reachability shouldBe DeclaredReachability.PUBLIC
        }

        test("booleans accept only true|false") {
            listOf("yes", "1", "", "on", "TRUEISH").forEach { bad ->
                shouldThrow<InvalidWiringOptionException> { resolve("--dht-fallback=$bad") }
                shouldThrow<InvalidWiringOptionException> { resolve("--publish-relay-reliability=$bad") }
            }
            resolve("--dht-fallback=false").dhtFallback shouldBe false
            resolve("--dht-fallback=TRUE").dhtFallback shouldBe true
            resolve("--publish-relay-reliability=true").publishRelayReliability shouldBe true
        }

        test("unknown, duplicate and malformed arguments are errors") {
            shouldThrow<InvalidWiringOptionException> { resolve("--frobnicate=true") }.message shouldContain "unknown"
            shouldThrow<InvalidWiringOptionException> { resolve("--dht-fallback=true", "--dht-fallback=false") }
                .message shouldContain "duplicate"
            shouldThrow<InvalidWiringOptionException> { NodeWiringOptions.parseCliArgs(listOf("node")) }
            shouldThrow<InvalidWiringOptionException> { NodeWiringOptions.parseCliArgs(listOf("--dht-fallback")) }
            shouldThrow<InvalidWiringOptionException> { NodeWiringOptions.parseCliArgs(listOf("--=true")) }
        }

        test("validateValues rejects a bad value of a single source even without the cross-option rules") {
            NodeWiringOptions.validateValues(mapOf("auto-relay" to "true")) // combination not checked here
            shouldThrow<InvalidWiringOptionException> {
                NodeWiringOptions.validateValues(
                    mapOf("auto-relay" to "maybe"),
                )
            }
        }

        test("environment variable names and extraction") {
            NodeWiringOptions.envNameOf("auto-relay") shouldBe "LAPISNET_AUTO_RELAY"
            NodeWiringOptions.envNameOf("publish-relay-reliability") shouldBe "LAPISNET_PUBLISH_RELAY_RELIABILITY"
            NodeWiringOptions.fromEnvironment(
                mapOf("LAPISNET_REACHABILITY" to "private", "LAPISNET_HOME" to "/x", "OTHER" to "y"),
            ) shouldBe mapOf("reachability" to "private")
        }

        test("the help text warns about older nodes and about the DHT metadata exposure") {
            val help = NodeWiringOptions.HELP_TEXT
            help shouldContain "older nodes reject v2 vectors as invalid"
            help shouldContain "METADATA"
            help shouldContain "query timing and key interest"
            help shouldContain "--dht-fallback=false"
        }

        test("hole punching: default auto, active only when the declared reachability is private") {
            resolve().holePunching shouldBe HolePunchMode.AUTO
            resolve().holePunchConfig().isActive(false) shouldBe false
            resolve("--reachability=public").holePunchConfig().isActive(false) shouldBe false
            resolve("--reachability=private").holePunchConfig().isActive(false) shouldBe true
            // declared private but auto-relay off: the library RelayConfig is not PRIVATE, the declaration still counts
            resolve("--reachability=private", "--auto-relay=false").holePunchConfig().isActive(false) shouldBe true
        }

        test("hole punching: on and off override the reachability, an invalid value aborts") {
            resolve("--hole-punching=on").holePunchConfig().isActive(false) shouldBe true
            resolve("--reachability=private", "--hole-punching=off").holePunchConfig().isActive(true) shouldBe false
            shouldThrow<InvalidWiringOptionException> { resolve("--hole-punching=maybe") }
                .message shouldContain "auto|on|off"
            shouldThrow<InvalidWiringOptionException> {
                NodeWiringOptions.validateValues(mapOf("hole-punching" to "yes"))
            }
        }

        test("hole punching: environment name, extraction and help text") {
            NodeWiringOptions.envNameOf("hole-punching") shouldBe "LAPISNET_HOLE_PUNCHING"
            NodeWiringOptions.fromEnvironment(mapOf("LAPISNET_HOLE_PUNCHING" to "off")) shouldBe
                mapOf("hole-punching" to "off")
            NodeWiringOptions.HELP_TEXT shouldContain "--hole-punching=auto|on|off"
            NodeWiringOptions.HELP_TEXT shouldContain "SO_REUSEPORT"
        }
    })
