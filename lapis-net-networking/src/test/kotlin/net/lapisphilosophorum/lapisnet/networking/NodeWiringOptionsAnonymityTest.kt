package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityPaddingMode
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.config.TransportKeyPolicy
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchConfig
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode

class NodeWiringOptionsAnonymityTest :
    FunSpec({
        fun resolve(vararg args: String) = NodeWiringOptions.resolve(NodeWiringOptions.parseCliArgs(args.toList()))

        test("the default is off") {
            resolve().anonymity shouldBe AnonymityMode.OFF
            resolve("--anonymity=off").anonymity shouldBe AnonymityMode.OFF
        }

        test("on and off are parsed, nothing else is") {
            resolve("--anonymity=on").anonymity shouldBe AnonymityMode.ON
            for (bad in listOf("ON", "On", "yes", "true", "", " on", "on ", "1")) {
                shouldThrow<InvalidWiringOptionException> { resolve("--anonymity=$bad") }
                    .message shouldBe "--anonymity must be on|off"
            }
        }

        test("the environment variable LAPISNET_ANONYMITY is read") {
            NodeWiringOptions.envNameOf(NodeWiringOptions.KEY_ANONYMITY) shouldBe "LAPISNET_ANONYMITY"
            val raw = NodeWiringOptions.fromEnvironment(mapOf("LAPISNET_ANONYMITY" to "on", "OTHER" to "x"))
            NodeWiringOptions.resolve(raw).anonymity shouldBe AnonymityMode.ON
            shouldThrow<InvalidWiringOptionException> {
                NodeWiringOptions.validateValues(
                    NodeWiringOptions.fromEnvironment(mapOf("LAPISNET_ANONYMITY" to "maybe")),
                )
            }
        }

        test("anonymity on with an explicit hole-punching on or auto is a conflict, off is fine") {
            for (mode in listOf("on", "auto", "ON", "Auto")) {
                shouldThrow<InvalidWiringOptionException> { resolve("--anonymity=on", "--hole-punching=$mode") }
                    .message shouldBe "hole-punching cannot be enabled while anonymity=on"
            }
            resolve("--anonymity=on", "--hole-punching=off").holePunching shouldBe HolePunchMode.OFF
        }

        test("anonymity on without a hole-punching key resolves hole punching to off, not to auto") {
            resolve("--anonymity=on").holePunching shouldBe HolePunchMode.OFF
            resolve("--anonymity=on", "--reachability=private").holePunching shouldBe HolePunchMode.OFF
            resolve("--anonymity=off").holePunching shouldBe HolePunchMode.AUTO
        }

        test("anonymity on together with an onion relay is a conflict") {
            shouldThrow<InvalidWiringOptionException> { resolve("--anonymity=on", "--onion-relay=true") }
                .message shouldBe "onion-relay cannot be combined with anonymity=on"
            resolve("--anonymity=on", "--onion-relay=false").onionRelay shouldBe false
            resolve("--anonymity=off", "--onion-relay=true").onionRelay shouldBe true
        }

        test("the hole-punch config is off whatever the base says, and marked as anonymity mode") {
            val on =
                resolve(
                    "--anonymity=on",
                    "--reachability=private",
                ).holePunchConfig(HolePunchConfig(mode = HolePunchMode.ON))
            on.mode shouldBe HolePunchMode.OFF
            on.anonymityMode shouldBe true
            on.answersIdentify shouldBe false
            on.isActive(reachabilityPrivate = true) shouldBe false
            resolve("--anonymity=off").holePunchConfig().anonymityMode shouldBe false
        }

        test("the library refuses a hole-punch config that is active in anonymity mode") {
            shouldThrow<IllegalArgumentException> { HolePunchConfig(mode = HolePunchMode.ON, anonymityMode = true) }
            shouldThrow<IllegalArgumentException> { HolePunchConfig(mode = HolePunchMode.AUTO, anonymityMode = true) }
            HolePunchConfig(mode = HolePunchMode.OFF, anonymityMode = true).anonymityMode shouldBe true
        }

        test("a node created from anonymity options has no hole punching and does not answer Identify") {
            val options = resolve("--anonymity=on", "--reachability=private")
            val node = LapisNode.create(DualKeyIdentity.generate(), holePunchConfig = options.holePunchConfig())
            node.start(bootstrapPeers = emptyList())
            try {
                node.holePunching shouldBe null
            } finally {
                node.stop()
            }
        }

        test("the help text names the option as experimental and says what it does not do") {
            NodeWiringOptions.HELP_TEXT shouldContain "--anonymity=on|off"
            NodeWiringOptions.HELP_TEXT shouldContain "(experimental, default off)"
            NodeWiringOptions.HELP_TEXT shouldContain "call media is direct"
            NodeWiringOptions.HELP_TEXT shouldContain "--anonymity-allow-call-media=true|false"
        }

        test("V0.10.0-G: anonymity-allow-call-media defaults to false and needs anonymity=on") {
            resolve().anonymityAllowCallMedia shouldBe false
            resolve("--anonymity=on").anonymityAllowCallMedia shouldBe false
            resolve("--anonymity=on", "--anonymity-allow-call-media=true").anonymityAllowCallMedia shouldBe true
            resolve("--anonymity-allow-call-media=false").anonymityAllowCallMedia shouldBe false
            shouldThrow<InvalidWiringOptionException> { resolve("--anonymity-allow-call-media=true") }
                .message shouldBe "--anonymity-allow-call-media requires --anonymity=on"
            shouldThrow<InvalidWiringOptionException> {
                resolve("--anonymity=off", "--anonymity-allow-call-media=true")
            }
            shouldThrow<InvalidWiringOptionException> { resolve("--anonymity=on", "--anonymity-allow-call-media=yes") }
        }

        test("V0.10.0-G: the environment variable and the known key exist, an invalid value fails in every source") {
            NodeWiringOptions.envNameOf(NodeWiringOptions.KEY_ANONYMITY_ALLOW_CALL_MEDIA) shouldBe
                "LAPISNET_ANONYMITY_ALLOW_CALL_MEDIA"
            (NodeWiringOptions.KEY_ANONYMITY_ALLOW_CALL_MEDIA in NodeWiringOptions.KNOWN_KEYS) shouldBe true
            val raw =
                NodeWiringOptions.fromEnvironment(
                    mapOf("LAPISNET_ANONYMITY" to "on", "LAPISNET_ANONYMITY_ALLOW_CALL_MEDIA" to "true"),
                )
            NodeWiringOptions.resolve(raw).anonymityAllowCallMedia shouldBe true
            shouldThrow<InvalidWiringOptionException> {
                NodeWiringOptions.validateValues(
                    NodeWiringOptions.fromEnvironment(mapOf("LAPISNET_ANONYMITY_ALLOW_CALL_MEDIA" to "maybe")),
                )
            }
        }

        test("the known keys contain anonymity") {
            (NodeWiringOptions.KEY_ANONYMITY in NodeWiringOptions.KNOWN_KEYS) shouldBe true
        }

        test(
            "V0.10.0-H: anonymity-padding defaults to standard, accepts exactly standard|off, also with anonymity off",
        ) {
            resolve().anonymityPadding shouldBe AnonymityPaddingMode.STANDARD
            resolve("--anonymity=on", "--anonymity-padding=off").anonymityPadding shouldBe AnonymityPaddingMode.OFF
            resolve("--anonymity=on", "--anonymity-padding=standard").anonymityPadding shouldBe
                AnonymityPaddingMode.STANDARD
            resolve("--anonymity-padding=off").anonymityPadding shouldBe AnonymityPaddingMode.OFF
            for (bad in listOf("STANDARD", "Off", "on", "", " off", "true")) {
                shouldThrow<InvalidWiringOptionException> { resolve("--anonymity-padding=$bad") }
                    .message shouldBe "--anonymity-padding must be standard|off"
            }
            NodeWiringOptions.envNameOf(NodeWiringOptions.KEY_ANONYMITY_PADDING) shouldBe "LAPISNET_ANONYMITY_PADDING"
            (NodeWiringOptions.KEY_ANONYMITY_PADDING in NodeWiringOptions.KNOWN_KEYS) shouldBe true
            NodeWiringOptions.HELP_TEXT shouldContain "--anonymity-padding=standard|off"
        }

        test(
            "V0.10.0-J1a: an explicit auto-relay, relay-reliability publishing or DHT fallback is a conflict with on",
        ) {
            shouldThrow<InvalidWiringOptionException> {
                resolve("--anonymity=on", "--reachability=private", "--auto-relay=true")
            }.message shouldBe "auto-relay cannot be enabled while anonymity=on"
            shouldThrow<InvalidWiringOptionException> {
                resolve("--anonymity=on", "--publish-relay-reliability=true")
            }.message shouldBe "publish-relay-reliability cannot be enabled while anonymity=on"
            shouldThrow<InvalidWiringOptionException> { resolve("--anonymity=on", "--dht-fallback=true") }
                .message shouldBe "dht-fallback cannot be enabled while anonymity=on"
            // explicit false is fine
            resolve("--anonymity=on", "--auto-relay=false", "--dht-fallback=false", "--publish-relay-reliability=false")
                .dhtFallback shouldBe false
        }

        test("V0.10.0-J1a: with on and no key, DHT fallback, auto-relay and publishing resolve to false") {
            val on = resolve("--anonymity=on", "--reachability=private")
            on.dhtFallback shouldBe false
            on.autoRelay shouldBe false
            on.publishRelayReliability shouldBe false
            // the relay config does not become PRIVATE (no reservation ever)
            on.relayConfig().reachability shouldBe
                net.lapisphilosophorum.lapisnet.networking.relay.NodeReachability.UNSPECIFIED
        }

        test("V0.10.0-J1a: mode off keeps every earlier default and combination") {
            resolve().dhtFallback shouldBe true
            resolve().autoRelay shouldBe false
            resolve("--reachability=private").autoRelay shouldBe true
            resolve(
                "--reachability=private",
                "--auto-relay=true",
                "--dht-fallback=true",
                "--publish-relay-reliability=true",
            ).publishRelayReliability shouldBe true
            resolve().transportKeyPolicy() shouldBe TransportKeyPolicy.IdentityDerived
            resolve().mdnsEnabled() shouldBe true
            resolve().effective() shouldBe resolve()
        }

        test(
            "V0.10.0-J1a: on means a per-run transport key, no mDNS, and effective() also covers options built in code",
        ) {
            val on = resolve("--anonymity=on")
            on.transportKeyPolicy() shouldBe TransportKeyPolicy.EphemeralPerRun
            on.mdnsEnabled() shouldBe false
            val built =
                NodeWiringOptions(anonymity = AnonymityMode.ON, autoRelay = true, publishRelayReliability = true)
            val effective = built.effective()
            effective.dhtFallback shouldBe false
            effective.autoRelay shouldBe false
            effective.publishRelayReliability shouldBe false
            effective.holePunching shouldBe HolePunchMode.OFF
            NodeWiringOptions.HELP_TEXT shouldContain "fresh per run"
        }
    })
