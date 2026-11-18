package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions

/** Wave V0.10.0-J2: `--onion-relay-lookup`. */
class NodeWiringOptionsRelayLookupTest :
    FunSpec({
        fun resolve(vararg args: String) = NodeWiringOptions.resolve(NodeWiringOptions.parseCliArgs(args.toList()))

        test("on by default; false switches the role off; only true and false are accepted") {
            resolve("--onion-relay=true").onionRelayLookup shouldBe true
            resolve().onionRelayLookup shouldBe true
            resolve("--onion-relay=true", "--onion-relay-lookup=false").onionRelayLookup shouldBe false
            resolve("--onion-relay=true", "--onion-relay-lookup=true").warnings.shouldBeEmpty()
            for (bad in listOf("yes", "1", "on", "")) {
                shouldThrow<InvalidWiringOptionException> { resolve("--onion-relay=true", "--onion-relay-lookup=$bad") }
                    .message shouldBe "--onion-relay-lookup must be true|false"
            }
        }

        test("an explicit true with anonymity on refuses the start; false or a missing key is fine") {
            shouldThrow<InvalidWiringOptionException> { resolve("--anonymity=on", "--onion-relay-lookup=true") }
                .message shouldBe "onion-relay-lookup cannot be enabled while anonymity=on"
            resolve("--anonymity=on", "--onion-relay-lookup=false").onionRelayLookup shouldBe false
            resolve("--anonymity=on").warnings.shouldBeEmpty()
        }

        test("an explicit true without --onion-relay is a warning without effect") {
            val o = resolve("--onion-relay-lookup=true")
            o.onionRelay shouldBe false
            o.warnings shouldBe listOf("--onion-relay-lookup=true has no effect without --onion-relay=true")
            resolve("--onion-relay-lookup=false").warnings.shouldBeEmpty()
        }

        test("the environment variable and the help text") {
            NodeWiringOptions.fromEnvironment(mapOf("LAPISNET_ONION_RELAY_LOOKUP" to "false")) shouldBe
                mapOf("onion-relay-lookup" to "false")
            NodeWiringOptions.HELP_TEXT shouldContain "--onion-relay-lookup=true|false"
            NodeWiringOptions.HELP_TEXT shouldContain "Refused with --anonymity=on"
        }
    })
