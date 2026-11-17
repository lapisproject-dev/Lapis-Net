package net.lapisphilosophorum.lapisnet.networking.confinement

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions

/** Wave V0.10.0-J1b: the wiring side of connection confinement. */
class NodeWiringOptionsConfinementTest :
    FunSpec({
        val on = NodeWiringOptions.resolve(mapOf("anonymity" to "on"))
        val off = NodeWiringOptions.resolve(emptyMap())

        test("anonymity on: a confinement, no listener; off: neither changes") {
            on.connectionConfinement() shouldNotBe null
            on.listensInboundConnections() shouldBe false
            off.connectionConfinement() shouldBe null
            off.listensInboundConnections() shouldBe true
        }

        test("anonymity on refuses a bootstrap address without /p2p or with /p2p-circuit; off accepts anything") {
            val id = PeerId.random()
            on.validateBootstrapPeers(listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/$id")))
            shouldThrow<InvalidWiringOptionException> {
                on.validateBootstrapPeers(listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001")))
            }.message!! shouldContain "bootstrap peer address must include /p2p/<peer id> while anonymity=on"
            shouldThrow<InvalidWiringOptionException> {
                on.validateBootstrapPeers(listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/$id/p2p-circuit/p2p/$id")))
            }
            off.validateBootstrapPeers(listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001")))
        }

        test("the help text no longer claims that the node meshes over direct connections") {
            NodeWiringOptions.HELP_TEXT shouldContain "connects only to its two guards"
            (NodeWiringOptions.HELP_TEXT.contains("still meshes")) shouldBe false
        }
    })
