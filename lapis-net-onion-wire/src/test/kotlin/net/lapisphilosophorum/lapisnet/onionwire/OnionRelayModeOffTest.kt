package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.nio.file.Files
import java.time.Clock
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

class OnionRelayModeOffTest :
    FunSpec({
        test("with relay mode off nobody can open an onion link, no descriptor is announced and no key file exists") {
            val nodes = ArrayList<WireTestNode>()
            try {
                val off = WireTestNode(relay = false).also { nodes += it }
                val other = WireTestNode(relay = false).also { nodes += it }
                other.connectTo(off)
                shouldThrow<ExecutionException> {
                    other.wire
                        .linksForTest()
                        .linkTo(off.peerId, off.node.listenAddresses())
                        .get(15, TimeUnit.SECONDS)
                }
                off.wire.relayService shouldBe null
                off.wire.currentDescriptor() shouldBe null
                off.wire.linkCount() shouldBe 0
                Files.exists(off.keyFile) shouldBe false
                Thread.sleep(3500) // longer than a republish interval of a relay in the fast test config
                other.wire.descriptors.current(off.key, Clock.systemUTC().millis() / 1000) shouldBe null
                other.wire.descriptors.size() shouldBe 0
            } finally {
                nodes.forEach { it.close() }
            }
        }
    })
