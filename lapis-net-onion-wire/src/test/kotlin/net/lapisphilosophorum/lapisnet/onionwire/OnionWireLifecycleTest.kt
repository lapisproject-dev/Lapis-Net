package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.time.Duration

private fun onionThreads(): List<String> =
    Thread
        .getAllStackTraces()
        .keys
        .filter { it.isAlive && (it.name.startsWith("lapis-net-onion") || it.name.startsWith("onion-wire-test")) }
        .map { it.name }

@OptIn(ExperimentalOnionApi::class)
class OnionWireLifecycleTest :
    FunSpec({
        test("20 start/stop cycles leave no threads, links, slots or keys behind") {
            repeat(20) { i ->
                val n = WireTestNode(relay = true)
                val service = n.wire.relayService!!
                val links = n.wire.linksForTest()
                service.currentDescriptor() shouldBe n.wire.currentDescriptor()
                (service.currentDescriptor() != null) shouldBe true
                n.close()
                // everything of the onion layer is gone after close
                service.relayModeActive shouldBe false
                service.ringForTest().current() shouldBe null
                links.linkCount() shouldBe 0
                links.reservedSlots() shouldBe 0
                links.pendingDialCount() shouldBe 0
                links.inboundPeerEntries() shouldBe 0
                awaitTrue(Duration.ofSeconds(10)) { onionThreads().isEmpty() } shouldBe true
                if (i % 5 == 4) System.gc()
            }
        }

        test("closing twice is harmless") {
            val n = WireTestNode(relay = true)
            n.wire.close()
            n.wire.close()
            n.close()
        }
    })
