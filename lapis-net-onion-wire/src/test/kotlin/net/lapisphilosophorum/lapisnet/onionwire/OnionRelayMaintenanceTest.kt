package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.nio.file.Files

class OnionRelayMaintenanceTest :
    FunSpec({
        val day = 86_400L

        test("maintenance rotates after rotateAfter, retires and persists, and re-keys when all keys expired") {
            val clock = WireTestClock()
            val node = WireTestNode(relay = true, clock = clock, passphrase = "test-passphrase".toCharArray())
            try {
                val service = node.wire.relayService!!
                val ring = service.ringForTest()
                val now = { clock.millis() / 1000 }
                val first = ring.current()!!
                service.publishDescriptor()
                val firstSeq = node.wire.currentDescriptor()!!.sequenceNumber

                // (a) younger than rotateAfter (4 days): nothing happens
                clock.advanceSeconds(3 * day)
                service.maintenance()
                ring.current() shouldBe first
                ring.accepted(now()).size shouldBe 1

                // (b) at/after rotateAfter: rotated, previous key still accepted, higher descriptor sequence
                clock.advanceSeconds(1 * day + 1)
                service.maintenance()
                val second = ring.current()!!
                (second.onionKey != first.onionKey) shouldBe true
                ring.accepted(now()).size shouldBe 2
                (node.wire.currentDescriptor()!!.sequenceNumber > firstSeq) shouldBe true

                // (c) the first key expires (7 days after creation): retired and the key file persisted
                val before = Files.readAllBytes(node.keyFile)
                clock.advanceSeconds(3 * day)
                service.maintenance()
                ring.current() shouldBe second
                ring.accepted(now()).size shouldBe 1
                (Files.readAllBytes(node.keyFile).contentEquals(before)) shouldBe false

                // (d) every key expired: current == null leads to an immediate rotation
                clock.advanceSeconds(30 * day)
                service.maintenance()
                val third = ring.current()!!
                (third.onionKey != second.onionKey) shouldBe true
                ring.accepted(now()).size shouldBe 1
            } finally {
                node.close()
            }
        }
    })
