package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalOnionApi::class)
class MultiNodeOnionRotationTest :
    FunSpec({
        test(
            "a rotated relay accepts the old key during the overlap, announces a higher sequence, and refuses the old key once retired",
        ) {
            val clock = WireTestClock()
            val nodes = ArrayList<WireTestNode>()
            try {
                val c = WireTestNode(relay = false).also { nodes += it }
                val r1 = WireTestNode(relay = true, clock = clock).also { nodes += it }
                val r2 = WireTestNode(relay = true).also { nodes += it }
                c.connectTo(r1)
                c.connectTo(r2)
                r1.connectTo(r2)
                r2.wire.relayService!!.localDeliveryHandler =
                    { _, msg -> RelayMessage(RelayCommand.DATA, msg.streamId, msg.data) }
                val service = r1.wire.relayService!!
                val d2 = r2.wire.currentDescriptor()!!
                val d1 = r1.wire.currentDescriptor()!!
                // R1 only extends to relays whose descriptor it has verified: wait for the gossip to deliver R2's
                awaitTrue(java.time.Duration.ofSeconds(60)) {
                    r1.wire.descriptors.current(r2.key, System.currentTimeMillis() / 1000) != null
                } shouldBe true
                val client = c.wire.diagnosticClient()

                val circuitA = client.build(listOf(d1, d2), 20.seconds).get(30, TimeUnit.SECONDS)
                circuitA.send(byteArrayOf(1, 2, 3)).get(15, TimeUnit.SECONDS).toList() shouldBe listOf<Byte>(1, 2, 3)

                clock.advanceSeconds(3600)
                service.rotateNow()
                val d1b = r1.wire.currentDescriptor()!!
                (d1b.sequenceNumber > d1.sequenceNumber) shouldBe true
                (d1b.onionKeyBinding.onionKey != d1.onionKeyBinding.onionKey) shouldBe true

                // new key works, old key still works during the overlap, and the established circuit keeps going
                val circuitB = client.build(listOf(d1b, d2), 20.seconds).get(30, TimeUnit.SECONDS)
                val circuitOld = client.build(listOf(d1, d2), 20.seconds).get(30, TimeUnit.SECONDS)
                circuitB.send(byteArrayOf(9)).get(15, TimeUnit.SECONDS).toList() shouldBe listOf<Byte>(9)
                circuitOld.send(byteArrayOf(8)).get(15, TimeUnit.SECONDS).toList() shouldBe listOf<Byte>(8)
                circuitA.send(byteArrayOf(7)).get(15, TimeUnit.SECONDS).toList() shouldBe listOf<Byte>(7)
                circuitOld.close()

                // retire exactly the old key (the new one expires an hour later)
                service.ringForTest().retireExpired(d1.onionKeyBinding.notValidAfterEpochSecond + 1) shouldBe 1
                shouldThrow<ExecutionException> { client.build(listOf(d1, d2), 20.seconds).get(30, TimeUnit.SECONDS) }
                val circuitC = client.build(listOf(d1b, d2), 20.seconds).get(30, TimeUnit.SECONDS)
                circuitC.send(byteArrayOf(5)).get(15, TimeUnit.SECONDS).toList() shouldBe listOf<Byte>(5)

                listOf(circuitA, circuitB, circuitC).forEach { it.close() }
                client.close()
            } finally {
                nodes.forEach { it.close() }
            }
        }
    })
