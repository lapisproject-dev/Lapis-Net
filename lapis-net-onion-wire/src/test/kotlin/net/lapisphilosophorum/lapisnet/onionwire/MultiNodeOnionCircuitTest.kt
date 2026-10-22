package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import java.time.Clock
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

/**
 * Four REAL nodes on loopback: client C and relays R1..R3 in relay mode. Descriptors travel over the real gossip; a
 * three-hop circuit is built over the real `/lapis/onion/1.0.0` links and 50 DATA messages are echoed by R3.
 */
@OptIn(ExperimentalOnionApi::class)
class MultiNodeOnionCircuitTest :
    FunSpec({
        val nodes = ArrayList<WireTestNode>()

        afterSpec { nodes.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        // C is also connected to every relay; relays are connected in a chain
        val c = WireTestNode(relay = false).also { nodes += it }
        val relays = List(3) { WireTestNode(relay = true).also { r -> nodes += r } }
        relays.forEach { c.connectTo(it) }
        relays[0].connectTo(relays[1])
        relays[1].connectTo(relays[2])

        test("relay descriptors reach the client through real gossip") {
            awaitTrue(java.time.Duration.ofSeconds(60)) {
                relays.all { r -> c.wire.descriptors.current(r.identity.secp256k1KeyPair.publicKey, now()) != null }
            } shouldBe true
            relays.forEach { r ->
                val seen = c.wire.descriptors.current(r.identity.secp256k1KeyPair.publicKey, now())!!
                seen shouldBe r.wire.currentDescriptor()
            }
        }

        test("a three-hop circuit carries 50 DATA messages to the exit and back, then tears down cleanly") {
            // pre-seeded variant: the descriptors come straight from the relays, independent of gossip timing
            val path = relays.map { it.wire.currentDescriptor()!! }
            relays[2].wire.relayService!!.localDeliveryHandler = { _, msg ->
                RelayMessage(RelayCommand.DATA, msg.streamId, msg.data)
            }
            val client = c.wire.diagnosticClient()
            val circuit = client.build(path, 20.seconds).get(30, TimeUnit.SECONDS)
            repeat(50) { i ->
                val payload = ByteArray(1 + (i * 7) % circuit.maxPayload) { (it * 31 + i).toByte() }
                val reply = circuit.send(payload).get(15, TimeUnit.SECONDS)
                reply.contentEquals(payload) shouldBe true
            }
            relays.forEach { it.wire.relayService!!.circuitCount() shouldBe 1 }

            // quality bookkeeping at R1 (towards R2) and R2 (towards R3)
            val day = Clock.systemUTC().millis() / 86_400_000L
            val q1 = relays[0].wire.relayService!!.qualityCounts(day)
            val q2 = relays[1].wire.relayService!!.qualityCounts(day)
            (q1[relays[1].identity.secp256k1KeyPair.publicKey]!!.extendLinkSuccesses >= 1) shouldBe true
            (q2[relays[2].identity.secp256k1KeyPair.publicKey]!!.extendLinkSuccesses >= 1) shouldBe true

            circuit.close()
            awaitTrue { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe true
            client.close()
        }

        test("links are reused: a second circuit over the same relays opens no further link") {
            val path = relays.map { it.wire.currentDescriptor()!! }
            val before = relays.map { it.wire.linkCount() }
            val client = c.wire.diagnosticClient()
            val a = client.build(path, 20.seconds).get(30, TimeUnit.SECONDS)
            val b = client.build(path, 20.seconds).get(30, TimeUnit.SECONDS)
            relays.map { it.wire.linkCount() } shouldBe before
            a.close()
            b.close()
            awaitTrue { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe true
            client.close()
        }
    })
