package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishBody
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishStatus
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.seconds

private class ScriptedMailboxSink : MailboxPublishSink {
    @Volatile var status: Byte = MailboxPublishStatus.ACCEPTED
    val calls = AtomicInteger()
    val items = ConcurrentLinkedQueue<ByteArray>()

    override fun publish(itemBytes: ByteArray): Byte {
        calls.incrementAndGet()
        items += itemBytes
        return status
    }
}

/** Lifecycle, failover and no-fallback behaviour of [OnionMailboxPublisher] against real relays on loopback. */
@OptIn(ExperimentalOnionApi::class)
class OnionMailboxPublisherTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val sinks = List(4) { ScriptedMailboxSink() }
        val relays = sinks.map { s -> WireTestNode(relay = true, mailboxSink = s).also { all += it } }
        val sender = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { sender.connectTo(it) }
        lateinit var descriptors: List<OnionRelayDescriptor>
        val provider =
            OnionPathProvider { last: OnionRelayDescriptor, _: CircuitPurpose ->
                descriptors.filter { it.identity != last.identity }.take(2) + last
            }
        val random = SecureRandom()

        fun item() = ByteArray(MailboxPublishBody.ITEM_SIZE).also(random::nextBytes)

        fun reset() =
            sinks.forEach {
                it.status = MailboxPublishStatus.ACCEPTED
                it.calls.set(0)
                it.items.clear()
            }

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                descriptors.all { d -> sender.wire.descriptors.current(d.identity, now()) != null }
            } shouldBe true
        }

        test("four items travel through one circuit, arrive intact at one relay and leave no circuit behind")
            .config(timeout = 180.seconds) {
                reset()
                val publisher = sender.wire.mailboxPublisher({ l, p -> provider.pathEndingAt(l, p) }, { descriptors })
                try {
                    val items = List(4) { item() }
                    publisher.publishItems(items).get(120, TimeUnit.SECONDS) shouldBe true
                    val receivedBy = sinks.filter { it.calls.get() > 0 }
                    receivedBy.size shouldBe 1
                    val got = receivedBy.single().items.toList()
                    got.size shouldBe 4
                    got.zip(items).all { (a, b) -> a.contentEquals(b) } shouldBe true
                    publisher.openCircuits() shouldBe 0
                    publisher.publicationCount() shouldBe 1
                } finally {
                    publisher.close()
                }
                awaitTrue(java.time.Duration.ofSeconds(30)) {
                    relays.all { it.wire.relayService!!.circuitCount() == 0 }
                } shouldBe true
            }

        test(
            "RATE_LIMITED moves on to the next relay; when every relay refuses, the result is false and nothing is published locally",
        ).config(timeout = 240.seconds) {
            reset()
            sinks.forEach { it.status = MailboxPublishStatus.RATE_LIMITED }
            sinks[3].status = MailboxPublishStatus.ACCEPTED
            val publisher =
                sender.wire.mailboxPublisher(
                    { l, p -> provider.pathEndingAt(l, p) },
                    { descriptors },
                    maxAttempts = 4,
                )
            try {
                publisher.publishItems(listOf(item())).get(180, TimeUnit.SECONDS) shouldBe true
                sinks[3].calls.get() shouldBe 1

                reset()
                sinks.forEach { it.status = MailboxPublishStatus.RATE_LIMITED }
                // every relay is penalised now; the answer must be false, not a local announcement
                publisher.publishItems(listOf(item())).get(180, TimeUnit.SECONDS) shouldBe false
                publisher.openCircuits() shouldBe 0
            } finally {
                publisher.close()
            }
        }

        test("a wrong item size, too many items and a closed publisher are refused without touching the network") {
            reset()
            val publisher = sender.wire.mailboxPublisher({ l, p -> provider.pathEndingAt(l, p) }, { descriptors })
            publisher.publishItems(emptyList()).get() shouldBe false
            publisher.publishItems(listOf(ByteArray(10))).get() shouldBe false
            publisher.publishItems(List(5) { item() }).get() shouldBe false
            publisher.close()
            publisher.publishItems(listOf(item())).get() shouldBe false
            sinks.sumOf { it.calls.get() } shouldBe 0
        }
    })
