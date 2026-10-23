package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.DirectoryObjectType
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishStatus
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** A relay-side sink whose answer and delay the test controls; counts how often the relay was asked. */
private class ScriptedSink : DirectoryPublishSink {
    @Volatile var status: Byte = DirectoryPublishStatus.ACCEPTED

    @Volatile var delayMillis = 0L

    @Volatile var gate: CountDownLatch? = null
    val calls = AtomicInteger()

    override fun publish(
        type: DirectoryObjectType,
        objectBytes: ByteArray,
    ): Byte {
        calls.incrementAndGet()
        gate?.await(30, TimeUnit.SECONDS)
        if (delayMillis > 0) Thread.sleep(delayMillis)
        return status
    }
}

/**
 * Failover, backoff, abort and timeout behaviour of [OnionDirectoryPublisher] against real relays on loopback whose
 * directory sink is scripted (no gossip involved).
 */
@OptIn(ExperimentalOnionApi::class)
class OnionDirectoryPublisherFailoverTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val sinks = List(4) { ScriptedSink() }
        val relays = sinks.map { s -> WireTestNode(relay = true, directorySink = s).also { all += it } }
        val sender = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { sender.connectTo(it) }
        lateinit var descriptors: List<OnionRelayDescriptor>
        val provider =
            OnionPathProvider { last: OnionRelayDescriptor, _: CircuitPurpose ->
                descriptors.filter { it.identity != last.identity }.take(2) + last
            }
        val record =
            AnonymousPeerRecord.create(
                sender.identity,
                Ed25519KeyPair.generate(),
                setOf(AnonymousCapability.DM),
                null,
                System.currentTimeMillis(),
                now() + 600,
            )

        fun reset() =
            sinks.forEach {
                it.status = DirectoryPublishStatus.ACCEPTED
                it.delayMillis = 0
                it.gate = null
                it.calls.set(0)
            }

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                descriptors.all { d -> sender.wire.descriptors.current(d.identity, now()) != null }
            } shouldBe true
        }

        test("RATE_LIMITED moves on to the next relay, and a penalised relay is skipped by the next publication")
            .config(timeout = 180.seconds) {
                reset()
                sinks.forEach { it.status = DirectoryPublishStatus.RATE_LIMITED }
                sinks[0].status = DirectoryPublishStatus.ACCEPTED
                val channel = sender.wire.directoryPublisher(provider, maxAttempts = 4)
                try {
                    channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe true
                    sinks[0].calls.get() shouldBe 1
                    val limitedCalls = sinks.drop(1).map { it.calls.get() }
                    limitedCalls.all { it <= 1 } shouldBe true
                    // backoff: every relay that answered RATE_LIMITED is not asked again right away
                    channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe true
                    // (a limited relay that was not tried the first time may be asked now; a tried one must not)
                    sinks.drop(1).map { it.calls.get() }.zip(limitedCalls).forEach { (after, first) ->
                        if (first == 1) after shouldBe 1
                    }
                    sinks[0].calls.get() shouldBe 2
                    channel.openCircuits() shouldBe 0
                } finally {
                    channel.close()
                }
            }

        test("UNKNOWN_TYPE (a relay without a directory sink) moves on to the next relay") {
            reset()
            sinks.forEach { it.status = DirectoryPublishStatus.UNKNOWN_TYPE }
            sinks[3].status = DirectoryPublishStatus.ACCEPTED
            val channel = sender.wire.directoryPublisher(provider, maxAttempts = 4)
            try {
                channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe true
                sinks[3].calls.get() shouldBe 1
            } finally {
                channel.close()
            }
        }

        for (
        (name, status) in
        listOf("INVALID" to DirectoryPublishStatus.INVALID, "MALFORMED" to DirectoryPublishStatus.MALFORMED)
        ) {
            test("$name aborts the publication: no other relay is asked for the same object") {
                reset()
                sinks.forEach { it.status = status }
                val channel = sender.wire.directoryPublisher(provider, maxAttempts = 4)
                try {
                    channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe false
                    sinks.sumOf { it.calls.get() } shouldBe 1
                    channel.openCircuits() shouldBe 0
                } finally {
                    channel.close()
                }
            }
        }

        test("an ack that does not arrive in time ends the attempt, closes the circuit and is reported as false") {
            reset()
            sinks.forEach { it.delayMillis = 4_000 }
            val channel = sender.wire.directoryPublisher(provider, ackTimeout = 500.milliseconds, maxAttempts = 2)
            try {
                channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe false
                awaitTrue { channel.openCircuits() == 0 } shouldBe true
            } finally {
                channel.close()
            }
        }

        test("close() during a running exchange completes the publication with false and drains the circuits") {
            reset()
            val gate = CountDownLatch(1)
            sinks.forEach { it.gate = gate }
            val channel = sender.wire.directoryPublisher(provider, maxAttempts = 1)
            try {
                val future = channel.publishAnonymousPeerRecord(record)
                awaitTrue(java.time.Duration.ofSeconds(60)) { sinks.any { it.calls.get() > 0 } } shouldBe true
                channel.close()
                future.get(60, TimeUnit.SECONDS) shouldBe false
                channel.openCircuits() shouldBe 0
                channel.publishAnonymousPeerRecord(record).get(5, TimeUnit.SECONDS) shouldBe false
            } finally {
                gate.countDown()
                channel.close()
            }
        }
    })
