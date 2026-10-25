@file:OptIn(ExperimentalOnionApi::class)

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
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishBody
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishStatus
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.WarmCircuitPool
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration.Companion.seconds

private class WarmDirSink : DirectoryPublishSink {
    @Volatile var status: Byte = DirectoryPublishStatus.ACCEPTED
    val calls = AtomicInteger()

    override fun publish(
        type: DirectoryObjectType,
        objectBytes: ByteArray,
    ): Byte {
        calls.incrementAndGet()
        return status
    }
}

private class WarmMailSink : MailboxPublishSink {
    @Volatile var status: Byte = MailboxPublishStatus.ACCEPTED
    val calls = AtomicInteger()

    override fun publish(itemBytes: ByteArray): Byte {
        calls.incrementAndGet()
        return status
    }
}

/**
 * The usage paths of a warm (pre-built) circuit (wave V0.10.0-H) against real relays on loopback: the rendezvous client
 * with a prebuilt rendezvous circuit, and the directory and mailbox publishers with a prebuilt publish circuit
 * (accepted, retry with the usual candidates, circuit already closed).
 */
class WarmCircuitUsageTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val dirSinks = List(4) { WarmDirSink() }
        val mailSinks = List(4) { WarmMailSink() }
        val relays = List(4) { WireTestNode(relay = true, directorySink = dirSinks[it], mailboxSink = mailSinks[it]) }
        all += relays
        val extra = List(3) { WireTestNode(relay = true).also { all += it } }
        val receiver = WireTestNode(relay = false).also { all += it }
        val sender = WireTestNode(relay = false).also { all += it }
        val meshed = relays + extra
        for (i in meshed.indices) for (j in i + 1 until meshed.size) meshed[i].connectTo(meshed[j])
        meshed.forEach {
            receiver.connectTo(it)
            sender.connectTo(it)
        }
        lateinit var descriptors: List<OnionRelayDescriptor>
        val providerCalls = AtomicInteger()
        val purposes = ConcurrentLinkedQueue<CircuitPurpose>()
        val provider =
            OnionPathProvider { last: OnionRelayDescriptor, purpose: CircuitPurpose ->
                providerCalls.incrementAndGet()
                purposes += purpose
                descriptors.filter { it.identity != last.identity }.take(2) + last
            }
        val random = SecureRandom()

        /** A built three-hop circuit ending at relay [lastIdx], as the warm pool would hand it out. */
        fun warmTo(lastIdx: Int): WarmCircuitPool.Prebuilt {
            val path =
                descriptors.indices
                    .filter { it != lastIdx }
                    .take(2)
                    .map { descriptors[it] } + descriptors[lastIdx]
            val circuit =
                sender.wire
                    .circuitFactory()
                    .build(path, 20.seconds)
                    .get(60, TimeUnit.SECONDS)
            return WarmCircuitPool.Prebuilt(circuit, descriptors[lastIdx], System.currentTimeMillis())
        }

        fun resetCounters() {
            dirSinks.forEach {
                it.status = DirectoryPublishStatus.ACCEPTED
                it.calls.set(0)
            }
            mailSinks.forEach {
                it.status = MailboxPublishStatus.ACCEPTED
                it.calls.set(0)
            }
            providerCalls.set(0)
            purposes.clear()
        }

        test("descriptors converge") {
            descriptors = meshed.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                (listOf(sender, receiver)).all { n ->
                    descriptors.all { d -> n.wire.descriptors.current(d.identity, now()) != null }
                }
            } shouldBe true
        }

        // ---- rendezvous client ---------------------------------------------------------------------

        test("a prebuilt circuit serves as the rendezvous circuit: no sender-side rendezvous path is requested")
            .config(timeout = 180.seconds) {
                resetCounters()
                val host =
                    receiver.wire.experimentalServiceHost(
                        Ed25519KeyPair.generate(),
                        OnionServiceConfig(),
                        provider,
                    )
                host.onConnection = { s -> s.onReceive { s.send(it) } }
                host.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
                val client = sender.wire.experimentalRendezvousClient()
                val warm = warmTo(4)
                try {
                    providerCalls.set(0)
                    purposes.clear()
                    val stream =
                        client
                            .connectWith(host.address, provider, descriptors[4], null, 60.seconds, warm.circuit)
                            .get(60, TimeUnit.SECONDS)
                    val got = ConcurrentLinkedQueue<ByteArray>()
                    stream.onReceive { got += it }
                    stream.send(byteArrayOf(1, 2, 3)) shouldBe true
                    awaitTrue(java.time.Duration.ofSeconds(30)) { got.size == 1 } shouldBe true
                    // the warm circuit carries the stream: still open, and no path for a sender rendezvous was asked for
                    warm.circuit.isClosed shouldBe false
                    purposes.contains(CircuitPurpose.RENDEZVOUS_SENDER) shouldBe false
                    stream.close()
                    awaitTrue(java.time.Duration.ofSeconds(30)) { warm.circuit.isClosed } shouldBe true
                } finally {
                    client.close()
                    host.close()
                }
            }

        test("an attempt that fails, a closed client and an unknown address all close the unused prebuilt circuit")
            .config(timeout = 180.seconds) {
                val keyA = Ed25519KeyPair.generate()
                val keyB = Ed25519KeyPair.generate()
                val hostA = receiver.wire.experimentalServiceHost(keyA, OnionServiceConfig(), provider)
                val hostB = receiver.wire.experimentalServiceHost(keyB, OnionServiceConfig(introPoints = 3), provider)
                hostA.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
                val dB = hostB.start(descriptors.drop(3).take(3)).get(60, TimeUnit.SECONDS)
                val client = sender.wire.experimentalRendezvousClient()
                try {
                    // the descriptor of B presented for the address of A: the attempt fails after the start
                    val failing = warmTo(4)
                    runCatching {
                        client
                            .connectWith(hostA.address, provider, descriptors[4], dB, 30.seconds, failing.circuit)
                            .get(60, TimeUnit.SECONDS)
                    }.isFailure shouldBe true
                    awaitTrue(java.time.Duration.ofSeconds(30)) { failing.circuit.isClosed } shouldBe true

                    // an address without a descriptor
                    val noDescriptor = warmTo(4)
                    val unknown = OnionServiceAddress(Ed25519KeyPair.generate().publicKey)
                    runCatching {
                        client
                            .connectWith(unknown, provider, descriptors[4], null, 5.seconds, noDescriptor.circuit)
                            .get(10, TimeUnit.SECONDS)
                    }.isFailure shouldBe true
                    noDescriptor.circuit.isClosed shouldBe true
                    client.pendingAttempts() shouldBe 0

                    // a closed client
                    val onClosed = warmTo(4)
                    client.close()
                    runCatching {
                        client
                            .connectWith(hostB.address, provider, descriptors[4], dB, 5.seconds, onClosed.circuit)
                            .get(10, TimeUnit.SECONDS)
                    }.isFailure shouldBe true
                    onClosed.circuit.isClosed shouldBe true
                } finally {
                    client.close()
                    hostA.close()
                    hostB.close()
                }
            }

        // ---- directory publisher -------------------------------------------------------------------

        val record =
            AnonymousPeerRecord.create(
                sender.identity,
                Ed25519KeyPair.generate(),
                setOf(AnonymousCapability.DM),
                null,
                System.currentTimeMillis(),
                now() + 600,
            )

        test("directory publisher: an accepted publish over the warm circuit asks no path and no other relay")
            .config(timeout = 180.seconds) {
                resetCounters()
                val handed = AtomicReference<WarmCircuitPool.Prebuilt?>(warmTo(1))
                val asked = ConcurrentLinkedQueue<CircuitPurpose>()
                val channel =
                    sender.wire.directoryPublisher(
                        provider,
                        { descriptors.take(4) },
                        maxAttempts = 4,
                        prebuilt = {
                            asked += it
                            handed.getAndSet(null)
                        },
                    )
                try {
                    providerCalls.set(0)
                    channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe true
                    dirSinks[1].calls.get() shouldBe 1
                    dirSinks.sumOf { it.calls.get() } shouldBe 1
                    providerCalls.get() shouldBe 0
                    asked.toList() shouldBe listOf(CircuitPurpose.DIRECTORY_PUBLISH)
                    channel.openCircuits() shouldBe 0
                } finally {
                    channel.close()
                }
            }

        test("directory publisher: a retry-able answer on the warm circuit penalises that relay and falls back")
            .config(timeout = 240.seconds) {
                resetCounters()
                dirSinks.forEach { it.status = DirectoryPublishStatus.ACCEPTED }
                dirSinks[1].status = DirectoryPublishStatus.RATE_LIMITED
                val handed = AtomicReference<WarmCircuitPool.Prebuilt?>(warmTo(1))
                val channel =
                    sender.wire.directoryPublisher(
                        provider,
                        { descriptors.take(4) },
                        maxAttempts = 4,
                        prebuilt = { handed.getAndSet(null) },
                    )
                try {
                    providerCalls.set(0)
                    channel.publishAnonymousPeerRecord(record).get(180, TimeUnit.SECONDS) shouldBe true
                    dirSinks[1].calls.get() shouldBe 1
                    (providerCalls.get() >= 1) shouldBe true
                    dirSinks.filterIndexed { i, _ -> i != 1 }.sumOf { it.calls.get() } shouldBe 1
                    // the penalised relay is skipped by the next publication
                    channel.publishAnonymousPeerRecord(record).get(180, TimeUnit.SECONDS) shouldBe true
                    dirSinks[1].calls.get() shouldBe 1
                    channel.openCircuits() shouldBe 0
                } finally {
                    channel.close()
                }
            }

        test("directory publisher: a warm circuit that died meanwhile is dropped and the usual path is taken")
            .config(timeout = 180.seconds) {
                resetCounters()
                val dead = warmTo(1)
                dead.circuit.close()
                val channel =
                    sender.wire.directoryPublisher(
                        provider,
                        { descriptors.take(4) },
                        maxAttempts = 4,
                        prebuilt = { dead },
                    )
                try {
                    providerCalls.set(0)
                    channel.publishAnonymousPeerRecord(record).get(120, TimeUnit.SECONDS) shouldBe true
                    (providerCalls.get() >= 1) shouldBe true
                    dirSinks.sumOf { it.calls.get() } shouldBe 1
                } finally {
                    channel.close()
                }
            }

        // ---- mailbox publisher ---------------------------------------------------------------------

        fun item() = ByteArray(MailboxPublishBody.ITEM_SIZE).also(random::nextBytes)

        test("mailbox publisher: an accepted publish over the warm circuit asks no path and counts one publication")
            .config(timeout = 180.seconds) {
                resetCounters()
                val handed = AtomicReference<WarmCircuitPool.Prebuilt?>(warmTo(2))
                val asked = ConcurrentLinkedQueue<CircuitPurpose>()
                val publisher =
                    sender.wire.mailboxPublisher(
                        { l, p -> provider.pathEndingAt(l, p) },
                        { descriptors.take(4) },
                        prebuilt = {
                            asked += it
                            handed.getAndSet(null)
                        },
                    )
                try {
                    providerCalls.set(0)
                    publisher.publishItems(listOf(item(), item())).get(120, TimeUnit.SECONDS) shouldBe true
                    mailSinks[2].calls.get() shouldBe 2
                    mailSinks.sumOf { it.calls.get() } shouldBe 2
                    providerCalls.get() shouldBe 0
                    asked.toList() shouldBe listOf(CircuitPurpose.MAILBOX_PUBLISH)
                    publisher.publicationCount() shouldBe 1
                    publisher.openCircuits() shouldBe 0
                } finally {
                    publisher.close()
                }
            }

        test("mailbox publisher: a retry-able answer on the warm circuit penalises that relay and falls back")
            .config(timeout = 240.seconds) {
                resetCounters()
                mailSinks[2].status = MailboxPublishStatus.RATE_LIMITED
                val handed = AtomicReference<WarmCircuitPool.Prebuilt?>(warmTo(2))
                val publisher =
                    sender.wire.mailboxPublisher(
                        { l, p -> provider.pathEndingAt(l, p) },
                        { descriptors.take(4) },
                        maxAttempts = 4,
                        prebuilt = { handed.getAndSet(null) },
                    )
                try {
                    providerCalls.set(0)
                    publisher.publishItems(listOf(item())).get(180, TimeUnit.SECONDS) shouldBe true
                    mailSinks[2].calls.get() shouldBe 1
                    (providerCalls.get() >= 1) shouldBe true
                    mailSinks.filterIndexed { i, _ -> i != 2 }.sumOf { it.calls.get() } shouldBe 1
                    publisher.publishItems(listOf(item())).get(180, TimeUnit.SECONDS) shouldBe true
                    mailSinks[2].calls.get() shouldBe 1
                    publisher.openCircuits() shouldBe 0
                } finally {
                    publisher.close()
                }
            }

        test("mailbox publisher: a warm circuit that died meanwhile is dropped and the usual path is taken")
            .config(timeout = 180.seconds) {
                resetCounters()
                val dead = warmTo(2)
                dead.circuit.close()
                val publisher =
                    sender.wire.mailboxPublisher(
                        { l, p -> provider.pathEndingAt(l, p) },
                        { descriptors.take(4) },
                        prebuilt = { dead },
                    )
                try {
                    providerCalls.set(0)
                    publisher.publishItems(listOf(item())).get(120, TimeUnit.SECONDS) shouldBe true
                    (providerCalls.get() >= 1) shouldBe true
                    mailSinks.sumOf { it.calls.get() } shouldBe 1
                } finally {
                    publisher.close()
                }
            }
    })
