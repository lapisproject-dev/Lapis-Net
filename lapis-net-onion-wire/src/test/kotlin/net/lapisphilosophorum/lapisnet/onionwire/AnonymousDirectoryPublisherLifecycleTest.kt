package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectGossipChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicInteger

private class CountingChannel(
    override val exposesOrigin: Boolean = false,
) : DirectoryPublicationChannel {
    val calls = AtomicInteger()

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> {
        calls.incrementAndGet()
        return CompletableFuture.completedFuture(true)
    }

    override fun publishPrekeyBundle(bundle: PrekeyBundle): CompletableFuture<Boolean> {
        calls.incrementAndGet()
        return CompletableFuture.completedFuture(true)
    }

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor): CompletableFuture<Boolean> =
        CompletableFuture.completedFuture(true)
}

@OptIn(ExperimentalOnionApi::class)
class AnonymousDirectoryPublisherLifecycleTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        fun publisherThreads() =
            Thread.getAllStackTraces().keys.count { it.name == "lapis-net-anonymous-directory" && it.isAlive }

        val a = WireTestNode(relay = false).also { all += it }
        val prekeys = PrekeyStore.create(Files.createTempDirectory("lifecycle-prekeys"), a.identity)

        test("a channel that exposes the origin is refused unless a test explicitly allows it") {
            val direct = CountingChannel(exposesOrigin = true)
            shouldThrow<IllegalArgumentException> {
                AnonymousDirectoryPublisher(
                    a.identity,
                    Ed25519KeyPair.generate(),
                    prekeys,
                    direct,
                    InMemoryDirectoryModeStore(),
                )
            }
            AnonymousDirectoryPublisher(
                a.identity,
                Ed25519KeyPair.generate(),
                prekeys,
                direct,
                InMemoryDirectoryModeStore(),
                allowDirectChannel = true,
            ).close()
            @Suppress("UNUSED_VARIABLE")
            val unused = DirectGossipChannel::class
        }

        test("start, tick and close are idempotent; nothing is published after close and no timer thread remains") {
            val before = publisherThreads()
            val channel = CountingChannel()
            val p =
                AnonymousDirectoryPublisher(
                    a.identity,
                    Ed25519KeyPair.generate(),
                    prekeys,
                    channel,
                    InMemoryDirectoryModeStore(),
                )
            p.start()
            p.start()
            awaitTrue(java.time.Duration.ofSeconds(20)) { p.publications >= 1 } shouldBe true
            (publisherThreads() > before) shouldBe true
            p.tick() shouldBe true // within the republish interval: still current, nothing new published
            val callsAfterStart = channel.calls.get()
            p.close()
            p.close()
            p.tick() shouldBe false
            channel.calls.get() shouldBe callsAfterStart
            awaitTrue(java.time.Duration.ofSeconds(10)) { publisherThreads() == before } shouldBe true
            p.start() // a closed publisher stays closed
            Thread.sleep(300)
            channel.calls.get() shouldBe callsAfterStart
            publisherThreads() shouldBe before
        }

        test("a failed publication is retried and does not mark the entry as current") {
            val failing =
                object : DirectoryPublicationChannel {
                    var succeed = false
                    override val exposesOrigin = false

                    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord) =
                        CompletableFuture.completedFuture(succeed)

                    override fun publishPrekeyBundle(bundle: PrekeyBundle) = CompletableFuture.completedFuture(true)

                    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor) =
                        CompletableFuture.completedFuture(true)
                }
            val p =
                AnonymousDirectoryPublisher(
                    a.identity,
                    Ed25519KeyPair.generate(),
                    prekeys,
                    failing,
                    InMemoryDirectoryModeStore(),
                )
            p.tick() shouldBe false
            p.publications shouldBe 0
            failing.succeed = true
            p.tick() shouldBe true
            p.publications shouldBe 1
            p.close()
        }

        test(
            "if a publish relay is down another one is tried; if all are down nothing is published from the own node",
        ) {
            val relays = List(4) { WireTestNode(relay = true).also { all += it } }
            for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
            val sender = WireTestNode(relay = false).also { all += it }
            relays.forEach { sender.connectTo(it) }
            val tap = AnonymityLeakScanner(sender)
            val descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                descriptors.all { d -> sender.wire.descriptors.current(d.identity, now()) != null }
            } shouldBe true
            val deadId = descriptors[0].identity
            val provider =
                OnionPathProvider { last: OnionRelayDescriptor, _: CircuitPurpose ->
                    descriptors.filter { it.identity != last.identity && it.identity != deadId }.take(2) + last
                }

            val dead = relays[0]
            val deadDescriptor = descriptors[0]
            dead.close()
            val channel =
                sender.wire.experimentalDirectoryPublisher(provider, publishRelays = {
                    listOf(deadDescriptor) +
                        descriptors.drop(1)
                })
            val record = AnonymousPeerRecordForTest.make(sender)
            // several attempts: whatever the shuffle picks first, the dead relay is skipped over
            repeat(3) {
                channel.publishAnonymousPeerRecord(record).get(120, java.util.concurrent.TimeUnit.SECONDS) shouldBe
                    true
            }
            tap.gossip.size shouldBe 0 // never fell back to publishing from the own node

            val none = sender.wire.experimentalDirectoryPublisher(provider, publishRelays = { listOf(deadDescriptor) })
            none.publishAnonymousPeerRecord(record).get(120, java.util.concurrent.TimeUnit.SECONDS) shouldBe false
            tap.gossip.size shouldBe 0
            none.openCircuits() shouldBe 0
            none.close()
            none.publishAnonymousPeerRecord(record).get(5, java.util.concurrent.TimeUnit.SECONDS) shouldBe false
            channel.close()
            awaitTrue { sender.wire.hiddenServiceRoutes() == 0 } shouldBe true
        }
    })

private object AnonymousPeerRecordForTest {
    fun make(node: WireTestNode): AnonymousPeerRecord =
        AnonymousPeerRecord.create(
            node.identity,
            Ed25519KeyPair.generate(),
            setOf(net.lapisphilosophorum.lapisnet.directory.AnonymousCapability.DM),
            null,
            System.currentTimeMillis(),
            System.currentTimeMillis() / 1000 + 600,
        )
}
