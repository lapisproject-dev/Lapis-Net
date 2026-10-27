package net.lapisphilosophorum.lapisnet.onionwire

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.DirectoryTransitionPlan
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.time.Clock
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

/**
 * Seven REAL nodes on loopback: five relays in a full mesh, node A in directory anonymity mode ON, node B in normal mode.
 * A publishes its directory presence ONLY through circuits (a relay announces on its behalf); B resolves A, builds a
 * rendezvous session and exchanges a message. A leak scanner searches everything A sends out on its own for its
 * addresses and its transport identity.
 */
@OptIn(ExperimentalOnionApi::class)
class MultiNodeAnonymousDirectoryTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        val logs = ListAppender<ILoggingEvent>().also { it.start() }
        val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
        val oldLevel = root.level
        root.level = Level.DEBUG
        root.addAppender(logs)
        afterSpec {
            all.forEach { it.close() }
            root.detachAppender(logs)
            root.level = oldLevel
        }

        fun now() = Clock.systemUTC().millis() / 1000

        val relays = List(5) { WireTestNode(relay = true).also { all += it } }
        val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        val b = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach {
            a.connectTo(it)
            b.connectTo(it)
        }

        lateinit var descriptors: List<OnionRelayDescriptor>
        var rotate = 0
        val provider =
            OnionPathProvider { last, _: CircuitPurpose ->
                val lastIdx = descriptors.indexOfFirst { it.identity == last.identity }
                val others = descriptors.indices.filter { it != lastIdx }
                val x = others[(rotate++) % others.size]
                val y = others.first { it != x }
                listOf(descriptors[x], descriptors[y], last)
            }

        val scanner = AnonymityLeakScanner(a)
        val dir = Files.createTempDirectory("anonymous-directory-test")
        val prekeys = PrekeyStore.create(dir.resolve("prekeys"), a.identity)
        val serviceKey = Ed25519KeyPair.generate()
        val directoryPublisher = a.wire.experimentalDirectoryPublisher(provider)
        val capturing = CapturingChannel(directoryPublisher)
        // A ran in normal mode before (persisted OFF), otherwise no tombstone is built
        val modeStore =
            InMemoryDirectoryModeStore(
                net.lapisphilosophorum.lapisnet.directory
                    .DirectoryModeState(DirectoryAnonymityMode.OFF, System.currentTimeMillis() - 5000),
            )
        var tombstone: PeerRecord? = null

        test("descriptors converge: every node knows every relay") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                (relays + a + b).all { n ->
                    descriptors.all { d -> n.wire.descriptors.current(d.identity, now()) != null }
                }
            } shouldBe true
        }

        test("a node in anonymity mode refuses to host a service that would publish from the node itself") {
            val e =
                runCatching { a.wire.experimentalServiceHost(serviceKey, OnionServiceConfig(), provider) }
                    .exceptionOrNull()
            e.shouldBeInstanceOf<IllegalArgumentException>()
        }

        test("A publishes presence, bundle and service descriptor through circuits and B resolves A as hidden").config(
            timeout = 180.seconds,
        ) {
            val host = a.wire.experimentalServiceHost(serviceKey, OnionServiceConfig(), provider, capturing)
            host.onConnection = { s -> s.onReceive { s.send(it) } }
            host.start(descriptors.take(3)).get(90, TimeUnit.SECONDS)

            val publisher =
                AnonymousDirectoryPublisher(
                    a.identity,
                    serviceKey,
                    prekeys,
                    capturing,
                    modeStore,
                    capabilities = setOf(AnonymousCapability.DM),
                    tombstonePublisher = {
                        tombstone = it
                        a.peerDirectory.announce(it) // the one permitted publication from the own node
                    },
                )
            try {
                publisher.tick() shouldBe true
                publisher.publications shouldBe 1
            } finally {
                publisher.close()
            }

            awaitTrue(java.time.Duration.ofSeconds(90)) {
                b.wire.anonymousDirectory().resolve(a.key) is DirectoryReachability.Hidden
            } shouldBe true
            val hidden =
                b.wire
                    .anonymousDirectory()
                    .resolve(a.key)
                    .shouldBeInstanceOf<DirectoryReachability.Hidden>()
            hidden.record.onionAddress shouldBe host.address
            hidden.descriptor.serviceKey shouldBe serviceKey.publicKey

            // B reaches A through the rendezvous machinery: infrastructure only, no DM
            val client = b.wire.experimentalRendezvousClient()
            val stream = client.connect(host.address, provider, descriptors[4]).get(90, TimeUnit.SECONDS)
            val got = ConcurrentLinkedQueue<ByteArray>()
            stream.onReceive { got += it }
            stream.send("ping".toByteArray()) shouldBe true
            awaitTrue(java.time.Duration.ofSeconds(30)) { got.size == 1 } shouldBe true
            String(got.single()) shouldBe "ping"
            client.close()
            host.close()
        }

        test("a service descriptor whose first publication fails still arrives, without any change of the host").config(
            timeout = 180.seconds,
        ) {
            val key = Ed25519KeyPair.generate()
            val failFirst = FailFirstDescriptorChannel(directoryPublisher)
            val host = a.wire.experimentalServiceHost(key, OnionServiceConfig(), provider, failFirst)
            try {
                host.start(descriptors.take(3)).get(90, TimeUnit.SECONDS)
                // the host publishes only on change and hourly: the retry comes from the early republication
                awaitTrue(java.time.Duration.ofSeconds(60)) {
                    b.wire.serviceDescriptors.current(key.publicKey, now()) != null
                } shouldBe true
                (failFirst.calls.get() >= 2) shouldBe true
            } finally {
                host.close()
            }
        }

        test("the leak scanner finds NOTHING of A's addresses or transport identity (positive control included)") {
            val toldTombstone = tombstone.shouldNotBeNull()
            val tombstoneBytes = PeerRecordCodec.encode(toldTombstone)
            // A published nothing by itself except the address-free tombstone, on the peer record topic
            scanner.gossip.size shouldBe 1
            scanner.gossip
                .single()
                .second
                .contentEquals(tombstoneBytes) shouldBe true

            val everything = scanner.gossip.map { it.second } + capturing.objects
            scanner.leaks(everything, scanner.addressNeedles()) shouldBe emptyList()
            // the identity needles are absent from every circuit object and from every gossip message except the tombstone
            val withoutTombstone =
                scanner.gossip.map { it.second }.filter { !it.contentEquals(tombstoneBytes) } + capturing.objects
            scanner.leaks(withoutTombstone, scanner.identityNeedles()) shouldBe emptyList()
            (capturing.objects.size >= 3) shouldBe true // record, bundle and service descriptor were really sent

            // positive control: an ordinary peer record of A is full of exactly these needles
            val ordinary =
                PeerRecord.create(
                    a.identity,
                    a.node.listenAddresses(),
                    setOf(PeerCapability.DM),
                    System.currentTimeMillis(),
                    now() + 600,
                )
            val encoded = listOf(PeerRecordCodec.encode(ordinary))
            // a record carries addresses in binary form: the binary multiaddr and the port component are found, the text form is not
            val addressHits = scanner.leaks(encoded, scanner.addressNeedles())
            addressHits shouldBe scanner.addressNeedles().indices.filter { it % 3 != 1 }
            scanner.leaks(encoded, scanner.identityNeedles()).size shouldBe scanner.identityNeedles().size
        }

        test("no other node holds an address for A: only the address-free tombstone, and a hidden entry") {
            val all2 = relays + b
            awaitTrue(java.time.Duration.ofSeconds(30)) {
                all2.all { n -> n.wire.anonymousDirectory().resolve(a.key) is DirectoryReachability.Hidden }
            } shouldBe true
            for (n in all2) {
                val record: PeerRecord? = n.peerDirectory.lookup(a.key)
                (record?.addresses ?: emptyList()).size shouldBe 0
            }
        }

        test("the logs of the whole run contain neither A's addresses, nor its onion address, nor its service key") {
            val forbidden =
                a.node.listenAddresses().map { it.toString() } +
                    listOf(
                        serviceKey.publicKey.bytes.joinToString("") { "%02x".format(it) },
                        net.lapisphilosophorum.lapisnet.onion
                            .OnionServiceAddress(serviceKey.publicKey)
                            .encode(),
                    )
            // the directory, onion and onion-wire layers; the transport layer logs its own peer ids locally (not a directory leak)
            val scoped = listOf(".directory.", ".onion.", ".onionwire.")
            val lines =
                logs.list
                    .filter { e -> scoped.any { e.loggerName.contains(it) || e.loggerName.endsWith(it.trimEnd('.')) } }
                    .map { it.formattedMessage + (it.throwableProxy?.message ?: "") }
            (lines.size > 0) shouldBe true
            val hits = lines.filter { l -> forbidden.any { l.contains(it) } }
            hits shouldBe emptyList()
        }

        test("a relay and anonymity mode on the same identity exclude each other, without leaking an address") {
            val e =
                runCatching {
                    WireTestNode(
                        relay = true,
                        directoryMode = DirectoryAnonymityMode.ON,
                    )
                }.exceptionOrNull()
            e.shouldNotBeNull()
            var cause: Throwable? = e
            while (cause != null && cause !is IllegalArgumentException) cause = cause.cause
            cause.shouldBeInstanceOf<IllegalArgumentException>()
            (cause.message ?: "").contains("/ip4/") shouldBe false
            (cause.message ?: "").contains("exclude each other") shouldBe true
        }

        test("OFF to ON to OFF on a normal node: the other nodes always hold exactly one current record type") {
            val c = WireTestNode(relay = false).also { all += it }
            relays.forEach { c.connectTo(it) }
            val store = InMemoryDirectoryModeStore()
            val cService = Ed25519KeyPair.generate()
            val cPrekeys = PrekeyStore.create(dir.resolve("prekeys-c"), c.identity)
            val cPublisherChannel = c.wire.experimentalDirectoryPublisher(provider)
            val watchers = relays + b
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                descriptors.all { d -> c.wire.descriptors.current(d.identity, now()) != null }
            } shouldBe true

            // 1. normal mode: an address-bearing record is published
            val transition0 = DirectoryModeTransition(c.identity, store)
            val normal =
                PeerRecord.create(
                    c.identity,
                    c.node.listenAddresses(),
                    setOf(PeerCapability.DM),
                    transition0.nextSequence(DirectoryAnonymityMode.OFF),
                    now() + 600,
                )
            c.peerDirectory.announce(normal)
            awaitTrue(java.time.Duration.ofSeconds(60)) {
                watchers.all {
                    it.peerDirectory
                        .lookup(c.key)
                        ?.addresses
                        ?.isNotEmpty() == true
                }
            } shouldBe true

            // 2. switch to ON: tombstone first, then the anonymous record through a circuit
            val publisher =
                AnonymousDirectoryPublisher(
                    c.identity,
                    cService,
                    cPrekeys,
                    cPublisherChannel,
                    store,
                    tombstonePublisher = { c.peerDirectory.announce(it) },
                )
            publisher.tick() shouldBe true
            publisher.close()
            awaitTrue(java.time.Duration.ofSeconds(60)) {
                watchers.all {
                    it.peerDirectory
                        .lookup(c.key)
                        ?.addresses
                        .isNullOrEmpty() &&
                        it.wire.anonymousDirectory().resolve(c.key) is DirectoryReachability.HiddenDescriptorMissing
                }
            } shouldBe true

            // a replay of the old address record is ignored everywhere
            c.peerDirectory.announce(normal)
            Thread.sleep(2000)
            watchers.forEach {
                it.peerDirectory
                    .lookup(c.key)
                    ?.addresses
                    .isNullOrEmpty() shouldBe true
            }

            // 3. switch back to OFF: a revocation (through a circuit), then a newer address record
            val transition2 = DirectoryModeTransition(c.identity, store)
            val plan =
                transition2
                    .prepare(
                        DirectoryAnonymityMode.OFF,
                    ).shouldBeInstanceOf<DirectoryTransitionPlan.Revocation>()
            cPublisherChannel.publishAnonymousPeerRecord(plan.record).get(60, TimeUnit.SECONDS) shouldBe true
            val back =
                PeerRecord.create(
                    c.identity,
                    c.node.listenAddresses(),
                    setOf(PeerCapability.DM),
                    transition2.nextSequence(DirectoryAnonymityMode.OFF),
                    now() + 600,
                )
            c.peerDirectory.announce(back)
            awaitTrue(java.time.Duration.ofSeconds(60)) {
                watchers.all { it.wire.anonymousDirectory().resolve(c.key) is DirectoryReachability.Direct }
            } shouldBe true
            // and the old address record is still dead, the newest one is current
            c.peerDirectory.announce(normal)
            Thread.sleep(1500)
            watchers.forEach { (it.peerDirectory.lookup(c.key)?.sequenceNumber ?: 0L) shouldBe back.sequenceNumber }
        }
    })

/** Fails the first service descriptor publication (acknowledged as not published), delegates everything else. */
@OptIn(ExperimentalOnionApi::class)
private class FailFirstDescriptorChannel(
    private val delegate: net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel,
) : net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel by delegate {
    val calls =
        java.util.concurrent.atomic
            .AtomicInteger()

    override fun publishServiceDescriptor(
        descriptor: net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor,
    ): java.util.concurrent.CompletableFuture<Boolean> =
        if (calls.getAndIncrement() == 0) {
            java.util.concurrent.CompletableFuture
                .completedFuture(false)
        } else {
            delegate.publishServiceDescriptor(descriptor)
        }
}
