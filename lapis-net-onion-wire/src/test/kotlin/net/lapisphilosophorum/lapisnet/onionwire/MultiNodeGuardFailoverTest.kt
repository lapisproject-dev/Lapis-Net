@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityErrorCode
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.EncryptedFileGuardStateStore
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardLoad
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardState
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.time.Duration
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

/**
 * Failure of the primary guard (wave I). Seven relays in a full mesh, A (hosts a service) and B (connects to it), both in
 * anonymity mode. The relay descriptor TTL is shortened to 90 seconds with a 30-second republication (7 relays then stay far below the
 * receivers' gossip rate limits of 6 per author and 60 in total per minute; no jumps of a shared clock: records, bindings
 * and key rotation would move with it), so that the descriptor of a dead relay leaves every index in real time.
 *
 * Security property under test: ONE guard outage does not rotate the guard (the primary stays in the persisted state, a
 * failure is only counted), the node never falls back to announcing from its own address, and as soon as the dead
 * primary's descriptor is gone the backup serves as first hop. The 72-hour and 24-hour rotation rules are covered by
 * the unit tests in `GuardManagerTest`, not here. Loopback with a synthetic locator, not real networks.
 */
class MultiNodeGuardFailoverTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { runCatching { it.close() } } }

        fun now() = Clock.systemUTC().millis() / 1000

        val shortTtl = fastWireConfig(true).copy(descriptorTtl = 90.seconds, descriptorRepublishInterval = 30.seconds)
        val relays = List(7) { WireTestNode(relay = true, config = shortTtl).also { all += it } }
        val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        val b = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach {
            a.connectTo(it)
            b.connectTo(it)
        }
        val scannerA = AnonymityLeakScanner(a)
        val locator = MapLocator()
        val serviceKeyA = Ed25519KeyPair.generate()
        lateinit var runtimeA: AnonymityRuntime
        lateinit var runtimeB: AnonymityRuntime
        val guardFileA = a.dir.resolve("onion").resolve("guards.bin")

        fun guardsOfA(): GuardState =
            EncryptedFileGuardStateStore(
                guardFileA,
                a.identity,
            ).use { it.load().shouldBeInstanceOf<GuardLoad.Loaded>().state }

        fun start(
            n: WireTestNode,
            key: Ed25519KeyPair,
        ): AnonymityRuntime {
            val dir = Files.createTempDirectory("guard-failover")
            return AnonymityRuntime.start(
                n.wire,
                n.identity,
                n.dir,
                { null },
                locator,
                InMemoryDirectoryModeStore(
                    DirectoryModeState(
                        DirectoryAnonymityMode.OFF,
                        System.currentTimeMillis() - 5000,
                    ),
                ),
                PrekeyStore.create(dir.resolve("prekeys"), n.identity),
                key,
                { t -> n.peerDirectory.announce(t) },
                n.supervisor,
                // short backoff: the failures during the outage (several circuits per round) must not push the retry after P's
                // descriptor expired beyond the test window (default backoff grows to 5 minutes)
                governor =
                    CircuitBuildGovernor(
                        Clock.systemUTC(),
                        ratePerMinute = 600,
                        burst = 100,
                        backoffMin = 1.seconds,
                        backoffMax = 10.seconds,
                    ),
            )
        }

        lateinit var primary: Secp256k1PublicKey
        lateinit var backup: Secp256k1PublicKey
        var sequenceBefore = 0L
        var introBefore: List<net.lapisphilosophorum.lapisnet.onion.IntroPointEntry> = emptyList()

        test(
            "A publishes over its primary guard; the guard file names primary P and backup K, A holds one onion link",
        ) {
            val descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                (relays + a + b).all { n ->
                    descriptors.all { d -> n.wire.descriptors.current(d.identity, now()) != null }
                }
            } shouldBe true
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(10 + i, i)) }
            runtimeA = start(a, serviceKeyA)
            runtimeB = start(b, Ed25519KeyPair.generate())
            runtimeA.serviceRouter().register(OnionServiceApp.DM) { s -> s.onReceive { s.send(it) } }
            awaitTrue(Duration.ofSeconds(200)) {
                runtimeA.maintenanceTick()
                runtimeB.maintenanceTick()
                runtimeA.publications() >= 1 && runtimeB.publications() >= 1
            } shouldBe true
            val state = guardsOfA()
            primary = state.primary.shouldNotBeNull().identity
            backup = state.backup.shouldNotBeNull().identity
            (primary == backup) shouldBe false
            a.wire.linkCount() shouldBe 1
            // B holds A's descriptor before P goes down
            awaitedDescriptor { b.wire.serviceDescriptors.current(serviceKeyA.publicKey, now()) }
        }

        test(
            "P goes down: builds fail at the first hop, nothing is published from the own node, no guard rotation",
        ).config(timeout = 240.seconds) {
            val p = relays.first { it.key == primary }
            val gossipBefore = scannerA.gossip.size
            p.close()
            // Reference point AFTER the outage began: early refresh versions sent before P went down must not count.
            // Early sends of an already running schedule keep the same introduction points, so the introduction points
            // are compared as well: only a rebuild over the backup yields new ones.
            val ref =
                b.wire.serviceDescriptors
                    .current(serviceKeyA.publicKey, now())
                    .shouldNotBeNull()
            sequenceBefore = ref.sequenceNumber
            introBefore = ref.introPoints
            // builds toward the dead guard fail: the failure is counted, the primary is NOT replaced
            var counted = false
            awaitTrue(Duration.ofSeconds(35)) {
                Thread.sleep(1000) // not a busy loop: it would drain the circuit build governor
                runtimeA.maintainNow()
                val st = guardsOfA()
                counted = st.primary?.consecutiveFailures?.let { it >= 1 } == true
                counted
            } shouldBe true
            val st = guardsOfA()
            st.primary.shouldNotBeNull().identity shouldBe primary
            st.backup.shouldNotBeNull().identity shouldBe backup
            // A never announces anything from its own node because of the outage (only the address-free tombstone exists)
            scannerA.gossip.size shouldBe gossipBefore
            scannerA.leaks(scannerA.gossip.map { it.second }, scannerA.addressNeedles()) shouldBe emptyList()
            println("TIMELINE guard-failover: failures counted=$counted, lastError=${runtimeA.status().lastError.wire}")
            setOf(
                AnonymityErrorCode.NONE,
                AnonymityErrorCode.BUILD_FAILED,
                AnonymityErrorCode.BUILD_TIMEOUT,
                AnonymityErrorCode.PUBLISH_FAILED,
            ).contains(runtimeA.status().lastError) shouldBe true
        }

        test(
            "once P's descriptor expired, the backup K is the first hop: publication succeeds again and B connects to A",
        ).config(timeout = 400.seconds) {
            // The directory objects are not due for republication, but A's service rebuilds its introduction circuits
            // over the backup and publishes a NEW service descriptor through circuits: B sees a higher sequence number.
            val published =
                awaitTrue(Duration.ofSeconds(300)) {
                    Thread.sleep(1000) // not a busy loop: it would drain the circuit build governor
                    runtimeA.maintainNow()
                    runtimeB.maintainNow()
                    val d = b.wire.serviceDescriptors.current(serviceKeyA.publicKey, now())
                    d != null && d.sequenceNumber > sequenceBefore && d.introPoints != introBefore
                }
            published shouldBe true
            // the only onion link of A leads to K; the persisted primary is still P (replacement comes after 72 hours)
            awaitTrue(Duration.ofSeconds(30)) { a.wire.linkCount() == 1 } shouldBe true
            guardsOfA().primary.shouldNotBeNull().identity shouldBe primary

            // B resolves the (possibly re-published) descriptor of A and talks to it over circuits. Right after the
            // failover A's new introduction circuits may still be settling, so a single rendezvous timeout is not a
            // defect: retry up to 3 times within 180 s, fetching a fresh descriptor for every attempt.
            val deadline = System.nanoTime() + Duration.ofSeconds(180).toNanos()
            var stream: OnionRendezvousStream? = null
            var lastFailure: Throwable? = null
            var attempt = 0
            while (stream == null && attempt < 3 && System.nanoTime() < deadline) {
                attempt++
                val descriptor =
                    awaitedDescriptor { b.wire.serviceDescriptors.current(serviceKeyA.publicKey, now()) }
                try {
                    stream =
                        runtimeB
                            .connectToService(descriptor, OnionServiceApp.DM, 45.seconds)
                            .get(60, TimeUnit.SECONDS)
                } catch (e: Exception) {
                    lastFailure = e
                    println("TIMELINE guard-failover: connect attempt $attempt failed: $e")
                    runtimeA.maintainNow()
                    runtimeB.maintainNow()
                    Thread.sleep(3000)
                }
            }
            if (stream == null) throw AssertionError("B could not connect to A after $attempt attempts", lastFailure)
            val got = ConcurrentLinkedQueue<ByteArray>()
            stream.onReceive { got += it }
            val sent = List(10) { i -> ByteArray(1 + i * 53) { (it + i).toByte() } }
            sent.forEach { stream.send(it) shouldBe true }
            awaitTrue(Duration.ofSeconds(60)) { got.size == 10 } shouldBe true
            got.toList().zip(sent).all { (x, y) -> x.contentEquals(y) } shouldBe true
            stream.close()
        }

        test("stopping leaves no circuits behind") {
            runtimeB.close()
            runtimeA.close()
            val alive = relays.filter { it.key != primary }
            awaitTrue(Duration.ofSeconds(60)) { alive.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe true
            runtimeA.status().activeCircuits shouldBe 0
            runtimeB.status().activeCircuits shouldBe 0
        }
    })

private fun awaitedDescriptor(
    supplier: () -> net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor?,
): net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor {
    awaitTrue(Duration.ofSeconds(120)) { supplier() != null } shouldBe true
    return supplier().shouldNotBeNull()
}
