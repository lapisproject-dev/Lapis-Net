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
 * failure is only counted), the node never falls back to announcing from its own address, and after the first
 * first-hop failure the dead primary is marked unreachable (in memory) so that the backup serves as first hop while
 * P's descriptor is still valid. The 72-hour and 24-hour rotation rules are covered by
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
        val guardFileB = b.dir.resolve("onion").resolve("guards.bin")
        var outageStartNanos = 0L
        var introBuiltAtOutage = 0L

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

        fun guardsOfB(): GuardState? =
            runCatching {
                EncryptedFileGuardStateStore(guardFileB, b.identity).use { (it.load() as? GuardLoad.Loaded)?.state }
            }.getOrNull()

        // Diagnostic timeline (counts and booleans only, no keys): how the outage unfolds on both nodes.
        fun timeline(label: String) {
            val sinceOutage = if (outageStartNanos == 0L) -1 else (System.nanoTime() - outageStartNanos) / 1_000_000_000
            val gb = guardsOfB()
            val pDescriptorAtA = a.wire.descriptors.current(primary, now()) != null
            println(
                "TIMELINE guard-failover [$label] t+${sinceOutage}s pDescriptorAtA=$pDescriptorAtA " +
                    "bPrimaryIsP=${gb?.primary?.identity == primary} bBackupIsP=${gb?.backup?.identity == primary} " +
                    "bBackupIsK=${gb?.backup?.identity == backup} " +
                    "A.lastError=${runtimeA.status().lastError.wire} B.lastError=${runtimeB.status().lastError.wire}",
            )
            println("TIMELINE guard-failover [$label] A.diagnostics=${runtimeA.diagnostics()}")
            println("TIMELINE guard-failover [$label] B.diagnostics=${runtimeB.diagnostics()}")
        }
        var sequenceBefore = 0L

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
        ).config(timeout = 300.seconds) {
            val p = relays.first { it.key == primary }
            val gossipBefore = scannerA.gossip.size
            introBuiltAtOutage =
                Regex("""intro\[[^\]]*built=(\d+)""")
                    .find(runtimeA.diagnostics().hostBuilds)!!
                    .groupValues[1]
                    .toLong()
            p.close()
            outageStartNanos = System.nanoTime()
            // Reference point AFTER the outage began.
            val ref =
                b.wire.serviceDescriptors
                    .current(serviceKeyA.publicKey, now())
                    .shouldNotBeNull()
            sequenceBefore = ref.sequenceNumber
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
            timeline("end of test 2")
            // INSUFFICIENT_RELAYS: an introduction slot that points at K is a path conflict once K is the first hop
            setOf(
                AnonymityErrorCode.NONE,
                AnonymityErrorCode.INSUFFICIENT_RELAYS,
                AnonymityErrorCode.BUILD_FAILED,
                AnonymityErrorCode.BUILD_TIMEOUT,
                AnonymityErrorCode.PUBLISH_FAILED,
            ).contains(runtimeA.status().lastError) shouldBe true

            // P is marked unreachable after its first failure: the backup K carries A's builds BEFORE P's descriptor
            // expired (before the fix: only once that descriptor had left A's index). Every first hop is P or K and P is
            // dead, so a newly built introduction circuit went over K. The republication of the service descriptor can
            // still take longer: an introduction slot that points at K is now a path conflict and is replaced only after
            // the host's slot backoff (pre-existing deterministic replacement, see docs/anonymity.adoc).
            fun introBuilt(): Long =
                Regex("""intro\[[^\]]*built=(\d+)""")
                    .find(runtimeA.diagnostics().hostBuilds)!!
                    .groupValues[1]
                    .toLong()
            val builtBefore = introBuiltAtOutage
            var pDescriptorStillKnown = false
            awaitTrue(Duration.ofSeconds(60)) {
                Thread.sleep(1000) // not a busy loop: it would drain the circuit build governor
                runtimeA.maintainNow()
                val known = a.wire.descriptors.current(primary, now()) != null
                val built = introBuilt() > builtBefore
                if (built) pDescriptorStillKnown = known
                built
            } shouldBe true
            timeline("first introduction circuit over the backup")
            pDescriptorStillKnown shouldBe true
            guardsOfA().primary.shouldNotBeNull().identity shouldBe primary
        }

        test(
            "after the failover to the backup K (P still dead, its descriptor expired): B connects to A over circuits",
        ).config(timeout = 500.seconds) {
            // A's service rebuilt its introduction circuits over K to the SAME introduction relays (they are alive; only
            // the first hop changed), so the introduction points of B's descriptor stay valid and need no republication.
            // Before the fix the rebuild came only after P's descriptor expired and then also replaced introduction
            // points; that is no longer required here. B must see a descriptor at least as new as at the outage.
            // While P's relay descriptor is still listed, P is a candidate middle hop and rendezvous point for EVERY node
            // (a dead relay stays in the directory until its descriptor expires; a general property, not the guard logic
            // tested here), so a circuit may still fail through it. The connection is therefore made once P's
            // descriptor has left both indexes, as before the fix.
            awaitTrue(Duration.ofSeconds(180)) {
                Thread.sleep(1000) // not a busy loop: it would drain the circuit build governor
                runtimeA.maintainNow()
                runtimeB.maintainNow()
                val d = b.wire.serviceDescriptors.current(serviceKeyA.publicKey, now())
                d != null &&
                    d.sequenceNumber >= sequenceBefore &&
                    a.wire.descriptors.current(primary, now()) == null &&
                    b.wire.descriptors.current(primary, now()) == null
            } shouldBe true
            // the only onion link of A leads to K; the persisted primary is still P (replacement comes after 72 hours)
            awaitTrue(Duration.ofSeconds(30)) { a.wire.linkCount() == 1 } shouldBe true
            guardsOfA().primary.shouldNotBeNull().identity shouldBe primary

            // B resolves the re-published descriptor of A and talks to it over circuits: ONE call. If B's rendezvous
            // point happens to be A's effective guard K, A can not build to it (no other usable guard: P is dead) and
            // drops the rendezvous; connectToService then retries once with another rendezvous point (RendezvousRetry).
            // Budget: 2 x 45 s per attempt + at most 6 s jitter + margin.
            val descriptor = awaitedDescriptor { b.wire.serviceDescriptors.current(serviceKeyA.publicKey, now()) }
            val stream =
                try {
                    runtimeB
                        .connectToService(descriptor, OnionServiceApp.DM, 45.seconds)
                        .get(120, TimeUnit.SECONDS)
                } catch (e: Exception) {
                    timeline("connect failed: $e")
                    throw e
                }
            timeline("connected, rendezvousRetries=${runtimeB.diagnostics().rendezvousRetries}")
            val got = ConcurrentLinkedQueue<ByteArray>()
            stream.onReceive { got += it }
            val sent = List(10) { i -> ByteArray(1 + i * 53) { (it + i).toByte() } }
            sent.forEach { stream.send(it) shouldBe true }
            awaitTrue(Duration.ofSeconds(60)) { got.size == 10 } shouldBe true
            got.toList().zip(sent).all { (x, y) -> x.contentEquals(y) } shouldBe true
            stream.close()
        }

        test(
            "B's rendezvous point equals A's effective guard K: A can not build to it, B retries once and connects",
        ).config(timeout = 300.seconds) {
            // once P's descriptor left A's index, K is A's only usable guard: a rendezvous circuit to K is impossible
            awaitTrue(Duration.ofSeconds(150)) {
                Thread.sleep(1000)
                a.wire.descriptors.current(primary, now()) == null
            } shouldBe true

            fun rendezvousGuardConflicts(): Long =
                Regex("""rendezvous\[[^\]]*guardConflict=(\d+)""")
                    .find(runtimeA.diagnostics().hostBuilds)!!
                    .groupValues[1]
                    .toLong()
            val conflictsBefore = rendezvousGuardConflicts()
            val retriesBefore = runtimeB.diagnostics().rendezvousRetries
            val k =
                b.wire.descriptors
                    .current(backup, now())
                    .shouldNotBeNull()
            val descriptor = awaitedDescriptor { b.wire.serviceDescriptors.current(serviceKeyA.publicKey, now()) }
            val stream =
                try {
                    runtimeB
                        .connectToServiceVia(descriptor, OnionServiceApp.DM, 45.seconds, k)
                        .get(120, TimeUnit.SECONDS)
                } catch (e: Exception) {
                    timeline("forced rendezvous point K failed: $e")
                    throw e
                }
            timeline("forced rendezvous point K connected")
            // If K is also B's own effective guard, B can not even build its rendezvous circuit to K (a locally chosen
            // last hop equal to the guard is a path conflict): the first attempt then fails at B with RENDEZVOUS_POINT
            // before A is involved. The retry covers both cases; A's guard conflict is only asserted in the first.
            val gb = guardsOfB()
            val bEffectiveGuard = if (gb?.primary?.identity == primary) gb.backup?.identity else gb?.primary?.identity
            if (bEffectiveGuard != backup) (rendezvousGuardConflicts() > conflictsBefore) shouldBe true
            runtimeB.diagnostics().rendezvousRetries shouldBe retriesBefore + 1
            val got = ConcurrentLinkedQueue<ByteArray>()
            stream.onReceive { got += it }
            stream.send(byteArrayOf(1, 2, 3)) shouldBe true
            awaitTrue(Duration.ofSeconds(60)) { got.size == 1 } shouldBe true
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
