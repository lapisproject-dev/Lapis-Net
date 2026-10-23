@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.PeerDirectoryRelayNetworkLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class AnonymityRuntimeLifecycleTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun start(
            n: WireTestNode,
            locator: net.lapisphilosophorum.lapisnet.onionwire.path.RelayNetworkLocator,
            governor: CircuitBuildGovernor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
        ): AnonymityRuntime =
            AnonymityRuntime.start(
                n.wire,
                n.identity,
                n.dir,
                { null },
                locator,
                InMemoryDirectoryModeStore(),
                PrekeyStore.create(Files.createTempDirectory("prekeys-lifecycle").resolve("p"), n.identity),
                Ed25519KeyPair.generate(),
                { },
                n.supervisor,
                governor = governor,
            )

        test("start, stop, start again on the same data directory leaves no circuit, host or job behind") {
            val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
            repeat(3) {
                val r = start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory))
                r.status().mode shouldBe "on"
                r.close()
                a.wire.hiddenCount() shouldBe 0
                a.wire.hiddenServiceRoutes() shouldBe 0
                r.status().activeCircuits shouldBe 0
            }
        }

        test("close is idempotent and a second start for a running data directory is refused") {
            val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
            val r = start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory))
            shouldThrow<IllegalStateException> { start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory)) }
            r.close()
            r.close()
            // after the stop the directory can be started again
            start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory)).close()
        }

        test("a runtime needs a wire in anonymity mode") {
            val n = WireTestNode(relay = false).also { all += it }
            shouldThrow<IllegalArgumentException> { start(n, PeerDirectoryRelayNetworkLocator(n.peerDirectory)) }
        }

        test("a start that races a stop waits for it, and the results are consistent") {
            val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
            val pool = Executors.newFixedThreadPool(2)
            try {
                repeat(5) {
                    val r = start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory))
                    val go = CountDownLatch(1)
                    val stop =
                        pool.submit {
                            go.await()
                            r.close()
                        }
                    val next =
                        pool.submit<AnonymityRuntime?> {
                            go.await()
                            // either the stop has not begun yet (refused) or it is running / done (waits, then starts)
                            runCatching { start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory)) }.getOrNull()
                        }
                    go.countDown()
                    stop.get(30, TimeUnit.SECONDS)
                    next.get(60, TimeUnit.SECONDS)?.close()
                    start(a, PeerDirectoryRelayNetworkLocator(a.peerDirectory)).close()
                }
            } finally {
                pool.shutdownNow()
            }
        }

        test("a stop while circuits are being built tears everything down") {
            val relays = List(5) { WireTestNode(relay = true).also { all += it } }
            val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
            for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
            relays.forEach { a.connectTo(it) }
            val locator = MapLocator()
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                relays.all { r -> a.wire.descriptors.current(r.key, System.currentTimeMillis() / 1000) != null }
            } shouldBe true
            relays.forEachIndexed { i, r -> locator.put(r.wire.currentDescriptor()!!, v4(20 + i, i)) }
            val r = start(a, locator)
            r.maintenanceTick() // host start, builds begin
            r.close()
            awaitTrue(
                java.time.Duration.ofSeconds(30),
            ) { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe
                true
            awaitTrue(java.time.Duration.ofSeconds(30)) { a.wire.hiddenServiceRoutes() == 0 } shouldBe true
        }
    })
