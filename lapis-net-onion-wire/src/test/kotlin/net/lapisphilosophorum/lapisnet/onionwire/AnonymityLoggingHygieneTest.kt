@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_INCOMPLETE_WARNING
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.PeerDirectoryRelayNetworkLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.time.Clock

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

/**
 * Runs anonymity mode at DEBUG level in two situations (a working node with injected networks, a node that finds no
 * diverse path plus a damaged guard file) and checks that no line of the onion layers contains an address, a peer id, a
 * key or a long hex string. The incomplete-anonymity warning must be present, exactly once per start.
 */
class AnonymityLoggingHygieneTest :
    FunSpec({
        test("anonymity mode logs counters and coarse reasons only, and warns about its limits") {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            val nodes = ArrayList<WireTestNode>()
            try {
                val relays = List(5) { WireTestNode(relay = true).also { nodes += it } }
                val a = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { nodes += it }
                val c = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { nodes += it }
                for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
                relays.forEach {
                    a.connectTo(it)
                    c.connectTo(it)
                }
                awaitTrue(java.time.Duration.ofSeconds(90)) {
                    relays.all { r ->
                        a.wire.descriptors.current(r.key, System.currentTimeMillis() / 1000) != null &&
                            c.wire.descriptors.current(r.key, System.currentTimeMillis() / 1000) != null
                    }
                } shouldBe true
                val locator = MapLocator()
                relays.forEachIndexed { i, r -> locator.put(r.wire.currentDescriptor()!!, v4(30 + i, i)) }

                fun go(
                    n: WireTestNode,
                    l: net.lapisphilosophorum.lapisnet.onionwire.path.RelayNetworkLocator,
                ) = AnonymityRuntime.start(
                    n.wire,
                    n.identity,
                    n.dir,
                    { null },
                    l,
                    InMemoryDirectoryModeStore(),
                    PrekeyStore.create(Files.createTempDirectory("hygiene").resolve("p"), n.identity),
                    Ed25519KeyPair.generate(),
                    { },
                    n.supervisor,
                    governor = CircuitBuildGovernor(Clock.systemUTC(), ratePerMinute = 600, burst = 100),
                )
                // c: a damaged guard file and the real locator (loopback = unknown networks, no diverse path)
                Files.createDirectories(c.dir.resolve("onion"))
                Files.write(c.dir.resolve("onion").resolve("guards.bin"), ByteArray(64) { 7 })
                val rc = go(c, PeerDirectoryRelayNetworkLocator(c.peerDirectory))
                rc.maintenanceTick()
                rc.status().lastError.wire shouldBe "guard-state-reset"
                rc.close()
                // a: works
                val ra = go(a, locator)
                awaitTrue(java.time.Duration.ofSeconds(120)) {
                    ra.maintenanceTick()
                    ra.publications() >= 1
                } shouldBe true
                // wave F1: the mailbox publisher and the mailbox role at the relay run under the same scanner
                (
                    ra
                        .publishMailboxItems(listOf(ByteArray(5_728) { (it * 7).toByte() }))
                        .get(120, java.util.concurrent.TimeUnit.SECONDS)
                ) shouldBe true
                ra.close()

                val forbidden = ArrayList<String>()
                for (n in nodes) {
                    forbidden += n.peerId.toBase58()
                    forbidden += hex(n.identity.secp256k1KeyPair.publicKey.bytes)
                    forbidden += hex(n.identity.ed25519KeyPair.publicKey.bytes)
                    forbidden +=
                        n.identity.secp256k1KeyPair.publicKey
                            .fingerprint()
                }
                val patterns = listOf("/ip4", "/ip6", "/tcp", "127.0.0.1", "localhost", "/p2p/", "12D3Koo", "Qm")
                val hexRun = Regex("[0-9a-fA-F]{32,}")
                val own = appender.list.filter { it.loggerName.contains("lapisnet.onion", ignoreCase = true) }
                (own.size > 0) shouldBe true
                for (event in own) {
                    val text = event.formattedMessage + " " + (event.throwableProxy?.message ?: "")
                    for (f in forbidden) (text.contains(f)) shouldBe false
                    for (p in patterns) (text.contains(p)) shouldBe false
                    (hexRun.containsMatchIn(text)) shouldBe false
                }
                // the warning: once per start (two starts), and the guard reset warning
                appender.list.count {
                    it.formattedMessage == ANONYMITY_INCOMPLETE_WARNING && it.level == Level.WARN
                } shouldBe
                    2
                appender.list.count { it.formattedMessage == "guard state invalid, reselected guards" } shouldBe 1
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
                nodes.forEach { it.close() }
            }
        }
    })
