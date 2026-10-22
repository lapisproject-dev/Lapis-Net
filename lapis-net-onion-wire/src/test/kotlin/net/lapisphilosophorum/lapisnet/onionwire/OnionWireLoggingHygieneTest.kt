package net.lapisphilosophorum.lapisnet.onionwire

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionConstants
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import org.slf4j.LoggerFactory
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

/**
 * Runs a full scenario (gossip, circuit with echo, hostile cells, failed extend, rotation) at DEBUG level and asserts that no
 * line logged by the onion layer contains a peer id, an address, a key or fingerprint, a digest or a cell body.
 */
@OptIn(ExperimentalOnionApi::class)
class OnionWireLoggingHygieneTest :
    FunSpec({
        test("the onion layer logs counters and coarse reasons only") {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            val nodes = ArrayList<WireTestNode>()
            try {
                val c = WireTestNode(relay = false).also { nodes += it }
                val r1 = WireTestNode(relay = true).also { nodes += it }
                val r2 = WireTestNode(relay = true).also { nodes += it }
                val stranger = WireTestNode(relay = true).also { nodes += it }
                c.connectTo(r1)
                c.connectTo(r2)
                r1.connectTo(r2)
                awaitTrue(java.time.Duration.ofSeconds(60)) {
                    r1.wire.descriptors.current(r2.key, System.currentTimeMillis() / 1000) != null
                } shouldBe true
                r2.wire.relayService!!.localDeliveryHandler =
                    { _, m -> RelayMessage(RelayCommand.DATA, m.streamId, m.data) }
                val client = c.wire.diagnosticClient()
                val d1 = r1.wire.currentDescriptor()!!
                val d2 = r2.wire.currentDescriptor()!!
                val circuit = client.build(listOf(d1, d2), 20.seconds).get(30, TimeUnit.SECONDS)
                circuit.send(ByteArray(40) { 3 }).get(15, TimeUnit.SECONDS)
                circuit.close()
                // failed extend, hostile cells on a raw link, rotation
                runCatching {
                    client
                        .build(
                            listOf(d1, stranger.wire.currentDescriptor()!!),
                            20.seconds,
                        ).get(25, TimeUnit.SECONDS)
                }.exceptionOrNull() is ExecutionException
                val attacker = WireTestNode(relay = false).also { nodes += it }
                val link =
                    attacker.wire
                        .linksForTest()
                        .linkTo(
                            r1.peerId,
                            r1.node.listenAddresses(),
                        ).get(15, TimeUnit.SECONDS)
                attacker.wire.linksForTest().writeRawForTest(
                    link,
                    ByteArray(OnionConstants.CELL_SIZE).also { it[4] = 77 },
                )
                attacker.wire.linksForTest().writeRawForTest(link, ByteArray(300))
                r1.wire.relayService!!.rotateNow()
                Thread.sleep(2500) // a republish round
                client.close()

                val forbidden = ArrayList<String>()
                for (n in nodes) {
                    forbidden += n.peerId.toBase58()
                    forbidden += n.peerId.toString()
                    forbidden +=
                        n.identity.secp256k1KeyPair.publicKey
                            .fingerprint()
                    forbidden += hex(n.identity.secp256k1KeyPair.publicKey.bytes)
                    forbidden += hex(n.identity.ed25519KeyPair.publicKey.bytes)
                }
                for (d in listOf(d1, d2, r1.wire.currentDescriptor()!!)) {
                    forbidden += hex(d.onionKeyBinding.onionKey.bytes)
                    forbidden += hex(d.onionKeyBinding.onionKeyFingerprint())
                    forbidden += hex(d.relayIdDigest())
                    forbidden += d.onionKeyBinding.onionKey.fingerprint()
                }
                val patterns = listOf("/ip4", "/ip6", "/tcp", "127.0.0.1", "localhost", "/p2p/")
                val hexRun = Regex("[0-9a-fA-F]{16,}")
                val own =
                    appender.list.filter {
                        it.loggerName.contains("lapisnet.onion", ignoreCase = true) ||
                            it.loggerName.contains("OnionRelayDescriptor") ||
                            it.loggerName.contains("OnionKey")
                    }
                (own.size > 0) shouldBe true
                for (event in own) {
                    val text = event.formattedMessage + " " + (event.throwableProxy?.message ?: "")
                    for (f in forbidden) (text.contains(f)) shouldBe false
                    for (p in patterns) (text.contains(p)) shouldBe false
                    (hexRun.containsMatchIn(text)) shouldBe false
                }
                // not vacuous: the scenario really produced the interesting log lines
                (
                    own.any {
                        it.formattedMessage.contains("malformed cell") ||
                            it.formattedMessage.contains("incomplete cell")
                    }
                ) shouldBe
                    true
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
                nodes.forEach { it.close() }
            }
        }
    })
