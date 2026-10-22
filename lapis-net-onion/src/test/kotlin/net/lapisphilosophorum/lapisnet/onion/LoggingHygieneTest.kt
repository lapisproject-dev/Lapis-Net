package net.lapisphilosophorum.lapisnet.onion

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import org.slf4j.LoggerFactory

/** Exercises the failure paths at DEBUG level and asserts that no log line (message or exception
 * text) contains the hex or base64 form of any key, ephemeral, AUTH value or cell body. */
class LoggingHygieneTest :
    FunSpec({
        test("failure paths log no key material") {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            val secrets = mutableListOf<ByteArray>()
            try {
                val r = newTestRelay()
                secrets += r.onion.privateKey.bytes
                secrets += r.onion.publicKey.bytes
                secrets += r.identity.privateKey.bytes

                // 1. wrong AUTH
                val (s1, c1) = NtorHandshake.clientStart(r.binding, 1)
                secrets += s1.x.bytes
                secrets += c1.clientEphemeral.bytes
                val srv = NtorHandshake.serverRespond(c1, r.onion.privateKey, r.binding)
                secrets += srv.keys.forwardRaw
                secrets += srv.keys.backwardRaw
                secrets += srv.created.auth
                secrets += srv.created.serverEphemeral.bytes
                shouldThrow<OnionHandshakeException> {
                    NtorHandshake.clientFinish(s1, CreatedBody(srv.created.serverEphemeral, ByteArray(32)))
                }
                // 2. CREATE for the wrong relay
                val other = newTestRelay()
                shouldThrow<OnionHandshakeException> {
                    NtorHandshake.serverRespond(
                        NtorHandshake.clientStart(other.binding, 1).second,
                        r.onion.privateKey,
                        r.binding,
                    )
                }
                // 3. tamper on a live circuit and 4. rate limits
                val clock = FixedClock()
                val net =
                    InMemoryOnionNetwork(
                        List(3) { newTestRelay(clock, limits = OnionRelayLimits(createsPerSecondPerLink = 2)) },
                    )
                val built = net.buildCircuit(listOf(0, 1, 2), clock = clock)
                net.relays.forEach { secrets += it.onion.privateKey.bytes }
                net.filter = { t ->
                    val b = t.cell.body
                    b[10] = (b[10].toInt() xor 1).toByte()
                    if (t.cell.command ==
                        CellCommand.RELAY
                    ) {
                        listOf(Cell(t.cell.circuitId, t.cell.command, b))
                    } else {
                        listOf(t.cell)
                    }
                }
                net.clientSend(
                    0,
                    built.link,
                    Cell(
                        built.circuitId,
                        CellCommand.RELAY,
                        built.circuit.wrapForward(RelayMessage(RelayCommand.DATA, 0, ByteArray(5))),
                    ),
                )
                repeat(6) {
                    net.relays[0].relay.onCell(
                        LinkId(99),
                        ClientCircuitBuilder(listOf(net.relays[0].binding), clock = clock).start(),
                    )
                }
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
            }
            appender.list.shouldNotBeEmpty() // the test is not vacuous
            val texts =
                appender.list.map { e ->
                    e.formattedMessage + (e.throwableProxy?.message ?: "") +
                        (e.argumentArray?.joinToString(",") ?: "")
                }
            val b64 = java.util.Base64.getEncoder()
            for (secret in secrets) {
                val h = hex(secret)
                val s = b64.encodeToString(secret)
                for (t in texts) {
                    (t.lowercase().contains(h)) shouldBe false
                    t.contains(s) shouldBe false
                }
            }
        }
    })
