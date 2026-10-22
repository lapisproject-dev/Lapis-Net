package net.lapisphilosophorum.lapisnet.onion

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.HsFlow
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import org.bouncycastle.util.encoders.Base32
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

class HiddenServiceHygieneTest :
    FunSpec({
        test("the whole hidden-service flow, failures included, logs no address, key, cookie or message body").config(
            timeout = 60.seconds,
        ) {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            val secrets = mutableListOf<ByteArray>()
            val textSecrets = mutableListOf<String>()
            try {
                val clock = FixedClock()
                val rnd = SecureRandom()
                val relays =
                    List(
                        7,
                    ) { newTestRelay(clock = clock, limits = OnionRelayLimits(introduce1PerSecondPerIntroPoint = 1)) }
                val net = InMemoryOnionNetwork(relays)
                val flow = HsFlow(net, clock, rnd)
                val serviceKey = Ed25519KeyPair.generate()
                val service =
                    OnionServiceStateMachine(serviceKey, OnionServiceConfig(), clock, rnd) { d, fp ->
                        relays
                            .firstOrNull {
                                it.binding.relayIdDigest().contentEquals(d) &&
                                    it.binding.onionKeyFingerprint().contentEquals(fp)
                            }?.binding
                    }
                flow.service = service
                flow.wire()
                flow.runService(service.start(relays.take(3).map { it.binding }))
                flow.settle()
                flow.tick()
                val d = flow.published.last()
                secrets += serviceKey.publicKey.bytes
                secrets += serviceKey.privateKey.seed
                secrets += (0..2).map { service.slotAuthKey(it)!!.publicKey.bytes }
                secrets += service.currentEncKeyPair().privateKey.bytes
                textSecrets += d.address().encode()

                // a successful session
                val ok =
                    RendezvousClientStateMachine(
                        d.address(),
                        d,
                        relays[4].binding,
                        RendezvousClientConfig(),
                        clock,
                        rnd,
                    )
                flow.client = ok
                flow.runClient(ok.start())
                flow.settle()
                ok.state shouldBe RendezvousClientState.OPEN

                // a rate-limited second and third introduction (failure paths at the relays), a wrong cookie, garbage INTRODUCE2
                flow.clientEp.deadRelays.clear()
                repeat(2) {
                    val m =
                        RendezvousClientStateMachine(
                            d.address(),
                            d,
                            relays[5].binding,
                            RendezvousClientConfig(),
                            clock,
                            rnd,
                        )
                    flow.client = m
                    flow.runClient(m.start())
                    flow.settle()
                }
                flow.clientEp.deadRelays += listOf(0, 1, 2)
                val failing =
                    RendezvousClientStateMachine(
                        d.address(),
                        d,
                        relays[5].binding,
                        RendezvousClientConfig(),
                        clock,
                        rnd,
                    )
                flow.client = failing
                flow.runClient(failing.start())
                flow.settle()
                failing.state shouldBe RendezvousClientState.FAILED
                flow.runService(
                    service.on(
                        HsEvent.RelayReceived(
                            service.slotRef(0)!!,
                            RelayMessage(
                                RelayCommand.INTRODUCE2,
                                0,
                                ByteArray(HsConstants.INTRODUCE_SIZE).also {
                                    it[0] =
                                        1
                                },
                            ),
                        ),
                    ),
                )
                val probe = net.newClient(0)
                val circuit = net.buildCircuitFor(probe, listOf(0), rnd, clock)
                net.clientSend(
                    0,
                    probe.link,
                    Cell(
                        probe.circuitId,
                        CellCommand.RELAY,
                        circuit.wrapForward(
                            RelayMessage(RelayCommand.RENDEZVOUS1, 0, ByteArray(HsConstants.RENDEZVOUS1_SIZE)),
                        ),
                    ),
                )
                flow.settle()
                secrets += flow.sent
                flow.runService(service.stop())
                flow.settle()
            } finally {
                root.detachAppender(appender)
                root.level = oldLevel
            }
            appender.list.shouldNotBeEmpty()
            val texts =
                appender.list.map { e ->
                    e.formattedMessage + (e.throwableProxy?.message ?: "") + (e.argumentArray?.joinToString(",") ?: "")
                }
            val b64 = java.util.Base64.getEncoder()
            for (t in texts) {
                for (s in textSecrets) t.lowercase().contains(s) shouldBe false
            }
            for (secret in secrets.filter { it.size >= 16 }) {
                val h = hex(secret)
                val s = b64.encodeToString(secret)
                val b32 = Base32.toBase32String(secret).lowercase()
                for (t in texts) {
                    t.lowercase().contains(h) shouldBe false
                    t.contains(s) shouldBe false
                    t.lowercase().contains(b32) shouldBe false
                }
            }
        }

        test(
            "concurrent traffic and teardown on a splice never deadlocks and leaks nothing",
        ).config(timeout = 180.seconds) {
            val clock = FixedClock()
            val big = 1_000_000_000
            val r =
                newTestRelay(
                    clock,
                    limits =
                        OnionRelayLimits(
                            cellsPerSecondPerCircuit = big,
                            createsPerSecondPerLink = big,
                            createsPerSecondTotal = big,
                        ),
                )
            val pool = Executors.newFixedThreadPool(3)
            val rnd = SecureRandom()
            try {
                repeat(500) { iter ->
                    val la = LinkId(2L * iter + 1)
                    val lb = LinkId(2L * iter + 2)

                    fun open(link: LinkId): Pair<ClientCircuit, Int> {
                        val b = ClientCircuitBuilder(listOf(r.binding), clock = clock)
                        val created = (r.relay.onCell(link, b.start()).single() as RelayAction.SendCell).cell
                        return (b.onCell(created) as BuilderStep.Built).circuit to b.firstLinkCircuitId
                    }
                    val (ca, ida) = open(la)
                    val (cb, idb) = open(lb)
                    val cookie = ByteArray(20).also { rnd.nextBytes(it) }
                    r.relay.onCell(
                        la,
                        Cell(
                            ida,
                            CellCommand.RELAY,
                            ca.wrapForward(RelayMessage(RelayCommand.ESTABLISH_RENDEZVOUS, 0, cookie)),
                        ),
                    )
                    r.relay.onCell(
                        lb,
                        Cell(
                            idb,
                            CellCommand.RELAY,
                            cb.wrapForward(
                                RelayMessage(
                                    RelayCommand.RENDEZVOUS1,
                                    0,
                                    cookie + ByteArray(64) { 1 },
                                ),
                            ),
                        ),
                    )
                    val blob = ByteArray(HsConstants.E2E_BLOB_SIZE) { it.toByte() }

                    fun cells(
                        c: ClientCircuit,
                        id: Int,
                    ) = List(
                        20,
                    ) {
                        Cell(
                            id,
                            CellCommand.RELAY,
                            c.wrapForward(RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, blob)),
                        )
                    }
                    val aCells = cells(ca, ida)
                    val bCells = cells(cb, idb)
                    val destroy = { l: LinkId, id: Int ->
                        r.relay.onCell(l, Cell(id, CellCommand.DESTROY, DestroyBody.encode(DestroyReason.FINISHED)))
                    }
                    val f1 = pool.submit { aCells.forEach { r.relay.onCell(la, it) } }
                    val f2 = pool.submit { bCells.forEach { r.relay.onCell(lb, it) } }
                    val f3 =
                        pool.submit {
                            Thread.sleep(0, rnd.nextInt(200_000))
                            if (rnd.nextBoolean()) {
                                destroy(la, ida)
                                destroy(lb, idb)
                            } else {
                                destroy(lb, idb)
                                destroy(la, ida)
                            }
                        }
                    listOf(f1, f2, f3).forEach { it.get(20, TimeUnit.SECONDS) }
                    destroy(la, ida)
                    destroy(lb, idb)
                    r.relay.circuitCount shouldBe 0
                    r.relay.splicedPairCount shouldBe 0
                    r.relay.pendingRendezvousCount shouldBe 0
                }
            } finally {
                pool.shutdownNow()
            }
        }
    })
