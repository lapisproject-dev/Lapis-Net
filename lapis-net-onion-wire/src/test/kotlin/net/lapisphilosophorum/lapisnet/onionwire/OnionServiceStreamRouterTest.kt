package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceConfig
import java.time.Clock
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalOnionApi::class)
class OnionServiceStreamRouterTest :
    FunSpec({
        test("the HELLO frame round-trips and rejects anything else") {
            OnionServiceHello.decode(OnionServiceHello.encode(OnionServiceApp.DM)) shouldBe OnionServiceApp.DM
            OnionServiceHello.decode(ByteArray(6)) shouldBe null
            OnionServiceHello.decode(ByteArray(0)) shouldBe null
            OnionServiceHello.decode(OnionServiceHello.encode(OnionServiceApp.DM) + 0) shouldBe null
            OnionServiceHello.decode(OnionServiceHello.encode(OnionServiceApp.DM).also { it[5] = 9 }) shouldBe null
            OnionServiceHello.decode(OnionServiceHello.encode(OnionServiceApp.DM).also { it[4] = 2 }) shouldBe null
        }

        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }

        fun now() = Clock.systemUTC().millis() / 1000

        val relays = List(7) { WireTestNode(relay = true).also { all += it } }
        val receiver = WireTestNode(relay = false).also { all += it }
        val sender = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach {
            receiver.connectTo(it)
            sender.connectTo(it)
        }
        lateinit var descriptors: List<OnionRelayDescriptor>
        var rotate = 0
        val provider =
            OnionPathProvider { last, _: CircuitPurpose ->
                val lastIdx = descriptors.indexOfFirst { it.identity == last.identity }
                val others = descriptors.indices.filter { it != lastIdx }
                val a = others[(rotate++) % others.size]
                val b = others.first { it != a }
                listOf(descriptors[a], descriptors[b], last)
            }

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                (relays + receiver + sender).all { n ->
                    descriptors.all { d -> n.wire.descriptors.current(d.identity, now()) != null }
                }
            } shouldBe true
        }

        test("a stream is routed by its HELLO, the HELLO is consumed, silence and unknown applications are closed")
            .config(timeout = 240.seconds) {
                val serviceKey = Ed25519KeyPair.generate()
                val host = receiver.wire.experimentalServiceHost(serviceKey, OnionServiceConfig(), provider)
                val router = OnionServiceStreamRouter(helloTimeoutMillis = 2_000)
                host.onConnection = router::route
                val seen = ConcurrentLinkedQueue<ByteArray>()
                val handled = ConcurrentLinkedQueue<OnionRendezvousStream>()
                router.register(OnionServiceApp.DM) { s ->
                    handled += s
                    s.onReceive { seen += it }
                }
                host.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
                awaitTrue(java.time.Duration.ofSeconds(90)) {
                    sender.wire.serviceDescriptors.current(serviceKey.publicKey, now()) != null
                } shouldBe true
                val client = sender.wire.experimentalRendezvousClient()
                try {
                    // 1. HELLO(DM) then a payload: the application sees only the payload
                    val ok = client.connect(host.address, provider, descriptors[4]).get(60, TimeUnit.SECONDS)
                    ok.send(OnionServiceHello.encode(OnionServiceApp.DM)) shouldBe true
                    ok.send(byteArrayOf(1, 2, 3)) shouldBe true
                    awaitTrue(java.time.Duration.ofSeconds(30)) { seen.size == 1 } shouldBe true
                    seen.single().toList() shouldBe listOf<Byte>(1, 2, 3)
                    handled.size shouldBe 1

                    // 2. no HELLO at all: the service closes the stream after the timeout
                    val silent = client.connect(host.address, provider, descriptors[5]).get(60, TimeUnit.SECONDS)
                    awaitTrue(java.time.Duration.ofSeconds(30)) { silent.isClosed } shouldBe true

                    // 3. an unknown application id: closed, never handed to a handler
                    val unknown = client.connect(host.address, provider, descriptors[6]).get(60, TimeUnit.SECONDS)
                    unknown.send(OnionServiceHello.encode(OnionServiceApp.DM).also { it[5] = 9 }) shouldBe true
                    awaitTrue(java.time.Duration.ofSeconds(30)) { unknown.isClosed } shouldBe true
                    handled.size shouldBe 1
                    ok.isClosed shouldBe false
                } finally {
                    client.close()
                    router.close()
                    host.close()
                }
            }
    })
