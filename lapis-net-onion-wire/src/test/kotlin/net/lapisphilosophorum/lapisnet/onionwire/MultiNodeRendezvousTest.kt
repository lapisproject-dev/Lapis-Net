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

/**
 * Nine REAL nodes on loopback: seven relays in a full mesh, one service node and one client node (neither is a relay).
 * Everything travels over real `/lapis/onion/1.0.0` links, real gossip and real circuits: the service establishes three
 * introduction points, publishes its descriptor through gossip, a client finds it in its local index, rendezvouses at
 * a relay of its own choice and exchanges end-to-end encrypted messages in both directions.
 */
@OptIn(ExperimentalOnionApi::class)
class MultiNodeRendezvousTest :
    FunSpec({
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
        receiver.connectTo(sender)

        val dead = HashSet<Int>()
        val paths = ConcurrentLinkedQueue<List<OnionRelayDescriptor>>()
        var rotate = 0
        lateinit var descriptors: List<OnionRelayDescriptor>

        // Fixed three-relay paths ending at the requested relay; the other two are alive relays in rotating order.
        val provider =
            OnionPathProvider { last, _: CircuitPurpose ->
                val lastIdx = descriptors.indexOfFirst { it.identity == last.identity }
                val others = descriptors.indices.filter { it != lastIdx && it !in dead }
                val a = others[(rotate++) % others.size]
                val b = others.first { it != a }
                listOf(descriptors[a], descriptors[b], last).also { paths += it }
            }

        fun allClear(vararg except: Int): Boolean =
            relays.withIndex().all { (i, r) ->
                i in except ||
                    (
                        r.wire.relayService!!.circuitCount() == 0 &&
                            r.wire.relayService!!.introPointCount() == 0 &&
                            r.wire.relayService!!.pendingRendezvousCount() == 0 &&
                            r.wire.relayService!!.splicedPairCount() == 0
                    )
            }

        test("descriptors converge: every node knows every relay") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                (relays + receiver + sender).all { n ->
                    descriptors.all { d -> n.wire.descriptors.current(d.identity, now()) != null }
                }
            } shouldBe true
        }

        test(
            "a client rendezvouses with a hidden service and exchanges 40 messages end to end",
        ).config(timeout = 180.seconds) {
            val serviceKey = Ed25519KeyPair.generate()
            val host = receiver.wire.experimentalServiceHost(serviceKey, OnionServiceConfig(), provider)
            val echoed = ConcurrentLinkedQueue<ByteArray>()
            host.onConnection = { s ->
                s.onReceive {
                    s.send(it)
                    echoed += it
                }
            }
            val published = host.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
            published.introPoints.size shouldBe 3
            relays.take(3).forEach { awaitTrue { it.wire.relayService!!.introPointCount() == 1 } shouldBe true }

            // the sender learns the descriptor through gossip, not by being handed it
            awaitTrue(java.time.Duration.ofSeconds(90)) {
                sender.wire.serviceDescriptors.current(serviceKey.publicKey, now()) != null
            } shouldBe true

            val seen = ConcurrentLinkedQueue<ByteArray>()
            relays[4].wire.relayService!!.observeRendezvousData { seen += it }
            val client = sender.wire.experimentalRendezvousClient()
            val stream = client.connect(host.address, provider, descriptors[4]).get(60, TimeUnit.SECONDS)
            val got = ConcurrentLinkedQueue<ByteArray>()
            stream.onReceive { got += it }
            stream.maxPayload shouldBe 910
            val sent = List(20) { i -> ByteArray(if (i == 19) 910 else 1 + i * 37) { (it * 31 + i).toByte() } }
            sent.forEach { stream.send(it) shouldBe true }
            awaitTrue(java.time.Duration.ofSeconds(30)) { got.size == 20 } shouldBe true
            got.toList().zip(sent).all { (a, b) -> a.contentEquals(b) } shouldBe true
            echoed.size shouldBe 20

            // 40 blobs crossed the rendezvous point, all fixed-size ciphertext, none containing a payload
            awaitTrue { seen.size >= 40 } shouldBe true
            seen.all { it.size == 929 } shouldBe true
            val needle = sent[19].copyOf(24)
            seen.none { b ->
                (0..b.size - needle.size).any { o ->
                    b.copyOfRange(o, o + needle.size).contentEquals(needle)
                }
            } shouldBe
                true
            relays[4].wire.relayService!!.splicedPairCount() shouldBe 1

            // every path was three distinct relays
            paths.all { p -> p.size == 3 && p.map { it.identity }.toSet().size == 3 } shouldBe true

            // closing the client also ends the streams it handed out
            client.close()
            stream.isClosed shouldBe true
            awaitTrue { host.openSessions() == 0 } shouldBe true
            host.close()
            awaitTrue(java.time.Duration.ofSeconds(30)) { allClear() } shouldBe true
            sender.wire.hiddenServiceRoutes() shouldBe 0
            receiver.wire.hiddenServiceRoutes() shouldBe 0
            relays[4].wire.relayService!!.observeRendezvousData(null)
        }

        test("wrong descriptors, unknown addresses and a closed client fail cleanly").config(timeout = 120.seconds) {
            val keyA = Ed25519KeyPair.generate()
            val keyB = Ed25519KeyPair.generate()
            val hostA = receiver.wire.experimentalServiceHost(keyA, OnionServiceConfig(), provider)
            val hostB = receiver.wire.experimentalServiceHost(keyB, OnionServiceConfig(introPoints = 3), provider)
            val dA = hostA.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
            val dB = hostB.start(descriptors.drop(3).take(3)).get(60, TimeUnit.SECONDS)
            val client = sender.wire.experimentalRendezvousClient()
            // the descriptor of B presented for the address of A
            val wrong = client.connect(hostA.address, provider, descriptors[4], descriptor = dB)
            runCatching { wrong.get(30, TimeUnit.SECONDS) }.isFailure shouldBe true
            // an address nobody knows
            val unknown =
                client.connect(
                    Ed25519KeyPair.generate().publicKey.let {
                        net.lapisphilosophorum.lapisnet.onion
                            .OnionServiceAddress(it)
                    },
                    provider,
                    descriptors[4],
                )
            runCatching { unknown.get(5, TimeUnit.SECONDS) }.isFailure shouldBe true
            (dA.introPoints.size + dB.introPoints.size) shouldBe 6
            client.pendingAttempts() shouldBe 0
            client.close()
            runCatching {
                client
                    .connect(
                        hostA.address,
                        provider,
                        descriptors[4],
                        descriptor = dA,
                    ).get(5, TimeUnit.SECONDS)
            }.isFailure shouldBe true
            hostA.close()
            hostB.close()
            awaitTrue(java.time.Duration.ofSeconds(30)) { allClear() } shouldBe true
            sender.wire.hiddenServiceRoutes() shouldBe 0
            receiver.wire.hiddenServiceRoutes() shouldBe 0
        }

        test(
            "stopping mid-build leaks nothing, and a restart with the same service key publishes a newer descriptor",
        ).config(
            timeout = 180.seconds,
        ) {
            val key = Ed25519KeyPair.generate()
            val early = receiver.wire.experimentalServiceHost(key, OnionServiceConfig(), provider)
            early.start(descriptors.take(3))
            early.close() // immediately, while circuits are still being built
            awaitTrue(
                java.time.Duration.ofSeconds(30),
            ) { allClear() && receiver.wire.hiddenServiceRoutes() == 0 } shouldBe
                true

            val first = receiver.wire.experimentalServiceHost(key, OnionServiceConfig(), provider)
            val d1 = first.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
            first.close()
            awaitTrue(java.time.Duration.ofSeconds(30)) { allClear() } shouldBe true
            val second = receiver.wire.experimentalServiceHost(key, OnionServiceConfig(), provider)
            val d2 = second.start(descriptors.drop(1).take(3)).get(60, TimeUnit.SECONDS)
            (d2.sequenceNumber > d1.sequenceNumber) shouldBe true
            second.close()
            awaitTrue(java.time.Duration.ofSeconds(30)) { allClear() } shouldBe true
        }

        test("open sessions are capped, and closed hosts and clients are dropped from the facade").config(
            timeout = 180.seconds,
        ) {
            val baseline = receiver.wire.hiddenCount()
            val senderBaseline = sender.wire.hiddenCount()
            val key = Ed25519KeyPair.generate()
            val host =
                receiver.wire.experimentalServiceHost(key, OnionServiceConfig(maxOpenSessions = 1), provider)
            host.onConnection = { s -> s.onReceive { s.send(it) } }
            val d = host.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)
            receiver.wire.hiddenCount() shouldBe baseline + 1

            val client = sender.wire.experimentalRendezvousClient()
            sender.wire.hiddenCount() shouldBe senderBaseline + 1
            val first = client.connect(host.address, provider, descriptors[4], descriptor = d).get(60, TimeUnit.SECONDS)
            awaitTrue { host.openSessions() == 1 } shouldBe true

            // the second accepted session exceeds the cap: the host closes it at once, the first one stays
            val second =
                runCatching {
                    client
                        .connect(
                            host.address,
                            provider,
                            descriptors[5],
                            descriptor = d,
                        ).get(60, TimeUnit.SECONDS)
                }
            if (second.isSuccess) {
                awaitTrue(java.time.Duration.ofSeconds(30)) { second.getOrThrow().isClosed } shouldBe
                    true
            }
            host.openSessions() shouldBe 1
            first.isClosed shouldBe false

            client.close()
            client.close() // idempotent
            sender.wire.hiddenCount() shouldBe senderBaseline
            host.close()
            receiver.wire.hiddenCount() shouldBe baseline
            awaitTrue(java.time.Duration.ofSeconds(30)) { allClear() } shouldBe true
        }

        test("a dead introduction point does not stop a client; a dead rendezvous point closes both streams").config(
            timeout = 240.seconds,
        ) {
            val key = Ed25519KeyPair.generate()
            val host = receiver.wire.experimentalServiceHost(key, OnionServiceConfig(), provider)
            val streamsAtService = ConcurrentLinkedQueue<OnionRendezvousStream>()
            host.onConnection = { s ->
                streamsAtService += s
                s.onReceive { s.send(it) }
            }
            val d = host.start(descriptors.take(3)).get(60, TimeUnit.SECONDS)

            // kill introduction relay 0; the client still has the old descriptor and must fall through to another point
            dead += 0
            relays[0].close()
            val client = sender.wire.experimentalRendezvousClient()
            val stream =
                client
                    .connect(
                        host.address,
                        provider,
                        descriptors[4],
                        descriptor = d,
                    ).get(90, TimeUnit.SECONDS)
            val got = ConcurrentLinkedQueue<ByteArray>()
            stream.onReceive { got += it }
            stream.send(byteArrayOf(1, 2, 3)) shouldBe true
            awaitTrue(java.time.Duration.ofSeconds(30)) { got.size == 1 } shouldBe true

            // now the rendezvous point dies while the session is open
            val closed =
                java.util.concurrent.atomic
                    .AtomicBoolean(false)
            stream.onClose { closed.set(true) }
            dead += 4
            relays[4].close()
            awaitTrue(java.time.Duration.ofSeconds(60)) { closed.get() && stream.isClosed } shouldBe true
            awaitTrue(java.time.Duration.ofSeconds(60)) { host.openSessions() == 0 } shouldBe true
            client.close()
            host.close()
            awaitTrue(java.time.Duration.ofSeconds(60)) { allClear(0, 4) } shouldBe true
            sender.wire.hiddenServiceRoutes() shouldBe 0
            receiver.wire.hiddenServiceRoutes() shouldBe 0
        }
    })
