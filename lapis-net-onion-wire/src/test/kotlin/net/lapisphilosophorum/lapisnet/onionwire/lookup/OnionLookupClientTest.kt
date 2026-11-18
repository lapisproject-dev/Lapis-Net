@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onion.RelayAction
import net.lapisphilosophorum.lapisnet.onionwire.CircuitPolicy
import net.lapisphilosophorum.lapisnet.onionwire.OnionPathProvider
import net.lapisphilosophorum.lapisnet.onionwire.WireTestNode
import net.lapisphilosophorum.lapisnet.onionwire.awaitTrue
import net.lapisphilosophorum.lapisnet.onionwire.fastWireConfig
import net.lapisphilosophorum.lapisnet.onionwire.key
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Lookups through real loopback relays; the relays' answers are scripted per test where a lie is needed. */
class OnionLookupClientTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }
        val random = SecureRandom()

        val sinks = List(4) { MapLookupSink() }
        val relayConfig =
            fastWireConfig(true).copy(
                lookupService =
                    OnionLookupServiceConfig(minAnswerDelay = 100.milliseconds, answerDelayJitter = 0.milliseconds),
            )
        val relays =
            sinks.map { s -> WireTestNode(relay = true, config = relayConfig, lookupSink = { s }).also { all += it } }
        // a real relay started with --onion-relay-lookup=false (a sink is offered, the role stays off)
        val disabledRelay =
            WireTestNode(relay = true, config = relayConfig.copy(relayLookup = false), lookupSink = { MapLookupSink() })
                .also { all += it }
        val sender = WireTestNode(relay = false).also { all += it }
        val noPolicy = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { disabledRelay.connectTo(it) }
        sender.connectTo(disabledRelay)
        relays.forEach {
            sender.connectTo(it)
            noPolicy.connectTo(it)
        }
        val governor =
            CircuitBuildGovernor(
                ratePerMinute = 600,
                burst = 100,
                lookupBuildsPerMinute = 600,
            )
        sender.wire.installCircuitPolicy(CircuitPolicy(governor))
        lateinit var descriptors: List<OnionRelayDescriptor>
        val provider =
            OnionPathProvider { last: OnionRelayDescriptor, _: CircuitPurpose ->
                descriptors.filter { it.identity != last.identity }.take(2) + last
            }
        val fast =
            OnionLookupClientConfig(buildTimeout = 15.seconds, answerTimeout = 10.seconds, maxAttempts = 2)

        fun client(
            relaysOf: () -> List<OnionRelayDescriptor>,
            config: OnionLookupClientConfig = fast,
            node: WireTestNode = sender,
        ) = node.wire.lookupClient(provider, relaysOf, config)

        fun reset() {
            sinks.forEach {
                it.blocks.clear()
                it.blockDelayMillis = 0
            }
            relays.forEach {
                it.wire.relayService!!.lookupAnswerOverrideForTest = null
                it.wire.relayService!!.simulateLegacyRelayForTest(false)
            }
        }

        fun override(
            index: Int,
            answer: (RelayAction.DeliverLookupRequest) -> List<ByteArray>?,
        ) {
            relays[index].wire.relayService!!.lookupAnswerOverrideForTest = answer
        }

        fun block(size: Int) = ByteArray(size).also(random::nextBytes)

        fun wait(f: java.util.concurrent.CompletableFuture<LookupResult>) = f.get(60, TimeUnit.SECONDS)

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                (descriptors + disabledRelay.wire.currentDescriptor()!!).all { d ->
                    sender.wire.descriptors.current(d.identity, Clock.systemUTC().millis() / 1000) != null
                }
            } shouldBe true
        }

        test("a block of a multi-fragment class and an IPNS record arrive verified; no circuit is left open")
            .config(timeout = 120.seconds) {
                reset()
                val bytes = block(9000)
                val cid = rawCid(bytes)
                val publisher = TestIpnsPublisher()
                val record = publisher.record(sequence = 3)
                sinks.forEach {
                    it.blocks[cid.toString()] = bytes
                    it.records[publisher.routingKey.toHexString()] = record
                }
                val c = client({ descriptors })
                try {
                    wait(c.fetchBlock(cid, 60.seconds)).shouldBeInstanceOf<LookupResult.Found>().bytes shouldBe bytes
                    wait(c.resolveIpnsRecord(publisher.routingKey, 60.seconds))
                        .shouldBeInstanceOf<LookupResult.Found>()
                        .bytes shouldBe record
                    c.openCircuits() shouldBe 0
                    c.statsForTest().circuitsBuilt shouldBe 2
                } finally {
                    c.close()
                }
                awaitTrue(Duration.ofSeconds(30)) { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe
                    true
            }

        test(
            "exactly one request per circuit: every request arrives on a circuit of its own",
        ).config(timeout = 120.seconds) {
            reset()
            val handles = ConcurrentHashMap<String, Int>()
            for (i in relays.indices) {
                override(i) { req ->
                    handles.merge("$i:${req.circuitHandle}", 1, Int::plus)
                    LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.NOT_FOUND, ByteArray(0), random)
                }
            }
            val c = client({ descriptors })
            try {
                repeat(3) { wait(c.fetchBlock(rawCid(block(10)), 60.seconds)) shouldBe LookupResult.NotFound }
                handles.size shouldBe 3
                handles.values.all { it == 1 } shouldBe true
                c.openCircuits() shouldBe 0
            } finally {
                c.close()
            }
        }

        test("NOT_FOUND is cached: a repeated lookup builds no new circuit").config(timeout = 120.seconds) {
            reset()
            val c = client({ descriptors })
            try {
                val cid = rawCid(block(10))
                wait(c.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.NotFound
                val built = c.statsForTest().circuitsBuilt
                wait(c.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.NotFound
                c.statsForTest().circuitsBuilt shouldBe built
                c.statsForTest().negativeHits shouldBe 1
            } finally {
                c.close()
            }
        }

        test("a manipulated block or record is rejected; the relay goes on backoff and the next relay answers")
            .config(timeout = 180.seconds) {
                reset()
                val bytes = block(3000)
                val cid = rawCid(bytes)
                sinks.forEach { it.blocks[cid.toString()] = bytes }
                override(0) { req ->
                    LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.FOUND, block(3000), random)
                }
                val only0 = client({ listOf(descriptors[0]) })
                try {
                    wait(only0.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.Unavailable(LookupFailure.MANIPULATED)
                    only0.inBackoff(relays[0].key) shouldBe true
                    only0.statsForTest().manipulated shouldBe 1
                } finally {
                    only0.close()
                }
                val two = client({ listOf(descriptors[0], descriptors[1]) }, fast.copy(maxAttempts = 2))
                try {
                    // whichever relay is asked first: the liar is caught and the honest one delivers
                    wait(two.fetchBlock(cid, 90.seconds)).shouldBeInstanceOf<LookupResult.Found>().bytes shouldBe bytes
                } finally {
                    two.close()
                }
                val publisher = TestIpnsPublisher()
                override(0) { req ->
                    LookupResponseBody.encodeAnswer(
                        req.requestId,
                        LookupStatus.FOUND,
                        TestIpnsPublisher().record(),
                        random,
                    )
                }
                val ipns = client({ listOf(descriptors[0]) })
                try {
                    wait(ipns.resolveIpnsRecord(publisher.routingKey, 60.seconds)) shouldBe
                        LookupResult.Unavailable(LookupFailure.MANIPULATED)
                } finally {
                    ipns.close()
                }
            }

        test("MALFORMED for a key the client checked is a manipulation; TOO_LARGE asks the next relay")
            .config(timeout = 240.seconds) {
                reset()
                val bytes = block(3000)
                val cid = rawCid(bytes)
                sinks.forEach { it.blocks[cid.toString()] = bytes }
                for ((status, expected) in listOf(
                    LookupStatus.MALFORMED to LookupFailure.MANIPULATED,
                    LookupStatus.TOO_LARGE to LookupFailure.REFUSED,
                )) {
                    override(0) { req -> LookupResponseBody.encodeAnswer(req.requestId, status, ByteArray(0), random) }
                    val only0 = client({ listOf(descriptors[0]) })
                    try {
                        wait(only0.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.Unavailable(expected)
                        // a lying exit relay no longer ends a lookup without consequences
                        only0.inBackoff(relays[0].key) shouldBe true
                        only0.statsForTest().manipulated shouldBe
                            (if (status == LookupStatus.MALFORMED) 1L else 0L)
                    } finally {
                        only0.close()
                    }
                    val two = client({ listOf(descriptors[0], descriptors[1]) }, fast.copy(maxAttempts = 2))
                    try {
                        // whichever relay is asked first: the second relay is asked and delivers
                        wait(two.fetchBlock(cid, 90.seconds)).shouldBeInstanceOf<LookupResult.Found>().bytes shouldBe
                            bytes
                    } finally {
                        two.close()
                    }
                }
            }

        test("broken fragments are rejected: request id, order, count, length, status").config(timeout = 240.seconds) {
            reset()
            val variants =
                listOf<(RelayAction.DeliverLookupRequest) -> List<ByteArray>>(
                    { r ->
                        LookupResponseBody.encodeAnswer(r.requestId xor 1, LookupStatus.NOT_FOUND, ByteArray(0), random)
                    },
                    { r ->
                        LookupResponseBody.encodeAnswer(r.requestId, LookupStatus.FOUND, block(3000), random).let {
                            listOf(it[1], it[0]) + it.drop(2)
                        }
                    },
                    { r ->
                        LookupResponseBody
                            .encodeAnswer(
                                r.requestId,
                                LookupStatus.FOUND,
                                block(3000),
                                random,
                            ).mapIndexed {
                                i,
                                f,
                                ->
                                if (i == 1) f.copyOf().also { it[5] = 3 } else f
                            }
                    },
                    { r ->
                        LookupResponseBody
                            .encodeAnswer(
                                r.requestId,
                                LookupStatus.NOT_FOUND,
                                ByteArray(0),
                                random,
                            ).mapIndexed {
                                i,
                                f,
                                ->
                                if (i == 0) f.copyOf().also { it[9] = 0x7F } else f
                            }
                    },
                    { r ->
                        LookupResponseBody
                            .encodeAnswer(
                                r.requestId,
                                LookupStatus.NOT_FOUND,
                                ByteArray(0),
                                random,
                            ).mapIndexed {
                                i,
                                f,
                                ->
                                if (i == 0) f.copyOf().also { it[6] = 42 } else f
                            }
                    },
                )
            for (v in variants) {
                override(1, v)
                val c = client({ listOf(descriptors[1]) })
                try {
                    wait(c.fetchBlock(rawCid(block(10)), 60.seconds)) shouldBe
                        LookupResult.Unavailable(LookupFailure.MANIPULATED)
                    c.inBackoff(relays[1].key) shouldBe true
                    c.openCircuits() shouldBe 0
                } finally {
                    c.close()
                }
            }
        }

        test("an older relay destroys the circuit: unsupported backoff, then another relay answers")
            .config(timeout = 180.seconds) {
                reset()
                val bytes = block(500)
                val cid = rawCid(bytes)
                sinks.forEach { it.blocks[cid.toString()] = bytes }
                relays[2].wire.relayService!!.simulateLegacyRelayForTest(true)
                val c = client({ listOf(descriptors[2]) })
                try {
                    wait(c.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.Unavailable(LookupFailure.REFUSED)
                    c.statsForTest().legacySuspected shouldBe 1
                    c.inBackoff(relays[2].key) shouldBe true
                } finally {
                    c.close()
                }
                var asked = listOf(descriptors[2])
                val d = client({ asked })
                try {
                    wait(d.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.Unavailable(LookupFailure.REFUSED)
                    // now in backoff for 30 minutes: never chosen again, the new relay answers
                    asked = listOf(descriptors[2], descriptors[3])
                    wait(d.fetchBlock(cid, 60.seconds)).shouldBeInstanceOf<LookupResult.Found>()
                    d.statsForTest().legacySuspected shouldBe 1
                } finally {
                    d.close()
                }
            }

        test("DISABLED moves on with a backoff; a silent relay times out").config(timeout = 180.seconds) {
            reset()
            override(
                3,
            ) { r -> LookupResponseBody.encodeAnswer(r.requestId, LookupStatus.DISABLED, ByteArray(0), random) }
            val c = client({ listOf(descriptors[3]) })
            try {
                wait(c.fetchBlock(rawCid(block(10)), 60.seconds)) shouldBe
                    LookupResult.Unavailable(LookupFailure.REFUSED)
                c.statsForTest().disabled shouldBe 1
                c.inBackoff(relays[3].key) shouldBe true
            } finally {
                c.close()
            }
            override(3) { emptyList() }
            val t = client({ listOf(descriptors[3]) }, fast.copy(answerTimeout = 3.seconds))
            try {
                wait(t.fetchBlock(rawCid(block(10)), 60.seconds)) shouldBe
                    LookupResult.Unavailable(LookupFailure.TIMEOUT)
                t.inBackoff(relays[3].key) shouldBe true
                t.openCircuits() shouldBe 0
            } finally {
                t.close()
            }
        }

        test("the caller's deadline ends a slow but honest lookup without a backoff for the relay")
            .config(timeout = 120.seconds) {
                reset()
                val bytes = block(200)
                val cid = rawCid(bytes)
                sinks[1].blocks[cid.toString()] = bytes
                sinks[1].blockDelayMillis = 5_000
                val c = client({ listOf(descriptors[1]) })
                try {
                    wait(c.fetchBlock(cid, 2.seconds)) shouldBe LookupResult.Unavailable(LookupFailure.TIMEOUT)
                    // the job itself ends at the same deadline and closes its circuit
                    awaitTrue(Duration.ofSeconds(30)) { c.openCircuits() == 0 } shouldBe true
                    Thread.sleep(500)
                    c.inBackoff(relays[1].key) shouldBe false
                    c.statsForTest().legacySuspected shouldBe 0
                } finally {
                    c.close()
                }
            }

        test("a merged lookup runs as long as its most patient caller").config(timeout = 120.seconds) {
            reset()
            val bytes = block(200)
            val cid = rawCid(bytes)
            sinks[1].blocks[cid.toString()] = bytes
            sinks[1].blockDelayMillis = 4_000
            val c = client({ listOf(descriptors[1]) })
            try {
                val impatient = c.fetchBlock(cid, 2.seconds)
                val patient = c.fetchBlock(cid, 40.seconds)
                c.statsForTest().deduplicated shouldBe 1
                wait(impatient) shouldBe LookupResult.Unavailable(LookupFailure.TIMEOUT)
                wait(patient).shouldBeInstanceOf<LookupResult.Found>().bytes shouldBe bytes
                c.inBackoff(relays[1].key) shouldBe false
                c.statsForTest().circuitsBuilt shouldBe 1
            } finally {
                c.close()
            }
        }

        test("a relay started with --onion-relay-lookup=false answers DISABLED; the circuit is not destroyed")
            .config(timeout = 120.seconds) {
                reset()
                disabledRelay.wire.relayService!!.lookupRoleActive shouldBe false
                val d = disabledRelay.wire.currentDescriptor()!!
                val c = client({ listOf(d) })
                try {
                    wait(c.fetchBlock(rawCid(block(10)), 60.seconds)) shouldBe
                        LookupResult.Unavailable(LookupFailure.REFUSED)
                    c.statsForTest().disabled shouldBe 1
                    c.statsForTest().legacySuspected shouldBe 0
                    c.inBackoff(d.identity) shouldBe true
                } finally {
                    c.close()
                }
            }

        test("single flight with a bounded queue: duplicates merge, the oldest waiting lookup is dropped")
            .config(timeout = 120.seconds) {
                reset()
                // relay 0 never answers: the first lookup keeps running
                override(0) { emptyList() }
                val c = client({ listOf(descriptors[0]) }, fast.copy(maxQueued = 2, answerTimeout = 20.seconds))
                try {
                    val first = c.fetchBlock(rawCid(block(10)), 60.seconds)
                    val a = c.fetchBlock(rawCid(block(10)), 60.seconds)
                    val dup = rawCid(block(10))
                    val b1 = c.fetchBlock(dup, 60.seconds)
                    val b2 = c.fetchBlock(dup, 60.seconds)
                    c.statsForTest().deduplicated shouldBe 1
                    val e = c.fetchBlock(rawCid(block(10)), 60.seconds)
                    // the queue held a and dup; e pushed a out
                    a.get(10, TimeUnit.SECONDS) shouldBe LookupResult.Unavailable(LookupFailure.ADMISSION)
                    c.statsForTest().dropped shouldBe 1
                    c.close()
                    listOf(first, b1, b2, e).forEach {
                        it.get(10, TimeUnit.SECONDS).shouldBeInstanceOf<LookupResult.Unavailable>()
                    }
                } finally {
                    c.close()
                }
            }

        test("fail closed: no relays, no circuit policy, lockdown").config(timeout = 60.seconds) {
            reset()
            val none = client({ emptyList() })
            wait(none.fetchBlock(rawCid(block(10)), 10.seconds)) shouldBe
                LookupResult.Unavailable(LookupFailure.NO_RELAY)
            none.close()
            val unpoliced = client({ descriptors }, node = noPolicy)
            wait(unpoliced.fetchBlock(rawCid(block(10)), 10.seconds)) shouldBe
                LookupResult.Unavailable(LookupFailure.ADMISSION)
            noPolicy.wire.hiddenServiceRoutes() shouldBe 0
            unpoliced.statsForTest().circuitsBuilt shouldBe 0
            unpoliced.close()
            governor.lockdown()
            val locked = client({ descriptors })
            wait(locked.fetchBlock(rawCid(block(10)), 10.seconds)) shouldBe
                LookupResult.Unavailable(LookupFailure.ADMISSION)
            locked.close()
        }
    })

/** A relay sink answering from maps. */
internal class MapLookupSink : OnionLookupSink {
    val blocks = ConcurrentHashMap<String, ByteArray>()
    val records = ConcurrentHashMap<String, ByteArray>()

    /** How long a block lookup takes inside the relay (an honest but slow DHT walk). */
    @Volatile var blockDelayMillis = 0L

    override fun fetchBlock(
        cid: io.ipfs.cid.Cid,
        maxBytes: Int,
        timeout: Duration,
    ): LookupOutcome {
        if (blockDelayMillis > 0) Thread.sleep(blockDelayMillis)
        return blocks[cid.toString()]?.let { LookupOutcome.Found(it) } ?: LookupOutcome.NotFound
    }

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): LookupOutcome = records[routingKey.toHexString()]?.let { LookupOutcome.Found(it) } ?: LookupOutcome.NotFound
}
