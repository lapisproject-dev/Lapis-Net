@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LookupOperation
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
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** System time plus an offset the test moves (the client's clock seam). */
internal class OffsetClock : Clock() {
    @Volatile var offsetMillis = 0L

    override fun millis(): Long = System.currentTimeMillis() + offsetMillis

    override fun instant(): Instant = Instant.ofEpochMilli(millis())

    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId?): Clock = this
}

/** A relay sink with a scriptable outcome (for the found mark of the relay's lookup service). */
private class ScriptSink : OnionLookupSink {
    val blocks = ConcurrentHashMap<String, ByteArray>()

    @Volatile var override: LookupOutcome? = null
    val calls = AtomicInteger()

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): LookupOutcome {
        calls.incrementAndGet()
        return override ?: blocks[cid.toString()]?.let { LookupOutcome.Found(it) } ?: LookupOutcome.NotFound
    }

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): LookupOutcome = LookupOutcome.NotFound
}

/** One request as the exit relay saw it. */
private data class Seen(
    val relay: Int,
    val handle: Long,
    val key: String,
    val op: LookupOperation,
)

/**
 * Wave V0.10.0-J3 on real loopback relays: circuit reuse for timeline lookups (4 per circuit, context separation, age
 * limit, no idle hold), the NOT_FOUND cross-check, the per-context queue bound, the status counters and the found mark
 * of the relay (what an attacker who asked first can do).
 */
class OnionLookupClientReuseTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }
        val random = SecureRandom()

        val sinks = List(4) { ScriptSink() }
        val relayConfig =
            fastWireConfig(true).copy(
                lookupService =
                    OnionLookupServiceConfig(minAnswerDelay = 100.milliseconds, answerDelayJitter = 0.milliseconds),
            )
        val relays =
            sinks.map { s -> WireTestNode(relay = true, config = relayConfig, lookupSink = { s }).also { all += it } }
        val sender = WireTestNode(relay = false).also { all += it }
        val noPolicy = WireTestNode(relay = false).also { all += it }
        // a client whose governor allows 6 lookup builds per minute and never waits longer than 200 ms for one
        val limited = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach {
            sender.connectTo(it)
            noPolicy.connectTo(it)
            limited.connectTo(it)
        }
        limited.wire.installCircuitPolicy(
            CircuitPolicy(
                CircuitBuildGovernor(ratePerMinute = 600, burst = 100, lookupBuildsPerMinute = 6),
                maxDefer = 200.milliseconds,
            ),
        )
        val governor = CircuitBuildGovernor(ratePerMinute = 600, burst = 100, lookupBuildsPerMinute = 600)
        sender.wire.installCircuitPolicy(CircuitPolicy(governor))
        lateinit var descriptors: List<OnionRelayDescriptor>
        val provider =
            OnionPathProvider { last: OnionRelayDescriptor, _: CircuitPurpose ->
                descriptors.filter { it.identity != last.identity }.take(2) + last
            }
        val fast = OnionLookupClientConfig(buildTimeout = 15.seconds, answerTimeout = 10.seconds, maxAttempts = 2)

        // what the scripted relays answer: block bytes by hex key; everything else NOT_FOUND
        val content = ConcurrentHashMap<String, ByteArray>()
        val seen = ConcurrentLinkedQueue<Seen>()
        val perHandle = ConcurrentHashMap<String, AtomicInteger>()

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

        fun honest(req: RelayAction.DeliverLookupRequest): List<ByteArray> {
            val bytes = content[hex(req.key)]
            return if (bytes != null) {
                LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.FOUND, bytes, random)
            } else {
                LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.NOT_FOUND, ByteArray(0), random)
            }
        }

        /** Scripts every relay: records the request, then [answer] (request number on its circuit, 1-based). */
        fun script(
            answer: (Int, RelayAction.DeliverLookupRequest, Int) -> List<ByteArray>? = { _, r, _ -> honest(r) },
        ) {
            for (i in relays.indices) {
                relays[i].wire.relayService!!.lookupAnswerOverrideForTest = { req ->
                    seen += Seen(i, req.circuitHandle, hex(req.key), req.op)
                    val n = perHandle.computeIfAbsent("$i:${req.circuitHandle}") { AtomicInteger() }.incrementAndGet()
                    answer(i, req, n)
                }
            }
        }

        fun reset() {
            content.clear()
            seen.clear()
            perHandle.clear()
            sinks.forEach {
                it.blocks.clear()
                it.override = null
            }
            relays.forEach {
                it.wire.relayService!!.lookupAnswerOverrideForTest = null
                it.wire.relayService!!.simulateLegacyRelayForTest(false)
            }
        }

        fun circuits(): Map<String, List<Seen>> = seen.groupBy { "${it.relay}:${it.handle}" }

        fun block(size: Int) = ByteArray(size).also(random::nextBytes)

        fun stored(size: Int = 200): Cid {
            val b = block(size)
            val cid = rawCid(b)
            content[hex(cidKey(cid))] = b
            return cid
        }

        fun wait(f: CompletableFuture<LookupResult>) = f.get(90, TimeUnit.SECONDS)

        fun client(
            relaysOf: () -> List<OnionRelayDescriptor>,
            config: OnionLookupClientConfig = fast,
            clock: Clock = Clock.systemUTC(),
            node: WireTestNode = sender,
        ) = node.wire.lookupClient(provider, relaysOf, config, clientClock = clock)

        fun noLeak(c: OnionLookupClient) {
            awaitTrue(Duration.ofSeconds(30)) { c.openCircuits() == 0 } shouldBe true
            // no idle hold: the governor's single lookup slot is free again
            awaitTrue(Duration.ofSeconds(30)) { governor.openCount() == 0 } shouldBe true
        }

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                descriptors.all { d ->
                    limited.wire.descriptors.current(d.identity, Clock.systemUTC().millis() / 1000) != null
                } &&
                    descriptors.all { d ->
                        sender.wire.descriptors.current(d.identity, Clock.systemUTC().millis() / 1000) !=
                            null
                    }
            } shouldBe true
        }

        test(
            "T-R1: four queued timeline lookups share one circuit (one build, three reuses)",
        ).config(timeout = 180.seconds) {
            reset()
            script()
            val cids = List(4) { stored() }
            val c = client({ descriptors })
            try {
                val futures = cids.map { c.fetchBlock(it, 60.seconds, LookupContext.TIMELINE) }
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                c.statsForTest().circuitsBuilt shouldBe 1
                c.statsForTest().circuitsReused shouldBe 3
                circuits().values.map { it.size } shouldBe listOf(4)
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("T-R2: a fifth timeline lookup gets a second circuit; the relay never sees a fifth request").config(
            timeout = 180.seconds,
        ) {
            reset()
            script()
            val cids = List(5) { stored() }
            val c = client({ descriptors })
            try {
                val futures = cids.map { c.fetchBlock(it, 60.seconds, LookupContext.TIMELINE) }
                // no RESOURCE_LIMIT teardown: every lookup is found
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                c.statsForTest().circuitsBuilt shouldBe 2
                c.statsForTest().circuitsReused shouldBe 3
                circuits().values.map { it.size }.sorted() shouldBe listOf(1, 4)
                (perHandle.values.maxOf { it.get() } <= 4) shouldBe true
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("T-R3: a circuit older than the reuse age takes no further request").config(timeout = 180.seconds) {
            reset()
            val clock = OffsetClock()
            // the first request ages the circuit beyond 10 minutes
            script { _, req, _ ->
                if (clock.offsetMillis == 0L) clock.offsetMillis = 10.minutes.inWholeMilliseconds + 1
                honest(req)
            }
            val cids = List(2) { stored() }
            val c = client({ descriptors }, clock = clock)
            try {
                val futures = cids.map { c.fetchBlock(it, 60.minutes, LookupContext.TIMELINE) }
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                c.statsForTest().circuitsBuilt shouldBe 2
                c.statsForTest().circuitsReused shouldBe 0
                circuits().size shouldBe 2
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("T-R4/T-R5: contexts never share a circuit; mailbox and IPNS use one circuit per request").config(
            timeout = 240.seconds,
        ) {
            reset()
            script()
            val timeline = List(2) { stored() }
            val mailbox = List(3) { stored() }
            val publisher = TestIpnsPublisher()
            val contextOf = HashMap<String, LookupContext>()
            timeline.forEach { contextOf[hex(cidKey(it))] = LookupContext.TIMELINE }
            mailbox.forEach { contextOf[hex(cidKey(it))] = LookupContext.MAILBOX }
            contextOf[hex(publisher.routingKey)] = LookupContext.IPNS
            val c = client({ descriptors })
            try {
                val futures =
                    listOf(
                        c.fetchBlock(timeline[0], 60.seconds, LookupContext.TIMELINE),
                        c.fetchBlock(mailbox[0], 60.seconds, LookupContext.MAILBOX),
                        c.fetchBlock(mailbox[1], 60.seconds),
                        c.resolveIpnsRecord(publisher.routingKey, 60.seconds),
                        c.fetchBlock(mailbox[2], 60.seconds, LookupContext.MAILBOX),
                        c.fetchBlock(timeline[1], 60.seconds, LookupContext.TIMELINE),
                    )
                futures.forEach { wait(it) }
                // every circuit carried one context; the two timeline lookups were not adjacent, so nothing was reused
                circuits().values.forEach { reqs -> reqs.map { contextOf.getValue(it.key) }.toSet().size shouldBe 1 }
                circuits()
                    .values
                    .filter { reqs -> contextOf.getValue(reqs.first().key) != LookupContext.TIMELINE }
                    .forEach { it.size shouldBe 1 }
                c.statsForTest().circuitsReused shouldBe 0
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test(
            "T-R6: a manipulated answer on a reused circuit is rejected; the next lookup runs on a new circuit",
        ).config(
            timeout = 240.seconds,
        ) {
            reset()
            val lieAt =
                java.util.concurrent.atomic
                    .AtomicReference<Seen?>(null)
            script { i, req, n ->
                if (n == 2 && lieAt.compareAndSet(null, Seen(i, req.circuitHandle, hex(req.key), req.op))) {
                    LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.FOUND, block(200), random)
                } else {
                    honest(req)
                }
            }
            val cids = List(3) { stored() }
            val c = client({ descriptors })
            try {
                val futures = cids.map { c.fetchBlock(it, 60.seconds, LookupContext.TIMELINE) }
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                val lie = checkNotNull(lieAt.get())
                c.statsForTest().rejected shouldBe 1
                c.statusCounters().rejected shouldBe 1
                c.inBackoff(relays[lie.relay].key) shouldBe true
                // the rejected request's circuit carried nothing after it; the retry ran on a new circuit, another exit
                val order = seen.toList()
                val after = order.drop(order.indexOfFirst { it == lie } + 1)
                after.none { it.relay == lie.relay && it.handle == lie.handle } shouldBe true
                (after.first().relay != lie.relay) shouldBe true
                after.first().key shouldBe lie.key
                c.statsForTest().circuitsBuilt shouldBe 2
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("T-R7: a network destroy on a reused circuit is a failure, never a legacy relay").config(
            timeout = 240.seconds,
        ) {
            reset()
            val first = AtomicInteger(-1)
            script { i, req, _ ->
                // after answering its first request the exit behaves like an older relay: request 2 is destroyed
                if (first.compareAndSet(-1, i)) relays[i].wire.relayService!!.simulateLegacyRelayForTest(true)
                honest(req)
            }
            val cids = List(2) { stored() }
            val c = client({ descriptors })
            try {
                val futures = cids.map { c.fetchBlock(it, 60.seconds, LookupContext.TIMELINE) }
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                c.statsForTest().circuitsReused shouldBe 1
                c.statsForTest().legacySuspected shouldBe 0
                // a failure backoff (30 s), not the unsupported one
                c.inBackoff(relays[first.get()].key) shouldBe true
                noLeak(c)
            } finally {
                relays.forEach { it.wire.relayService!!.simulateLegacyRelayForTest(false) }
                c.close()
            }
        }

        test("T-C1: NOT_FOUND at two different exits is confirmed and cached for ten minutes").config(
            timeout = 180.seconds,
        ) {
            reset()
            script()
            val clock = OffsetClock()
            val cid = rawCid(block(10))
            val c = client({ descriptors }, clock = clock)
            try {
                wait(c.fetchBlock(cid, 60.seconds, LookupContext.TIMELINE)) shouldBe LookupResult.NotFound(true)
                seen.map { it.relay }.distinct().size shouldBe 2
                seen.size shouldBe 2
                c.statsForTest().crossChecks shouldBe 1
                clock.offsetMillis = 9.minutes.inWholeMilliseconds
                wait(c.fetchBlock(cid, 60.seconds, LookupContext.TIMELINE)) shouldBe LookupResult.NotFound(true)
                c.statsForTest().negativeHits shouldBe 1
                seen.size shouldBe 2
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test(
            "T-C2: one relay known: an unconfirmed NOT_FOUND, cached for two minutes only",
        ).config(timeout = 180.seconds) {
            reset()
            script()
            val clock = OffsetClock()
            val cid = rawCid(block(10))
            val c = client({ listOf(descriptors[0]) }, clock = clock)
            try {
                wait(c.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.NotFound(false)
                c.statsForTest().notFoundUnconfirmed shouldBe 1
                c.statsForTest().notFound shouldBe 0
                wait(c.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.NotFound(false)
                c.statsForTest().negativeHits shouldBe 1
                val built = c.statsForTest().circuitsBuilt
                clock.offsetMillis = 2.minutes.inWholeMilliseconds + 1
                wait(c.fetchBlock(cid, 60.seconds)) shouldBe LookupResult.NotFound(false)
                c.statsForTest().circuitsBuilt shouldBe built + 1
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("T-C3: NOT_FOUND at A, FOUND at B: found, A is not penalised").config(timeout = 180.seconds) {
            reset()
            val cid = stored()
            val asked = AtomicInteger()
            script { _, req, _ ->
                if (asked.incrementAndGet() == 1) {
                    LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.NOT_FOUND, ByteArray(0), random)
                } else {
                    honest(req)
                }
            }
            val c = client({ descriptors })
            try {
                wait(c.fetchBlock(cid, 60.seconds, LookupContext.TIMELINE)).shouldBeInstanceOf<LookupResult.Found>()
                c.statsForTest().notFoundContradicted shouldBe 1
                val a = seen.first().relay
                (seen.toList()[1].relay != a) shouldBe true
                c.inBackoff(relays[a].key) shouldBe false
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("T-C4: NOT_FOUND at A, silence at B: unconfirmed, never a third relay").config(timeout = 180.seconds) {
            reset()
            val asked = AtomicInteger()
            script { _, req, _ ->
                if (asked.incrementAndGet() == 1) {
                    LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.NOT_FOUND, ByteArray(0), random)
                } else {
                    emptyList()
                }
            }
            val c = client({ descriptors }, fast.copy(answerTimeout = 3.seconds))
            try {
                wait(c.fetchBlock(rawCid(block(10)), 60.seconds, LookupContext.TIMELINE)) shouldBe
                    LookupResult.NotFound(false)
                Thread.sleep(500)
                seen.size shouldBe 2
                seen.map { it.relay }.distinct().size shouldBe 2
                c.statsForTest().notFoundUnconfirmed shouldBe 1
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test(
            "T-C5: the found mark: a relay that found a block answers TIMEOUT, never NOT_FOUND; a second relay delivers",
        ).config(timeout = 240.seconds) {
            reset()
            val bytes = block(400)
            val cid = rawCid(bytes)
            sinks[0].blocks[cid.toString()] = bytes
            sinks[1].blocks[cid.toString()] = bytes
            // an attacker asks relay A first: A finds the block and sets its found mark
            val attacker = client({ listOf(descriptors[0]) })
            try {
                wait(attacker.fetchBlock(cid, 60.seconds)).shouldBeInstanceOf<LookupResult.Found>()
            } finally {
                attacker.close()
            }
            // the Bitswap gap: A can not get the block again (its holder does not resend)
            sinks[0].override = LookupOutcome.NotFound
            val onlyA = client({ listOf(descriptors[0]) })
            try {
                // denied (TIMEOUT while the mark lasts): unavailable, never a (cached) NOT_FOUND
                wait(onlyA.fetchBlock(cid, 60.seconds)).shouldBeInstanceOf<LookupResult.Unavailable>()
                onlyA.statsForTest().notFound shouldBe 0
                onlyA.statsForTest().notFoundUnconfirmed shouldBe 0
            } finally {
                onlyA.close()
            }
            val both = client({ listOf(descriptors[0], descriptors[1]) })
            try {
                wait(both.fetchBlock(cid, 90.seconds)).shouldBeInstanceOf<LookupResult.Found>().bytes shouldBe bytes
            } finally {
                both.close()
            }
        }

        test("T-Q: a full timeline queue drops its oldest timeline lookup, never a mailbox lookup").config(
            timeout = 120.seconds,
        ) {
            reset()
            // the exit never answers: the first lookup keeps running
            script { _, _, _ -> emptyList() }
            val c = client({ descriptors }, fast.copy(answerTimeout = 30.seconds))
            try {
                val running = c.fetchBlock(rawCid(block(10)), 60.seconds, LookupContext.TIMELINE)
                val mailbox = c.fetchBlock(rawCid(block(10)), 60.seconds, LookupContext.MAILBOX)
                val timeline = List(29) { c.fetchBlock(rawCid(block(10)), 60.seconds, LookupContext.TIMELINE) }
                // 29 queued timeline lookups, at most 24 wait: the five oldest are dropped
                timeline.take(5).forEach {
                    it.get(10, TimeUnit.SECONDS) shouldBe LookupResult.Unavailable(LookupFailure.ADMISSION)
                }
                c.statsForTest().dropped shouldBe 5
                timeline.drop(5).none { it.isDone } shouldBe true
                mailbox.isDone shouldBe false
                running.isDone shouldBe false
                // the stuck lookup's circuit is built (its build no longer holds the governor's pending lookup slot)
                awaitTrue(Duration.ofSeconds(30)) { c.statsForTest().circuitsBuilt == 1L } shouldBe true
            } finally {
                c.close()
                // the circuit of the stuck lookup may still have been building: it is closed once built, and the
                // governor's single lookup slot is free again before the next test
                noLeak(c)
            }
        }

        test("T-P: a full circuit pool is a pause, not a failure: the lookup waits for the slot and then delivers")
            .config(timeout = 180.seconds) {
                reset()
                val stuck = AtomicInteger()
                // the first exchange (client A) gets no answer and holds the governor's single lookup slot
                script { _, req, _ -> if (stuck.incrementAndGet() == 1) emptyList() else honest(req) }
                val a = client({ descriptors }, fast.copy(answerTimeout = 30.seconds))
                val b = client({ descriptors })
                try {
                    val held = a.fetchBlock(rawCid(block(10)), 60.seconds, LookupContext.TIMELINE)
                    awaitTrue(Duration.ofSeconds(30)) { stuck.get() == 1 } shouldBe true
                    val cid = stored()
                    val waiting = b.fetchBlock(cid, 60.seconds, LookupContext.TIMELINE)
                    awaitTrue(Duration.ofSeconds(30)) { b.statsForTest().admissionPauses >= 1 } shouldBe true
                    waiting.isDone shouldBe false
                    // A gives the slot back: B gets its circuit within its deadline
                    a.close()
                    held.get(10, TimeUnit.SECONDS).shouldBeInstanceOf<LookupResult.Unavailable>()
                    wait(waiting).shouldBeInstanceOf<LookupResult.Found>()
                    b.statsForTest().failed shouldBe 0
                    noLeak(b)
                } finally {
                    a.close()
                    b.close()
                }
            }

        test("T-P2: a rate-limited build is a pause too: the lookup waits for the next token and delivers")
            .config(timeout = 180.seconds) {
                reset()
                script()
                val c = client({ descriptors }, node = limited)
                try {
                    // six tokens: six mailbox lookups (one circuit each) build at once, the seventh waits about 10 s
                    repeat(7) { wait(c.fetchBlock(stored(), 60.seconds)).shouldBeInstanceOf<LookupResult.Found>() }
                    (c.statsForTest().admissionPauses >= 1) shouldBe true
                    c.statsForTest().failed shouldBe 0
                    c.statsForTest().circuitsBuilt shouldBe 7
                    awaitTrue(Duration.ofSeconds(30)) { c.openCircuits() == 0 } shouldBe true
                } finally {
                    c.close()
                }
            }

        test("T-S: the status counters add up and contain no identity").config(timeout = 240.seconds) {
            reset()
            script()
            val c = client({ descriptors })
            try {
                val present = stored()
                val missing = rawCid(block(10))
                wait(c.fetchBlock(present, 60.seconds, LookupContext.TIMELINE)).shouldBeInstanceOf<LookupResult.Found>()
                wait(c.fetchBlock(missing, 60.seconds, LookupContext.TIMELINE)) shouldBe LookupResult.NotFound(true)
                wait(c.fetchBlock(missing, 60.seconds, LookupContext.TIMELINE)) shouldBe LookupResult.NotFound(true)
                val s = c.statsForTest()
                val st = c.statusCounters()
                st.requested shouldBe 3
                st.requested shouldBe
                    st.found + st.notFound + st.notFoundUnconfirmed + st.failed + s.negativeHits + s.deduplicated
                st.relaysKnown shouldBe 4
                st.relaysAvailable shouldBe 4
                st.relaysOnBackoff shouldBe 0
                Regex("[0-9a-fA-F]{32,}").containsMatchIn(st.toString()) shouldBe false
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("fail closed: without a circuit policy no circuit is built").config(timeout = 60.seconds) {
            reset()
            val unpoliced = client({ descriptors }, node = noPolicy)
            try {
                wait(unpoliced.fetchBlock(rawCid(block(10)), 10.seconds, LookupContext.TIMELINE)) shouldBe
                    LookupResult.Unavailable(LookupFailure.ADMISSION)
                unpoliced.statsForTest().circuitsBuilt shouldBe 0
            } finally {
                unpoliced.close()
            }
        }
    })
