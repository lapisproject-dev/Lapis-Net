@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LookupBatchResponseBody
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
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** One batch or request as an exit relay saw it. */
private class SeenBatch(
    val relay: Int,
    val handle: Long,
    val keys: List<String>,
    val batch: Boolean,
)

/**
 * Wave Q16 on real loopback relays: LOOKUP version 2 (batches of timeline block lookups), the version-1 fallback, the
 * per-item verdicts and the counters.
 */
class OnionLookupClientBatchTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        afterSpec { all.forEach { it.close() } }
        val random = SecureRandom()

        val relayConfig =
            fastWireConfig(true).copy(
                lookupService =
                    OnionLookupServiceConfig(minAnswerDelay = 100.milliseconds, answerDelayJitter = 0.milliseconds),
            )
        val relays =
            List(3) {
                WireTestNode(relay = true, config = relayConfig, lookupSink = { ScriptSink2() }).also {
                    all +=
                        it
                }
            }
        val sender = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        relays.forEach { sender.connectTo(it) }
        val governor = CircuitBuildGovernor(ratePerMinute = 600, burst = 100, lookupBuildsPerMinute = 600)
        sender.wire.installCircuitPolicy(CircuitPolicy(governor))
        lateinit var descriptors: List<OnionRelayDescriptor>
        val provider =
            OnionPathProvider { last: OnionRelayDescriptor, _: CircuitPurpose ->
                descriptors.filter { it.identity != last.identity }.take(2) + last
            }
        val fast = OnionLookupClientConfig(buildTimeout = 15.seconds, answerTimeout = 10.seconds, maxAttempts = 2)

        val content = ConcurrentHashMap<String, ByteArray>()
        val seen = ConcurrentLinkedQueue<SeenBatch>()

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

        fun statusOf(key: ByteArray): Pair<Byte, ByteArray> {
            val bytes = content[hex(key)]
            return if (bytes != null) LookupStatus.FOUND to bytes else LookupStatus.NOT_FOUND to ByteArray(0)
        }

        /** Per item: (relay index, item index, key) to the answer; the default is honest. */
        fun script(item: (Int, Int, ByteArray) -> Pair<Byte, ByteArray> = { _, _, k -> statusOf(k) }) {
            for (i in relays.indices) {
                val svc = relays[i].wire.relayService!!
                svc.lookupAnswerOverrideForTest = { req: RelayAction.DeliverLookupRequest ->
                    seen += SeenBatch(i, req.circuitHandle, listOf(hex(req.key)), false)
                    val (st, c) = item(i, 0, req.key)
                    LookupResponseBody.encodeAnswer(req.requestId, st, c, random)
                }
                svc.lookupBatchAnswerOverrideForTest = { req: RelayAction.DeliverLookupBatch ->
                    val keys = req.keys
                    seen += SeenBatch(i, req.circuitHandle, keys.map { hex(it) }, true)
                    LookupBatchResponseBody.encodeBatch(
                        req.requestId,
                        keys.mapIndexed { n, k -> item(i, n, k) },
                        random,
                    )
                }
            }
        }

        fun reset() {
            content.clear()
            seen.clear()
            relays.forEach {
                val s = it.wire.relayService!!
                s.lookupAnswerOverrideForTest = null
                s.lookupBatchAnswerOverrideForTest = null
                s.simulateLegacyRelayForTest(false)
                s.simulateLookupV1OnlyForTest(false)
            }
        }

        fun block(size: Int) = ByteArray(size).also(random::nextBytes)

        fun stored(size: Int = 200): Cid2 {
            val b = block(size)
            val cid = rawCid(b)
            content[hex(cidKey(cid))] = b
            return Cid2(cid, b)
        }

        fun wait(f: CompletableFuture<LookupResult>) = f.get(90, TimeUnit.SECONDS)

        fun client(
            relaysOf: () -> List<OnionRelayDescriptor> = { descriptors },
            config: OnionLookupClientConfig = fast,
        ) = sender.wire.lookupClient(provider, relaysOf, config, clientClock = Clock.systemUTC())

        fun noLeak(c: OnionLookupClient) {
            awaitTrue(Duration.ofSeconds(30)) { c.openCircuits() == 0 } shouldBe true
            awaitTrue(Duration.ofSeconds(30)) { governor.openCount() == 0 } shouldBe true
        }

        test("descriptors converge") {
            descriptors = relays.map { it.wire.currentDescriptor()!! }
            awaitTrue(Duration.ofSeconds(90)) {
                descriptors.all { d ->
                    sender.wire.descriptors.current(d.identity, Clock.systemUTC().millis() / 1000) != null
                }
            } shouldBe true
        }

        test("Q16-1: four queued timeline lookups are one version-2 request on one circuit; every item is verified") {
            reset()
            script()
            val blocks = List(4) { stored() }
            val c = client()
            try {
                val futures = blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }
                futures.forEachIndexed { i, f ->
                    wait(f).shouldBeInstanceOf<LookupResult.Found>().bytes.contentEquals(blocks[i].bytes) shouldBe true
                }
                val st = c.statsForTest()
                st.batchesSent shouldBe 1
                st.batchItemsSent shouldBe 4
                st.circuitsBuilt shouldBe 1
                st.v1Fallbacks shouldBe 0
                seen.size shouldBe 1
                seen.single().batch shouldBe true
                seen.single().keys.size shouldBe 4
                // each item counted exactly once
                val sc = c.statusCounters()
                sc.requested shouldBe 4
                sc.found shouldBe 4
                sc.rejected shouldBe 0
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("Q16-2: a single lookup stays version 1; MAILBOX and IPNS lookups are never batched").config(
            timeout = 240.seconds,
        ) {
            reset()
            script()
            val b = stored()
            val c = client()
            try {
                wait(c.fetchBlock(b.cid, 60.seconds, LookupContext.TIMELINE)).shouldBeInstanceOf<LookupResult.Found>()
                seen.single().batch shouldBe false
                seen.clear()
                val mailbox = List(3) { stored() }
                val futures = mailbox.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.MAILBOX) }
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                seen.none { it.batch } shouldBe true
                seen.map { it.handle to it.relay }.distinct().size shouldBe 3
                c.statsForTest().batchesSent shouldBe 0
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("Q16-3: batching can be switched off; the lookups then run one after the other as before").config(
            timeout = 240.seconds,
        ) {
            reset()
            script()
            val blocks = List(3) { stored() }
            val c = client(config = fast.copy(batchItemsTimeline = 1))
            try {
                blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                c.statsForTest().batchesSent shouldBe 0
                seen.none { it.batch } shouldBe true
                seen.size shouldBe 3
                c.statsForTest().circuitsReused shouldBe 2
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test(
            "Q16-4: a lying item: the relay gets the 24 h backoff, verified items are kept, the rest goes to another exit",
        ).config(
            timeout = 240.seconds,
        ) {
            reset()
            val blocks = List(4) { stored() }
            val liar = AtomicInteger(-1)
            script { relay, n, k ->
                if (n == 1 && liar.compareAndSet(-1, relay)) {
                    LookupStatus.FOUND to block(200)
                } else {
                    statusOf(k)
                }
            }
            val c = client()
            try {
                val futures = blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }
                futures.forEachIndexed { i, f ->
                    wait(f).shouldBeInstanceOf<LookupResult.Found>().bytes.contentEquals(blocks[i].bytes) shouldBe true
                }
                c.statsForTest().rejected shouldBe 1
                c.statusCounters().rejected shouldBe 1
                c.inBackoff(relays[liar.get()].key) shouldBe true
                // item 1 (the lie) was asked again elsewhere; the verified items 0, 2 and 3 were not
                val first = seen.first()
                first.batch shouldBe true
                val later = seen.drop(1)
                later.sumOf { it.keys.size } shouldBe 1
                later.none { it.relay == liar.get() } shouldBe true
                c.statusCounters().found shouldBe 4
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("Q16-5: MALFORMED for a key the client checked is a manipulation").config(timeout = 240.seconds) {
            reset()
            val blocks = List(2) { stored() }
            val liar = AtomicInteger(-1)
            script { relay, n, k ->
                if (n == 0 && liar.compareAndSet(-1, relay)) LookupStatus.MALFORMED to ByteArray(0) else statusOf(k)
            }
            val c = client()
            try {
                blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                c.inBackoff(relays[liar.get()].key) shouldBe true
                c.statsForTest().rejected shouldBe 1
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("Q16-6: NOT_FOUND for two of four items: those two are cross-checked as a batch at a second exit").config(
            timeout = 240.seconds,
        ) {
            reset()
            val present = List(2) { stored() }
            val missing = List(2) { Cid2(rawCid(block(20)), ByteArray(0)) }
            script()
            val c = client()
            try {
                val futures =
                    listOf(present[0], missing[0], present[1], missing[1]).map {
                        c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE)
                    }
                wait(futures[0]).shouldBeInstanceOf<LookupResult.Found>()
                wait(futures[1]) shouldBe LookupResult.NotFound(true)
                wait(futures[2]).shouldBeInstanceOf<LookupResult.Found>()
                wait(futures[3]) shouldBe LookupResult.NotFound(true)
                val batches = seen.filter { it.batch }
                batches.size shouldBe 2
                batches[0].keys.size shouldBe 4
                // the second batch carries only the two missing keys, at a different exit
                batches[1].keys.size shouldBe 2
                (batches[1].relay != batches[0].relay) shouldBe true
                c.statsForTest().crossChecks shouldBe 2
                val sc = c.statusCounters()
                sc.requested shouldBe 4
                sc.found shouldBe 2
                sc.notFound shouldBe 2
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test(
            "Q16-7: a refusal of some items costs the relay nothing; a refusal of all items puts it on the failure backoff",
        ).config(
            timeout = 240.seconds,
        ) {
            reset()
            val blocks = List(3) { stored() }
            val limited = AtomicInteger(-1)
            script { relay, n, k ->
                if (n == 0 &&
                    limited.compareAndSet(-1, relay)
                ) {
                    LookupStatus.RATE_LIMITED to ByteArray(0)
                } else {
                    statusOf(k)
                }
            }
            val c = client()
            try {
                blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                c.inBackoff(relays[limited.get()].key) shouldBe false
                c.statsForTest().rejected shouldBe 0
                // the refused item was asked at another exit
                seen.drop(1).none { it.relay == limited.get() } shouldBe true
                noLeak(c)
            } finally {
                c.close()
            }
            reset()
            val refuser = AtomicInteger(-1)
            script { relay, _, k ->
                if (refuser.compareAndSet(-1, relay) || refuser.get() == relay) {
                    LookupStatus.RATE_LIMITED to ByteArray(0)
                } else {
                    statusOf(k)
                }
            }
            val more = List(3) { stored() }
            val c2 = client()
            try {
                more.map { c2.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                c2.inBackoff(relays[refuser.get()].key) shouldBe true
                noLeak(c2)
            } finally {
                c2.close()
            }
        }

        test(
            "Q16-8: a relay that knows version 1 only: the group goes on as version-1 requests on the same circuit, no penalty",
        ).config(
            timeout = 240.seconds,
        ) {
            reset()
            script()
            relays.forEach { it.wire.relayService!!.simulateLookupV1OnlyForTest(true) }
            val blocks = List(4) { stored() }
            val c = client({ listOf(descriptors[0]) })
            try {
                blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                val st = c.statsForTest()
                st.v1Fallbacks shouldBe 1
                st.batchesSent shouldBe 1
                // the refused batch used one of the four requests a circuit takes: three keys follow on it, the fourth
                // needs a new circuit (its exit has seen the key already, so no further key is shown)
                st.circuitsBuilt shouldBe 2
                st.circuitsReused shouldBe 2
                c.inBackoff(relays[0].key) shouldBe false
                seen.filter { !it.batch }.size shouldBe 4
                seen.map { it.handle }.distinct().size shouldBe 2
                val sc = c.statusCounters()
                sc.requested shouldBe 4
                sc.found shouldBe 4
                // the exit is remembered: a later group is not sent as a batch again
                val more = List(3) { stored() }
                more.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                c.statsForTest().batchesSent shouldBe 1
                noLeak(c)
            } finally {
                relays.forEach { it.wire.relayService!!.simulateLookupV1OnlyForTest(false) }
                c.close()
            }
        }

        test(
            "Q16-9: a relay older than the lookup role destroys the circuit on a batch: unsupported backoff, found elsewhere",
        ).config(
            timeout = 240.seconds,
        ) {
            reset()
            script()
            relays[0].wire.relayService!!.simulateLegacyRelayForTest(true)
            val blocks = List(3) { stored() }
            val c = client({ listOf(descriptors[0], descriptors[1], descriptors[2]) })
            try {
                blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }.forEach {
                    wait(it).shouldBeInstanceOf<LookupResult.Found>()
                }
                // random exit choice: if relay 0 was picked, it is on the unsupported backoff and nothing was penalised twice
                if (c.statsForTest().legacySuspected > 0) {
                    c.statsForTest().legacySuspected shouldBe 1
                    c.inBackoff(relays[0].key) shouldBe true
                }
                noLeak(c)
            } finally {
                relays[0].wire.relayService!!.simulateLegacyRelayForTest(false)
                c.close()
            }
        }

        test(
            "Q16-10: the batch size and the keys per circuit are bounded (six lookups: a batch of four, then a new circuit)",
        ).config(
            timeout = 240.seconds,
        ) {
            reset()
            script()
            val blocks = List(6) { stored() }
            val c = client()
            try {
                val futures = blocks.map { c.fetchBlock(it.cid, 60.seconds, LookupContext.TIMELINE) }
                futures.forEach { wait(it).shouldBeInstanceOf<LookupResult.Found>() }
                // six lookups: a batch of four, then the rest on a new circuit (a circuit shows 4 keys to its exit)
                seen.filter { it.batch }.all { it.keys.size <= 4 } shouldBe true
                seen.groupBy { it.handle to it.relay }.values.all { g -> g.sumOf { it.keys.size } <= 4 } shouldBe true
                c.statsForTest().circuitsBuilt shouldBe 2
                noLeak(c)
            } finally {
                c.close()
            }
        }

        test("Q16-11: configuration is validated") {
            shouldThrow<IllegalArgumentException> { OnionLookupClientConfig(batchItemsTimeline = 0) }
            shouldThrow<IllegalArgumentException> { OnionLookupClientConfig(batchItemsTimeline = 9) }
            shouldThrow<IllegalArgumentException> {
                OnionLookupClientConfig(batchItemsTimeline = 4, itemsPerCircuitTimeline = 3)
            }
            shouldThrow<IllegalArgumentException> { OnionLookupClientConfig(itemsPerCircuitTimeline = 17) }
            shouldThrow<IllegalArgumentException> { OnionLookupClientConfig(v1OnlyMemoEntries = 0) }
            shouldThrow<IllegalArgumentException> { OnionLookupClientConfig(v1OnlyMemoTtl = kotlin.time.Duration.ZERO) }
            OnionLookupClientConfig(batchItemsTimeline = 8, itemsPerCircuitTimeline = 8).batchItemsTimeline shouldBe 8
        }
    })

private class Cid2(
    val cid: io.ipfs.cid.Cid,
    val bytes: ByteArray,
)

/** A sink that finds nothing (the overrides answer instead). */
private class ScriptSink2 : OnionLookupSink {
    override fun fetchBlock(
        cid: io.ipfs.cid.Cid,
        maxBytes: Int,
        timeout: java.time.Duration,
    ): LookupOutcome = LookupOutcome.NotFound

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: java.time.Duration,
    ): LookupOutcome = LookupOutcome.NotFound
}
