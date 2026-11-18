@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.confinement.ConnectionConfinement
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onionwire.WireTestNode
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import net.lapisphilosophorum.lapisnet.onionwire.awaitTrue
import net.lapisphilosophorum.lapisnet.onionwire.fastWireConfig
import net.lapisphilosophorum.lapisnet.onionwire.key
import net.lapisphilosophorum.lapisnet.onionwire.path.CircuitBuildGovernor
import net.lapisphilosophorum.lapisnet.onionwire.path.MapLocator
import net.lapisphilosophorum.lapisnet.onionwire.path.v4
import net.lapisphilosophorum.lapisnet.onionwire.peerId
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.DeferredRemoteContentSource
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockState
import java.nio.file.Files
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private fun nowSeconds() = Clock.systemUTC().millis() / 1000

private fun bootstrap(n: WireTestNode): Multiaddr =
    n.node
        .listenAddresses()
        .first()
        .withP2P(n.peerId)

/** The production sink with a call counter. */
private class CountedSink(
    storage: NabuStorage,
) : OnionLookupSink {
    private val delegate = NabuLookupSink(storage)
    val calls = AtomicLong()

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): LookupOutcome {
        calls.incrementAndGet()
        return delegate.fetchBlock(cid, maxBytes, timeout)
    }

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): LookupOutcome {
        calls.incrementAndGet()
        return delegate.resolveIpnsRecord(routingKey, timeout)
    }
}

/**
 * Wave V0.10.0-J3 on real loopback nodes: the consumers of lookups through circuits. A holder in normal mode `provide`s
 * post bodies explicitly (in production nobody announces post bodies in the DHT, see docs/anonymity.adoc, Q20); five
 * relays with the production sink; a confined client in anonymity mode. Covers the timeline code path
 * ([NabuStorage.localOrRemoteState], as the browser's `TimelineBodyResolver` uses it) with circuit reuse, the context
 * separation, the NOT_FOUND cross-check, the Bitswap gap behind a found mark, and a lying relay. All nodes sit on
 * 127.0.0.1 with an injected locator; network diversity is NOT verified over real networks here.
 */
class MultiNodeOnionLookupConsumersTest :
    FunSpec({
        val all = ArrayList<WireTestNode>()
        val runtimes = ArrayList<AnonymityRuntime>()
        afterSpec {
            runtimes.forEach { runCatching { it.close() } }
            all.forEach { it.close() }
        }
        val relayConfig =
            fastWireConfig(true).copy(
                lookupService =
                    OnionLookupServiceConfig(minAnswerDelay = 200.milliseconds, answerDelayJitter = 100.milliseconds),
            )
        val sinks = ArrayList<CountedSink>()
        val relays =
            List(5) {
                WireTestNode(
                    relay = true,
                    config = relayConfig,
                    lookupSink = { s -> CountedSink(s).also { c -> synchronized(sinks) { sinks += c } } },
                ).also { all += it }
            }
        val holder = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = MapLocator()
        val random = SecureRandom()
        lateinit var client: WireTestNode
        lateinit var runtime: AnonymityRuntime
        lateinit var confinement: ConnectionConfinement
        val deferred = DeferredRemoteContentSource()

        // the lookup-relay seam: null = every relay; otherwise only these identities are lookup candidates
        val allowedRef =
            java.util.concurrent.atomic
                .AtomicReference<Set<Secp256k1PublicKey>?>(null)

        fun calls(): List<Long> = synchronized(sinks) { sinks.map { it.calls.get() } }

        fun lookup() = runtime.lookupClientForTest()

        /** Relays the path selector offers as exits (the client's guards are never its exits). */
        fun exitRelays(): List<WireTestNode> {
            val guards = runtime.guardIdentitiesForTest().toSet()
            return relays.filter { it.key !in guards }
        }

        fun publish(size: Int): Pair<Cid, ByteArray> {
            val bytes = ByteArray(size).also(random::nextBytes)
            val cid = holder.storage.put(bytes)
            holder.storage.provide(cid)
            return cid to bytes
        }

        test("setup: relays reach the holder through the DHT; a confined client runs anonymity mode").config(
            timeout = 180.seconds,
        ) {
            relays.forEach { r ->
                r.peerDirectory.announce(
                    PeerRecord.create(
                        r.identity,
                        r.node.listenAddresses(),
                        emptySet(),
                        1,
                        nowSeconds() + 3600,
                    ),
                )
                r.storage.connectToDhtPeer(bootstrap(holder)) shouldBe true
                holder.storage.connectToDhtPeer(bootstrap(r)) shouldBe true
            }
            val descriptors =
                relays.map { r ->
                    awaitTrue { r.wire.currentDescriptor() != null }.let { r.wire.currentDescriptor()!! }
                }
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(30 + i, i)) }
            awaitTrue(Duration.ofSeconds(90)) {
                descriptors.all { d ->
                    relays[0].wire.descriptors.current(d.identity, nowSeconds()) != null &&
                        relays[0].peerDirectory.lookup(d.identity) != null
                }
            } shouldBe true
            confinement = ConnectionConfinement()
            client =
                WireTestNode(
                    relay = false,
                    directoryMode = DirectoryAnonymityMode.ON,
                    confinement = confinement,
                    remote = deferred,
                ).also { all += it }
            runtime =
                AnonymityRuntime
                    .start(
                        client.wire,
                        client.identity,
                        client.dir,
                        { null },
                        locator,
                        InMemoryDirectoryModeStore(
                            DirectoryModeState(
                                DirectoryAnonymityMode.OFF,
                                System.currentTimeMillis() - 5000,
                            ),
                        ),
                        PrekeyStore.create(Files.createTempDirectory("j3-prekeys").resolve("prekeys"), client.identity),
                        Ed25519KeyPair.generate(),
                        supervisor = client.supervisor,
                        governor =
                            CircuitBuildGovernor(
                                Clock.systemUTC(),
                                ratePerMinute = 600,
                                burst = 100,
                                lookupBuildsPerMinute = 600,
                            ),
                        confinement = confinement,
                        bootstrapPeers = listOf(bootstrap(relays[0])),
                        lookupRelayFilter = { d -> allowedRef.get()?.contains(d.identity) ?: true },
                    ).also { runtimes += it }
            deferred.bind(runtime.remoteContentSource())
            awaitTrue(Duration.ofSeconds(90)) {
                runtime.status().connectionState == "guards-only" && runtime.status().guards == 2
            } shouldBe true
            // the lookup relays are known (the three relays that are not guards), so the first lookups find an exit
            awaitTrue(Duration.ofSeconds(90)) { runtime.status().lookupRelaysKnown >= 3 } shouldBe true
        }

        fun guardPeers(): Set<PeerId> =
            runtime
                .guardIdentitiesForTest()
                .mapNotNull {
                    client.wire.descriptors
                        .current(
                            it,
                            nowSeconds(),
                        )?.peerId
                }.toSet()

        fun clientRemotes(): Set<PeerId> =
            client.node.host.network.connections
                .filter { !it.closeFuture().isDone }
                .map { it.secureSession().remoteId }
                .toSet()

        fun holderSeesClient(): Boolean =
            holder.node.host.network.connections
                .any { it.secureSession().remoteId == client.node.peerId }

        test(
            "(a) six timeline bodies arrive through at most two circuits; only guards, no Bitswap, holder blind",
        ).config(
            timeout = 300.seconds,
        ) {
            val posts = List(6) { publish(600 + it * 100) }
            val refusedBefore = confinement.refusedDials
            val builtBefore = lookup().statsForTest().circuitsBuilt
            val reusedBefore = lookup().statsForTest().circuitsReused
            val started = System.nanoTime()
            // exactly the timeline code path: a non-blocking view that schedules background lookups
            posts.forEach { (cid, _) ->
                client.storage.localOrRemoteState(cid, schedule = true).state shouldBe
                    RemoteBlockState.FETCHING
            }
            // as the timeline does on every reload: a body whose lookup ended without reaching a relay is asked again
            val arrived =
                awaitTrue(Duration.ofSeconds(240)) {
                    posts.all { (cid, _) ->
                        client.storage.localOrRemoteState(cid, schedule = true).state == RemoteBlockState.CACHED
                    }
                }
            println("J3 measurement: (a) client stats ${lookup().statsForTest()}")
            arrived shouldBe true
            val millis = (System.nanoTime() - started) / 1_000_000
            posts.forEach { (cid, bytes) -> client.storage.getLocal(cid)!!.toList() shouldBe bytes.toList() }
            val built = lookup().statsForTest().circuitsBuilt - builtBefore
            val reused = lookup().statsForTest().circuitsReused - reusedBefore
            println("J3 measurement: 6 timeline bodies in $millis ms over $built circuit(s), $reused reused request(s)")
            (built <= 2) shouldBe true
            reused shouldBe (6 - built)
            (clientRemotes() - guardPeers()).shouldBeEmpty()
            confinement.refusedDials shouldBe refusedBefore
            client.storage.bitswapRequestCount shouldBe 0
            holderSeesClient() shouldBe false
            awaitTrue(Duration.ofSeconds(30)) { lookup().openCircuits() == 0 } shouldBe true
        }

        test("(b) a timeline lookup and a mailbox lookup at the same time never share a circuit").config(
            timeout = 240.seconds,
        ) {
            val (timelineCid, _) = publish(500)
            val (mailboxCid, mailboxBytes) = publish(700)
            val before = lookup().statsForTest()
            client.storage.localOrRemoteState(timelineCid, schedule = true)
            val mailbox = lookup().fetchBlock(mailboxCid, 120.seconds)
            mailbox
                .get(150, TimeUnit.SECONDS)
                .shouldBeInstanceOf<LookupResult.Found>()
                .bytes
                .toList() shouldBe
                mailboxBytes.toList()
            awaitTrue(Duration.ofSeconds(150)) {
                client.storage.localOrRemoteState(timelineCid, schedule = false).state == RemoteBlockState.CACHED
            } shouldBe true
            val after = lookup().statsForTest()
            (after.circuitsBuilt - before.circuitsBuilt) shouldBe 2
            (after.circuitsReused - before.circuitsReused) shouldBe 0
        }

        test("(d) a CID nobody holds: two different exits looked it up, the result is a confirmed NOT_FOUND").config(
            timeout = 240.seconds,
        ) {
            val missing = rawCid(ByteArray(64).also(random::nextBytes))
            val before = calls()
            val started = System.nanoTime()
            lookup().fetchBlock(missing, 120.seconds, LookupContext.TIMELINE).get(150, TimeUnit.SECONDS) shouldBe
                LookupResult.NotFound(confirmed = true)
            println("J3 measurement: confirmed NOT_FOUND in ${(System.nanoTime() - started) / 1_000_000} ms")
            calls().zip(before).count { (a, b) -> a > b } shouldBe 2
            holderSeesClient() shouldBe false
        }

        test("(c) the Bitswap gap: a relay that already delivered X does not answer NOT_FOUND; a second relay delivers")
            .config(timeout = 300.seconds) {
                val (x, bytes) = publish(900)
                val a = exitRelays()[0]
                val b = exitRelays()[1]
                allowedRef.set(setOf(a.key))
                try {
                    lookup()
                        .fetchBlock(
                            x,
                            120.seconds,
                        ).get(150, TimeUnit.SECONDS)
                        .shouldBeInstanceOf<LookupResult.Found>()
                    // the same key again through A only (the client has no positive cache): never a NOT_FOUND
                    val again = lookup().fetchBlock(x, 120.seconds).get(150, TimeUnit.SECONDS)
                    println("J3 measurement: second lookup of X through the same relay: $again")
                    // the found mark: denied (TIMEOUT, then unavailable), never a NOT_FOUND that would be cached
                    again.shouldBeInstanceOf<LookupResult.Unavailable>()
                    allowedRef.set(setOf(a.key, b.key))
                    val third = lookup().fetchBlock(x, 120.seconds).get(150, TimeUnit.SECONDS)
                    third.shouldBeInstanceOf<LookupResult.Found>().bytes.toList() shouldBe bytes.toList()
                } finally {
                    allowedRef.set(null)
                }
            }

        test("(e) a lying relay: its answer is rejected, it goes on backoff, the next relay delivers the right block")
            .config(timeout = 300.seconds) {
                val (cid, bytes) = publish(800)
                // the exit of (c) may still be on its backoff: the third exit lies, the second one is honest
                val liar = exitRelays()[2]
                val honest = exitRelays()[1]
                allowedRef.set(setOf(liar.key))
                liar.wire.relayService!!.lookupAnswerOverrideForTest = { req ->
                    // the liar is asked first; from now on the honest relay is a candidate too
                    allowedRef.set(setOf(liar.key, honest.key))
                    LookupResponseBody.encodeAnswer(
                        req.requestId,
                        LookupStatus.FOUND,
                        ByteArray(800).also(random::nextBytes),
                        random,
                    )
                }
                try {
                    val rejectedBefore = lookup().statsForTest().rejected
                    val r = lookup().fetchBlock(cid, 120.seconds).get(150, TimeUnit.SECONDS)
                    r.shouldBeInstanceOf<LookupResult.Found>().bytes.toList() shouldBe bytes.toList()
                    (lookup().statsForTest().rejected - rejectedBefore) shouldBe 1
                    lookup().inBackoff(liar.key) shouldBe true
                    runtime.status().lookupRejected shouldBe lookup().statusCounters().rejected
                } finally {
                    liar.wire.relayService!!.lookupAnswerOverrideForTest = null
                    allowedRef.set(null)
                }
            }

        test("stop: the source is unbound, no lookup circuit stays open").config(timeout = 60.seconds) {
            deferred.unbind()
            runtime.close()
            lookup().openCircuits() shouldBe 0
            awaitTrue(Duration.ofSeconds(30)) { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe
                true
        }
    })
