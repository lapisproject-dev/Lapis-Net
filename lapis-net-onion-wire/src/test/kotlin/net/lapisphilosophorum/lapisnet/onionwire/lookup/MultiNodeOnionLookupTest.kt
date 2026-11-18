@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.confinement.ConnectionConfinement
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPrivKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
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
import java.nio.file.Files
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private fun now() = Clock.systemUTC().millis() / 1000

private fun bootstrapAddress(n: WireTestNode): Multiaddr =
    n.node
        .listenAddresses()
        .first()
        .withP2P(n.peerId)

/** The production sink with a call counter. */
private class CountingSink(
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
 * Wave V0.10.0-J2 on real loopback nodes: a holder in normal mode with a block of a multi-fragment class and an IPNS
 * value; five relays (normal mode, `--onion-relay`, the production [NabuLookupSink] on their own network-mode storage,
 * DHT-connected to the holder); a confined client in anonymity mode whose LOCAL_ONLY storage gets the circuit-backed
 * source through a [DeferredRemoteContentSource]. The client reaches the content only through circuits: it holds
 * connections to its guards only and the holder never sees it. All nodes sit on 127.0.0.1, so the locator is injected
 * with synthetic networks; network diversity is NOT verified over real networks here.
 */
class MultiNodeOnionLookupTest :
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
        val sinks = ArrayList<CountingSink>()
        val relays =
            List(5) {
                WireTestNode(
                    relay = true,
                    config = relayConfig,
                    lookupSink = { s -> CountingSink(s).also { c -> synchronized(sinks) { sinks += c } } },
                ).also { all += it }
            }
        val holder = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = MapLocator()
        val payload = ByteArray(12_000).also(SecureRandom()::nextBytes) // class 2 (32 KiB, 46 cells)
        lateinit var cid: Cid
        lateinit var client: WireTestNode
        lateinit var runtime: AnonymityRuntime
        lateinit var confinement: ConnectionConfinement
        val deferred = DeferredRemoteContentSource()

        fun holderAddress() = bootstrapAddress(holder)

        test("the holder publishes a block and an IPNS value; the relays reach it through the DHT").config(
            timeout = 120.seconds,
        ) {
            relays.forEach { r ->
                r.peerDirectory.announce(
                    PeerRecord.create(
                        r.identity,
                        r.node.listenAddresses(),
                        emptySet(),
                        1,
                        now() + 3600,
                    ),
                )
                r.storage.connectToDhtPeer(holderAddress()) shouldBe true
                holder.storage.connectToDhtPeer(bootstrapAddress(r)) shouldBe true
            }
            cid = holder.storage.put(payload)
            holder.storage.provide(cid)
            val published =
                holder.storage.publishIpnsValue(
                    holder.identity.deriveLibp2pPrivKey(),
                    "holder value".toByteArray(),
                    7,
                    Instant.now().plus(Duration.ofHours(1)),
                )
            (published.acknowledged >= 1) shouldBe true
            val descriptors =
                relays.map { r ->
                    awaitTrue { r.wire.currentDescriptor() != null }.let { r.wire.currentDescriptor()!! }
                }
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(20 + i, i)) }
            awaitTrue(Duration.ofSeconds(90)) {
                descriptors.all { d ->
                    relays[0].wire.descriptors.current(d.identity, now()) != null &&
                        relays[0].peerDirectory.lookup(d.identity) != null
                }
            } shouldBe true
        }

        test(
            "a confined client starts anonymity mode with the circuit-backed source bound",
        ).config(timeout = 120.seconds) {
            confinement = ConnectionConfinement()
            client =
                WireTestNode(
                    relay = false,
                    directoryMode = DirectoryAnonymityMode.ON,
                    confinement = confinement,
                    remote = deferred,
                ).also { all += it }
            val modeStore =
                InMemoryDirectoryModeStore(
                    DirectoryModeState(
                        DirectoryAnonymityMode.OFF,
                        System.currentTimeMillis() - 5000,
                    ),
                )
            runtime =
                AnonymityRuntime
                    .start(
                        client.wire,
                        client.identity,
                        client.dir,
                        { null },
                        locator,
                        modeStore,
                        PrekeyStore.create(
                            Files.createTempDirectory("lookup-prekeys").resolve("prekeys"),
                            client.identity,
                        ),
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
                        bootstrapPeers = listOf(bootstrapAddress(relays[0])),
                    ).also { runtimes += it }
            deferred.bind(runtime.remoteContentSource())
            awaitTrue(Duration.ofSeconds(90)) {
                runtime.status().connectionState == "guards-only" && runtime.status().guards == 2
            } shouldBe true
        }

        fun guardPeers(): Set<PeerId> =
            runtime
                .guardIdentitiesForTest()
                .mapNotNull {
                    client.wire.descriptors
                        .current(it, now())
                        ?.peerId
                }.toSet()

        fun clientRemotes(): Set<PeerId> =
            client.node.host.network.connections
                .filter { !it.closeFuture().isDone }
                .map { it.secureSession().remoteId }
                .toSet()

        fun holderSeesClient(): Boolean =
            holder.node.host.network.connections
                .any { it.secureSession().remoteId == client.node.peerId }

        test("the block and the IPNS value arrive through circuits; only one exit relay looked them up").config(
            timeout = 240.seconds,
        ) {
            val refusedBefore = confinement.refusedDials
            val callsBefore = synchronized(sinks) { sinks.map { it.calls.get() } }
            val started = System.nanoTime()
            val got = client.storage.getThroughRemote(cid, Duration.ofSeconds(120)).shouldNotBeNull()
            val blockMillis = (System.nanoTime() - started) / 1_000_000
            got.toList() shouldBe payload.toList()
            client.storage.getLocal(cid).shouldNotBeNull()
            val afterBlock = synchronized(sinks) { sinks.map { it.calls.get() } }
            afterBlock.zip(callsBefore).count { (a, b) -> a > b } shouldBe 1

            val ipnsStart = System.nanoTime()
            val value = client.storage.resolveIpnsValue(holder.node.peerId, Duration.ofSeconds(120)).shouldNotBeNull()
            val ipnsMillis = (System.nanoTime() - ipnsStart) / 1_000_000
            String(value.value) shouldBe "holder value"
            value.sequence shouldBe 7
            val afterIpns = synchronized(sinks) { sinks.map { it.calls.get() } }
            afterIpns.zip(afterBlock).count { (a, b) -> a > b } shouldBe 1
            println("J2 measurement: block of ${payload.size} bytes in $blockMillis ms, IPNS value in $ipnsMillis ms")

            // only guard connections; the lookups caused no refused dial; the holder never saw the client
            (clientRemotes() - guardPeers()).shouldBeEmpty()
            confinement.refusedDials shouldBe refusedBefore
            holderSeesClient() shouldBe false
            runtime.lookupClientForTest().openCircuits() shouldBe 0
        }

        test("only older relays: the lookup ends unavailable without a direct dial, then another relay answers").config(
            timeout = 300.seconds,
        ) {
            val refusedBefore = confinement.refusedDials
            relays.forEach { it.wire.relayService!!.simulateLegacyRelayForTest(true) }
            val second = ByteArray(700).also(SecureRandom()::nextBytes)
            val secondCid = holder.storage.put(second)
            holder.storage.provide(secondCid)
            val lookup = runtime.lookupClientForTest()
            lookup
                .fetchBlock(secondCid, 120.seconds)
                .get(150, java.util.concurrent.TimeUnit.SECONDS)
                .shouldBeInstanceOf<LookupResult.Unavailable>()
            (lookup.statsForTest().legacySuspected >= 1) shouldBe true
            val penalised = relays.filter { lookup.inBackoff(it.key) }
            (penalised.size in 1..2) shouldBe true
            confinement.refusedDials shouldBe refusedBefore
            holderSeesClient() shouldBe false
            (clientRemotes() - guardPeers()).shouldBeEmpty()

            // the relays are upgraded; the penalised ones stay on their backoff and are not chosen
            relays.forEach { it.wire.relayService!!.simulateLegacyRelayForTest(false) }
            val callsBefore = synchronized(sinks) { sinks.map { it.calls.get() } }
            client.storage
                .getThroughRemote(secondCid, Duration.ofSeconds(120))
                .shouldNotBeNull()
                .toList() shouldBe
                second.toList()
            val answering =
                relays.indices.filter { i -> synchronized(sinks) { sinks[i].calls.get() } > callsBefore[i] }
            answering.size shouldBe 1
            penalised.none { it === relays[answering.single()] } shouldBe true
            holderSeesClient() shouldBe false
        }

        test("stopping unbinds the source first; afterwards a miss is answered locally with null").config(
            timeout = 60.seconds,
        ) {
            deferred.unbind()
            runtime.close()
            val missing = holder.storage.put("never fetched".toByteArray())
            client.storage.getThroughRemote(missing, Duration.ofSeconds(2)) shouldBe null
            awaitTrue(Duration.ofSeconds(30)) { relays.all { it.wire.relayService!!.circuitCount() == 0 } } shouldBe
                true
        }
    })
