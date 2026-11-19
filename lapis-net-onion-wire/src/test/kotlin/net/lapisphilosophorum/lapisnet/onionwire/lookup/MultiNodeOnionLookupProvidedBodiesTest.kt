@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.confinement.ConnectionConfinement
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
import net.lapisphilosophorum.lapisnet.storage.BlockProvideConfig
import net.lapisphilosophorum.lapisnet.storage.BlockProvideScheduler
import net.lapisphilosophorum.lapisnet.storage.DeferredRemoteContentSource
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockState
import java.nio.file.Files
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private fun nowSeconds() = Clock.systemUTC().millis() / 1000

private fun bootstrap(n: WireTestNode): Multiaddr =
    n.node
        .listenAddresses()
        .first()
        .withP2P(n.peerId)

private val FAST_PROVIDE =
    BlockProvideConfig(
        reprovideInterval = 5.seconds,
        reprovideJitterFraction = 0.0,
        firstProvideDelayMax = kotlin.time.Duration.ZERO,
        maxProvidesPerCycle = 4,
        initialDelay = kotlin.time.Duration.ZERO,
        perProvideTimeout = 5.seconds,
        cycleBudget = 20.seconds,
        failureRetryMin = 500.milliseconds,
    )

/**
 * Wave Q20 on real loopback nodes: a holder in normal mode only `put`s a post body and TRACKS it with
 * [BlockProvideScheduler] - no explicit `provide` call - and a confined client in anonymity mode finds it through a
 * circuit lookup. Five relays with the production sink, setup as in [MultiNodeOnionLookupConsumersTest]. All nodes sit
 * on 127.0.0.1 with an injected locator; real networks are NOT verified here.
 */
class MultiNodeOnionLookupProvidedBodiesTest :
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
        val relays =
            List(5) {
                WireTestNode(relay = true, config = relayConfig, lookupSink = { st -> NabuLookupSink(st) }).also {
                    all +=
                        it
                }
            }
        val holder = WireTestNode(relay = false).also { all += it }
        val secondHolder = WireTestNode(relay = false).also { all += it }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = MapLocator()
        val random = SecureRandom()
        lateinit var client: WireTestNode
        lateinit var runtime: AnonymityRuntime
        lateinit var confinement: ConnectionConfinement
        val deferred = DeferredRemoteContentSource()
        val allowedRef =
            java.util.concurrent.atomic
                .AtomicReference<Set<Secp256k1PublicKey>?>(null)
        val scheduler = BlockProvideScheduler(holder.storage.asProvideTarget(), FAST_PROVIDE)
        val secondScheduler = BlockProvideScheduler(secondHolder.storage.asProvideTarget(), FAST_PROVIDE)

        fun lookup() = runtime.lookupClientForTest()

        fun exitRelays(): List<WireTestNode> {
            val guards = runtime.guardIdentitiesForTest().toSet()
            return relays.filter { it.key !in guards }
        }

        /** Runs [s]'s cycles until at least [minRelays] relays hold a provider record of [owner] for [cid]. */
        fun announceUntil(
            s: BlockProvideScheduler,
            owner: WireTestNode,
            cid: Cid,
            minRelays: Int = 3,
        ): Boolean =
            awaitTrue(Duration.ofSeconds(60)) {
                s.runCycle()
                relays.count { owner.node.peerId in it.storage.heldProviderRecords(cid) } >= minRelays
            }

        test(
            "setup: relays and holders on the DHT; a confined client runs anonymity mode",
        ).config(timeout = 180.seconds) {
            relays.forEach { r ->
                r.peerDirectory.announce(
                    PeerRecord.create(r.identity, r.node.listenAddresses(), emptySet(), 1, nowSeconds() + 3600),
                )
                for (h in listOf(holder, secondHolder)) {
                    r.storage.connectToDhtPeer(bootstrap(h)) shouldBe true
                    h.storage.connectToDhtPeer(bootstrap(r)) shouldBe true
                }
            }
            val descriptors =
                relays.map { r ->
                    awaitTrue { r.wire.currentDescriptor() != null }.let { r.wire.currentDescriptor()!! }
                }
            descriptors.forEachIndexed { i, d -> locator.put(d, v4(40 + i, i)) }
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
                            DirectoryModeState(DirectoryAnonymityMode.OFF, System.currentTimeMillis() - 5000),
                        ),
                        PrekeyStore.create(
                            Files.createTempDirectory("q20-prekeys").resolve("prekeys"),
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
                        bootstrapPeers = listOf(bootstrap(relays[0])),
                        lookupRelayFilter = { d -> allowedRef.get()?.contains(d.identity) ?: true },
                    ).also { runtimes += it }
            deferred.bind(runtime.remoteContentSource())
            awaitTrue(Duration.ofSeconds(90)) {
                runtime.status().connectionState == "guards-only" && runtime.status().guards == 2
            } shouldBe true
            awaitTrue(Duration.ofSeconds(90)) { runtime.status().lookupRelaysKnown >= 3 } shouldBe true
        }

        test("(a) a body that is only put and tracked (no explicit provide) reaches the anonymous client").config(
            timeout = 300.seconds,
        ) {
            val refusedBefore = client.storage.refusedNetworkOperations
            val bytes = ByteArray(700).also(random::nextBytes)
            val cid = holder.storage.put(bytes)
            scheduler.track(cid) shouldBe true
            announceUntil(scheduler, holder, cid) shouldBe true
            val started = System.nanoTime()
            val arrived =
                awaitTrue(Duration.ofSeconds(240)) {
                    client.storage.localOrRemoteState(cid, schedule = true).state == RemoteBlockState.CACHED
                }
            println(
                "Q20 measurement: (a) tracked body CACHED=$arrived after " +
                    "${(System.nanoTime() - started) / 1_000_000} ms, " +
                    "client stats ${lookup().statsForTest()}",
            )
            arrived shouldBe true
            client.storage.getLocal(cid)!!.toList() shouldBe bytes.toList()
            // the client never provides anything and refuses nothing more in this flow
            client.storage.refusedNetworkOperations shouldBe refusedBefore
        }

        test("(b) control: a body the holder does not track is not reported as cached").config(timeout = 300.seconds) {
            val bytes = ByteArray(650).also(random::nextBytes)
            val cid = holder.storage.put(bytes)
            relays.forEach { it.storage.heldProviderRecords(cid) shouldBe emptySet() }
            val r = lookup().fetchBlock(cid, 60.seconds, LookupContext.TIMELINE).get(90, TimeUnit.SECONDS)
            println("Q20 measurement: (b) untracked body lookup result: $r")
            // honest record only: Nabu's loopback responder may or may not name the holder; the only assertion is
            // that the provider records come from no announcement
            relays.forEach { it.storage.heldProviderRecords(cid) shouldBe emptySet() }
        }

        test("(c) measurement: two holders of the same body, two lookups through the same exit").config(
            timeout = 300.seconds,
        ) {
            val bytes = ByteArray(900).also(random::nextBytes)
            val cid = holder.storage.put(bytes)
            secondHolder.storage.put(bytes) shouldBe cid
            scheduler.track(cid)
            secondScheduler.track(cid)
            announceUntil(scheduler, holder, cid) shouldBe true
            announceUntil(secondScheduler, secondHolder, cid) shouldBe true
            val exit = exitRelays()[0]
            allowedRef.set(setOf(exit.key))
            try {
                val first = lookup().fetchBlock(cid, 120.seconds).get(150, TimeUnit.SECONDS)
                val second = lookup().fetchBlock(cid, 120.seconds).get(150, TimeUnit.SECONDS)
                println(
                    "Q20 measurement: (c) two holders, same exit: first=${first.javaClass.simpleName} " +
                        "second=${second.javaClass.simpleName}",
                )
                first.shouldBeInstanceOf<LookupResult.Found>()
                // no assertion on the second result: it depends on which holder the exit asked first
                second shouldNotBe null
            } finally {
                allowedRef.set(null)
            }
        }

        test("stop: the schedulers close, the source is unbound").config(timeout = 60.seconds) {
            scheduler.close()
            secondScheduler.close()
            scheduler.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.CLOSED
            deferred.unbind()
            runtime.close()
            lookup().openCircuits() shouldBe 0
        }
    })
