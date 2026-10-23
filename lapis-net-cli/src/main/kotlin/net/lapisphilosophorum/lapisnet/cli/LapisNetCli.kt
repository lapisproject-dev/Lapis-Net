@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository
import net.lapisphilosophorum.lapisnet.identity.PassphraseProvider
import net.lapisphilosophorum.lapisnet.identity.defaultIdentityDirectory
import net.lapisphilosophorum.lapisnet.identity.resolveKeystorePassphrase
import net.lapisphilosophorum.lapisnet.networking.BootstrapConfig
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_INCOMPLETE_WARNING
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPath
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CountDownLatch
import kotlin.system.exitProcess

private val logger = KotlinLogging.logger {}

/** Disposable warm-up topic - see [runMultiNodeTrustPropagationDemo]'s warm-up phase. Separate
 * from [VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC], mirroring
 * [net.lapisphilosophorum.lapisnet.trust.ThreeNodeVeritasGossipRelayTest]'s own warm-up topic. */
private const val WARMUP_TOPIC = "lapisnet-cli-demo:warmup:v1"

/**
 * Entry point. **Without arguments** it runs the multi-node demo exactly as before V0.9.15; with arguments it is the
 * `node` subcommand or `--help` (see [runCli]).
 */
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        runDemo()
        return
    }
    exitProcess(runCli(args.toList(), System.out, System.err))
}

private fun runDemo() {
    logger.info { "Starting Lapis Net CLI (V0.1.8 multi-node trust-propagation demo)" }

    runIdentityAndStorageDemo()
    println()
    val result = runMultiNodeTrustPropagationDemo()
    println("Final resolved trust score A -> C on node C: ${result.resolvedPathOnC?.scoreFraction}")
}

/** Exit code for an unknown subcommand/flag or an invalid option value. */
internal const val EXIT_USAGE = 2

private val CLI_USAGE =
    """
    |Usage:
    |  lapisnet                      run the multi-node demo (no network egress beyond localhost)
    |  lapisnet node [options]       run a headless node (relay selection, DHT directory, Madli); no DM, no mail
    |  lapisnet --help
    |
    """.trimMargin()

/**
 * The testable body of [main] for the non-demo cases. Returns the process exit code: `0` after a clean run or `--help`,
 * [EXIT_USAGE] for an unknown subcommand/flag or an invalid option (one line on [err], no stack trace).
 *
 * @param awaitShutdown blocks until the process should end; it is handed the stop action so a shutdown hook can run it.
 * @param startNode seam for tests; the default starts a real [HeadlessNode] with the operator's identity
 * @param demo seam for the no-argument case
 */
internal fun runCli(
    args: List<String>,
    out: PrintStream,
    err: PrintStream,
    awaitShutdown: (stop: () -> Unit) -> Unit = ::blockUntilShutdown,
    startNode: (NodeWiringOptions) -> HeadlessNode = ::startDefaultHeadlessNode,
    demo: () -> Unit = ::runDemo,
): Int {
    if (args.isEmpty()) {
        demo()
        return 0
    }
    if (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
        out.println(CLI_USAGE)
        out.println(NodeWiringOptions.HELP_TEXT)
        return 0
    }
    if (args[0] != "node") {
        err.println("lapisnet: unknown command '${args[0]}'")
        err.println(CLI_USAGE)
        return EXIT_USAGE
    }
    val rest = args.drop(1)
    if ("--help" in rest || "-h" in rest) {
        out.println(NodeWiringOptions.HELP_TEXT)
        return 0
    }
    val options =
        try {
            NodeWiringOptions.resolve(NodeWiringOptions.parseCliArgs(rest))
        } catch (e: InvalidWiringOptionException) {
            err.println("lapisnet node: ${e.message}")
            return EXIT_USAGE
        }
    val headless = startNode(options)
    try {
        out.println("Lapis Net node running. PeerId: ${headless.node.peerId.toBase58().take(12)}...")
        out.println(
            "  reachability=${options.reachability.name.lowercase()} auto-relay=${options.autoRelay} " +
                "dht-fallback=${options.dhtFallback} publish-relay-reliability=${options.publishRelayReliability} " +
                "hole-punching=${options.holePunching.name.lowercase()} onion-relay=${options.onionRelay} " +
                "anonymity=${options.anonymity.name.lowercase()}" +
                if (headless.node.holePunching != null) " (active)" else "",
        )
        if (options.dhtFallback) {
            out.println(
                "  note: DHT lookups reveal query timing and key interest to DHT peers - disable with --dht-fallback=false",
            )
        }
        if (options.onionRelay) {
            out.println("  onion relay: infrastructure only, no traffic is anonymised")
        }
        if (options.anonymity == AnonymityMode.ON) {
            out.println("  anonymity: experimental and incomplete (see the warning on stderr)")
            err.println("WARNING: $ANONYMITY_INCOMPLETE_WARNING")
        }
        out.println("Press Ctrl+C to stop.")
        awaitShutdown(headless::stop)
    } finally {
        headless.stop()
    }
    return 0
}

private fun lapisnetHome(): Path =
    Path.of(
        System.getenv("LAPISNET_HOME") ?: (System.getProperty("user.home") + "/.lapisnet"),
    )

private fun startDefaultHeadlessNode(options: NodeWiringOptions): HeadlessNode {
    // The passphrase is asked for once and reused for the identity keystore and the onion key file (--onion-relay):
    // a second prompt could be mistyped on first creation and lock the node out for good.
    val shared = SharedPassphrase(warningPassphraseProvider())
    try {
        val repository = FileIdentityRepository(defaultIdentityDirectory(), shared)
        val identity = repository.loadDefault() ?: repository.generateAndSave()
        val bootstrap = BootstrapConfig.resolve()
        val listen = BootstrapConfig.resolveListenAddress()
        return HeadlessNode.start(
            options = options,
            identity = identity,
            bootstrapPeers = bootstrap,
            listenAddress = listen,
            dataDirectory = lapisnetHome().resolve("cli-node-storage"),
            onionKeyPassphrase = shared::get,
        )
    } finally {
        shared.wipe()
    }
}

/** Resolves the passphrase from [delegate] at most once; every [get] returns a fresh copy (callers zero theirs). */
private class SharedPassphrase(
    private val delegate: PassphraseProvider,
) : PassphraseProvider {
    private var resolved = false
    private var value: CharArray? = null

    @Synchronized
    override fun get(): CharArray? {
        if (!resolved) {
            value = delegate.get()
            resolved = true
        }
        return value?.copyOf()
    }

    @Synchronized
    fun wipe() {
        value?.fill('\u0000')
        value = null
    }
}

/** Blocks the calling thread until the JVM receives SIGINT/SIGTERM; [stop] runs inside the shutdown hook. */
private fun blockUntilShutdown(stop: () -> Unit) {
    val latch = CountDownLatch(1)
    Runtime.getRuntime().addShutdownHook(
        Thread {
            logger.info { "shutting down Lapis Net node" }
            runCatching { stop() }
            latch.countDown()
        },
    )
    latch.await()
}

/**
 * [PassphraseProvider] for a real process entry point (V0.4): defers to
 * [resolveKeystorePassphrase] (env var, else interactive console, else `null`) and, on `null`,
 * logs a warning rather than failing - a headless run (this project's own CI/demo runs, which have
 * neither an env var nor a console) must keep working exactly as it did before V0.4, just with the
 * identity stored unencrypted (legacy v1 keystore, POSIX permissions only). Mirrors
 * `lapis-net-browser`'s `BrowserMain.warningPassphraseProvider` exactly.
 */
private fun warningPassphraseProvider(): PassphraseProvider =
    PassphraseProvider {
        val passphrase = resolveKeystorePassphrase()
        if (passphrase == null) {
            logger.warn {
                "no keystore passphrase available (set LAPISNET_KEYSTORE_PASSPHRASE, or run with an " +
                    "interactive console) - identity will be stored UNENCRYPTED on disk (legacy v1 " +
                    "keystore format, protected only by POSIX file permissions)"
            }
        }
        passphrase
    }

/**
 * Single-node identity + local storage demo (V0.1.4-era content, unchanged in substance beyond
 * being extracted into its own function): proves a loaded/generated identity round-trips through
 * Nabu's local blockstore. No network exercise here - see [runMultiNodeTrustPropagationDemo] for
 * the multi-node GossipSub/Veritas harness.
 */
fun runIdentityAndStorageDemo() {
    val repository = FileIdentityRepository(defaultIdentityDirectory(), warningPassphraseProvider())
    val identity = repository.loadDefault() ?: repository.generateAndSave()

    println("secp256k1 identity fingerprint: ${identity.secp256k1KeyPair.publicKey.fingerprint()}")
    println("Ed25519 (libp2p) fingerprint:   ${identity.ed25519KeyPair.publicKey.fingerprint()}")
    println("identity binding verifies:      ${identity.verifyBinding()}")
    println("libp2p PeerId:                  ${identity.deriveLibp2pPeerId().toBase58()}")

    // No bootstrap dials here - keeps this demo fast and non-hanging, with no real network egress
    // required. Multi-node connectivity (direct dial, GossipSub, Veritas propagation) is
    // demonstrated separately by runMultiNodeTrustPropagationDemo().
    val node = LapisNode.create(identity)
    try {
        node.start(bootstrapPeers = emptyList())
        println("listening on:                   ${node.listenAddresses()}")

        // Single-node local storage demo - no DHT/Bitswap network exercise here, just proof
        // that Nabu's blockstore is wired up.
        // Temp directory is left in place (JVM/OS temp cleanup applies) - not worth the extra
        // recursive-delete machinery for a throwaway demo directory.
        val storage = NabuStorage.attach(node, Files.createTempDirectory("lapisnet-cli-storage"))
        try {
            val cid = storage.put("hello from the Lapis Net CLI storage demo".toByteArray())
            val roundTripped = storage.get(cid)
            println("Nabu storage demo: put+get cid $cid succeeded: ${roundTripped != null}")
        } finally {
            storage.stop()
        }
    } finally {
        node.stop()
    }
}

/**
 * Final observed state of [runMultiNodeTrustPropagationDemo] - returned rather than only printed,
 * so the scenario is independently assertable by a test without scraping console output.
 */
data class MultiNodeTrustDemoResult(
    val peerIdA: PeerId,
    val peerIdB: PeerId,
    val peerIdC: PeerId,
    val grant: VeritasGrant,
    val grantsOnA: Collection<VeritasGrant>,
    val grantsOnB: Collection<VeritasGrant>,
    val grantsOnC: Collection<VeritasGrant>,
    val resolvedPathOnC: TrustPath?,
)

/**
 * Multi-node CLI demo: three in-process nodes chained A<->B<->C - A and C are never directly
 * dialed, mirroring
 * [net.lapisphilosophorum.lapisnet.trust.ThreeNodeVeritasGossipRelayTest]'s topology exactly
 * (chosen specifically because it proves GossipSub *relay*, not just direct delivery). Node A
 * issues a Veritas trust-edge grant to node C's own identity; the grant is gossiped through relay
 * node B and resolved into a trust score on node C.
 *
 * [narrate] is the human-readable output seam for everything the demo is FOR - defaults to
 * [println] for a real CLI run, but a test can pass a no-op to keep output quiet while still
 * asserting on the returned [MultiNodeTrustDemoResult].
 *
 * [overallTimeout] bounds the ENTIRE function - a single deadline is computed once at entry and
 * shared by both the warm-up phase and the real grant-announce phase below, rather than each
 * phase independently claiming up to its own full budget. This is a hard cap, not the expected
 * runtime: in practice both phases resolve in low single-digit seconds on ordinary hardware,
 * matching [net.lapisphilosophorum.lapisnet.trust.ThreeNodeVeritasGossipRelayTest]'s observed
 * timing.
 */
fun runMultiNodeTrustPropagationDemo(
    overallTimeout: Duration = Duration.ofSeconds(60),
    narrate: (String) -> Unit = ::println,
): MultiNodeTrustDemoResult {
    val deadline = Instant.now().plus(overallTimeout)

    val identityA = DualKeyIdentity.generate()
    val identityB = DualKeyIdentity.generate()
    val identityC = DualKeyIdentity.generate()
    val nodeA = LapisNode.create(identityA)
    val nodeB = LapisNode.create(identityB)
    val nodeC = LapisNode.create(identityC)
    try {
        nodeA.start(bootstrapPeers = emptyList())
        nodeB.start(bootstrapPeers = emptyList())
        nodeC.start(bootstrapPeers = emptyList())
        narrate(
            "peer IDs known: A=${nodeA.peerId.toBase58()} B=${nodeB.peerId.toBase58()} " +
                "C=${nodeC.peerId.toBase58()}",
        )

        val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("lapisnet-cli-demo-a"))
        val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("lapisnet-cli-demo-b"))
        val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("lapisnet-cli-demo-c"))

        // GossipPubSub (a ConnectionHandler) must be attached on ALL THREE nodes BEFORE ANY
        // connect() call below - see GossipPubSub.attach's doc comment. Attaching after a
        // connection is already up means GossipSub never opens a mesh stream on it.
        val pubsubA = GossipPubSub.attach(nodeA)
        val pubsubB = GossipPubSub.attach(nodeB)
        val pubsubC = GossipPubSub.attach(nodeC)
        val veritasA = VeritasGossip.attach(pubsubA, storageA)
        val veritasB = VeritasGossip.attach(pubsubB, storageB)
        val veritasC = VeritasGossip.attach(pubsubC, storageC)

        // Chain topology: A<->B, B<->C - A and C are never directly dialed. Node C only ever
        // learns about A's grant via B's relay.
        nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))
        nodeC.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

        // Warm-up phase - a disposable topic where every message always validates Valid, so
        // distinct retried payloads keep getting relayed by B regardless of duplicate content
        // (unlike the real Veritas topic's content-addressed dedup). NOT optional: skipping it
        // makes this 3-node demo flaky in a way a 2-node case never is, because grant dedup means
        // a lost mesh-formation race is not recoverable by simply retrying the identical grant
        // bytes - see ThreeNodeVeritasGossipRelayTest's class doc comment for the full mechanism.
        val warmupReceivedOnC = Collections.synchronizedList(mutableListOf<ByteArray>())
        pubsubB.subscribe(WARMUP_TOPIC) { _, _ -> ValidationResult.Valid }
        pubsubC.subscribe(WARMUP_TOPIC) { bytes, _ ->
            warmupReceivedOnC.add(bytes)
            ValidationResult.Valid
        }
        var warmupSeq = 0
        while (warmupReceivedOnC.isEmpty() && Instant.now().isBefore(deadline)) {
            warmupSeq++
            runCatching { pubsubA.publish(WARMUP_TOPIC, "warmup-$warmupSeq".toByteArray()) }
            Thread.sleep(200)
        }
        check(warmupReceivedOnC.isNotEmpty()) { "warm-up phase did not complete within $overallTimeout" }
        narrate("warm-up complete: the A->B->C GossipSub mesh is hot")

        // Node A grants trust to node C's OWN secp256k1 identity - deliberately not a throwaway
        // keypair, so the demo can narrate a concrete "A trusts C" story between two of its own
        // live participants. Target must be C's secp256k1 key (the Veritas identity), never its
        // Ed25519 key (libp2p transport identity - a completely different purpose).
        val grant =
            VeritasGrant.create(
                truster = identityA.secp256k1KeyPair,
                target = identityC.secp256k1KeyPair.publicKey,
                trustMicros = 900_000,
                comment = "issued by the V0.1.8 CLI demo",
            )

        // publish() silently no-ops with no mesh peers yet - retry announce() itself inside the
        // bounded poll loop below, never call it exactly once and assert.
        var grantsOnC = veritasC.currentGrants()
        while (grantsOnC.isEmpty() && Instant.now().isBefore(deadline)) {
            veritasA.announce(grant)
            Thread.sleep(500)
            grantsOnC = veritasC.currentGrants()
        }
        check(grantsOnC.isNotEmpty()) { "grant did not propagate from A to C within $overallTimeout" }
        narrate("grant announced by A")
        narrate("grant observed on C (final endpoint)")

        // Relay node B's own durable tracking, not just the final endpoint - demonstrates
        // propagation actually happened at the intermediate hop, not just at the destination.
        val grantsOnB = veritasB.currentGrants()
        narrate("grant observed on B (relay): ${grantsOnB.isNotEmpty()}")

        val graphC = TrustGraph.fromGrants(grantsOnC)
        val resolvedPathOnC =
            TrustPathFinder.findPath(
                graphC,
                identityA.secp256k1KeyPair.publicKey,
                identityC.secp256k1KeyPair.publicKey,
            )
        narrate(
            "resolved trust score A -> C on node C: ${resolvedPathOnC?.scoreFraction} " +
                "(${resolvedPathOnC?.hops} hop(s))",
        )
        narrate(
            "note: the NETWORK path is 2 hops (A->B->C), but the resolved TRUST GRAPH edge is 1 hop " +
                "(A->C directly) - the grant is a single signed A->C statement, and B only relayed the " +
                "bytes, it never becomes a graph node itself",
        )
        narrate(
            "note: this demo never exercises NabuStorage's cross-node DHT provider discovery (a known " +
                "gap) - grants gossip as full bytes, not CIDs, so it's never needed here",
        )

        val result =
            MultiNodeTrustDemoResult(
                peerIdA = nodeA.peerId,
                peerIdB = nodeB.peerId,
                peerIdC = nodeC.peerId,
                grant = grant,
                grantsOnA = veritasA.currentGrants(),
                grantsOnB = grantsOnB,
                grantsOnC = grantsOnC,
                resolvedPathOnC = resolvedPathOnC,
            )

        // Deliberately sequential here rather than duplicated in the finally block below: all
        // three types' stop() are no-ops or purely in-memory today (no independently-owned
        // socket/thread), and node.stop() in finally unconditionally tears down the actual bound
        // Host/socket regardless of whether these nine calls are reached - so skipping them on an
        // earlier exception (e.g. a check() failure above) leaks nothing observable.
        veritasA.stop()
        veritasB.stop()
        veritasC.stop()
        pubsubA.stop()
        pubsubB.stop()
        pubsubC.stop()
        storageA.stop()
        storageB.stop()
        storageC.stop()

        return result
    } finally {
        // Cleanup must survive a mid-scenario exception, and one node's stop() failing must never
        // skip another node's - runCatching wraps EACH node's stop() individually rather than one
        // unprotected block that could itself throw partway through.
        runCatching { nodeA.stop() }
        runCatching { nodeB.stop() }
        runCatching { nodeC.stop() }
    }
}
