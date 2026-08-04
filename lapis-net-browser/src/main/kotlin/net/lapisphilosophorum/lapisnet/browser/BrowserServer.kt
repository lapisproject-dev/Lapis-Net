package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.libp2p.core.multiformats.Multiaddr
import kotlinx.coroutines.runBlocking
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.ElectrumTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Path

private val logger = KotlinLogging.logger {}

/** Grace period passed to [EmbeddedServer.stop] - how long Netty waits for in-flight requests to
 * finish before forcefully shutting down. */
private const val HTTP_STOP_GRACE_PERIOD_MILLIS = 1_000L

/** Hard timeout passed to [EmbeddedServer.stop] - how long Netty is allowed to take overall
 * before shutdown is forced regardless of in-flight requests. */
private const val HTTP_STOP_TIMEOUT_MILLIS = 5_000L

/** Default HTTP port for a real (non-test) [BrowserServer.start] call. Tests should pass `0` to
 * get an OS-assigned port and read it back via [BrowserServer.boundPort] instead, to avoid port
 * collisions between concurrently running test servers. */
const val DEFAULT_BROWSER_HTTP_PORT = 7878

/**
 * The Minimal-Browser MVP's process wiring: a real [LapisNode] (identity, libp2p host, GossipSub,
 * Nabu storage, Veritas/Virtus/post gossip) plus an embedded, LOOPBACK-ONLY Ktor HTTP server
 * serving [installBrowserApi]'s JSON routes and the static UI, all inside the same JVM process.
 * Mirrors [net.lapisphilosophorum.lapisnet.cli.LapisNetCli]'s node/gossip lifecycle wiring pattern
 * ([LapisNode.create] -> `start()` -> [NabuStorage.attach] -> [GossipPubSub.attach] -> per-domain
 * gossip `attach()` calls) exactly - see [start]'s doc comment.
 *
 * **Binds `127.0.0.1` only, never `0.0.0.0`.** This process holds a real secp256k1 signing key
 * ([identity]) - the HTTP API must never be reachable from anything other than the local machine.
 * Treated as a hard security requirement throughout this module, not a configurable default.
 */
class BrowserServer private constructor(
    private val identity: DualKeyIdentity,
    private val node: LapisNode,
    private val storage: NabuStorage,
    private val pubsub: GossipPubSub,
    private val veritas: VeritasGossip,
    private val virtus: LtrGossip,
    private val karma: KarmaGossip,
    private val karmaAnchorCache: KarmaAnchorCache,
    private val posts: PostAnnouncementGossip,
    private val mailInbox: InboxGossip,
    private val httpEngine: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>,
    /** The HTTP port actually bound, resolved after [httpEngine] started - may differ from the
     * `httpPort` passed to [start] when that was `0` (OS-assigned). */
    val boundPort: Int,
) {
    /** Test seam only - exposes the underlying [LapisNode] so tests can read its [LapisNode.peerId]/
     * [LapisNode.listenAddresses] to build a direct-dial multiaddr (e.g. for
     * `POST /api/peers/connect`) without a real discovery mechanism, and exposes the underlying
     * [GossipPubSub] so tests can run [net.lapisphilosophorum.lapisnet.cli.LapisNetCli]'s
     * established warm-up-topic mesh-formation trick before relying on gossip propagation of real
     * content. Not part of the public API surface external callers should use. */
    internal val nodeForTesting: LapisNode get() = node

    /** See [nodeForTesting]'s doc comment. */
    internal val pubsubForTesting: GossipPubSub get() = pubsub

    /**
     * Symmetric teardown, mirroring
     * [net.lapisphilosophorum.lapisnet.cli.LapisNetCli.runMultiNodeTrustPropagationDemo]'s
     * established ordering exactly: the HTTP engine and every gossip/storage layer are stopped in
     * the reverse order they were attached in [start].
     * [posts]/[karma]/[virtus]/[veritas]/[pubsub]/[storage]
     * are plain, unwrapped calls, since each of those is documented as a genuine no-op (verified:
     * their `stop()` implementations are literal no-ops or trivial flag-sets - unlike [httpEngine],
     * none of them owns a real socket or thread pool). [httpEngine] (a real Netty socket + thread
     * pool) and [LapisNode.stop] (which tears down the actual bound libp2p socket and event-loop
     * threads) are each the one call in their respective step that can genuinely throw, so both are
     * individually wrapped in [runCatching] - [httpEngine]'s as the first statement in the outer
     * `try` (still guaranteeing a throwing Netty shutdown can never skip the rest of teardown, since
     * [runCatching] swallows the failure before execution reaches the next statement), and
     * [LapisNode.stop]'s in the outer `finally` block, so a failure in any earlier step never leaks
     * the underlying host/socket.
     *
     * **[karma] does not own an Electrum connection to tear down here.** [KarmaAnchorCache]'s
     * lazily-established Electrum connection (if any was ever made) is a separate, known, documented
     * resource-lifecycle gap for this wave - see [KarmaAnchorCache]'s doc comment.
     * [karma].`stop()` itself is a plain GossipSub unsubscribe, exactly like
     * [virtus]/[veritas]/[posts].
     */
    fun stop() {
        try {
            runCatching { httpEngine.stop(HTTP_STOP_GRACE_PERIOD_MILLIS, HTTP_STOP_TIMEOUT_MILLIS) }
            mailInbox.stop()
            posts.stop()
            karma.stop()
            virtus.stop()
            veritas.stop()
            pubsub.stop()
            storage.stop()
        } finally {
            runCatching { node.stop() }
        }
    }

    companion object {
        /**
         * Builds and starts a full [BrowserServer]: a real [LapisNode] (identity, GossipSub, Nabu
         * storage, Veritas/Virtus/Karma/post gossip - in that attach order, mirroring
         * [net.lapisphilosophorum.lapisnet.cli.LapisNetCli]'s established wiring pattern exactly)
         * plus the embedded HTTP server. [httpHost] MUST stay `127.0.0.1` - see this class's doc
         * comment. [httpPort] `0` requests an OS-assigned port, read back via the returned
         * server's [boundPort]. [listenAddress] is the *libp2p* listen address (separate from
         * [httpHost]/[httpPort], which is the loopback-only HTTP admin bind) - defaults to loopback
         * with an OS-assigned port, matching [LapisNode.create]'s own default, so a node is not
         * reachable from other machines unless an operator explicitly configures otherwise (V0.4,
         * see [net.lapisphilosophorum.lapisnet.networking.BootstrapConfig.resolveListenAddress]).
         *
         * [KarmaAnchorCache] is built here over [karmaAnchorSource], which defaults to a real
         * [ElectrumTimeAnchorSource] using its default, no-argument constructor - i.e.
         * [net.lapisphilosophorum.lapisnet.karma.ElectrumServers.PLACEHOLDER]'s empty server list,
         * unless/until a real deployment configuration wires in a real server list. Constructing the
         * default does no network I/O by itself (the underlying Electrum connection is established
         * lazily, on the first real vote - see
         * [net.lapisphilosophorum.lapisnet.karma.RealElectrumRpc]'s doc comment), so this is safe to
         * do unconditionally on every [start] call. [karmaAnchorSource] is overridable purely as a
         * test seam (mirroring [nodeForTesting]/[pubsubForTesting]'s established reasoning) - with
         * the default empty [net.lapisphilosophorum.lapisnet.karma.ElectrumServers.PLACEHOLDER],
         * every real `POST /api/karma` call fails with a clean 502 in any environment without a
         * configured, reachable Electrum server (see `BrowserApi`'s `/api/karma` route), which would
         * make a real end-to-end test of Karma vote propagation impossible without this override.
         */
        fun start(
            identity: DualKeyIdentity,
            httpHost: String = "127.0.0.1",
            httpPort: Int = DEFAULT_BROWSER_HTTP_PORT,
            bootstrapPeers: List<Multiaddr> = emptyList(),
            listenAddress: Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/0"),
            dataDirectory: Path,
            karmaAnchorSource: BitcoinTimeAnchorSource = ElectrumTimeAnchorSource(),
        ): BrowserServer {
            require(httpHost == "127.0.0.1") {
                "BrowserServer must bind 127.0.0.1 only - refusing to start on '$httpHost' " +
                    "(this process holds a real signing key and must never be network-reachable)"
            }

            val node = LapisNode.create(identity, listenAddress)
            node.start(bootstrapPeers = bootstrapPeers)

            val storage = NabuStorage.attach(node, dataDirectory)
            // GossipPubSub must attach before any LapisNode.connect() call - see
            // GossipPubSub.attach's doc comment. BrowserServer.start() never calls connect()
            // itself (that happens later, via POST /api/peers/connect), so this ordering
            // constraint is satisfied by construction, not by caller discipline.
            val pubsub = GossipPubSub.attach(node)
            val veritas = VeritasGossip.attach(pubsub, storage)
            val virtus = LtrGossip.attach(pubsub, storage)
            val karma = KarmaGossip.attach(pubsub, storage)
            val posts = PostAnnouncementGossip.attach(pubsub, storage)
            val karmaAnchorCache = KarmaAnchorCache(karmaAnchorSource)
            // V0.9.3 - InboxGossip.attach subscribes this identity's own inbox topic immediately,
            // same "attach = subscribe now" contract as veritas/virtus/karma/posts above.
            // MailSender/SentFolder are plain, resource-free objects - constructed here purely so
            // every BrowserServer has its own instance, never shared across servers in a
            // multi-node test.
            val mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
            val mailSender = MailSender(pubsub, storage)
            val sentFolder = SentFolder()

            val deps =
                BrowserApiDependencies(
                    identity,
                    node,
                    storage,
                    veritas,
                    virtus,
                    karma,
                    posts,
                    karmaAnchorCache,
                    mailInbox,
                    mailSender,
                    sentFolder,
                )
            val httpEngine =
                embeddedServer(Netty, port = httpPort, host = httpHost) {
                    installBrowserApi(deps)
                }
            // wait = false: this factory function must return promptly with a running server, not
            // block the calling thread until shutdown - BrowserMain.kt is what blocks the process,
            // and tests need start() to return so they can run further setup (e.g. connecting a
            // second BrowserServer) and eventually call stop().
            httpEngine.start(wait = false)
            val boundPort =
                runBlocking {
                    httpEngine.engine
                        .resolvedConnectors()
                        .first()
                        .port
                }

            logger.info { "BrowserServer listening on http://$httpHost:$boundPort (peer ${node.peerId.toBase58()})" }
            return BrowserServer(
                identity,
                node,
                storage,
                pubsub,
                veritas,
                virtus,
                karma,
                karmaAnchorCache,
                posts,
                mailInbox,
                httpEngine,
                boundPort,
            )
        }
    }
}
