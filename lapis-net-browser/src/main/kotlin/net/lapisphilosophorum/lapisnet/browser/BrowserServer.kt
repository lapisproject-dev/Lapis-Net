package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.libp2p.core.multiformats.Multiaddr
import kotlinx.coroutines.runBlocking
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.dm.DmStore
import net.lapisphilosophorum.lapisnet.dm.MailboxGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.PassphraseProvider
import net.lapisphilosophorum.lapisnet.identity.resolveKeystorePassphrase
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.ElectrumTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Path
import java.time.Instant

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

/** How long [start]'s one-shot self [PeerRecord]/prekey-bundle publish stays valid for - see the
 * `publishSelfForDm` call site's own comment for why this wave does not periodically re-publish
 * (an explicit, stated scope cut, not an oversight). Generous enough that a browser session left
 * running overnight stays dialable for DM without a restart. */
private const val DM_SELF_RECORD_TTL_SECONDS = 24L * 3600

/**
 * Fallback DM **session**-store passphrase used ONLY when neither `LAPISNET_KEYSTORE_PASSPHRASE`
 * nor an interactive console is available (see [resolveKeystorePassphrase]) - mirrors
 * `BrowserMain.warningPassphraseProvider`'s identical "keep working headless, but loudly warn"
 * policy for identity-keystore encryption, applied here to [DmSessionManager]'s own
 * encryption-at-rest. A headless environment (this project's own CI/demo runs) must not
 * hard-fail DM wiring just because no real passphrase was configured.
 *
 * **[DmSessionManager.attach] has no "unencrypted" mode** - unlike [PrekeyStore] (see
 * [BrowserServer.start]'s `dmPrekeyPassphraseProvider`, which honestly returns `null` - the same
 * v1/unencrypted-but-migratable fallback [FileIdentityRepository]/`BrowserMain` use for the
 * identity keystore - rather than ever touching this placeholder), it always derives an
 * encryption key from whatever [CharArray] it is handed, so a concrete non-null passphrase is
 * unavoidable here when no real one is configured. This is a narrower, already-accepted
 * V0.8.6b trade-off, not something this function's caller can route around the way it can for
 * [PrekeyStore].
 *
 * **A fresh [CharArray] on every call, never a shared instance.** [DmSessionManager.attach] zeroes
 * the passphrase [CharArray] it is handed the instant it is done with it (see its own doc comment
 * - "a caller must not reuse this CharArray after calling attach()") - reusing a single top-level
 * `val` across more than one call would read back as all-NUL bytes on the second and later calls,
 * silently deriving a different (and non-reproducible across process restarts) encryption key.
 */
private fun insecureDefaultDmPassphrase(): CharArray =
    "lapisnet-browser-dm-insecure-default-passphrase"
        .toCharArray()

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
    /** V0.8.6b - see [DmApiDependencies]'s own doc comment; owns [PeerDirectoryGossip]/
     * [PrekeyBundleGossip]/[MailboxGossip]/[DmSessionManager] teardown in [stop]. */
    private val peerDirectory: PeerDirectoryGossip,
    private val prekeyBundleGossip: PrekeyBundleGossip,
    private val mailboxGossip: MailboxGossip,
    private val dmSessionManager: DmSessionManager,
    private val dmPrekeyStore: PrekeyStore,
    /** The single, once-resolved DM prekey-store passphrase for this server's entire lifetime -
     * see the `dmPrekeyMasterPassphrase` local in [start] for the full reasoning on why this is
     * resolved exactly once rather than per file access. [dmPrekeyPassphraseProvider] there only
     * ever hands out `copyOf()` copies of this array to [PrekeyStore] (which zeroes each copy it
     * receives), so this master array is never mutated during normal operation - it is zeroed
     * exactly once, here in [stop], once no further prekey-store access can occur. `null` when no
     * real passphrase was ever configured (headless, no console) - nothing to zero in that case. */
    private val dmPrekeyMasterPassphrase: CharArray?,
    private val dmStore: DmStore,
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

    /** Test seam only - see [nodeForTesting]'s doc comment. Lets a test (e.g. `DmXssRenderingTest`)
     * `put` a blob into this server's own [NabuStorage] directly - e.g. to mint a real [DmAttachmentRef]
     * whose `cid` actually resolves, without needing a second full [BrowserServer]/[LapisNode] just
     * to reach a `NabuStorage` instance. */
    internal val storageForTesting: NabuStorage get() = storage

    /** Test seam only - see [nodeForTesting]'s doc comment. Re-announces this node's
     * [PeerRecord]/prekey bundle on demand, mirroring [DmTestNode.publishSelf]'s own
     * repeat-until-converged pattern (`lapis-net-dm`'s test fixture) - needed because [start]'s
     * own one-shot publish (see [DM_SELF_RECORD_TTL_SECONDS]'s doc comment) happens BEFORE any
     * test has connected two [BrowserServer]s together, so GossipSub's mesh (GRAFT) has not
     * formed yet and that first publish is never replayed to a peer who joins later - exactly
     * [DmTestNode.publishSelf]'s own reasoning, restated here for the browser layer's first DM
     * two-node test. */
    internal fun republishSelfForDmTesting() {
        val notValidAfter = Instant.now().epochSecond + DM_SELF_RECORD_TTL_SECONDS
        peerDirectory.announce(
            PeerRecord.create(
                identity = identity,
                addresses = node.listenAddresses(),
                capabilities = setOf(PeerCapability.DM),
                sequenceNumber = Instant.now().toEpochMilli(),
                notValidAfterEpochSecond = notValidAfter,
            ),
        )
        prekeyBundleGossip.announce(dmPrekeyStore.publishBundle(identity, notValidAfter))
    }

    /** See [nodeForTesting]'s doc comment. */
    internal val peerDirectoryForDmTesting: PeerDirectoryGossip get() = peerDirectory

    /** See [nodeForTesting]'s doc comment. */
    internal val prekeyBundleGossipForDmTesting: PrekeyBundleGossip get() = prekeyBundleGossip

    /** Test seam only - see [nodeForTesting]'s doc comment. Lets a test (e.g. `DmXssRenderingTest`)
     * write a [net.lapisphilosophorum.lapisnet.dm.DmInboundMessage] directly into this server's
     * [DmStore] without a real two-node handshake/gossip round trip - mirrors
     * [MailXssRenderingTest]'s own reasoning for testing rendering against synchronously-populated
     * data rather than adding gossip-round-trip flakiness to a security regression test. */
    internal val dmStoreForTesting: DmStore get() = dmStore

    /**
     * Symmetric teardown, mirroring
     * [net.lapisphilosophorum.lapisnet.cli.LapisNetCli.runMultiNodeTrustPropagationDemo]'s
     * established ordering exactly: the HTTP engine and every gossip/storage layer are stopped in
     * the reverse order they were attached in [start].
     * [mailboxGossip]/[prekeyBundleGossip]/[peerDirectory]/[mailInbox]/[posts]/[karma]/[virtus]/
     * [veritas]/[pubsub]/[storage] are plain, unwrapped calls, since each of those is documented as
     * a genuine no-op (verified: their `stop()` implementations are literal no-ops or trivial
     * flag-sets - unlike [httpEngine]/[dmSessionManager], none of them owns a real socket or thread
     * pool). [httpEngine] (a real Netty socket + thread pool), [dmSessionManager] (owns Ratchet
     * sessions plus its own protocol handler, mailbox poller/redelivery scheduler, and
     * replenishment executor - see the `runCatching` call site's own comment) and [LapisNode.stop]
     * (which tears down the actual bound libp2p socket and event-loop threads) are each the one
     * call in their respective step that can genuinely throw, so all three are individually
     * wrapped in [runCatching] - [httpEngine]'s and [dmSessionManager]'s as the first two
     * statements in the outer `try` (still guaranteeing a throwing shutdown can never skip the
     * rest of teardown, since [runCatching] swallows the failure before execution reaches the next
     * statement), and [LapisNode.stop]'s in the outer `finally` block, so a failure in any earlier
     * step never leaks the underlying host/socket.
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
            // V0.8.6b - reverse of the attach order in start(): dmSessionManager was attached
            // LAST (after mailInbox/mailSender/sentFolder), so it is stopped FIRST here, mirroring
            // every other layer's reverse-of-attach teardown in this method. Wrapped in runCatching
            // (unlike the plain-no-op calls below) because DmSessionManager.stop() is NOT a no-op -
            // it tears down Ratchet sessions and calls dmProtocol.stop()/mailboxPoller.stop()/
            // mailboxRedeliveryScheduler.stop()/replenishmentExecutor.shutdownNow(), any of which can
            // throw. Without this wrapper, a throw here would skip every subsequent teardown line
            // (mailboxGossip/prekeyBundleGossip/peerDirectory/.../storage), leaking their
            // subscriptions/handles - exactly the failure mode this method's own doc comment
            // describes for httpEngine/node.stop().
            runCatching { dmSessionManager.stop() }
            mailboxGossip.stop()
            prekeyBundleGossip.stop()
            peerDirectory.stop()
            mailInbox.stop()
            posts.stop()
            karma.stop()
            virtus.stop()
            veritas.stop()
            pubsub.stop()
            storage.stop()
        } finally {
            // Zeroed exactly once, here, now that no further dmPrekeyPassphraseProvider.get() call
            // can occur (dmSessionManager/mailboxGossip/prekeyBundleGossip/peerDirectory are all
            // already stopped above) - see [dmPrekeyMasterPassphrase]'s own doc comment.
            dmPrekeyMasterPassphrase?.fill('\u0000')
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
            /** Test seam only - mirrors [karmaAnchorSource]'s established reasoning. Defaults to
             * [resolveKeystorePassphrase] (env var, else interactive console, else `null`), exactly
             * the real production behavior. Overriding this lets a test exercise the
             * `configuredDmPassphrase != null` production path deterministically - across a real
             * stop()/start() restart - WITHOUT depending on `LAPISNET_KEYSTORE_PASSPHRASE` actually
             * being set in the test process's environment (see `BrowserServerRestartTest`'s restart
             * test using this). Called potentially many times per [start] (PrekeyStore invokes the
             * provider built over this on every exclusive file access), so an override must return
             * an independent, fresh [CharArray] copy on every call, never the same shared instance -
             * both [PrekeyStore] and [DmSessionManager] zero the array they are handed once done
             * with it.
             */
            dmKeystorePassphraseSource: () -> CharArray? = ::resolveKeystorePassphrase,
        ): BrowserServer {
            require(httpHost == "127.0.0.1") {
                "BrowserServer must bind 127.0.0.1 only - refusing to start on '$httpHost' " +
                    "(this process holds a real signing key and must never be network-reachable)"
            }

            // V0.9.4 - rollback guard: everything from LapisNode.create() through the final
            // `return BrowserServer(...)` below can throw (a Netty port conflict, a keystore
            // decryption failure via the passphrase providers above, ...). Without this guard a
            // throw here would leak whatever was already attached (libp2p host, Nabu file
            // handles, GossipSub subscriptions, DmSessionManager coroutines/scheduler) - fatal
            // under a crash-looping supervisor (systemd Restart=always, Docker
            // restart: unless-stopped), which would keep leaking sockets/handles every restart
            // until the process fails on an unrelated resource-exhaustion error instead of the
            // real cause. cleanupOnFailure records one rollback action immediately after each
            // resource is successfully attached/started, and on any exception they are all run,
            // in reverse (most-recently-attached first), before the exception is rethrown - the
            // same reverse-of-attach-order contract this class's own stop() documents for the
            // ordinary (non-failure) shutdown path.
            val cleanupOnFailure = mutableListOf<() -> Unit>()
            try {
                val node = LapisNode.create(identity, listenAddress)
                node.start(bootstrapPeers = bootstrapPeers)
                cleanupOnFailure += { runCatching { node.stop() } }

                val storage = NabuStorage.attach(node, dataDirectory)
                cleanupOnFailure += { runCatching { storage.stop() } }
                // GossipPubSub must attach before any LapisNode.connect() call - see
                // GossipPubSub.attach's doc comment. BrowserServer.start() never calls connect()
                // itself (that happens later, via POST /api/peers/connect), so this ordering
                // constraint is satisfied by construction, not by caller discipline.
                val pubsub = GossipPubSub.attach(node)
                cleanupOnFailure += { runCatching { pubsub.stop() } }
                val veritas = VeritasGossip.attach(pubsub, storage)
                cleanupOnFailure += { runCatching { veritas.stop() } }
                val virtus = LtrGossip.attach(pubsub, storage)
                cleanupOnFailure += { runCatching { virtus.stop() } }
                val karma = KarmaGossip.attach(pubsub, storage)
                cleanupOnFailure += { runCatching { karma.stop() } }
                val posts = PostAnnouncementGossip.attach(pubsub, storage)
                cleanupOnFailure += { runCatching { posts.stop() } }
                val karmaAnchorCache = KarmaAnchorCache(karmaAnchorSource)
                // V0.9.3 - InboxGossip.attach subscribes this identity's own inbox topic immediately,
                // same "attach = subscribe now" contract as veritas/virtus/karma/posts above.
                // MailSender/SentFolder are plain, resource-free objects - constructed here purely so
                // every BrowserServer has its own instance, never shared across servers in a
                // multi-node test.
                val mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
                cleanupOnFailure += { runCatching { mailInbox.stop() } }
                val mailSender = MailSender(pubsub, storage)
                val sentFolder = SentFolder()

                // V0.8.6b - DM browser wiring. Mirrors DmTestNode/buildDmTestNode's established
                // attach order exactly (peerDirectory -> prekeyBundleGossip -> mailboxGossip ->
                // prekeyStore -> DmSessionManager.attach), the first production (non-test) call site
                // for any of this.
                val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
                cleanupOnFailure += { runCatching { peerDirectory.stop() } }
                val prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
                cleanupOnFailure += { runCatching { prekeyBundleGossip.stop() } }
                val mailboxGossip = MailboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
                cleanupOnFailure += { runCatching { mailboxGossip.stop() } }
                // Resolved EXACTLY ONCE per start() call - not once per PrekeyStore file access. A
                // prior revision of this code re-resolved via dmKeystorePassphraseSource() on every
                // single provider.get() call, on the theory that a captured-then-zeroed local was
                // the only danger to guard against. That is unsafe: resolveKeystorePassphrase() is
                // NOT idempotent when LAPISNET_KEYSTORE_PASSPHRASE is unset - with an attached
                // console it calls System.console().readPassword() again on every invocation, and
                // on EOF/a detached console it returns null. Re-resolving per call therefore risked
                // (a) a LATER call returning null while an EARLIER one returned the real passphrase,
                // silently downgrading an already-v2-encrypted prekey store to plaintext v1 the next
                // time persistAtomically ran (see its `if (passphrase != null) encodeEncrypted else
                // encode` branch below), (b) the same later-null case inside
                // withExclusiveFileAccess throwing KeystoreDecryptionException and hard-aborting
                // start()/a runtime prekey operation while the exclusive OS file lock was held
                // (self-DoS for every other prekey operation), and (c) an interactive operator being
                // prompted many times per start() (plus twice more per consumeOneTimePrekey at
                // runtime) with every prompt a chance to type a DIFFERENT passphrase than the one
                // the store was actually encrypted with, silently re-encrypting it and permanently
                // locking the operator out on the next start(). Resolving once here and handing out
                // `copyOf()` copies below avoids all of that while still avoiding the ORIGINAL
                // zeroed-shared-array bug this was meant to fix: PrekeyStore/DmSessionManager only
                // ever zero the copy they were handed, never this master, and this master itself is
                // zeroed exactly once, in [stop] (see [dmPrekeyMasterPassphrase]'s doc comment
                // there).
                val dmPrekeyMasterPassphrase = dmKeystorePassphraseSource()
                // Zeroed on a rollback too, not just on a successful stop() - without this, a
                // failure anywhere between here and the final `return BrowserServer(...)` (Netty
                // port conflict, a later step throwing, ...) would leak this master passphrase for
                // the remainder of the JVM process's lifetime instead of it ever being zeroed.
                cleanupOnFailure += { dmPrekeyMasterPassphrase?.fill('\u0000') }
                if (dmPrekeyMasterPassphrase == null) {
                    logger.warn {
                        "no keystore passphrase available for the DM prekey/session stores (set " +
                            "LAPISNET_KEYSTORE_PASSPHRASE, or run with an interactive console) - " +
                            "DM prekeys will be stored UNENCRYPTED on disk (legacy v1 keystore " +
                            "format, protected only by POSIX file permissions, exactly like " +
                            "BrowserMain's identity-keystore fallback) and DM sessions will be " +
                            "encrypted at rest under a fixed, publicly-known placeholder " +
                            "passphrase instead of a real secret"
                    }
                }
                // Hands PrekeyStore an INDEPENDENT copy on every get(), never the master array
                // itself. PrekeyStore zeroes whatever CharArray its provider returns the instant it
                // is done with it (see withExclusiveFileAccess/persistAtomically below) - handing it
                // dmPrekeyMasterPassphrase directly would leave the master all-NUL after the very
                // first file access, permanently breaking decryption of a store that was correctly
                // encrypted with the real passphrase at creation/open time. `null` here (when
                // dmPrekeyMasterPassphrase is null) is honest, not a lie-then-placeholder: PrekeyStore
                // treats a null-returning provider exactly like FileIdentityRepository does for the
                // identity keystore - v1, unencrypted, POSIX-permission-only, and auto-migrated to v2
                // the moment a real passphrase shows up (see PrekeyStore.open's own doc comment).
                val dmPrekeyPassphraseProvider =
                    PassphraseProvider { dmPrekeyMasterPassphrase?.copyOf() }
                // Open-first: PrekeyStore.create refuses to overwrite an existing file (a silent
                // overwrite would destroy one-time-prekey consumption tombstones and re-enable reuse),
                // so every BrowserServer.start() call after the very first one on the same
                // dataDirectory MUST go through open(), never unconditionally through create() - see
                // PrekeyStore.create's own doc comment for the `check(!file.exists())` this would
                // otherwise trip on a second process start.
                val prekeyStoreDirectory = dataDirectory.resolve("dm-prekeystore")
                val prekeyStore =
                    PrekeyStore.open(prekeyStoreDirectory, passphraseProvider = dmPrekeyPassphraseProvider)
                        ?: PrekeyStore.create(
                            prekeyStoreDirectory,
                            identity,
                            passphraseProvider = dmPrekeyPassphraseProvider,
                        )
                // Another independent copy for the DM session store, which - unlike PrekeyStore -
                // has no unencrypted mode and therefore still needs insecureDefaultDmPassphrase()'s
                // placeholder when no real passphrase is configured (see that function's own doc
                // comment for why this is a narrower, separately-accepted trade-off). Must be a copy,
                // not dmPrekeyMasterPassphrase itself: DmSessionManager.attach zeroes the exact
                // CharArray instance it is handed once during attach() (see its own doc comment),
                // which would zero the master here too if passed directly.
                val dmPassphrase = dmPrekeyMasterPassphrase?.copyOf() ?: insecureDefaultDmPassphrase()
                val dmStore = DmStore()
                val dmAcceptedContacts = DmAcceptedContacts()
                val dmSessionManager =
                    DmSessionManager.attach(
                        identity,
                        prekeyStore,
                        node,
                        peerDirectory,
                        prekeyBundleGossip,
                        mailboxGossip,
                        storage,
                        pubsub,
                        dataDirectory.resolve("dm-sessions"),
                        dmPassphrase,
                        // acceptedContacts wired so an outbound send (DmApi.kt's `POST /api/dm/{peerHex}`)
                        // marks the recipient accepted - see DmAcceptedContacts's own doc comment for
                        // "this node itself sent that peer a message" being one of the two ways a peer
                        // becomes accepted. `acceptance` (a DmAcceptanceCheck with real gates) is
                        // DELIBERATELY left null/unwired this wave - see DmApi.kt's class doc comment for
                        // the full, explicit scope-cut statement (mirrors lapis-net-mail's own identical
                        // "MailAcceptanceCheck has zero production callers" state).
                        acceptedContacts = dmAcceptedContacts,
                    )
                cleanupOnFailure += { runCatching { dmSessionManager.stop() } }
                dmSessionManager.addInboundListener { message -> dmStore.recordInbound(message) }
                // One-shot publish so this node is dialable/handshakeable for DM as soon as it starts -
                // see DM_SELF_RECORD_TTL_SECONDS's own doc comment for why this wave does not also
                // periodically re-publish (a stated scope cut: a browser session running longer than
                // the TTL needs a restart to remain DM-reachable by a peer that has not cached an
                // earlier record/bundle).
                val selfRecordNotValidAfter = Instant.now().epochSecond + DM_SELF_RECORD_TTL_SECONDS
                peerDirectory.announce(
                    PeerRecord.create(
                        identity = identity,
                        addresses = node.listenAddresses(),
                        capabilities = setOf(PeerCapability.DM),
                        // Wall-clock epoch millis, NOT System.nanoTime() - nanoTime's absolute value is
                        // boot-relative and meaningless across JVM/machine restarts (see
                        // PeerPresenceAnnouncer's own doc comment on this exact restriction), but
                        // PeerRecordIndex.add rejects any sequenceNumber lower than the highest one it has
                        // already seen for this identity as an anti-rollback measure. A restarted node
                        // publishing a smaller nanoTime-derived sequence number than its own pre-restart
                        // value would be permanently unresolvable/undialable by every peer that stayed up
                        // across the restart. Epoch millis only goes backwards if the system clock itself
                        // is set backwards, which is a far narrower and more honest failure mode.
                        sequenceNumber = Instant.now().toEpochMilli(),
                        notValidAfterEpochSecond = selfRecordNotValidAfter,
                    ),
                )
                prekeyBundleGossip.announce(prekeyStore.publishBundle(identity, selfRecordNotValidAfter))

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
                        dm = DmApiDependencies(peerDirectory, dmSessionManager, dmStore, dmAcceptedContacts),
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
                cleanupOnFailure += {
                    runCatching { httpEngine.stop(HTTP_STOP_GRACE_PERIOD_MILLIS, HTTP_STOP_TIMEOUT_MILLIS) }
                }
                val boundPort =
                    runBlocking {
                        httpEngine.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    }

                logger.info {
                    "BrowserServer listening on http://$httpHost:$boundPort (peer ${node.peerId.toBase58()})"
                }
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
                    peerDirectory,
                    prekeyBundleGossip,
                    mailboxGossip,
                    dmSessionManager,
                    prekeyStore,
                    dmPrekeyMasterPassphrase,
                    dmStore,
                    httpEngine,
                    boundPort,
                )
            } catch (e: Exception) {
                cleanupOnFailure.asReversed().forEach { action -> runCatching(action) }
                throw e
            }
        }
    }
}
