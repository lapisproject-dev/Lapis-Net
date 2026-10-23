package net.lapisphilosophorum.lapisnet.browser

import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.call.CallMediaEngine
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtLimits
import net.lapisphilosophorum.lapisnet.dm.MailboxRedeliveryScheduler
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import net.lapisphilosophorum.lapisnet.networking.relay.AutoRelayConfig
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal object WiringNoAnchor : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/** A fresh copy on every call - the browser zeroes what it is handed. */
internal fun testPassphrase(): CharArray = "wiring-test-passphrase".toCharArray()

/**
 * Starts a real [BrowserServer] on an OS-assigned loopback port with the V0.9.15 seams exposed. Background jobs default to
 * a very long first delay so that a test which does not care about them is not disturbed by them.
 */
internal fun startWiredTestServer(
    identity: DualKeyIdentity = DualKeyIdentity.generate(),
    config: BrowserConfig = BrowserConfig.DEFAULT,
    dataDirectory: Path = Files.createTempDirectory("wired-test"),
    callMediaEngineFactory: (() -> CallMediaEngine?)? = { FakeBrowserCallMediaEngine() },
    callRemoteOverride: CallRemote? = null,
    directoryDhtLimits: DirectoryDhtLimits = DirectoryDhtLimits(),
    dhtMaintenanceInterval: Duration = 60.seconds,
    dhtMaintenanceInitialDelay: Duration = 600.seconds,
    dhtMaintenanceHook: (() -> Unit)? = null,
    selfRecordCheckInterval: Duration = 600.seconds,
    mailboxRedeliverIntervalSeconds: Long = MailboxRedeliveryScheduler.DEFAULT_REDELIVER_INTERVAL_SECONDS,
    mailboxPollIntervalSeconds: Long = 60L,
    acceptanceRefreshInterval: Duration = 600.seconds,
    autoRelayConfig: AutoRelayConfig = AutoRelayConfig(),
    karmaLookupOverride: KarmaScoreLookup? = null,
    listenAddress: Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/0"),
    httpPort: Int = 0,
    anonymityLocator: ((net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip) -> Any)? = null,
): BrowserServer =
    BrowserServer.start(
        identity = identity,
        httpPort = httpPort,
        listenAddress = listenAddress,
        dataDirectory = dataDirectory,
        karmaAnchorSource = WiringNoAnchor,
        dmKeystorePassphraseSource = ::testPassphrase,
        callMediaEngineFactory = callMediaEngineFactory,
        callRemoteOverride = callRemoteOverride,
        config = config,
        directoryDhtLimits = directoryDhtLimits,
        dhtMaintenanceInterval = dhtMaintenanceInterval,
        dhtMaintenanceInitialDelay = dhtMaintenanceInitialDelay,
        dhtMaintenanceHook = dhtMaintenanceHook,
        selfRecordCheckInterval = selfRecordCheckInterval,
        mailboxRedeliverIntervalSeconds = mailboxRedeliverIntervalSeconds,
        mailboxPollIntervalSeconds = mailboxPollIntervalSeconds,
        acceptanceRefreshInterval = acceptanceRefreshInterval,
        autoRelayConfig = autoRelayConfig,
        karmaLookupOverride = karmaLookupOverride,
        anonymityLocator = anonymityLocator,
    )

/** A raw HTTP/1.1 exchange, because the JDK client forbids setting `Host`. Returns `(status, body)`. */
internal fun rawHttp(
    port: Int,
    method: String,
    path: String,
    headers: Map<String, String> = emptyMap(),
    body: String? = null,
): Pair<Int, String> {
    Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 15_000
        val bytes = body?.toByteArray(Charsets.UTF_8)
        val request =
            buildString {
                append("$method $path HTTP/1.1\r\n")
                headers.forEach { (k, v) -> append("$k: $v\r\n") }
                if (bytes != null) append("Content-Length: ${bytes.size}\r\n")
                append("Connection: close\r\n\r\n")
            }
        socket.getOutputStream().write(request.toByteArray(Charsets.UTF_8))
        if (bytes != null) socket.getOutputStream().write(bytes)
        socket.getOutputStream().flush()
        val response = socket.getInputStream().readBytes().toString(Charsets.UTF_8)
        val status =
            response
                .lineSequence()
                .first()
                .split(' ')[1]
                .toInt()
        return status to response.substringAfter("\r\n\r\n", "")
    }
}

internal fun hexOfKey(key: Secp256k1PublicKey): String = key.bytes.joinToString("") { "%02x".format(it) }

internal fun awaitCondition(
    timeoutSeconds: Long,
    message: String,
    condition: () -> Boolean,
) {
    val deadline = System.nanoTime() + timeoutSeconds * 1_000_000_000L
    while (System.nanoTime() < deadline) {
        if (condition()) return
        Thread.sleep(100)
    }
    check(condition()) { message }
}
