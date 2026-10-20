package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository
import net.lapisphilosophorum.lapisnet.identity.PassphraseProvider
import net.lapisphilosophorum.lapisnet.identity.defaultIdentityDirectory
import net.lapisphilosophorum.lapisnet.identity.resolveKeystorePassphrase
import net.lapisphilosophorum.lapisnet.networking.BootstrapConfig
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import kotlin.system.exitProcess

private val logger = KotlinLogging.logger {}

/** Resolves the default on-disk Nabu blockstore directory for the browser MVP:
 * `$LAPISNET_HOME/browser-storage`, or `~/.lapisnet/browser-storage` - a sibling of
 * [defaultIdentityDirectory]'s `identity` directory under the same `LAPISNET_HOME` root. */
private fun defaultBrowserDataDirectory(): Path {
    val home = System.getenv("LAPISNET_HOME") ?: (System.getProperty("user.home") + "/.lapisnet")
    return Path.of(home, "browser-storage")
}

/**
 * [PassphraseProvider] for a real process entry point (V0.4): defers to
 * [resolveKeystorePassphrase] (env var, else interactive console, else `null`) and, on `null`,
 * logs a prominent warning rather than failing - a headless process with neither an env var nor a
 * console (e.g. this project's own CI/demo runs) must keep working exactly as it did before V0.4,
 * just with the identity stored unencrypted (legacy v1 keystore, POSIX permissions only), never
 * hard-failing on a missing passphrase.
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

/** Exit code for an invalid command line, environment or `browser.properties` (nothing is started). */
internal const val EXIT_INVALID_CONFIGURATION = 2

fun main(args: Array<String>) {
    val code = runBrowserMain(args.toList(), System.getenv(), System.out, System.err)
    if (code != 0) exitProcess(code)
}

/**
 * The testable body of [main]: returns instead of exiting. `--help` prints the options and returns `0`; an invalid
 * configuration prints ONE line (no stack trace) to [err] and returns [EXIT_INVALID_CONFIGURATION] without starting
 * anything. Otherwise it starts the server and blocks until the JVM shuts down.
 */
internal fun runBrowserMain(
    args: List<String>,
    env: Map<String, String>,
    out: PrintStream,
    err: PrintStream,
    startServer: (BrowserConfig) -> Unit = ::runBrowserServer,
): Int {
    if ("--help" in args || "-h" in args) {
        out.println("Usage: lapisnet-browser [--key=value ...]")
        out.println(NodeWiringOptions.HELP_TEXT)
        out.println(BrowserConfig.HELP_TEXT)
        return 0
    }
    val config =
        try {
            BrowserConfig.load(args, env)
        } catch (e: InvalidWiringOptionException) {
            err.println("lapisnet-browser: ${e.message}")
            return EXIT_INVALID_CONFIGURATION
        }
    startServer(config)
    return 0
}

private fun runBrowserServer(config: BrowserConfig) {
    logger.info { "Starting Lapis Net Browser (V0.9.15 wiring)" }

    // Load-or-generate the identity exactly like LapisNetCli.runIdentityAndStorageDemo() does -
    // this process holds the same kind of real signing key, so identity handling must be
    // consistent with the CLI's established, permission-hardened FileIdentityRepository path.
    // As of V0.4, a real passphrase (env var or interactive console) enables encryption at rest -
    // see warningPassphraseProvider()'s doc comment for the headless/no-passphrase fallback.
    val repository = FileIdentityRepository(defaultIdentityDirectory(), warningPassphraseProvider())
    val identity = repository.loadDefault() ?: repository.generateAndSave()

    val dataDirectory = defaultBrowserDataDirectory()
    Files.createDirectories(dataDirectory)

    val bootstrapPeers = BootstrapConfig.resolve()
    val listenAddress = BootstrapConfig.resolveListenAddress()
    if (bootstrapPeers.isEmpty() && listenAddress.toString().contains("/127.0.0.1/")) {
        logger.warn {
            "no bootstrap peers configured (set ${BootstrapConfig.ENV_VAR} or a bootstrap.peers file) and " +
                "listen address is loopback-only (set ${BootstrapConfig.LISTEN_ENV_VAR} for a real, " +
                "reachable address) - this node will only ever reach peers via mDNS or a manual " +
                "POST /api/peers/connect"
        }
    }
    logger.info { "resolved ${bootstrapPeers.size} bootstrap peer(s); libp2p listen address: $listenAddress" }

    val server =
        BrowserServer.start(
            identity = identity,
            bootstrapPeers = bootstrapPeers,
            listenAddress = listenAddress,
            dataDirectory = dataDirectory,
            config = config,
        )

    println("Lapis Net Browser is running.")
    println("Open http://127.0.0.1:${server.boundPort} in your browser.")
    if (server.callsAvailable) {
        // Console only, deliberately NOT logger.info: the fragment carries the call session token and
        // a log appender could persist it to disk for the whole process lifetime.
        println("Open calls: ${server.callRemoteControlUrl}")
        println("  (same device only - the link contains a one-time-per-start secret)")
        logger.info { "call remote-control token issued" }
    } else {
        println("Calls are not available on this node (no usable WebRTC native library).")
    }
    println("Identity fingerprint: ${identity.secp256k1KeyPair.publicKey.fingerprint()}")
    println("Press Ctrl+C to stop.")

    // httpEngine.start(wait = false) inside BrowserServer.start() already returned - this thread
    // must stay alive for the process to keep serving, so it blocks on a latch that only a JVM
    // shutdown hook (SIGINT/SIGTERM) ever counts down, after cleanly stopping the server.
    val shutdownLatch = CountDownLatch(1)
    Runtime.getRuntime().addShutdownHook(
        Thread {
            logger.info { "shutting down Lapis Net Browser" }
            runCatching { server.stop() }
            shutdownLatch.countDown()
        },
    )
    shutdownLatch.await()
}
