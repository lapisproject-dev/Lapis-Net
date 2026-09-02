package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import java.nio.file.Files

private object RestartTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/**
 * Regression coverage for the V0.8.6b DM wiring bug where [BrowserServer.start] unconditionally
 * called `PrekeyStore.create(...)` on every invocation. [net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore.create]
 * refuses to overwrite an existing `.lnpk` file (`check(!file.exists())`), so a SECOND
 * [BrowserServer.start] call against the same persistent `dataDirectory` - exactly what
 * `BrowserMain`'s real process entry point does on every restart, since
 * `defaultBrowserDataDirectory()` is a fixed, persistent path under `LAPISNET_HOME` - used to throw
 * an uncaught `IllegalStateException` and take down the entire node (Timeline/Mail/Peers/HTTP, not
 * just DM), not just fail to restart the DM prekey store. [BrowserServer.start] must instead open
 * an existing prekey store when one is already on disk, and only create a fresh one on a genuinely
 * first start.
 */
class BrowserServerRestartTest :
    FunSpec({
        test("BrowserServer.start() against a persistent dataDirectory that already has DM state does not throw") {
            val identity = DualKeyIdentity.generate()
            val dataDirectory = Files.createTempDirectory("browser-restart-test")

            val first =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                )
            try {
                first.boundPort shouldNotBe 0
            } finally {
                first.stop()
            }

            // The real regression: BrowserServer.start() a SECOND time against the SAME
            // dataDirectory - which now already has a `dm-prekeystore/default.lnpk` file on disk
            // from the first start above - must succeed rather than throwing
            // `IllegalStateException: refusing to overwrite existing prekey store file ...`.
            val second =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                )
            try {
                second.boundPort shouldNotBe 0
            } finally {
                second.stop()
            }

            // A third start proves it is not merely "create, then open once" - the prekey store
            // keeps opening cleanly across arbitrarily many restarts.
            val third =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                )
            try {
                third.boundPort shouldNotBe 0
            } finally {
                third.stop()
            }
        }

        test("BrowserServer.start() with no configured keystore passphrase does not crash across a restart") {
            // Exercises the INSECURE_DEFAULT_DM_PASSPHRASE fallback path (no
            // LAPISNET_KEYSTORE_PASSPHRASE set in this test environment) across two starts against
            // the same dataDirectory - regression coverage for the fallback passphrase having been
            // a single shared, mutable CharArray that DmSessionManager.attach zeroes after first
            // use, which would make every subsequent start() derive its session-store key from an
            // all-NUL array instead of the documented placeholder literal.
            val identity = DualKeyIdentity.generate()
            val dataDirectory = Files.createTempDirectory("browser-restart-test-no-passphrase")

            val first =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                )
            first.stop()

            val second =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                )
            try {
                second.boundPort shouldNotBe 0
            } finally {
                second.stop()
            }
        }

        test(
            "BrowserServer.start() with a REAL configured keystore passphrase decrypts the DM " +
                "prekey store across a restart and a later publishBundle call",
        ) {
            // Regression coverage for the CRITICAL bug where dmPrekeyPassphraseProvider was built
            // over a captured `configuredDmPassphrase` local that got zeroed (`fill(NUL)`)
            // immediately after the FIRST open()/create() call - every LATER provider.get()
            // invocation (PrekeyStore.withExclusiveFileAccess/persistAtomically, invoked here by
            // both this start() call's own self-publish AND republishSelfForDmTesting() below) then
            // decrypted with an all-NUL CharArray instead of the real passphrase and threw
            // KeystoreDecryptionException (AEADBadTagException: Tag mismatch). Uses the
            // `dmKeystorePassphraseSource` test seam rather than the LAPISNET_KEYSTORE_PASSPHRASE
            // env var, so this test is deterministic and independent of the process environment.
            val identity = DualKeyIdentity.generate()
            val dataDirectory = Files.createTempDirectory("browser-restart-test-real-passphrase")
            val realPassphrase = "correct-horse-battery-staple-test-passphrase"
            val passphraseSource = { realPassphrase.toCharArray() }

            val first =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                    dmKeystorePassphraseSource = passphraseSource,
                )
            try {
                first.boundPort shouldNotBe 0
                // Forces a SECOND decrypt within the same process/start() call, exactly like the
                // CRITICAL finding's reproduction (start()'s own initial publishBundle already
                // decrypted once via PrekeyStore.create/open; this is the "later" call that the
                // zeroed-variable bug broke).
                first.republishSelfForDmTesting()
            } finally {
                first.stop()
            }

            // The real restart: a SECOND BrowserServer.start() against the same dataDirectory with
            // the SAME real passphrase must open (not fail to decrypt) the store created above, and
            // a publishBundle call afterward must succeed too.
            val second =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                    karmaAnchorSource = RestartTestNoAnchorSource,
                    dmKeystorePassphraseSource = passphraseSource,
                )
            try {
                second.boundPort shouldNotBe 0
                second.republishSelfForDmTesting()
            } finally {
                second.stop()
            }
        }
    })
